import http from "http";
import { URL } from "url";
import { randomUUID } from "crypto";
import { generateCodeVerifier, generateCodeChallenge, generateState } from "./pkce.js";
import { validateMicrosoftEndpoint, decodeJwtPayload } from "../kiroExternalIdp.js";
import { KiroService } from "../services/kiro.js";

// kiroSso.js implements the Kiro hosted browser sign-in flow — the same flow the
// Kiro IDE uses at https://app.kiro.dev/signin. It federates Google, GitHub AND
// enterprise identity providers (Microsoft 365 / Entra ID) behind one PKCE
// authorization-code flow. This is the only way an Entra tenant account (neither
// an AWS Builder ID nor an IAM Identity Center account) can sign in to Kiro.
//
// Two legs, one transient loopback listener on the fixed redirect port:
//   - Social (Google/GitHub): the portal redirects the authorization code
//     straight back to the loopback redirect; exchanged at the Kiro social token
//     endpoint.
//   - Enterprise / external IdP (Entra): the portal redirects to /signin/callback
//     with the IdP descriptor (issuer_url, client_id, scopes) instead of a code.
//     We drive a SECOND OIDC authorization-code+PKCE flow directly against Entra
//     (loopback redirect to /oauth/callback) and exchange the code at the Entra
//     token endpoint. The resulting IdP access token is used as the runtime bearer.
//
// Ported from kiro-reverse-api/auth/kiro_sso.go. Same Start/Poll/Cancel session
// pattern the admin panel drives.

const KIRO_SIGNIN_BASE = "https://app.kiro.dev/signin";
// The portal validates this fixed loopback redirect. Host is "localhost" (what
// the portal expects) while the listener binds 127.0.0.1; the browser resolving
// "localhost" to loopback bridges the two. With `ssh -L 3128:127.0.0.1:3128` the
// operator's browser reaches the listener running on the 9router host.
const KIRO_REDIRECT_URI = "http://localhost:3128";
const KIRO_REDIRECT_PORT = 3128;
const KIRO_REDIRECT_FROM = "KiroIDE";
// Path the enterprise (external IdP) leg redirects the authorization code back
// to — distinct from the portal's /signin/callback so the two legs are separable.
const KIRO_OAUTH_CALLBACK_PATH = "/oauth/callback";
// Cognito-backed social code-exchange endpoint. Deliberately different from the
// social refresh endpoint (/refreshToken): login exchanges at /oauth/token.
const KIRO_SOCIAL_TOKEN_URL = "https://prod.us-east-1.auth.desktop.kiro.dev/oauth/token";
const KIRO_SSO_LOGIN_TIMEOUT_MS = 10 * 60 * 1000;
const DEFAULT_REGION = "us-east-1";

// Session registry keyed by sessionId.
const sessions = new Map();

function emailFromToken(token) {
  const payload = decodeJwtPayload(token);
  if (!payload) return null;
  for (const key of ["email", "preferred_username", "upn", "unique_name", "sub"]) {
    const v = payload[key];
    if (typeof v === "string" && v.includes("@")) return v;
  }
  return null;
}

// startKiroSsoLogin generates PKCE codes, binds the loopback listener, and
// returns the session id plus the hosted sign-in URL the operator must open.
export async function startKiroSsoLogin(region = DEFAULT_REGION) {
  const safeRegion = region || DEFAULT_REGION;
  const verifier = generateCodeVerifier();
  const challenge = generateCodeChallenge(verifier);
  const state = generateState();
  const sessionId = randomUUID();

  const session = {
    id: sessionId,
    verifier, // social-leg PKCE verifier
    state, // portal anti-CSRF state echoed on the social redirect
    region: safeRegion,
    expiresAt: Date.now() + KIRO_SSO_LOGIN_TIMEOUT_MS,
    capture: null, // set once the listener captures a code (or error)
    leg2: null, // enterprise leg-2 context, set when the IdP descriptor arrives
    server: null,
    timer: null,
  };

  await bindListener(session);
  sessions.set(sessionId, session);

  // Self-teardown at the deadline: free the loopback port even if the operator
  // abandons the sign-in and polling stops. The redirect port is fixed, so a
  // stuck listener would block every subsequent SSO login.
  session.timer = setTimeout(() => {
    closeSession(session);
    sessions.delete(sessionId);
  }, KIRO_SSO_LOGIN_TIMEOUT_MS);

  const params = new URLSearchParams({
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    redirect_uri: KIRO_REDIRECT_URI,
    redirect_from: KIRO_REDIRECT_FROM,
  });
  const signInUrl = `${KIRO_SIGNIN_BASE}?${params.toString()}`;

  return { sessionId, signInUrl };
}

// pollKiroSsoAuth reports login status. Returns { status: "pending" } until the
// listener captures a code, then exchanges it and returns the resolved
// credential with status "completed". Terminal failures throw.
export async function pollKiroSsoAuth(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) throw new Error("session not found or expired");

  if (session.capture) {
    // Terminal: a code (or error) was captured. Tear down regardless of outcome.
    const capture = session.capture;
    closeSession(session);
    sessions.delete(sessionId);
    if (capture.error) throw new Error(capture.error);
    return { status: "completed", credential: await exchangeCapture(session, capture) };
  }

  if (Date.now() > session.expiresAt) {
    closeSession(session);
    sessions.delete(sessionId);
    throw new Error("SSO login timed out");
  }

  return { status: "pending" };
}

// cancelKiroSsoLogin tears an in-flight session down immediately (operator
// cancelled), freeing the loopback port without waiting for the deadline.
export function cancelKiroSsoLogin(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return;
  closeSession(session);
  sessions.delete(sessionId);
}

function closeSession(session) {
  if (session.timer) {
    clearTimeout(session.timer);
    session.timer = null;
  }
  if (session.server) {
    try {
      session.server.close();
    } catch {
      // ignore
    }
    session.server = null;
  }
}

// exchangeCapture swaps a captured authorization code for tokens and assembles
// the credential shape createProviderConnection expects (matches import-cli-proxy).
async function exchangeCapture(session, capture) {
  if (capture.kind === "external_idp") {
    const { accessToken, refreshToken, expiresIn } = await exchangeExternalIdpCode(capture);
    const kiro = new KiroService();
    let profileArn = null;
    try {
      // External IdP tokens resolve their profile against the Kiro management
      // gateway (not codewhisperer.amazonaws.com) — pass the auth method so
      // listAvailableProfiles routes to the right host with TokenType header.
      profileArn = await kiro.listAvailableProfiles(accessToken, session.region, "external_idp");
    } catch {
      // profileArn resolves lazily at runtime if this fails; not fatal to login.
    }
    const expiresAt = new Date(Date.now() + (expiresIn || 3600) * 1000).toISOString();
    return {
      accessToken,
      refreshToken,
      expiresAt,
      email: emailFromToken(accessToken),
      providerSpecificData: {
        authMethod: "external_idp",
        provider: "Microsoft365",
        clientId: capture.clientId,
        tokenEndpoint: capture.tokenEndpoint,
        scope: capture.scopes,
        region: session.region,
        ...(profileArn ? { profileArn } : {}),
      },
    };
  }

  // Social leg (Google/GitHub) — kept for flow compatibility.
  const { accessToken, refreshToken, expiresIn, profileArn } = await exchangeSocialCode(
    capture.code,
    session.verifier
  );
  const expiresAt = new Date(Date.now() + (expiresIn || 3600) * 1000).toISOString();
  return {
    accessToken,
    refreshToken,
    expiresAt,
    email: emailFromToken(accessToken),
    providerSpecificData: {
      authMethod: "social",
      provider: "Kiro SSO",
      region: session.region,
      ...(profileArn ? { profileArn } : {}),
    },
  };
}

// --- Loopback callback listener (state machine across the legs) -------------

// bindListener binds the SSO callback listener on 127.0.0.1:3128 and serves the
// redirect state machine. Rejects if the port is already in use (a prior login
// still holds it).
function bindListener(session) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => handleCallback(session, req, res));
    server.on("error", (err) => {
      if (err.code === "EADDRINUSE") {
        reject(new Error(`Port ${KIRO_REDIRECT_PORT} is already in use (another Kiro SSO login may be in progress).`));
      } else {
        reject(err);
      }
    });
    server.listen(KIRO_REDIRECT_PORT, "127.0.0.1", () => {
      session.server = server;
      resolve();
    });
  });
}

function deliver(session, capture) {
  if (!session.capture) session.capture = capture;
}

// handleCallback implements the redirect state machine: enterprise leg-1
// descriptor -> 302 to Entra; enterprise leg-2 code at /oauth/callback;
// otherwise the social code.
async function handleCallback(session, req, res) {
  // Only browser GET redirects are expected.
  if (req.method !== "GET") {
    res.writeHead(405);
    res.end();
    return;
  }

  const url = new URL(req.url, KIRO_REDIRECT_URI);
  const q = url.searchParams;
  const path = url.pathname;

  // --- Enterprise leg-1: external IdP descriptor (no code) ---
  // Gate on path != /oauth/callback so a forged /oauth/callback?issuer_url=...
  // cannot be routed here and reset an in-flight leg-2.
  const loginOption = (q.get("login_option") || "").trim().toLowerCase();
  const issuerUrl = (q.get("issuer_url") || "").trim();
  if (path !== KIRO_OAUTH_CALLBACK_PATH && (loginOption === "external_idp" || issuerUrl !== "")) {
    // Single-shot: once leg-2 is in flight, ignore further descriptors so a
    // stray or forged local request cannot reset/hijack the active login.
    if (session.leg2) {
      res.writeHead(204);
      res.end();
      return;
    }
    const clientId = (q.get("client_id") || "").trim();
    const scopes = (q.get("scopes") || "").trim();
    const loginHint = (q.get("login_hint") || "").trim();
    if (!clientId) {
      writeResultPage(res, false);
      deliver(session, { error: "invalid external IdP descriptor (missing client_id)" });
      return;
    }
    let endpoints;
    try {
      endpoints = await oidcDiscover(issuerUrl);
    } catch (err) {
      writeResultPage(res, false);
      deliver(session, { error: err.message });
      return;
    }
    const verifier = generateCodeVerifier();
    const state2 = generateState();
    const redirectUri = KIRO_REDIRECT_URI + KIRO_OAUTH_CALLBACK_PATH;
    session.leg2 = {
      state: state2,
      verifier,
      tokenEndpoint: endpoints.tokenEndpoint,
      issuerUrl,
      clientId,
      scopes,
      redirectUri,
    };
    const authUrl = externalIdpAuthorizeUrl(
      endpoints.authEndpoint,
      clientId,
      redirectUri,
      scopes,
      generateCodeChallenge(verifier),
      state2,
      loginHint
    );
    // Redirect the SAME browser tab on to the Entra login page.
    res.writeHead(302, { Location: authUrl });
    res.end();
    return;
  }

  // --- Enterprise leg-2: IdP authorization code at /oauth/callback ---
  if (path === KIRO_OAUTH_CALLBACK_PATH) {
    const ctx2 = session.leg2;
    const code = (q.get("code") || "").trim();
    const state = (q.get("state") || "").trim();
    const errParam = (q.get("error") || "").trim();
    // Ignore callbacks that don't match the in-flight leg-2 state.
    if (!ctx2 || !state || state !== ctx2.state) {
      res.writeHead(204);
      res.end();
      return;
    }
    if (errParam) {
      const desc = (q.get("error_description") || "").trim();
      writeResultPage(res, false);
      deliver(session, { error: `external IdP authorization error: ${errParam} ${desc}`.trim() });
      return;
    }
    if (!code) {
      res.writeHead(204);
      res.end();
      return;
    }
    writeResultPage(res, true);
    deliver(session, {
      kind: "external_idp",
      code,
      tokenEndpoint: ctx2.tokenEndpoint,
      issuerUrl: ctx2.issuerUrl,
      clientId: ctx2.clientId,
      scopes: ctx2.scopes,
      redirectUri: ctx2.redirectUri,
      codeVerifier: ctx2.verifier,
    });
    return;
  }

  // --- Social leg-1: Cognito authorization code ---
  const code = (q.get("code") || "").trim();
  const errParam = (q.get("error") || "").trim();
  const state = (q.get("state") || "").trim();
  if (!code && !errParam) {
    res.writeHead(204);
    res.end();
    return;
  }
  if (!session.state || state !== session.state) {
    res.writeHead(204);
    res.end();
    return;
  }
  if (errParam) {
    const desc = (q.get("error_description") || "").trim();
    writeResultPage(res, false);
    deliver(session, { error: `SSO authorization error: ${errParam} ${desc}`.trim() });
    return;
  }
  writeResultPage(res, true);
  deliver(session, { kind: "social", code });
}

// --- OIDC discovery + token exchange (enterprise / external IdP leg) ---------

// oidcDiscover fetches the OpenID Connect discovery document for issuerUrl and
// returns its authorization and token endpoints. The issuer and BOTH discovered
// endpoints are validated against the Microsoft host allow-list; redirects are
// NOT followed (so a discovery host cannot bounce the fetch to an internal
// target); no response body is echoed into errors.
async function oidcDiscover(issuerUrl) {
  validateMicrosoftEndpoint(issuerUrl);
  const docUrl = issuerUrl.replace(/\/+$/, "") + "/.well-known/openid-configuration";
  const resp = await fetch(docUrl, {
    method: "GET",
    headers: { Accept: "application/json" },
    redirect: "manual",
  });
  if (!resp.ok) {
    throw new Error(`OIDC discovery failed (status ${resp.status})`);
  }
  let doc;
  try {
    doc = await resp.json();
  } catch {
    throw new Error("failed to parse OIDC discovery document");
  }
  const authEndpoint = doc.authorization_endpoint;
  const tokenEndpoint = doc.token_endpoint;
  if (!authEndpoint || !tokenEndpoint) {
    throw new Error("OIDC discovery document missing authorization_endpoint or token_endpoint");
  }
  validateMicrosoftEndpoint(authEndpoint);
  validateMicrosoftEndpoint(tokenEndpoint);
  return { authEndpoint, tokenEndpoint };
}

// externalIdpAuthorizeUrl builds the Entra authorization-code+PKCE URL the
// browser is redirected to. scopes is passed through verbatim from the portal.
function externalIdpAuthorizeUrl(authEndpoint, clientId, redirectUri, scopes, challenge, state, loginHint) {
  const q = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    redirect_uri: redirectUri,
    scope: scopes,
    code_challenge: challenge,
    code_challenge_method: "S256",
    response_mode: "query",
    state,
  });
  if (loginHint) q.set("login_hint", loginHint);
  return `${authEndpoint}?${q.toString()}`;
}

// exchangeExternalIdpCode exchanges an Entra authorization code (with its PKCE
// verifier) for tokens at the discovered token endpoint. Standard OAuth2
// authorization_code grant for a public client (PKCE, no client secret).
async function exchangeExternalIdpCode(capture) {
  const tokenEndpoint = validateMicrosoftEndpoint(capture.tokenEndpoint);
  const form = new URLSearchParams({
    client_id: capture.clientId,
    grant_type: "authorization_code",
    code: capture.code,
    redirect_uri: capture.redirectUri,
    code_verifier: capture.codeVerifier,
  });
  if (capture.scopes) form.set("scope", capture.scopes);

  const resp = await fetch(tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: form,
  });
  const body = await resp.text();
  let out = {};
  try {
    out = JSON.parse(body);
  } catch {
    // fall through to error handling below
  }
  if (!resp.ok || !out.access_token) {
    const detail = out.error ? `${out.error}: ${out.error_description || ""}`.trim() : body;
    throw new Error(`enterprise SSO token exchange failed (status ${resp.status}): ${detail}`);
  }
  return {
    accessToken: out.access_token,
    refreshToken: out.refresh_token || "",
    expiresIn: out.expires_in || 3600,
  };
}

// exchangeSocialCode exchanges a Cognito authorization code (with its PKCE
// verifier) for Kiro tokens at the social token endpoint. Response is camelCase.
async function exchangeSocialCode(code, codeVerifier) {
  const resp = await fetch(KIRO_SOCIAL_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({ code, code_verifier: codeVerifier, redirect_uri: KIRO_REDIRECT_URI }),
  });
  const body = await resp.text();
  let out = {};
  try {
    out = JSON.parse(body);
  } catch {
    // fall through
  }
  if (!resp.ok || !out.accessToken) {
    throw new Error(`social token exchange failed (status ${resp.status}): ${body}`);
  }
  return {
    accessToken: out.accessToken,
    refreshToken: out.refreshToken || "",
    expiresIn: out.expiresIn || 3600,
    profileArn: out.profileArn || null,
  };
}

// writeResultPage renders a minimal HTML page shown after the final redirect.
function writeResultPage(res, ok) {
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  const msg = ok
    ? "Kiro sign-in complete. You can close this tab and return to 9router."
    : "Kiro sign-in failed. Return to 9router and try again.";
  res.end(
    `<!doctype html><html><head><meta charset="utf-8"><title>Kiro Sign-In</title></head><body style="font-family:sans-serif;padding:2rem"><p>${msg}</p></body></html>`
  );
}

export {
  KIRO_REDIRECT_URI,
  KIRO_REDIRECT_PORT,
  KIRO_OAUTH_CALLBACK_PATH,
  KIRO_SOCIAL_TOKEN_URL,
};
