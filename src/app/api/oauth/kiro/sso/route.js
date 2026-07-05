import { NextResponse } from "next/server";
import { createProviderConnection } from "@/models";
import {
  startKiroSsoLogin,
  pollKiroSsoAuth,
  cancelKiroSsoLogin,
} from "@/lib/oauth/utils/kiroSso";

/**
 * POST /api/oauth/kiro/sso
 * Kiro hosted-portal sign-in (Microsoft 365 / Entra ID enterprise SSO, plus
 * Google/GitHub). Start/Poll/Cancel session pattern driven by the auth modal.
 *
 * Body: { action: "start" | "poll" | "cancel", region?, sessionId? }
 */
export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid or empty request body" }, { status: 400 });
  }

  const action = body?.action;

  try {
    if (action === "start") {
      const { sessionId, signInUrl } = await startKiroSsoLogin(body?.region);
      return NextResponse.json({ sessionId, signInUrl, interval: 2 });
    }

    if (action === "poll") {
      const sessionId = body?.sessionId;
      if (!sessionId) {
        return NextResponse.json({ error: "sessionId is required" }, { status: 400 });
      }

      const result = await pollKiroSsoAuth(sessionId);
      if (result.status === "pending") {
        return NextResponse.json({ completed: false, status: "pending" });
      }

      const cred = result.credential;
      const connection = await createProviderConnection({
        provider: "kiro",
        authType: "oauth",
        accessToken: cred.accessToken,
        refreshToken: cred.refreshToken,
        expiresAt: cred.expiresAt,
        email: cred.email || null,
        providerSpecificData: cred.providerSpecificData,
        testStatus: "active",
      });

      return NextResponse.json({
        completed: true,
        connection: {
          id: connection.id,
          provider: connection.provider,
          email: connection.email,
          authMethod: cred.providerSpecificData?.authMethod,
        },
      });
    }

    if (action === "cancel") {
      if (body?.sessionId) cancelKiroSsoLogin(body.sessionId);
      return NextResponse.json({ success: true });
    }

    return NextResponse.json({ error: "Unknown action" }, { status: 400 });
  } catch (error) {
    return NextResponse.json({ error: error?.message || "Kiro SSO failed" }, { status: 400 });
  }
}
