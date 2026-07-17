/**
 * Kiro client fingerprint headers.
 *
 * The Kiro upstream (both the runtime/management gateway and the streaming
 * CodeWhisperer surface) validates the client `User-Agent` / `x-amz-user-agent`
 * and expects them to look like the Kiro IDE's AWS SDK client. A generic UA
 * (e.g. "AWS-SDK-JS/3.0.0 kiro-ide/1.0.0") is both rejected on some paths
 * (400 "format ... is invalid") and an obvious tell that the traffic is not the
 * real IDE — which raises the odds of the account being flagged/banned.
 *
 * This mirrors buildKiroHeaderValues in the Kiro-Go reference fork:
 *   aws-sdk-js/{sdk} ua/2.1 os/{os}#{osver} lang/js md/nodejs#{node} \
 *     api/{apiName}#{sdk} {mode} KiroIDE-{kiroVer}-{machineId}
 *
 * Two request families use different SDK identities, exactly like the IDE:
 *   - streaming (chat / GenerateAssistantResponse): codewhispererstreaming, m/E
 *   - runtime   (profiles / usage / models):        codewhispererruntime,   m/N,E
 *
 * The machineId is stable per account (see resolveKiroMachineId) so every
 * request from one connection presents the same device identity — again matching
 * the IDE, which sends a fixed machine id for the lifetime of an install.
 */

import { v4 as uuidv4 } from "uuid";
import { createHash } from "crypto";

// Client identity constants — kept aligned with a recent Kiro IDE build.
const KIRO_STREAMING_SDK_VERSION = "1.0.34";
const KIRO_RUNTIME_SDK_VERSION = "1.0.0";
const KIRO_AGENT_OS = "windows";
const KIRO_AGENT_OS_VERSION = "10.0.26200";
const KIRO_NODE_VERSION = "22.21.1";
const KIRO_VERSION = "0.10.32";

/**
 * Derive a stable per-account machine id. Prefers an explicitly stored id
 * (providerSpecificData.machineId), otherwise hashes whatever stable identifier
 * the credential carries so the same account always presents the same id.
 */
export function resolveKiroMachineId(credentials) {
  const explicit = credentials?.providerSpecificData?.machineId;
  if (explicit && typeof explicit === "string") return explicit;

  const seed =
    credentials?.providerSpecificData?.clientId
    || credentials?.refreshToken
    || credentials?.providerSpecificData?.profileArn
    || credentials?.accessToken
    || "kiro-anonymous";
  return createHash("sha256").update(String(seed)).digest("hex");
}

/**
 * Build the Kiro client fingerprint headers for a credential.
 *
 * @param {object} credentials  the account credential
 * @param {"streaming"|"runtime"} mode  streaming for chat, runtime for api calls
 */
export function buildKiroFingerprintHeaders(credentials, mode = "streaming") {
  const isStreaming = mode === "streaming";
  const sdkVersion = isStreaming ? KIRO_STREAMING_SDK_VERSION : KIRO_RUNTIME_SDK_VERSION;
  const apiName = isStreaming ? "codewhispererstreaming" : "codewhispererruntime";
  const apiMode = isStreaming ? "m/E" : "m/N,E";
  const machineId = resolveKiroMachineId(credentials);

  const userAgent =
    `aws-sdk-js/${sdkVersion} ua/2.1 ` +
    `os/${KIRO_AGENT_OS}#${KIRO_AGENT_OS_VERSION} ` +
    `lang/js md/nodejs#${KIRO_NODE_VERSION} ` +
    `api/${apiName}#${sdkVersion} ${apiMode} ` +
    `KiroIDE-${KIRO_VERSION}-${machineId}`;
  const amzUserAgent = `aws-sdk-js/${sdkVersion} KiroIDE-${KIRO_VERSION}-${machineId}`;

  return {
    "User-Agent": userAgent,
    "x-amz-user-agent": amzUserAgent,
    "x-amzn-kiro-agent-mode": "vibe",
    "x-amzn-codewhisperer-optout": "true",
    "amz-sdk-request": "attempt=1; max=1",
    "amz-sdk-invocation-id": uuidv4(),
    "Accept": "application/json",
  };
}

export {
  KIRO_STREAMING_SDK_VERSION,
  KIRO_RUNTIME_SDK_VERSION,
  KIRO_VERSION,
};
