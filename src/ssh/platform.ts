export type SshClientPlatform = "linux" | "macos" | "windows" | "android" | "ios" | "unknown";

export function sshPlatformCapability(platform: SshClientPlatform) {
  switch (platform) {
    case "linux":
    case "macos":
      return { status: "supported" as const, reason: "OpenSSH connects through the authenticated Bloom WebSocket proxy", fallback: "browser-terminal" as const };
    case "windows":
      return { status: "conditional" as const, reason: "Windows requires the optional OpenSSH client plus Node.js for the signed Bloom proxy helper", fallback: "browser-terminal" as const };
    case "android":
    case "ios":
      return { status: "fallback" as const, reason: "Mobile uses the authenticated browser terminal; native SSH configuration is not distributed", fallback: "browser-terminal" as const };
    default:
      return { status: "fallback" as const, reason: "This platform has not passed the native SSH client gate", fallback: "browser-terminal" as const };
  }
}
