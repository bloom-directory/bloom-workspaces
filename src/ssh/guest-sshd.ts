import { normalizeAccessMode, workspacePrincipal, type SshAccessMode } from "./contracts.js";
import { parseSshPublicKey } from "../ssh-public-key.js";

export type GuestSshdPlan = {
  principal: string;
  principals: string[];
  directory: { path: "/run/bloom/ssh"; mode: 0o700; uid: 0; gid: 0 };
  files: Array<{ path: string; mode: 0o600 | 0o644; content: string }>;
  hostKeygen: { program: "/usr/bin/ssh-keygen"; args: string[] };
  hostPublicKeyPath: "/run/bloom/ssh/ssh_host_ed25519_key.pub";
  argv: string[];
  hostPort: 22;
};

type GuestSshdPlanInput = { workspaceId: string; wallet: string; caPublicKey: string } & (
  | { mode: SshAccessMode; modes?: never }
  | { modes: readonly SshAccessMode[]; mode?: never }
);

/**
 * Launch one workspace's guest sshd. The runtime may publish port 22 only to a
 * host-private loopback/Unix transport. This config never creates a password or
 * grants root access, and ordinary authorized_keys files are ignored.
 */
export function guestSshdPlan(input: GuestSshdPlanInput): GuestSshdPlan {
  const modes = ("mode" in input ? [input.mode] : [...input.modes]).map((mode) => normalizeAccessMode(mode));
  if (modes.length < 1 || modes.length > 2 || new Set(modes).size !== modes.length) throw new Error("Invalid guest SSH access modes");
  const principals = modes.map((mode) => workspacePrincipal(input.workspaceId, input.wallet, mode));
  const principal = principals[0]!;
  const caPublicKey = parseSshPublicKey(input.caPublicKey).normalized;
  const common = [
    "/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config",
    "-o", "HostKey=/run/bloom/ssh/ssh_host_ed25519_key",
    "-o", "TrustedUserCAKeys=/run/bloom/ssh/user_ca.pub",
    "-o", "AuthorizedPrincipalsFile=/run/bloom/ssh/authorized_principals",
    "-o", "AuthorizedKeysFile=none",
    "-o", "AuthenticationMethods=publickey",
    "-o", "PubkeyAuthentication=yes",
    "-o", "PasswordAuthentication=no",
    "-o", "KbdInteractiveAuthentication=no",
    "-o", "PermitEmptyPasswords=no",
    "-o", "PermitRootLogin=no",
    "-o", "AllowUsers=workspace",
    "-o", "AllowAgentForwarding=no",
    "-o", "AllowStreamLocalForwarding=no",
    "-o", "X11Forwarding=no",
    "-o", "PermitTunnel=no",
    "-o", "PermitUserEnvironment=no",
    "-o", "PermitUserRC=no",
    "-o", "GatewayPorts=no",
    "-o", "LoginGraceTime=20",
    "-o", "MaxAuthTries=3",
    "-o", "ClientAliveInterval=30",
    "-o", "ClientAliveCountMax=2",
  ];
  const modeOptions = modes.length === 2
    ? [
        "-o", "AllowTcpForwarding=local",
        "-o", "PermitOpen=127.0.0.1:2049",
        "-o", "PermitListen=none",
        "-o", "PermitTTY=yes",
        "-o", "MaxSessions=1",
      ]
    : modes[0] === "shell"
    ? [
        "-o", "DisableForwarding=yes",
        "-o", "PermitTTY=yes",
        "-o", "MaxSessions=1",
        "-o", "ForceCommand=/usr/local/libexec/bloom-workspace-shell",
      ]
    : [
        "-o", "AllowTcpForwarding=local",
        "-o", "PermitOpen=127.0.0.1:2049",
        "-o", "PermitListen=none",
        "-o", "PermitTTY=no",
        "-o", "MaxSessions=0",
      ];
  return {
    principal,
    principals,
    directory: { path: "/run/bloom/ssh", mode: 0o700, uid: 0, gid: 0 },
    files: [
      { path: "/run/bloom/ssh/authorized_principals", mode: 0o600, content: `${principals.join("\n")}\n` },
      { path: "/run/bloom/ssh/user_ca.pub", mode: 0o644, content: `${caPublicKey}\n` },
    ],
    hostKeygen: { program: "/usr/bin/ssh-keygen", args: ["-q", "-t", "ed25519", "-N", "", "-f", "/run/bloom/ssh/ssh_host_ed25519_key"] },
    hostPublicKeyPath: "/run/bloom/ssh/ssh_host_ed25519_key.pub",
    argv: [...common, ...modeOptions],
    hostPort: 22,
  };
}
