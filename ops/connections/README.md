# Private workspace connections

SSH and NFS are optional owner-only connections. They do not open a public guest
port. The control plane authenticates the wallet, accepts only an OpenSSH
Ed25519 **public** key, and returns a short-lived user certificate plus a
high-entropy bearer lease. The user's private key never leaves their device.

The runtime publishes guest SSH only on a host-private loopback or Unix socket.
`SshLeaseManager` checks the wallet, workspace, access mode, token, expiry, and
connection quota before opening that endpoint. Stopping a workspace or revoking
the lease destroys its active streams. Deployments terminate the outer
`bloom-ssh-v1` WebSocket tunnel in the authenticated control plane; the private
endpoint must never be sent to a browser or bound to a public address.
`bloom-ssh-proxy.mjs` is the OpenSSH `ProxyCommand` bridge. It reads the bearer
from a private file and sends it only as an HTTPS Authorization header, never in
argv or a URL.

There are two disjoint certificate modes:

- `shell` permits one PTY, forces `workspace-ssh-session`, rejects one-shot
  remote commands, and disables every kind of forwarding;
- `nfs` permits no PTY or SSH session and only a local forward whose destination
  is guest loopback TCP 2049.

Both modes may share one guest sshd: the global daemon allows the union needed
by the two modes, while critical certificate options force shell certificates
through the workspace helper and NFS certificates through `/bin/false` if they
try to open a session. Certificate extensions independently deny forwarding to
shell certificates and PTYs to NFS certificates.

The runtime installs `workspace-ssh-session` as
`/usr/local/libexec/bloom-workspace-shell`, writes the operator CA **public** key
and the generated principal to `/run/bloom/ssh`, creates an ephemeral guest host
key, and starts the argv returned by `guestSshdPlan`. Passwords, root login,
ordinary `authorized_keys`, agent forwarding, X11, remote forwarding, Unix
socket forwarding, and public port 2049 remain disabled.

## Native NFS reference path

Native NFS is deliberately narrower than browser file access:

1. QEMU attaches the owner's persistent `/workspace` volume.
2. A custom pinned Linux 6.1.155 kernel enables the in-kernel NFSD server. The
   stock Firecracker kernel does not, so Firecracker reports NFS unavailable.
3. The guest exports only `/workspace` to `127.0.0.1`, NFSv4 only, and maps all
   requests to UID/GID 1000. Only the guest's port 2049 is carried by the NFS-mode
   SSH tunnel; mountd and other guest ports are not published. The guest gets a
   workspace-unique hostname before NFSD starts so concurrent local mounts are
   not advertised as the same NFSv4 server.
4. Expiring or revoking the SSH lease tears down the only reachable transport.

`build-nfs-kernel.sh` downloads the pinned kernel.org source and exact
Firecracker v1.16.1 base configuration, checks their SHA-256 digests, applies
`nfsd.config`, builds `vmlinux`, verifies the required settings, and emits the
binary, final configuration, and checksums. Run it in the same reviewed builder
used for guest image artifacts; it needs the standard Linux kernel build tools.
`build-nfs-kernel.sh --print-inputs` prints the immutable upstream versions and
digests without downloading or building them.

Linux uses a hard NFS mount to avoid silent write corruption. If the SSH lease
expires, filesystem operations can wait until the tunnel is restored or the
mount is unmounted; clients should unmount before the displayed lease deadline.

The connection API should return argv arrays from `createNfsClientPlan`, not an
interpolated shell command. Linux is the reference client. macOS uses its native
NFSv4 client but remains a real-device validation gate. Windows is conditional:
it needs built-in OpenSSH, the optional Client for NFS, administrator access to
bind local port 2049, and an NFSv4 compatibility probe; otherwise use browser
files. Android and iOS always use the authenticated browser file API.

Native SSH follows the same desktop boundary: Linux and macOS use OpenSSH;
Windows is conditional on its optional OpenSSH client and Node.js helper;
Android and iOS use the authenticated browser terminal.

## Connection API

`POST /api/workspaces/:id/connections/ssh` accepts `publicKey`, `mode`, and an
optional `requestedTtlMs`. To receive exact client argv, include a `client`
object with `platform`, absolute `proxyHelperPath`, `tokenFilePath`,
`privateKeyPath`, `certificatePath`, and `knownHostsPath`; NFS callers may also
set `localPort` and `mountPoint`. The browser intentionally requests only the
grant because it cannot safely guess paths on another device.

The response returns the one-time bearer, user certificate, user-key
fingerprint, pinned guest known-hosts line, public WebSocket route, helper
download URL, and—when requested—`sshArgv` or the NFS tunnel/mount/unmount argv.
Write the bearer to the named token file with mode 0600 and the certificate to
the path supplied in the plan. Install the helper plus its `ws` dependency in a
reviewed local Node package. Revoke early with
`DELETE /api/workspaces/:id/connections/ssh/:leaseId`.

Never mount an untrusted workspace on an operator host. The native mount is for
the authenticated user's device, over their short-lived SSH tunnel.
