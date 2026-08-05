# Native NFS decision and client matrix

Issue [pm#38](https://github.com/bloom-directory/pm/issues/38) asked whether a wallet-authenticated user could mount an Internet-hosted NFS workspace without a custom client. Direct public NFS with Kerberos was rejected as the primary product: its KDC/DNS/port/ticket lifecycle creates substantial onboarding and revocation risk, and Bloom's existing `embednfs` path does not provide RPCSEC_GSS.

The implemented design is narrower: Linux NFSD runs inside a QEMU guest, binds only to guest loopback port 2049, and is reachable only through a short-lived NFS-mode SSH certificate carried by the HTTPS WebSocket gateway. No NFS, SSH, mountd, or rpcbind port is public.

## Security and failure behavior

- Only persistent `/workspace` volumes are exportable.
- The verified custom kernel has NFSD and NFSv4 built in; NFSv2/v3 and pNFS are not offered.
- The export is NFSv4-only, `all_squash`, UID/GID 1000, synchronous, and rooted at `/workspace`.
- NFS certificates cannot request a PTY or shell and may forward only to `127.0.0.1:2049`. Shell certificates cannot forward.
- The agent binds QEMU SSH to host loopback, and every public tunnel is checked against wallet, workspace, mode, token, connection count, and expiry.
- A hard NFS mount can block callers if the short lease expires or connectivity drops. Clients must unmount before expiry; the browser file API remains the recovery path.
- Never mount an untrusted tenant workspace on an operator host. The mount is for the authenticated user's own device.

## Client matrix

| Platform | Decision | Requirements |
|---|---|---|
| Linux | Reference implementation | OpenSSH, Node + `ws` proxy helper, NFSv4 client, administrator mount permission |
| macOS | Implemented, release-gated | Built-in OpenSSH/NFS client, Node helper, admin mount permission, real-device validation on supported macOS versions |
| Windows | Conditional | Optional OpenSSH and Client for NFS, Node helper, administrator access to bind local port 2049, NFSv4 compatibility probe |
| Android / iOS | Not offered | Use authenticated browser files and terminal |

The API returns the certificate, pinned known-hosts entry, bearer lease, gateway path, and capability explanation. Client applications may use `createNfsClientPlan` to obtain argv arrays for the SSH forward, mount, and unmount operations. Values remain argv entries rather than interpolated shell commands.

## Reproducible kernel gate

`ops/connections/build-nfs-kernel.sh` pins Linux 6.1.155 and the Firecracker 1.16.1 reference config by SHA-256, applies the reviewed NFSD fragment, and emits the kernel, final config, and `SHA256SUMS`. `build-nfs-kernel-container.sh` runs that build in a digest-pinned disposable environment.

At agent startup, `BLOOM_NFS_ENABLED=1` also requires `BLOOM_NFS_KERNEL_CONFIG`. The agent reads the selected kernel, config, and adjacent manifest, verifies both digests and every required NFSD setting, and refuses to advertise NFS on any mismatch.

Direct NFSv4.1/`krb5p`, non-admin macOS mounting, laptop sleep behavior, and Windows compatibility remain separate experiments. None is required for the browser product or used to overstate its portability.
