# NFS research and product decision

Issue [pm#38](https://github.com/bloom-directory/pm/issues/38) asks whether wallet-authenticated users can mount an Internet-hosted NFSv4.1 workspace with no downloaded client.

## Conclusion

`sec=krb5p` is a credible encrypted NFS transport, but it is not the best primary onboarding path. Kerberos issuance, DNS discovery, blocked ports, hard-mount failure behavior, laptop sleep, and revocation semantics create more product risk than value. The workspace service therefore uses HTTPS/WSS in the browser first. Native mounts remain optional research.

Most importantly, Bloom's current Rust `embednfs` path recognizes only AUTH_SYS/None and treats RPCSEC_GSS as unknown. It must never be exposed publicly or described as `krb5p`-protected.

## Comparison

| Transport | Zero install | Confidentiality | Revocation | Network reliability | Recommendation |
|---|---:|---|---|---|---|
| Browser terminal over WSS/443 | Yes | TLS | Close WSS and destroy VM | Best | Primary |
| Native SSH | Usually | SSH | Gateway closes sessions; VM expiry | Good | Power-user follow-up |
| NFS over SSH tunnel | Uses built-in SSH/NFS on macOS | SSH plus optional NFS security | Kill tunnel and VM | Good on 443 | Optional mount experiment |
| Direct NFSv4.1 `krb5p` | OS-native on macOS | RPC payload privacy/integrity | Ticket expiry is not immediate | Ports 88/2049 often fragile | Research only |
| Tailscale/WireGuard | Requires install/enrollment | Tunnel encryption | Peer policy | Good | Conflicts with zero-install goal |
| WebDAV/HTTPS | OS support varies | TLS | HTTP session | Good | File-only fallback candidate |

## Security facts

- RPCSEC_GSS privacy encrypts RPC arguments/results, while enough RPC header information for routing remains visible. See [RFC 2203](https://www.rfc-editor.org/rfc/rfc2203).
- A Kerberos service can validate an already-issued ticket without consulting the KDC. Disabling a principal therefore does not instantly revoke every ticket; the data plane must enforce the hard lease. See [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120).
- Apple's current NFS sources contain NFSv4.1, `sec=krb5p`, custom port, mount ownership, and non-reserved-port support. `resvport` is the root-requiring option, so a user-owned mountpoint may support a non-root flow. See [Apple NFS](https://github.com/apple-oss-distributions/NFS).
- Hard NFS mounts can block applications during network loss. A public onboarding product should not make this failure mode its only interface.

## macOS experiment, not production instructions

On an isolated test realm and disposable workspace, the intended direct test remains:

```bash
kinit temporary-user@REALM.EXAMPLE
mkdir -p "$HOME/RemoteWorkspace"
mount -t nfs -o vers=4.1,sec=krb5p,soft,intr,deadtimeout=30 \
  files.example.com:/workspace "$HOME/RemoteWorkspace"
```

This requires a real NFSv4.1 server that disables AUTH_SYS, a KDC, an `nfs/<hostname>` service principal, correct DNS/time, and client-matrix validation. It is intentionally not wired to the public workspace deployment.

For an SSH-tunnel test, bind NFS only inside the workspace/private node network and forward a high local port over a short-lived SSH certificate. The exact macOS `mount_nfs` custom-port behavior must be tested across Tahoe patch releases before it is offered in UI.

## Success criteria status

The implemented browser product satisfies wallet login, short-lived isolated workspace access, confidentiality over HTTPS/WSS, hard expiry, reconnect, and no persistent client modification. Direct native mount, Kerberos credential UX, non-admin Tahoe behavior, and hostile-network behavior remain explicit empirical experiments. A failure in those experiments does not remove the working product.
