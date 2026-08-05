# Bloom CLI in the curated guest

This directory builds Bloom v0.1.3 natively for x86_64 musl and provisions a
workspace with only the authenticated EVM address as a watch wallet. It does
not copy a host binary into Alpine, add a glibc compatibility layer, create or
import signing keys, accept a passphrase, or compile Bloom's
`unsafe-debug-signer` feature.

## Build and verify

```sh
ops/bloom/build-musl.sh
ops/bloom/smoke-alpine.sh
```

The build downloads the exact source commit behind v0.1.3, verifies both the
archive and tagged `Cargo.lock`, and compiles with Cargo `--locked` in a pinned
Alpine 3.24 image. The only enabled Bloom CLI feature is `mount`. Cargo registry
checksums and exact Git dependency revisions remain enforced by `Cargo.lock`.
The output directory contains the stripped binary, SHA-256 checksum, source and
builder provenance, toolchain/package inventory, `file`/`ldd` evidence, and
captured `bloom --version` output.

The build needs Docker, HTTPS access to GitHub and crates.io, approximately 10
GiB of temporary space, and substantial RAM/CPU. It intentionally fails if a
pinned Alpine package version has disappeared rather than silently changing the
toolchain. The release dependency graph is large (Wasmtime, Alloy, WebAuthn,
Revm, and embedded NFS); a cold build can take tens of minutes.

The smoke test runs the result in the pinned, otherwise clean Alpine image with
networking disabled. It verifies that the binary executes without installing a
runtime compatibility package, initializes only the watch wallet, and supports
read-only VFS access. Kernel NFS mounting is not exercised by that unprivileged
smoke; the integration VM still needs NFSv4 client support and mount privilege.

## Guest bootstrap contract

The image should install `guest-bootstrap.sh` as
`/usr/local/sbin/bloom-guest-bootstrap`. The control plane passes the validated
SIWE login address, never a key:

```sh
bloom-guest-bootstrap init 0x1111111111111111111111111111111111111111
```

This creates `/workspace/.bloom/keystore/workspace-login` with only `address`,
`kind=watch`, and an empty public-key placeholder, then asks Bloom itself to
parse and return the address. Existing wallets, signer files, symlinks, unknown
keystore entries, signer-related environment variables, and address changes are
fail-closed. Bloom v0.1.3's default network-fetched Petal provisioning is
persistently disabled before `bloom init`; guests may not silently acquire
remote executable content. The durable Bloom home therefore follows
`/workspace` while the mount point remains `/bloom`.

Starting the mount additionally requires the host-provisioned egress markers:

```sh
BLOOM_EGRESS_MODE=controlled-proxy \
HTTPS_PROXY=http://10.0.2.100:3128 \
bloom-guest-bootstrap serve 0x1111111111111111111111111111111111111111
```

The marker is not itself a network sandbox. The VM runtime must continue to
make the policy proxy the guest's only route; the helper merely refuses to
claim network-capable Bloom service when that route was not provisioned. It
also rejects `NO_PROXY=*`. Bloom receives no wallet signing authority from the
workspace authentication flow.
