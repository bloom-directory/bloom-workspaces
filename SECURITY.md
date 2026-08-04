# Security policy

Bloom Workspaces is experimental isolation software. Please do not open a public issue for a vulnerability that could affect a deployed host or another tenant.

Report security issues privately through GitHub's **Report a vulnerability** flow for this repository. Include the affected commit, runtime (QEMU or Firecracker), host/guest versions, reproduction, impact, and whether the issue crosses a tenant or host boundary.

No release in the `0.x` series is approved for funded wallet keys, seed phrases, production signing credentials, or unrestricted public egress. See the [threat model](docs/threat-model.md) and [public launch gates](docs/public-launch.md).
