# Guest control service

`bloom-guest-control.py` is the guest-owned implementation of protocol v1. It
supports bounded file chunks, structured jobs, absolute-cursor log reads,
process-group cancellation, watch-only Bloom status, one-time SSH/NFS
configuration, and wallet signing relay (relays `personal_sign`,
`eth_sendTransaction`, and `eth_signTypedData_v4` requests to the user's
browser wallet via the agent↔control↔browser polling chain). It has no TCP listener: the production transports are QEMU virtio-serial stdio, AF_VSOCK port
5001, and a mode-0600 guest-local Unix socket for `bloom-workspace`. Stdio and
socket transports may run concurrently and share one bounded job table.

The image should install:

- `bloom-guest-control.py` at `/usr/local/libexec/bloom-guest-control`;
- `bloom-workspace` at `/usr/local/bin/bloom-workspace`.

Start the controller as root so an untrusted workspace process cannot signal or
ptrace it:

```sh
/usr/local/libexec/bloom-guest-control \
  --workspace /workspace \
  --workspace-quota-bytes 134217728 \
  --job-uid 1000 --job-gid 1000 \
  --unix-socket /run/bloom/guest-control.sock \
  --vsock-port 5001
```

For QEMU, replace `--vsock-port 5001` with `--stdio` while retaining the Unix
socket for the guest helper. `.` is the explicit `/workspace` sentinel for
directory listing and job cwd only; file read/write/delete operations require a
non-root relative path. File write/delete responses include current
`usedBytes` and `quotaBytes` without returning file content.

Jobs never pass through a shell added by the service. The requested argv is
executed by `prlimit` and `setpriv`: UID/GID 1000, empty capability sets,
no-new-privileges, a private process group, 64 processes, 64 descriptors, no
core dumps, and 64 MiB per-file output. User-provided environment keys are
limited to documented safe names and `APP_`, `JOB_`, or `TEST_` namespaces.
The controller copies only the operator's controlled proxy and CA path settings;
it does not inherit wallet, control-plane, or host credentials.

`bloom.status` reports only the public watch address, whether `/bloom` is
mounted, and explicit false values for wallet signing and transactions. It
never reads or returns passphrases, private keys, cookies, or session material.

`connections.configure` is accepted once per guest scope and only by the
root-owned controller. It validates an Ed25519 CA **public** key, creates an
ephemeral host key, writes wallet/workspace principals, and starts the locked
guest sshd. With the verified QEMU NFSD kernel and a persistent volume it may
also export guest-loopback NFSv4. The CA private key and user private key never
enter the guest.
