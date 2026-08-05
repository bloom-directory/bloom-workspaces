# Bloom workspace surface

This workspace is linked to the public address in `identity` as a **watch-only**
Bloom wallet. It cannot sign transactions and has no wallet private key.

- `bloom-workspace status` shows the verified guest capabilities.
- `bloom-workspace jobs start --cwd . -- <command> ...` runs a bounded job.
- `bloom vfs ls /` and `bloom vfs cat <path>` use Bloom without a kernel mount.

The `/bloom` kernel mount is optional. The Bloom CLI VFS remains the supported
fallback when the guest cannot mount NFS locally.
