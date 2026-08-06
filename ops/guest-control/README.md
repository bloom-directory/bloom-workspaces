# bloom-guest-control

A single Rust binary that serves as both the guest-side control daemon and the
guest-local CLI client.

## Server mode

The server accepts the version-1 JSON-line protocol over AF_VSOCK, a guest-local
Unix socket, and/or stdio. It provides:

- Bounded file CRUD (`fs.list`, `fs.read`, `fs.write`, `fs.delete`)
- Structured job execution (`job.start`, `job.status`, `job.cancel`) with
  `prlimit` + `setpriv` isolation as the unprivileged workspace account
- Bloom status reporting (`bloom.status`)
- Ceremony pending scan (`ceremony.pending`)
- Connection configuration (`connections.configure`)

Each job is exec'd via `prlimit` and `setpriv` as the unprivileged workspace
account with no capabilities and no-new-privileges.

## Client mode

When invoked with a subcommand (`status`, `hello`, `files`, `jobs`), the binary
runs as a guest-local CLI client that connects to the server's Unix socket.

## Building

```sh
cargo build --release
```

For the Alpine guest image (static musl):

```sh
cargo build --release --target x86_64-unknown-linux-musl
```

## Binary layout in the guest image

- `bloom-guest-control` at `/usr/local/libexec/bloom-guest-control` (server mode)
- `bloom-workspace` at `/usr/local/bin/bloom-workspace` (client mode — same binary)
