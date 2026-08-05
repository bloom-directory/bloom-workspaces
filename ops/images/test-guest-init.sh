#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
parser="$script_dir/guest/bloom-workspace-device"
identity_parser="$script_dir/guest/bloom-workspace-identity"
init="$script_dir/guest/bloom-init"
agent_source="$script_dir/guest/bloom-vsock-agent.c"

assert_equal() {
  local expected="$1"
  local actual="$2"
  [[ "$actual" == "$expected" ]] || {
    printf 'expected %q, got %q\n' "$expected" "$actual" >&2
    exit 1
  }
}

assert_equal "" "$(sh "$parser" root=/dev/vda bloom_workspace=/dev/vdc)"
assert_equal "" "$(sh "$parser" bloom_workspace=/dev/vdbx)"
assert_equal "/dev/vdb" "$(sh "$parser" root=/dev/vda bloom_workspace=/dev/vdb quiet)"
assert_equal "/dev/vdb" "$(sh "$parser" bloom_workspace=/dev/vdc bloom_workspace=/dev/vdb)"
assert_equal "" "$(sh "$identity_parser" bloom_identity=0x1234)"
assert_equal "" "$(sh "$identity_parser" bloom_identity=0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)"
assert_equal "0x1111111111111111111111111111111111111111" "$(sh "$identity_parser" root=/dev/vda bloom_identity=0x1111111111111111111111111111111111111111)"

grep -Fq 'mount -t ext4 -o rw,nodev,nosuid "$workspace_device" /workspace' "$init"
grep -Fq 'poweroff -f' "$init"
grep -Fq 'if [ "$guest_transport" = "vsock" ] && [ -c /dev/vsock ] && [ -x /usr/local/sbin/bloom-vsock-agent ]; then' "$init"
grep -Fq '/usr/bin/setsid /bin/setpriv' "$init"
grep -Fq -- '--reuid=1000 --regid=1000 --clear-groups --no-new-privs' "$init"
grep -Fq -- '--bounding-set=-all --inh-caps=-all --ambient-caps=-all' "$init"
grep -Fq 'bloom_egress=qemu' "$init"
grep -Fq 'bloom_egress=vsock' "$init"
grep -Fq 'bloom_transport=qemu' "$init"
grep -Fq 'bloom_transport=vsock' "$init"
grep -Fq 'VSOCK-CONNECT:2:3128' "$init"
grep -Fq '. /run/bloom/egress.env' "$script_dir/guest/profile"
grep -Fq -- '--vsock-port 5001' "$init"
grep -Fq -- '--stdio' "$init"
grep -Fq '"$(cat "$name_file")" = "org.bloom.control"' "$init"
grep -Fq '<"$control_device" >"$control_device"' "$init"
if grep -Fq 'setsid /bin/ash' "$init"; then
  printf 'serial fallback must not start a root shell\n' >&2
  exit 1
fi
if grep -Fq 'This VM is disposable' "$agent_source"; then
  printf 'vsock banner must describe capability-based persistence\n' >&2
  exit 1
fi
printf 'guest workspace-device and transport contracts verified\n'
