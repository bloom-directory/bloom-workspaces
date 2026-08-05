#!/bin/sh
set -eu

# Provision Bloom inside a workspace using the authenticated login address as a
# watch-only wallet. This helper has no direct signer path: it accepts one EVM
# address, never a key/passphrase, and refuses to run beside signer state.
# Transaction signing uses Bloom's native outbox system: the guest controller
# reads pending outbox entries from bloom serve via IPC and relays plan.md to
# the user's browser for approval. Private keys never enter the workspace VM.

BLOOM_BIN=${BLOOM_BIN:-/usr/local/bin/bloom}
BLOOM_WORKSPACE_ROOT=/workspace
BLOOM_HOME=${BLOOM_WORKSPACE_ROOT}/.bloom
BLOOM_MOUNT=/bloom
BLOOM_WALLET_NAME=workspace-login

die() {
  printf 'bloom guest bootstrap: %s\n' "$*" >&2
  exit 1
}

reject_signer_inputs() {
  [ -z "${BLOOM_PASSPHRASE+x}" ] || die 'BLOOM_PASSPHRASE is forbidden in a watch-only workspace'
  [ -z "${PRIVATE_KEY+x}" ] || die 'PRIVATE_KEY is forbidden in a watch-only workspace'
  [ -z "${EVM_PRIVATE_KEY+x}" ] || die 'EVM_PRIVATE_KEY is forbidden in a watch-only workspace'
  [ -z "${MNEMONIC+x}" ] || die 'MNEMONIC is forbidden in a watch-only workspace'
  [ -z "${BLOOM_UNSAFE_DEBUG_SIGNER+x}" ] || die 'unsafe debug signing is forbidden in a workspace'
}

normalize_address() {
  [ "$#" -eq 1 ] || die 'expected exactly one EVM login address'
  address=$1
  [ "${#address}" -eq 42 ] || die 'EVM login address must be 0x followed by 40 hexadecimal characters'
  case "$address" in
    0x*) address_hex=${address#0x} ;;
    *) die 'EVM login address must start with 0x' ;;
  esac
  case "$address_hex" in
    *[!0123456789abcdefABCDEF]*) die 'EVM login address contains a non-hexadecimal character' ;;
  esac
  printf '0x%s\n' "$(printf '%s' "$address_hex" | tr '[:upper:]' '[:lower:]')"
}

require_regular_directory() {
  path=$1
  label=$2
  [ ! -L "$path" ] || die "$label must not be a symlink: $path"
  if [ -e "$path" ]; then
    [ -d "$path" ] || die "$label is not a directory: $path"
  else
    mkdir -p "$path"
  fi
}

verify_watch_only_keystore() {
  expected=$1
  keystore=${BLOOM_HOME}/keystore
  wallet=${keystore}/${BLOOM_WALLET_NAME}

  require_regular_directory "$keystore" 'keystore'
  for entry in "$keystore"/*; do
    [ -e "$entry" ] || continue
    [ "$(basename -- "$entry")" = "$BLOOM_WALLET_NAME" ] || \
      die "unexpected wallet state present; refusing to start: $entry"
  done

  [ ! -L "$wallet" ] || die 'watch wallet directory must not be a symlink'
  [ -d "$wallet" ] || die 'watch wallet directory is missing'
  for entry in "$wallet"/*; do
    [ -e "$entry" ] || continue
    [ -f "$entry" ] && [ ! -L "$entry" ] || die "unexpected non-regular watch wallet entry: $entry"
    case "$(basename -- "$entry")" in
      address|kind|pubkey) ;;
      *) die "signer or unknown state is forbidden in watch wallet: $entry" ;;
    esac
  done

  [ "$(tr -d '\r\n' < "$wallet/kind")" = watch ] || die 'workspace wallet is not watch-only'
  [ ! -s "$wallet/pubkey" ] || die 'watch wallet pubkey placeholder must be empty'
  stored=$(tr '[:upper:]' '[:lower:]' < "$wallet/address" | tr -d '\r\n')
  [ "$stored" = "$expected" ] || die 'stored watch address does not match the authenticated login address'
}

validate_preinstalled_petals() {
  config=$1
  approved=$2
  # Extract the preinstalled array contents from config.toml.
  # Handles both single-line (preinstalled = ["a", "b"]) and multi-line forms.
  entries=$(sed -n '/^preinstalled = \[/,/^\]/p' "$config" | tr -d '\n' | sed 's/.*\[//; s/\].*//')
  # If empty array, nothing to check.
  [ -n "$(printf '%s' "$entries" | tr -d ' \t')" ] || return 0
  # Extract quoted values.
  configured=$(printf '%s' "$entries" | tr ',' '\n' | sed 's/^[ \t]*"//; s/"[ \t]*$//' | grep -v '^$' || true)
  # Build approved set from comma-separated list.
  approved_set=$(printf '%s' "$approved" | tr ',' '\n' | grep -v '^$' || true)
  # Check each configured petal is in the approved set.
  while IFS= read -r petal; do
    [ -n "$petal" ] || continue
    case "$approved_set" in
      *"$petal"*) ;;
      *) die "preinstalled Petal '$petal' is not in the operator-approved list (BLOOM_PREINSTALLED_PETALS)" ;;
    esac
  done <<EOF
$configured
EOF
}

initialize_watch_wallet() {
  address=$1
  command -v "$BLOOM_BIN" >/dev/null 2>&1 || die "Bloom binary is unavailable: $BLOOM_BIN"
  "$BLOOM_BIN" --version >/dev/null 2>&1 || die "Bloom binary cannot execute: $BLOOM_BIN"

  require_regular_directory "$BLOOM_WORKSPACE_ROOT" 'workspace root'
  require_regular_directory "$BLOOM_HOME" 'Bloom home'
  export BLOOM_HOME

  # `bloom init` provisions network-fetched Petals by default in v0.1.3.
  # First let a non-provisioning read command create Bloom's complete default
  # config, then atomically persist the operator-approved Petal list. This keeps
  # bootstrap deterministic: only operator-curated Petals enter the guest, not
  # arbitrary remote executable content. Users can still `bloom install` explicit
  # additions from the terminal (subject to the egress proxy allowlist).
  config=${BLOOM_HOME}/config.toml
  operator_petals=${BLOOM_PREINSTALLED_PETALS:-}
  if [ ! -e "$config" ]; then
    "$BLOOM_BIN" --home "$BLOOM_HOME" --quiet status >/dev/null
    [ -f "$config" ] && [ ! -L "$config" ] || die 'Bloom did not create a regular config file'
    [ "$(grep -c '^preinstalled = ' "$config")" -eq 1 ] || \
      die 'Bloom config does not contain exactly one preinstalled Petals setting'
    config_staging=${config}.workspace-bootstrap
    # Build the TOML array value from the operator-approved comma-separated list.
    toml_array='[]'
    if [ -n "$operator_petals" ]; then
      toml_array=''
      remainder=$operator_petals
      while [ -n "$remainder" ]; do
        petal=${remainder%%,*}
        [ -n "$petal" ] || { remainder=${remainder#*,}; continue; }
        case "$petal" in
          *[!a-zA-Z0-9_-]*) die "invalid petal name in BLOOM_PREINSTALLED_PETALS: $petal" ;;
        esac
        toml_array="${toml_array}\"$(printf '%s' "$petal" | sed 's/\\/\\\\/g; s/"/\\"/g')\", "
        remainder=${remainder#$petal}
        remainder=${remainder#,}
      done
      toml_array="[${toml_array%, }]"
    fi
    awk -v replacement="preinstalled = $toml_array" '
      BEGIN { in_preinstalled = 0; seen = 0 }
      in_preinstalled == 1 {
        if ($0 ~ /^]$/) { in_preinstalled = 0 }
        next
      }
      /^preinstalled = \[/ {
        print replacement
        seen++
        if ($0 !~ /]$/) { in_preinstalled = 1 }
        next
      }
      { print }
      END { if (seen != 1 || in_preinstalled != 0) exit 42 }
    ' "$config" > "$config_staging" || die 'could not safely set preinstalled Petals'
    chmod 0600 "$config_staging"
    mv -- "$config_staging" "$config"
  else
    [ -f "$config" ] && [ ! -L "$config" ] || die 'Bloom config must be a regular file'
    # On re-bootstrap (persistent workspace), validate that the preinstalled
    # list contains only operator-approved entries.  This allows user-initiated
    # `bloom install` additions that match the approved list while catching
    # unexpected entries that may have entered through compromise.
    validate_preinstalled_petals "$config" "$operator_petals"
  fi
  "$BLOOM_BIN" --home "$BLOOM_HOME" --quiet init >/dev/null

  keystore=${BLOOM_HOME}/keystore
  wallet=${keystore}/${BLOOM_WALLET_NAME}
  require_regular_directory "$keystore" 'keystore'
  if [ ! -e "$wallet" ]; then
    umask 077
    staging=$(mktemp -d "${keystore}/.${BLOOM_WALLET_NAME}.XXXXXX")
    printf '%s\n' "$address" > "${staging}/address"
    printf '%s\n' watch > "${staging}/kind"
    : > "${staging}/pubkey"
    mv -- "$staging" "$wallet"
  fi

  verify_watch_only_keystore "$address"
  listed=$(
    "$BLOOM_BIN" --home "$BLOOM_HOME" --quiet wallet address "$BLOOM_WALLET_NAME" |
      tail -n 1 |
      tr '[:upper:]' '[:lower:]' |
      tr -d '\r\n'
  )
  [ "$listed" = "$address" ] || die 'Bloom rejected or changed the watch wallet address'
}

require_controlled_egress() {
  [ "${BLOOM_EGRESS_MODE:-}" = controlled-proxy ] || \
    die 'controlled egress is unavailable (BLOOM_EGRESS_MODE=controlled-proxy is required)'
  proxy=${HTTPS_PROXY:-${https_proxy:-}}
  [ -n "$proxy" ] || die 'controlled egress is unavailable (HTTPS_PROXY is required)'
  case "$proxy" in
    http://*) ;;
    *) die 'HTTPS_PROXY must identify the workspace HTTP CONNECT proxy using http://'
  esac
  [ "${NO_PROXY:-${no_proxy:-}}" != '*' ] || die 'NO_PROXY=* would bypass controlled egress'
}

serve_bloom() {
  address=$1
  require_controlled_egress
  initialize_watch_wallet "$address"
  command -v mount >/dev/null 2>&1 || die 'mount command is unavailable in the guest image'
  require_regular_directory "$BLOOM_MOUNT" 'Bloom mount point'
  [ -z "$(find "$BLOOM_MOUNT" -mindepth 1 -maxdepth 1 -print -quit)" ] || \
    die "$BLOOM_MOUNT must be empty before mounting"
  exec "$BLOOM_BIN" --home "$BLOOM_HOME" --quiet serve --mount "$BLOOM_MOUNT"
}

reject_signer_inputs
[ "$#" -eq 2 ] || die 'usage: guest-bootstrap.sh validate|init|serve 0x<40-hex-login-address>'
command_name=$1
login_address=$(normalize_address "$2")

case "$command_name" in
  validate) printf '%s\n' "$login_address" ;;
  init) initialize_watch_wallet "$login_address" ;;
  serve) serve_bloom "$login_address" ;;
  *) die 'usage: guest-bootstrap.sh validate|init|serve 0x<40-hex-login-address>' ;;
esac
