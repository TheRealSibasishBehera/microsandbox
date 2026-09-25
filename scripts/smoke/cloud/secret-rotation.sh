#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

required=(
  MSB_SECRET_TEST_API_URL
  MSB_SECRET_TEST_API_KEY
  MSB_SECRET_TEST_SANDBOX
  MSB_SECRET_TEST_NAME
  MSB_SECRET_TEST_VALUE
)

for name in "${required[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "required environment variable is missing: $name" >&2
    exit 2
  fi
done

if [[ "${MSB_SECRET_TEST_CONFIRM_MUTATION:-}" != "cloud-secret-rotation" ]]; then
  cat >&2 <<'EOF'
Refusing to mutate a Cloud secret without explicit acknowledgement.
Set MSB_SECRET_TEST_CONFIRM_MUTATION=cloud-secret-rotation after verifying the
API URL, sandbox, and secret name belong to the disposable single-node run.
EOF
  exit 2
fi

if ! grep -q '^pub mod secret;' "$ROOT_DIR/sdk/rust/lib/lib.rs"; then
  echo "public Secret API is absent from this source tree" >&2
  exit 2
fi

head_sha="$(git -C "$ROOT_DIR" rev-parse HEAD)"

if command -v sha256sum >/dev/null 2>&1; then
  hash_stream() { sha256sum | awk '{print $1}'; }
  hash_file() { sha256sum "$1" | awk '{print $1}'; }
else
  hash_stream() { shasum -a 256 | awk '{print $1}'; }
  hash_file() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

source_state_sha="$({
  git -C "$ROOT_DIR" diff --binary HEAD --
  while IFS= read -r -d '' path; do
    printf 'untracked %q %s\n' "$path" "$(hash_file "$ROOT_DIR/$path")"
  done < <(git -C "$ROOT_DIR" ls-files --others --exclude-standard -z)
} | hash_stream)"

printf 'microsandbox_head=%s\n' "$head_sha"
printf 'microsandbox_source_state_sha256=%s\n' "$source_state_sha"
printf 'sandbox=%s\n' "$MSB_SECRET_TEST_SANDBOX"
printf 'secret_name=%s\n' "$MSB_SECRET_TEST_NAME"

cargo test \
  --manifest-path "$ROOT_DIR/Cargo.toml" \
  -p microsandbox \
  --no-default-features \
  --features cloud \
  --test cloud_secret_rotation \
  -- \
  --ignored \
  --exact cloud_secret_rotation_api_smoke \
  --nocapture
