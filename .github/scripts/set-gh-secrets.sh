#!/usr/bin/env bash
set -euo pipefail

required_vars=(
  AURA_KEYSTORE_BASE64
  AURA_STORE_PASSWORD
  AURA_KEY_ALIAS
  AURA_KEY_PASSWORD
  AURA_PUBLIC_KEY_ENV
)

for var in "${required_vars[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    printf 'Missing required environment variable: %s\n' "$var" >&2
    exit 1
  fi
done

if ! command -v gh >/dev/null 2>&1; then
  printf 'GitHub CLI (gh) is required but not installed.\n' >&2
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  printf 'GitHub CLI is not authenticated. Run: gh auth login\n' >&2
  exit 1
fi

printf 'Publishing GitHub Action secrets...\n'

gh secret set AURA_KEYSTORE_BASE64 --app actions --body "$AURA_KEYSTORE_BASE64"
gh secret set AURA_STORE_PASSWORD --app actions --body "$AURA_STORE_PASSWORD"
gh secret set AURA_KEY_ALIAS --app actions --body "$AURA_KEY_ALIAS"
gh secret set AURA_KEY_PASSWORD --app actions --body "$AURA_KEY_PASSWORD"
gh secret set AURA_PUBLIC_KEY_ENV --app actions --body "$AURA_PUBLIC_KEY_ENV"

printf 'Secrets configured successfully.\n'
