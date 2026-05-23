#!/bin/bash
# load-secrets.sh -- Pull secrets from macOS Keychain and export as env vars.
#
# USAGE:
#   source load-secrets.sh                     # Load all secrets in SECRETS array
#   source load-secrets.sh --verify            # Load + print status of each secret
#   source load-secrets.sh --dry-run           # Show what would be loaded (no export)
#
# CONVENTION:
#   - Keychain service name (-s) = env var name (e.g. OPENAI_API_KEY)
#   - Keychain account name (-a) = your macOS username ($(whoami))
#   - Secrets never touch the filesystem in plaintext
#
# SETUP:
#   1. Add a secret:  ./add-secret.sh MY_API_KEY
#   2. List secrets:  ./add-secret.sh --list
#   3. Source this file before launching your app/agent
#
# CUSTOMIZATION:
#   Edit the SECRETS array below with the env var names your project needs.
#   Each entry maps 1:1 to a Keychain item with the same service name.

set -euo pipefail

# =========================================================================
# SECRETS REGISTRY
# Add your env var names here. Each one maps to a Keychain entry.
# =========================================================================
SECRETS=(
    # LLM Providers
    # OPENAI_API_KEY
    # ANTHROPIC_API_KEY
    # OPENROUTER_API_KEY

    # Version Control
    # GITHUB_TOKEN

    # Communication
    # SLACK_BOT_TOKEN
    # SLACK_APP_TOKEN

    # Add your secrets below:

)

# =========================================================================
# LOADER (no changes needed below this line)
# =========================================================================

_ACCOUNT="$(whoami)"
_FAILED=()
_LOADED=()
_MODE="${1:-}"

for _key in "${SECRETS[@]}"; do
    # Skip empty lines and comments
    [[ -z "$_key" || "$_key" =~ ^# ]] && continue

    _val=$(security find-generic-password -s "$_key" -a "$_ACCOUNT" -w 2>/dev/null) || true

    if [ -n "$_val" ]; then
        if [ "$_MODE" = "--dry-run" ]; then
            echo "[dry-run] Would export: $_key (found in Keychain)"
        else
            export "$_key"="$_val"
            _LOADED+=("$_key")
        fi
    else
        _FAILED+=("$_key")
    fi
done

# Status output
if [ "$_MODE" = "--verify" ] || [ "$_MODE" = "--dry-run" ]; then
    echo ""
    echo "=== Brokered Secrets Status ==="
    echo "Keychain account: $_ACCOUNT"
    echo "Loaded: ${#_LOADED[@]}"
    echo "Failed: ${#_FAILED[@]}"
    if [ ${#_FAILED[@]} -gt 0 ]; then
        echo ""
        echo "Missing secrets (add with ./add-secret.sh):"
        for _f in "${_FAILED[@]}"; do
            echo "  - $_f"
        done
    fi
    echo "==============================="
    echo ""
fi

if [ "$_MODE" != "--dry-run" ] && [ ${#_FAILED[@]} -gt 0 ]; then
    echo "[load-secrets] WARNING: Could not load: ${_FAILED[*]}" >&2
fi

# Clean up temp vars (don't leak into env)
unset _ACCOUNT _FAILED _LOADED _key _val _MODE _f
