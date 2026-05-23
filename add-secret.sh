#!/bin/bash
# add-secret.sh -- Add, update, list, or remove secrets in macOS Keychain.
#
# USAGE:
#   ./add-secret.sh MY_API_KEY              # Add or update a secret (prompts for value)
#   ./add-secret.sh MY_API_KEY "sk-abc123"  # Add with value inline (careful with shell history)
#   ./add-secret.sh --list                  # List all secrets in the registry
#   ./add-secret.sh --remove MY_API_KEY     # Remove a secret from Keychain + registry
#   ./add-secret.sh --check                 # Check which secrets are present/missing
#
# This script:
#   1. Stores the secret in macOS Keychain (encrypted, never on disk)
#   2. Automatically adds it to the SECRETS array in load-secrets.sh
#   3. Documents the secret in .env (comment only, no plaintext value)
#   4. Tells you to re-source load-secrets.sh to pick it up
#
# CONVENTION:
#   Service name (-s) = env var name
#   Account name (-a) = $(whoami)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOADER="$SCRIPT_DIR/load-secrets.sh"
ENVFILE="$SCRIPT_DIR/.env"
ACCOUNT="$(whoami)"

# =========================================================================
# HELPERS
# =========================================================================

usage() {
    echo "Usage:"
    echo "  $0 VAR_NAME              # Add/update a secret (will prompt for value)"
    echo "  $0 VAR_NAME \"value\"       # Add/update with inline value"
    echo "  $0 --list                 # List registered secrets and their status"
    echo "  $0 --remove VAR_NAME      # Remove from Keychain and registry"
    echo "  $0 --check                # Check all registered secrets"
    exit 1
}

# Extract SECRETS array entries from load-secrets.sh
get_registered_secrets() {
    # Parse the SECRETS array, skip comments and blanks
    sed -n '/^SECRETS=(/,/^)/p' "$LOADER" \
        | grep -v '^SECRETS=(' \
        | grep -v '^)' \
        | sed 's/#.*//' \
        | tr -d ' ' \
        | grep -v '^$'
}

# Check if a var name is already in the SECRETS array
is_registered() {
    local var="$1"
    grep -q "^    $var\$" "$LOADER" 2>/dev/null
}

# Add a var name to the SECRETS array in load-secrets.sh
register_secret() {
    local var="$1"
    if is_registered "$var"; then
        echo "[add-secret] $var already registered in load-secrets.sh"
        return
    fi

    # Insert before the "Add your secrets below" comment, or before the closing )
    if grep -q "# Add your secrets below:" "$LOADER"; then
        sed -i '' "s/# Add your secrets below:/# Add your secrets below:\n    $var/" "$LOADER"
    else
        # Fallback: insert before closing paren of SECRETS array
        sed -i '' "/^)/i\\
    $var
" "$LOADER"
    fi
    echo "[add-secret] Registered $var in load-secrets.sh"
}

# Remove a var from the SECRETS array
unregister_secret() {
    local var="$1"
    if ! is_registered "$var"; then
        echo "[add-secret] $var not found in load-secrets.sh registry"
        return
    fi
    sed -i '' "/^    ${var}$/d" "$LOADER"
    echo "[add-secret] Removed $var from load-secrets.sh"
}

# Add a documentation comment to .env
document_in_env() {
    local var="$1"
    [ ! -f "$ENVFILE" ] && return
    # Skip if already documented
    if grep -q "^# ${var} " "$ENVFILE" 2>/dev/null; then
        echo "[add-secret] $var already documented in .env"
        return
    fi
    echo "# ${var} -- loaded from macOS Keychain via load-secrets.sh" >> "$ENVFILE"
    echo "[add-secret] Documented $var in .env"
}

# Remove documentation comment from .env
undocument_from_env() {
    local var="$1"
    [ ! -f "$ENVFILE" ] && return
    if grep -q "^# ${var} " "$ENVFILE" 2>/dev/null; then
        sed -i '' "/^# ${var} /d" "$ENVFILE"
        echo "[add-secret] Removed $var documentation from .env"
    fi
}

# =========================================================================
# COMMANDS
# =========================================================================

case "${1:-}" in
    --list)
        echo "=== Registered Secrets ==="
        while IFS= read -r var; do
            [ -z "$var" ] && continue
            if security find-generic-password -s "$var" -a "$ACCOUNT" -w &>/dev/null; then
                echo "  [OK]      $var"
            else
                echo "  [MISSING] $var"
            fi
        done <<< "$(get_registered_secrets)"
        echo "========================="
        ;;

    --check)
        echo "Checking all registered secrets against Keychain..."
        _ok=0
        _miss=0
        while IFS= read -r var; do
            [ -z "$var" ] && continue
            if security find-generic-password -s "$var" -a "$ACCOUNT" -w &>/dev/null; then
                ((_ok++))
            else
                echo "  MISSING: $var"
                ((_miss++))
            fi
        done <<< "$(get_registered_secrets)"
        echo ""
        echo "Result: $_ok present, $_miss missing"
        ;;

    --remove)
        [ -z "${2:-}" ] && { echo "Error: --remove requires a VAR_NAME"; usage; }
        VAR_NAME="$2"
        # Remove from Keychain
        if security delete-generic-password -s "$VAR_NAME" -a "$ACCOUNT" &>/dev/null; then
            echo "[add-secret] Removed $VAR_NAME from Keychain"
        else
            echo "[add-secret] $VAR_NAME not found in Keychain (may already be removed)"
        fi
        # Remove from registry
        unregister_secret "$VAR_NAME"
        # Remove .env documentation
        undocument_from_env "$VAR_NAME"
        echo ""
        echo "Done. Re-source load-secrets.sh to apply: source $LOADER"
        ;;

    -h|--help|"")
        usage
        ;;

    *)
        VAR_NAME="$1"

        # Validate name (env var format)
        if ! [[ "$VAR_NAME" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
            echo "Error: '$VAR_NAME' is not a valid env var name"
            echo "Use uppercase with underscores: MY_API_KEY, GITHUB_TOKEN, etc."
            exit 1
        fi

        # Get the value
        if [ -n "${2:-}" ]; then
            SECRET_VALUE="$2"
            echo "[add-secret] Using provided value for $VAR_NAME"
        else
            echo -n "Enter value for $VAR_NAME: "
            read -rs SECRET_VALUE
            echo ""
        fi

        if [ -z "$SECRET_VALUE" ]; then
            echo "Error: Secret value cannot be empty"
            exit 1
        fi

        # Check if it already exists
        if security find-generic-password -s "$VAR_NAME" -a "$ACCOUNT" -w &>/dev/null; then
            echo "[add-secret] Updating existing Keychain entry for $VAR_NAME"
            security delete-generic-password -s "$VAR_NAME" -a "$ACCOUNT" &>/dev/null || true
        fi

        # Store in Keychain
        security add-generic-password -s "$VAR_NAME" -a "$ACCOUNT" -w "$SECRET_VALUE"
        echo "[add-secret] Stored $VAR_NAME in macOS Keychain"

        # Register in load-secrets.sh
        register_secret "$VAR_NAME"

        # Document in .env
        document_in_env "$VAR_NAME"

        echo ""
        echo "Done. To activate: source $LOADER"
        echo "Or restart your app/agent to pick up the new secret."

        # Clean up
        unset SECRET_VALUE
        ;;
esac
