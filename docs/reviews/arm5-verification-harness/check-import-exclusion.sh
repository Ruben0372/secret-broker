#!/bin/bash
# Verify the Import-node exclusion is real, not just claimed.
#
# Usage: ./check-import-exclusion.sh <repo-root>
#
# WHY THIS IS NOT A GREP FOR "Import":
# In swift-api-digester -dump-sdk output an Import node serialises as
#   declKind: "Import", kind: "Import", name: "Foundation", printedName: "Foundation"
# The printedName is the bare module name. So if the golden stores printed names
# only, an UNFILTERED Import appears in the file as a line reading exactly
#   Foundation
# with the word "Import" nowhere in the file. Grepping for "Import" would then
# report clean while the goldens are in fact contaminated: a false clear.
# The reliable check is to look for the module names themselves.

set -uo pipefail
ROOT="${1:?usage: check-import-exclusion.sh <repo-root>}"
cd "$ROOT" || exit 1

# Implicit imports observed in a local 6.3.2 dump of these modules.
# Space-separated rather than an array: /bin/bash on macOS is 3.2, which has no
# mapfile and treats an empty array as unset under set -u. An earlier version of
# this script used both and died on an unbound variable before printing anything.
IMPLICIT="Foundation SwiftOnoneSupport _Concurrency _StringProcessing _SwiftConcurrencyShims CryptoKit Swift"

GOLDEN_LIST="$(mktemp)"
trap 'rm -f "$GOLDEN_LIST"' EXIT
find Tests -path "*Golden*" -type f 2>/dev/null > "$GOLDEN_LIST"
COUNT="$(wc -l < "$GOLDEN_LIST" | tr -d ' ')"
if [ "$COUNT" -eq 0 ]; then
    echo "INCONCLUSIVE: no golden files found under Tests"
    exit 9
fi

echo "golden files found: $COUNT"
fail=0
while IFS= read -r g; do
    [ -z "$g" ] && continue
    echo "--- $g"
    # Golden files carry a '#' comment header that legitimately mentions
    # Import while documenting the exclusion. Scanning it produced a false
    # positive, so comments are stripped before any matching.
    body="$(grep -vE '^[[:space:]]*#' "$g")"
    # 1. Structural marker, if the golden preserves kinds at all.
    if printf '%s\n' "$body" | grep -qE '"?declKind"?[[:space:]]*[:=][[:space:]]*"?Import|(^|[^A-Za-z])Import([^A-Za-z]|$)'; then
        echo "    FAIL: an Import kind marker is present"
        grep -nE '"?declKind"?\s*[:=]\s*"?Import|(^|[^A-Za-z])Import([^A-Za-z]|$)' "$g" | head -3 | sed 's/^/      /'
        fail=1
    fi
    # 2. The real check: bare module names, which is how an unfiltered Import
    #    looks when the golden stores printed names only.
    for mod in $IMPLICIT; do
        if printf '%s\n' "$body" | grep -qE "(^|[[:space:]\"'])${mod}([[:space:]\"',]|\$)"; then
            echo "    SUSPECT: bare module name '${mod}' appears; could be an unfiltered Import"
            grep -nE "(^|[[:space:]\"'])${mod}([[:space:]\"',]|$)" "$g" | head -2 | sed 's/^/      /'
            fail=1
        fi
    done
    [ "$fail" -eq 0 ] && echo "    clean: no Import marker, no bare implicit-module name"
done < "$GOLDEN_LIST"

echo
echo "--- parser side: does the code actually filter Import? ---"
if grep -rn "Import" Tests --include=*.swift | grep -viE "^\S+:\s*//" | head -5; then
    echo "  (inspect the above: an explicit declKind/kind == \"Import\" filter should be present)"
else
    echo "  WARNING: no reference to Import in the test sources. If the goldens are"
    echo "  clean it may be because the generator filtered them, but the parser then"
    echo "  has no guard should a future regeneration include them."
    fail=1
fi

echo
[ "$fail" -eq 0 ] && echo "VERDICT: Import exclusion verified" || echo "VERDICT: Import exclusion NOT established"
exit "$fail"
