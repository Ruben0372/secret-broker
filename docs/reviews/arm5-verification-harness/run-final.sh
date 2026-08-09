#!/bin/bash
# ARM-5 correction-2 final verification runner.
#
# Usage: ./run-final.sh <repo-or-worktree-path> <head-sha>
#
# Covers the full agreed set:
#   baseline under BOTH build-directory forms (D1)
#   probes A and A-prime under both forms (they exercise the artifact layer)
#   probes B, C, D under the default form
#   golden-file wired-correctly red cycles (standing requirement)
#   presence check for the F2 keyed-digest tests
#
# Every stage is gated. A case can only be reported as caught if the clone
# validated, the patch applied, and the suite produced a recognizable result.
# Anything else is INCONCLUSIVE, never a verdict. This exists because the first
# version of the earlier runner reported every probe as caught when the clone
# had silently failed and nothing had run.

set -uo pipefail

REPO="${1:?usage: run-final.sh <repo-path> <head-sha>}"
HEAD_SHA="${2:?usage: run-final.sh <repo-path> <head-sha>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Work directory deliberately defaults OUTSIDE the script's own directory. This
# runner makes about a dozen git clones and builds each one, so defaulting to
# $HERE would dump hundreds of megabytes of clones and build trees into whatever
# directory the harness is archived in. Override with ARM5_WORKDIR if you want
# them somewhere specific.
WORK="${ARM5_WORKDIR:-${TMPDIR:-/tmp}/arm5-verification-work}"
HARNESS_ERROR=9

rm -rf "$WORK" && mkdir -p "$WORK"
declare -a RESULTS=()

prepare() {
    local name
    local dest
    name="$1"
    dest="$WORK/$name"
    if ! git clone --quiet --no-local "$REPO" "$dest" 2>"$WORK/$name.clone.log"; then
        echo "  HARNESS ERROR: clone failed for $name" >&2
        return 1
    fi
    if ! git -C "$dest" checkout --quiet "$HEAD_SHA" 2>"$WORK/$name.checkout.log"; then
        echo "  HARNESS ERROR: checkout of $HEAD_SHA failed for $name" >&2
        return 1
    fi
    if [ ! -f "$dest/Package.swift" ] || [ ! -d "$dest/Sources/SecretBrokerDaemon" ]; then
        echo "  HARNESS ERROR: $dest is not the secret-broker package" >&2
        return 1
    fi
    PREPARED="$dest"
    return 0
}

# run_suite <dir> <label> <mode: default|scratch>
run_suite() {
    local dir="$1" label="$2" mode="$3"
    local code summary
    if [ -z "$dir" ] || [ ! -d "$dir" ]; then
        echo "  $label: HARNESS ERROR (no prepared directory)"
        return $HARNESS_ERROR
    fi
    if [ "$mode" = "scratch" ]; then
        ( cd "$dir" && swift test --scratch-path "$dir/.sp" >"$dir/out.txt" 2>&1 )
    else
        ( cd "$dir" && swift test >"$dir/out.txt" 2>&1 )
    fi
    code=$?
    if [ ! -s "$dir/out.txt" ]; then
        echo "  $label: HARNESS ERROR (no output)"
        return $HARNESS_ERROR
    fi
    summary="$(grep -E "Test run with .* (passed|failed)" "$dir/out.txt" | tail -1)"
    if [ -n "$summary" ]; then
        echo "  $label: exit=$code  $summary"
        return $code
    fi
    if grep -qE "error:" "$dir/out.txt"; then
        echo "  $label: exit=$code  BUILD FAILED, no tests ran"
        grep -m2 -E "error:" "$dir/out.txt" | sed 's/^[[:space:]]*/      /'
        return $code
    fi
    echo "  $label: HARNESS ERROR (no summary, no build error)"
    return $HARNESS_ERROR
}

record() { RESULTS+=("$1|$2|$3"); }

# case <name> <label> <want: pass|fail> <mode> [setup command...]
case_run() {
    local name="$1" label="$2" want="$3" mode="$4"; shift 4
    echo "[$label] expect $want (${mode} build dir)"
    if ! prepare "$name"; then record "$label" "$HARNESS_ERROR" "$want"; echo; return; fi
    local dir="$PREPARED"
    if [ "$#" -gt 0 ]; then
        if ! ( cd "$dir" && "$@" >"$dir/setup.log" 2>&1 ); then
            echo "  HARNESS ERROR: setup did not apply"
            sed 's/^/      /' "$dir/setup.log"
            record "$label" "$HARNESS_ERROR" "$want"; echo; return
        fi
        sed 's/^/      /' "$dir/setup.log"
    fi
    run_suite "$dir" "$label" "$mode"
    record "$label" "$?" "$want"
    echo
}

# Token hygiene guard: a probe that leaks a scanned token is caught for the
# wrong reason and its result means nothing.
hygiene() {
    local file="$1" leaked=0
    while IFS= read -r tok; do
        [ -z "$tok" ] && continue
        grep -qF -- "$tok" "$file" && { echo "      WARNING leaked token: $tok"; leaked=1; }
    done < "$HERE/forbidden-tokens.txt"
    [ "$leaked" -eq 0 ] && echo "      token hygiene clean"
    return $leaked
}

export -f hygiene
export HERE

blank_golden() {
    local found=0
    while IFS= read -r f; do
        : > "$f"; found=1; echo "blanked golden file: $f"
    done < <(find Tests -path "*Golden*" -type f)
    [ "$found" -eq 1 ] || { echo "no golden files found; cannot run this red cycle"; return 1; }
}

remove_golden() {
    local d
    d="$(find Tests -type d -name Golden | head -1)"
    [ -n "$d" ] || { echo "no Golden directory found; cannot run this red cycle"; return 1; }
    rm -rf "$d"; echo "removed golden directory: $d"
}

# Append a plausible, inert symbol to whichever golden the current toolchain
# selects. Distinguishes benign drift from a real capability: the suite must go
# red, and the message must say drift rather than capability.
drift_golden() {
    local f
    f="$(find Tests -path "*Golden*" -type f | head -1)"
    [ -n "$f" ] || { echo "no golden file found; cannot run this red cycle"; return 1; }
    printf '_swift_a_symbol_that_does_not_exist\n' >> "$f"
    echo "appended an inert unknown symbol to: $f"
}

echo "=== ARM-5 correction-2 final verification, head $HEAD_SHA ==="
echo "repo: $REPO"
echo

PREPARED=""
case_run base-default  "baseline default"  pass default
case_run base-scratch  "baseline scratch"  pass scratch
case_run a-default     "probe A default"   fail default bash -c 'cp "$HERE/probe-a-legacybridge.swift" Sources/SecretBrokerDaemon/LegacyBridge.swift && hygiene Sources/SecretBrokerDaemon/LegacyBridge.swift'
case_run a-scratch     "probe A scratch"   fail scratch bash -c 'cp "$HERE/probe-a-legacybridge.swift" Sources/SecretBrokerDaemon/LegacyBridge.swift && hygiene Sources/SecretBrokerDaemon/LegacyBridge.swift'
case_run ap-default    "probe A-prime default" fail default bash -c 'cp "$HERE/probe-a-prime-nodlsym.swift" Sources/SecretBrokerDaemon/LegacyBridgePrime.swift && hygiene Sources/SecretBrokerDaemon/LegacyBridgePrime.swift'
case_run ap-scratch    "probe A-prime scratch" fail scratch bash -c 'cp "$HERE/probe-a-prime-nodlsym.swift" Sources/SecretBrokerDaemon/LegacyBridgePrime.swift && hygiene Sources/SecretBrokerDaemon/LegacyBridgePrime.swift'
case_run b             "probe B"           fail default python3 "$HERE/probe-b-export-adapters.py"
case_run c             "probe C"           fail default python3 "$HERE/probe-c2-seam-widening.py"
case_run d             "probe D"           fail default python3 "$HERE/probe-d-pin-evasion.py"
case_run g-blank       "golden blanked"    fail default bash -c "$(declare -f blank_golden); blank_golden"
case_run g-removed     "golden removed"    fail default bash -c "$(declare -f remove_golden); remove_golden"
case_run g-drift       "golden drifted"    fail default bash -c "$(declare -f drift_golden); drift_golden"

# Three-way message distinction. The ruling requires a reader to tell a real
# capability from toolchain drift from an unreviewed identity. Same red, three
# different causes: if the messages do not differ, the distinction is decorative.
echo "=== three-way failure message distinction ==="
extract() {
    local dir="$WORK/$1" label="$2"
    if [ -s "$dir/out.txt" ]; then
        local msg
        # Match only real test-failure output. An earlier version grepped the
        # whole log for the keywords, and "capability" matched the compile line
        # "Compiling ... ArtifactCapabilityTests.swift", so the capability row
        # showed build noise instead of an assertion message. Three rows that
        # differ because one captured a filename prove nothing.
        msg="$(grep -E '✘|↳|Expectation failed' "$dir/out.txt" \
               | grep -ivE "Compiling|Building|^\[[0-9]+/[0-9]+\]|Suite .* started" \
               | grep -iE "capability|toolchain|identity|drift|unreviewed|golden|symbol" \
               | head -2 | sed 's/^[[:space:]]*//' | cut -c1-160)"
        printf "  %-22s %s\n" "$label" "${msg:-<no failure message matched>}"
    else
        printf "  %-22s %s\n" "$label" "<no output>"
    fi
}
extract a-default "capability:"
extract g-drift   "toolchain drift:"
extract g-removed "unreviewed identity:"
echo "  (these three must read differently; identical text means the distinction is not implemented)"
echo

echo "=== F2 keyed-digest tests present and executed ==="
BASEOUT="$WORK/base-default/out.txt"
if [ -s "$BASEOUT" ]; then
    for t in "stable" "differ" "unsalted" "Distinct references" "key, salt, or nonce"; do
        if grep -qi -- "$t" "$BASEOUT"; then echo "  present: $t"; else echo "  MISSING: $t"; fi
    done
else
    echo "  INCONCLUSIVE: no baseline output"
fi
echo

echo "=== verdict ==="
for row in "${RESULTS[@]}"; do
    IFS='|' read -r label code want <<< "$row"
    if [ "$code" -eq "$HARNESS_ERROR" ]; then
        printf "  %-24s INCONCLUSIVE (harness error)\n" "$label"
    elif [ "$want" = "pass" ]; then
        [ "$code" -eq 0 ] && printf "  %-24s OK\n" "$label" || printf "  %-24s MISS (should pass, failed)\n" "$label"
    else
        [ "$code" -ne 0 ] && printf "  %-24s OK (caught)\n" "$label" || printf "  %-24s MISS (should fail, passed)\n" "$label"
    fi
done
