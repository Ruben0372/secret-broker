# ARM-5 verification harness

Independent-reviewer tooling for issue ARM-5 / W0-005, secret-broker daemon
foundations, PR https://github.com/Ruben0372/secret-broker/pull/4.

Preserved because these artifacts were produced in a session scratchpad and
would otherwise be lost. They are review tooling, not part of the package under
review, and nothing here belongs in the secret-broker repository.

## Toolchain identity

All results below were produced under:

    Apple Swift version 6.3.2 (swiftlang-6.3.2.1.108 clang-2100.1.1.101)
    Target: arm64-apple-macosx26.0

This matters: the package keys its golden symbol allowlists to exactly this
identity string. Running the harness under a different toolchain produces an
UNREVIEWED TOOLCHAIN failure, which is the selection logic working correctly,
not a defect.

Note that `/bin/bash` on macOS is 3.2. The shell scripts here are written for
it: no `mapfile`, no bash arrays. An earlier version used both and died on an
unbound variable before printing anything.

## Running the twelve-case gate set

    ./run-final.sh <repo-or-worktree-path> <head-sha>

It clones the repository at the given sha into an isolated working directory,
applies each probe to a pristine copy, and never modifies the source. Cases:

Work directory: about a dozen clones are made and each is built, so the work
directory defaults to `$TMPDIR/arm5-verification-work`, deliberately outside
this archive. Set `ARM5_WORKDIR` to put it elsewhere. Do not point it at this
directory unless you want several hundred megabytes of clones and build trees
alongside the harness.

| Case | Expectation |
|---|---|
| baseline, default build dir | passes |
| baseline, `--scratch-path` | passes |
| probe A, both build dirs | caught |
| probe A-prime, both build dirs | caught |
| probe B | caught |
| probe C | caught |
| probe D | caught |
| golden blanked | caught |
| golden removed | caught |
| golden drifted | caught |

Every stage is gated. A case can only be reported as caught if the clone
validated, the patch applied, and the suite produced a recognizable result.
Anything else reports INCONCLUSIVE, never a verdict. This exists because the
first version of the runner reported every probe as caught when the clone had
silently failed and nothing had run at all.

## Files

| File | What it is |
|---|---|
| `run-final.sh` | The twelve-case runner described above, plus the three-way failure-message side-by-side comparison |
| `forbidden-tokens.txt` | The thirteen source-scan tokens; required by `run-final.sh` for probe token hygiene |
| `probe-a-legacybridge.swift` | Capability probe: bulk environment read, subprocess spawn of the legacy export path, dynamic symbol resolution, environment mutation. Contains no literal forbidden token, including in comments |
| `probe-a-prime-nodlsym.swift` | Probe A with the dynamic-resolution paths removed. Distinguishes a denylist that merely satisfies the gate from one that closes the capability class |
| `probe-b-export-adapters.py` | Exports `SecretBrokerAdapters` as a public library product |
| `probe-c-plaintext-seam.py` | Opens the custody seam: plaintext-returning custodian operation, value-carrying type, reveal case, daemon method returning raw material. Detects whether the digest helper is static or instance, so it does not fail on a stale API instead of on the pins |
| `probe-c2-seam-widening.py` | Probe C re-anchored for the caller-bound dispatch shape. ARM-24 deleted the public `handle(_:)` that `probe-c-plaintext-seam.py` anchored on, so that probe now reports INCONCLUSIVE instead of exercising the seam. This one anchors on the private `execute(_:)`, falls back to `handle(_:)` on older heads, and deliberately completes the switches that a new request case makes non-exhaustive so that the pins fail rather than the compiler. |
| `probe-d-pin-evasion.py` | Evades the source-text seam pins by declaration form: sibling protocol outside the anchored block, plus a `public static func` the line-prefix parser never collects |
| `probe-e-swiftnative.swift` | The E1 reproduction. Arbitrary filesystem read and write through Swift-native Foundation value types |
| `classify-symbols.py` | Classifies undefined symbols as capability-bearing or inert, with the overlay accept and block lists published before the symbols were seen |
| `check-import-exclusion.sh` | Verifies Import-node exclusion in both the goldens and the parser |
| `self-test-expectations.md` | Predictions written before running, so a harness bug shows up as a mismatch rather than something to explain away |
| `keyed-digest-properties.md` | The five F2 keyed-digest properties and three trap cases |
| `digest_probe.py`, `digest_check.swift` | The original F2 finding: recovering a reference from an unsalted receipt digest, and the Swift reproduction confirming the Python mirror matched byte for byte |
| `evidence/final-e8184bd.txt` | Full recorded output of the final twelve-of-twelve run |
| `evidence/extended-selftest.txt` | Harness self-test at 6ed1e60 |
| `evidence/local-6.3.2-symbols.txt` | Clean-baseline undefined symbols, 189 entries, reference input for `classify-symbols.py` |

## Validated against

**6ed1e60**, used as the known-answer head for validating the harness itself.
Expected signature there, all eleven predictions matched: baseline default
passes; baseline scratch fails; probes A, B and C caught; probes A-prime and D
pass, that is, uncaught; all golden cases INCONCLUSIVE because no golden
directory exists at that sha. A golden case reporting "caught" at 6ed1e60 would
mean the runner is crediting a failed setup as a probe success.

**e8184bd**. Twelve of twelve gates met: baseline green under both
build-directory forms at 41 tests in 8 suites, all five probes caught, all three
golden red cycles firing. Both shipped symbol goldens classify clean, 119
entries for the daemon and 122 for contracts. The archived copy of this harness
was later re-run against e8184bd and reproduced the same twelve of twelve, which
is the evidence that this archive is a working tool and not a snapshot of one.

**90581a4**, the final settled head. Twelve of twelve again, goldens byte
identical to e8184bd, and the E1 micro-delta verified: the Foundation manglings
now surface as NEW UNCLASSIFIED SYMBOL, TOOLCHAIN DRIFT still fires for a
genuinely inert runtime symbol, and probe A still names all four capability
symbols.

## Operational caution: orphaned build objects

SwiftPM leaves orphaned object files behind after a source file is deleted, and
the symbol scan reads whatever objects it finds. So a capability symbol can
persist in the scan after the code that caused it is gone.

The runner sidesteps this by giving every case a fresh clone with no build
directory, which is why probes here never inherit a previous probe's symbols. If
you deviate from that and reuse a working tree, revert and `rm -rf .build`
between probes. If you ever see a capability symbol you cannot find in the
source, suspect an orphaned object before you suspect the code.

Registered upstream as DISC-015.

## E1, the finding this harness closed

Registered as DISC-014. CLOSED at 90581a4 by an owner-authorized correction
implementing the narrow fix below verbatim; verified by the reviewer with the
five-check micro-delta. The description is kept because the reproduction is the
regression test for it.

At e8184bd, `ArtifactCapabilityTests.classify(_:)` treated every symbol
beginning `_$s` as carrying no capability, but `_$s` is the Swift mangling prefix for any
declaration reference, not runtime plumbing. To reproduce: add an internal
helper to `SecretBrokerDaemon` using `Data(contentsOf:)` and `Data.write(to:)`,
reference it from `DaemonBootstrap` so it is not dead code, and run the suite.
It fails, but no capability message appears. The reviewer sees TOOLCHAIN DRIFT
listing 65 symbols including the filesystem calls themselves, described as
carrying no capability and suggesting the golden was produced under a different
compiler, plus one NEW UNCLASSIFIED SYMBOL which is `__swiftEmptyArrayStorage`,
stdlib noise unrelated to the capability. The API surface pin does not fire
because the helper is internal. Following the dominant message's own guidance
and regenerating the golden would admit arbitrary filesystem read and write.

Narrow fix: keep `_swift_`, `__swift_FORCE_LOAD_$_` and `___` as drift; within
`_$s`, treat the Swift stdlib manglings `_$ss` and `_$sS` as drift, and let a
module-qualified mangling such as `_$s10Foundation...` fall through to
unclassified so it inherits the "treat as a capability finding until reviewed"
wording. This adds no noise on real toolchain drift, because the shipped
goldens already contain the Foundation-mangled symbols the modules legitimately
use, three in the daemon and six in contracts, so the rule only fires on
symbols outside the reviewed set.

## Two caveats to carry with any use of this material

**Attestation scope.** The reviewer sign-off covers the 6.3.2 identity and the
contents of the goldens. Cross-toolchain behaviour is not verifiable by anyone
in the fleet, because GitHub Actions is not available and no second toolchain
can be run locally.

**E1 is a messaging defect, not a hole.** The suite does go red on the injected
capability, so the shipped head is sound. The risk is that a maintainer follows
the message's own advice and regenerates the golden.

## Standing lesson

A check that fires is not a check that says the right thing. The message is
part of the control.

Nine checks written during this review produced comfortable-looking wrong
answers, including a harness that reported every probe caught when nothing had
run, two probes caught by their own comments rather than their behaviour, and
two greps that reported a sentence absent because it wrapped across lines and
carried comment markers. Each was found by reading the mechanism rather than
the verdict line. That is why `self-test-expectations.md` exists.
