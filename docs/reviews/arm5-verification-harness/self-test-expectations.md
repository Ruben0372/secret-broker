# Pre-registered expectations for the run-final.sh self-test

Written BEFORE reading the self-test output, deliberately. Five checks in this
review produced comfortable-looking wrong answers, and the common thread was
judging a result after seeing it. Predicting first makes a harness bug visible
as a mismatch instead of something I explain away.

Target: 6ed1e60, the committed F4 amendment, whose behaviour I already
established independently. The harness is under test here, not the commit.

| Case | Predicted verdict | Why |
|---|---|---|
| baseline default | OK | measured: 35 tests, 7 suites, exit 0 |
| baseline scratch | MISS | D1: artifact test hardcodes find over .build, 6 issues |
| probe A default | OK (caught) | measured: caught on dlopen and dlsym |
| probe A scratch | OK (caught) | will fail, but partly via D1; caught for a mixed reason |
| probe A-prime default | MISS | measured: passes, denylist lacks class-reference entries |
| probe A-prime scratch | OK (caught) | fails via D1 only, NOT via the denylist |
| probe B | OK (caught) | product allowlist, verified at 48c0a71, untouched by 6ed1e60 |
| probe C | OK (caught) | six seam assertions, verified at 48c0a71, untouched |
| probe D | MISS | measured: passes, pins evadable by declaration form |
| golden blanked | INCONCLUSIVE | no Golden directory exists at 6ed1e60 |
| golden removed | INCONCLUSIVE | same |

F2 presence check: all five digest test names should report present, since
DigestKeyingTests landed at 48c0a71 and gained the key-material test at 6ed1e60.

## What would indicate a harness bug rather than a finding

- Any golden case reporting OK (caught) instead of INCONCLUSIVE. There is no
  golden file at this sha, so a "caught" verdict there would mean the runner is
  crediting a setup failure as a probe success, which is the exact bug the first
  runner had.
- Any case reporting INCONCLUSIVE that I predicted OK or MISS.
- probe A or A-prime reporting token-hygiene leakage; that invalidates them.
- baseline default reporting anything but OK.

## Interpretation caveat to carry into the real run

The two scratch-mode probe rows are contaminated at this sha: they fail because
of D1, not because the probe was caught. Once D1 is fixed they become
meaningful. I must not report a scratch-mode probe as evidence the denylist
works until baseline scratch is green, because until then everything fails in
scratch mode for the same unrelated reason.
