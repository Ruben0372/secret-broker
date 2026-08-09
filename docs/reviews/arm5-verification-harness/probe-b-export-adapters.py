"""PROBE B, ARM-5 delta re-verification.

Exports SecretBrokerAdapters as a public library product. At e48db09 this
passed all 21 tests (exit 0). Pass criterion for the corrected head: FAIL.

Run from the repo root of the clone under test.
"""
import re
import sys

PATH = "Package.swift"
src = open(PATH).read()

if "SecretBrokerAdapters" not in src:
    sys.exit("probe-b: adapters target not found; manifest shape changed, re-author probe")

# Insert the adapters library immediately after the last existing .library line
# so this survives reordering of the products block.
lines = src.split("\n")
idx = [i for i, l in enumerate(lines) if ".library(" in l]
if not idx:
    sys.exit("probe-b: no .library product found; manifest shape changed, re-author probe")

insert_at = idx[-1] + 1
indent = re.match(r"\s*", lines[idx[-1]]).group(0)
lines.insert(
    insert_at,
    f'{indent}.library(name: "SecretBrokerAdapters", targets: ["SecretBrokerAdapters"]),',
)
open(PATH, "w").write("\n".join(lines))
print("probe-b applied: SecretBrokerAdapters exported as a library product")
