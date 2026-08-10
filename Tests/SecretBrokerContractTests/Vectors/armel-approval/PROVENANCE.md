# EXTERNAL VENDORED FIXTURE, NOT AUTHORED HERE

These files are byte-for-byte copies taken from another repository. Nothing in
this directory is a claim made by secret-broker. Do not read a statement in
these files as this repository asserting it, and do not treat a match found
here as independent corroboration of anything: a provenance search that finds a
sentence in this directory has found the source repository's words, copied.

- Source repository: `Ruben0372/armel-approval`
- Source commit: `68285bfd` (merge of PR 5, ARM-47 canonical JSON escaping vectors; supersedes `6f36fe66a427`)
- Source path: `packages/vectors/vectors/`
- Vendored by: ARM-25 / B1-002, secret-broker
- Vendored at: 2026-08-09

## Why these are copied rather than referenced

The enforced digest constants in this test target recompute over these bytes on
every run. That check is only meaningful against bytes this repository controls
and reviews. Referencing another repository at build time would mean a silent
upstream edit changes what this suite verifies, which is the drift the pinning
exists to catch.

The duplication is deliberate and is the point.

## Digest rule

`DIGESTS.json` publishes SHA-256 over the raw file bytes as checked in,
including the trailing newline, and excludes itself from its own listing. That
rule is the upstream publisher's, reproduced here so the recompute is legible
without leaving this directory.

## Independence boundary

These vectors are consumed as black-box known answers. The verifier
implementations in `armel-approval` and `armel` were deliberately NOT read
while building the secret-broker verifiers, so a shared misreading of the
specification cannot be reproduced from their code. The specification was read
from the contract documents instead:

- `docs/REPOSITORY-LAYOUT.md` in `armel-approval` at the commit above
- `packages/vectors/README.md` in `armel-approval` at the commit above

Upstream states a limitation worth carrying: these vectors and the
implementations that consume them were written by the same author in the same
change, so a vector cannot catch a misreading baked into both at once. It
catches drift, cross-language asymmetry, and regression. Independent review of
a vector is therefore review of the specification claim, not only of the data.

## Known residual, tracked as ARM-48

Duplicate map keys are rejected by byte equality on both sides. Two keys that
differ in bytes but are canonically equivalent, for example under a Unicode
normalisation, are not currently treated as duplicates. The owner decision is
reject-as-duplicate on both sides, extending ARM-32 F1, and lands as ARM-48.
Named here so a consumer cannot read the duplicate-key rule as already covering
canonical equivalence.

## ARM-47 escaping oracle, now closed

The earlier gap is closed. `canonical_json_escaping_v1`, `canonical_json_unicode_v1`
and `canonical_json_structure_v1` pin every C0 control point, both boundaries,
every character JSON gives special meaning, non-ASCII across BMP and astral, key
ordering by UTF-8 byte value, whitespace, and integer form. Canonical-on-input is
enforced against those branches here, and the ARM-47-pending marker is dropped
for them.

One thing upstream deliberately does NOT pin, and neither does this repository:
lone surrogates. They are not representable in a UTF-8 vector file, and upstream
measured that the two JSON readers diverge on the escaped form. Nothing here
claims a behaviour for them.
