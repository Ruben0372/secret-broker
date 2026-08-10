# EXTERNAL VENDORED FIXTURE, NOT AUTHORED HERE

This file is a byte-for-byte copy taken from another repository. Nothing in
this directory is a claim made by secret-broker. A provenance search that finds
a sentence here has found the source repository's words, copied, and must not
count it as independent corroboration.

- Source repository: `Ruben0372/armel`
- Source commit: `b3624695`
- Source path: `contracts/authority/v1/vectors/authority-v1-vectors.json`
- Family: `armel-authority-v1`, status `published_inactive`
- Consumed digest: `a8e58f3f` (SHA-256 over the raw file bytes), the
  verify_only input named in the ARM-25 claim and reproduced independently here
- Vendored by: ARM-25 / B1-002, secret-broker
- Vendored at: 2026-08-09

## Specification source

The normative rules were read from the contract document
`contracts/authority/v1/README.md` at the commit above, which is an explicit
reimplementation contract rather than a pointer to code. It states the
canonical encoding (deterministic CBOR, RFC 8949 section 4.2.1, restricted to
unsigned integer, text string, array, map and boolean, with seven enforced
rules) and the digest construction `SHA-256(domain || 0x00 || canonical_cbor)`.

That document also records that its governing specification, the Armel
Supervisor and Intake V1 specification section 4, is not held in that
repository and is pinned by content digest
`sha256:fdf567d45805e60341a0238518c47ead1a888acab99f9768cdbabcba5e336599`.
Where the two disagree, the specification wins. This repository has not read
that pinned specification, so any disagreement between it and the contract
document would not be visible here.

## Independence boundary

The `contracts/authority/v1/` Python modules that implement this family were
deliberately NOT read. The vectors are consumed as black-box known answers: 5
positive cases pinning canonical hex and digest, and 11 negative cases pinning
an expected reason code each.

## Derived, not spec-frozen

Upstream marks several values DERIVED rather than specification-stated,
including the `TradeSpecV1` digest domain, the task-envelope and run-lease
digest domains that produce `task_authority_digest`, and the cadence-context
nested domains. Peers must adopt them exactly. A derived value moving upstream
moves the digests here, so these are pinned as enforced constants that
recompute every run rather than trusted as stable.
