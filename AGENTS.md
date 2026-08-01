# Secret Broker — Agent Operating Guide

## Mission

Secret Broker v1.0.1 is Armel's macOS-local trust root. It owns bootstrap credentials, linked Signal device state, and broker-only Keychain access. It exposes typed, caller-pinned operations, never raw secret export.

## Security invariants

- The broker is a separately supervised per-user daemon/service. Authenticate every client with OS-level caller identity and bind allowed operations to that identity.
- Armel's model/runtime process never receives a secret value, token, Keychain item, or environment export. The broker performs the narrowly scoped operation or returns a redacted result.
- Inputs are typed, action-bound, audience-bound, expiry-bound, and one-use where the contract requires. Persist consumption before executing an effect; ambiguous post-effect state is `unknown`, never retried automatically.
- Keep secret data out of environment variables, arguments, standard output/error, crash reports, logs, IPC payloads visible to untrusted callers, temporary files, and test fixtures.
- Signal inbound/outbound receipts are append-only, caller-pinned, replay-resistant, and separate ordinary intent from approval/control proofs.
- Broker has no human-approval UI and does not decide whether an effect is allowed; it verifies/consumes a valid capability from the Supervisor.

## Expected layout and tests

- `daemon/` or `service/`: lifecycle, XPC/IPC server, caller validation;
- `keychain/`: isolated Keychain adapter;
- `operations/`: typed secret-bound profiles and Signal transport;
- `ledger/`: durable idempotency/receipt state;
- `contracts/` and `tests/`: public schemas plus redacted vectors.

Start with fake Keychain and fake Signal peer tests. Prove: denied wrong caller, denied wrong operation, one-use receipt replay denial, crash/restart recovery, and a valid typed profile operation with no value leakage. Use a dedicated test Keychain namespace only.

## Do not

- Do not revive `source load-secrets.sh` or any bulk shell-environment export path.
- Do not log full requests when they may contain data material; log stable IDs, digests, decision/result class, and redacted error codes.
- Do not accept a bearer string as caller authentication or let the model choose arbitrary Keychain labels/Signal destinations.
- Do not test with a real user Signal link, production Cadence OAuth credential, or a real Vault export token.
