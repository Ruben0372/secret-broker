<!--
Generated file. Do not edit by hand.
Policy: armel-agents/v1
Repository: Ruben0372/secret-broker
Source digest: dc7695474448d26a519207acfbb94bfb2927200a8a6b9b8c21c4880f81598f12
-->

# Secret Broker Agent Operating Guide

## Mission

Secret Broker v1.0.1 is Armel's macOS-local trust root. It owns bootstrap
credentials, linked Signal device state, and broker-only Keychain access. It
exposes caller-pinned typed operations, never raw secret export.

## Current state and expected map

The current repository contains two legacy shell scripts. They are provenance
only and are not an Armel runtime. W0-005 will establish the Swift package,
daemon, contracts, tests, and CI.

- `Sources/SecretBrokerDaemon/`: per-user daemon and IPC dispatch.
- `Sources/SecretBrokerCore/`: policy-neutral operation orchestration.
- `Sources/SecretBrokerContracts/`: typed request, result, and receipt schemas.
- `Sources/SecretBrokerKeychain/`: isolated Keychain custody.
- `Sources/SecretBrokerSignal/`: linked-device transport behind typed profiles.
- `Tests/`: caller, custody, replay, crash, redaction, and fake transport tests.

## Commands and activation state

Do not claim a Swift gate exists until `Package.swift` is present. After W0-005
creates it, use focused `swift test --filter <test>` followed by `swift test`,
subject to the checked-in package and CI at execution time.

## Broker invariants

- Run as a separately supervised per-user daemon. Authenticate every client
  with OS-level caller identity and bind operations to that identity.
- Armel never receives a secret value, token, Keychain item, or environment
  export. The Broker performs a narrow operation and returns a redacted result.
- Bind inputs to operation, audience, expiry, nonce, and one-use state when the
  contract requires it.
- Persist consumption before dispatch. An ambiguous post-effect result is
  `unknown` and is not retried automatically.
- Keep secret material out of environment variables, arguments, output,
  crashes, logs, temporary files, IPC visible to untrusted callers, and tests.
- Separate ordinary Signal intent from approval and owner-control evidence.
- The Broker verifies and consumes Supervisor capability. It does not decide
  whether work is authorized.

## Test requirements

- Start with fake Keychain, fake caller identity, fake clock, and fake Signal.
- Prove wrong-caller and wrong-operation denial, replay denial, crash recovery,
  redaction, and one valid typed operation without value leakage.
- Use a dedicated test Keychain namespace. Never link a real Signal device or
  use production Cadence, Vault, provider, or approval credentials.

## Repository-specific prohibitions

- Do not revive `source load-secrets.sh` or any bulk environment export path.
- Do not accept a bearer string as caller authentication.
- Do not let a model select arbitrary Keychain labels or Signal destinations.
- Do not log full requests when they may contain data material. Log stable IDs,
  digests, result classes, and redacted error codes.

## Shared operating contract

This repository uses `armel-agents/v1`. Repository-specific rules narrow this
contract. They may not weaken authority, security, evidence, review, or data
boundaries. When instructions conflict, stop and report the exact conflict to
the orchestrator.

### Evidence and source hierarchy

1. Treat current code, tests, schemas, build files, and runtime-safe probes as
   stronger evidence than prose.
2. Treat the repository's accepted contracts and current ADRs as stronger than
   worktree copies, plans, examples, release history, or remembered context.
3. Label claims as observed, inferred, proposed, or unverified. Never present
   a design or stale document as implemented behavior.
4. Verify mutable facts at execution time. Do not hard-code a current migration
   head, dependency version, branch state, CI check name, host capacity, or
   external service state into this guide.
5. When evidence cannot resolve an ambiguity, ask only if the answer changes
   scope, authority, data exposure, cost, compatibility, or an irreversible
   result. Otherwise choose the smallest reversible path and record it.

### Session start and context loading

1. Read this file, the assigned issue or owner instruction, and the files that
   govern the touched package before making changes.
2. Locate repository-local source-of-truth documents, schemas, templates, and
   test commands. Load only context relevant to the task.
3. Inspect git status, the current branch, the base revision, and existing user
   changes before editing.
4. Confirm the repository root. A parent workspace can contain multiple git
   repositories and must not receive cross-repository commits.
5. Search for existing implementations and documentation before creating a new
   abstraction, file, tracker, memory store, or capability.

### Work authority, scope, and concurrency

1. Do not self-select work. Execute only the issue or owner-authorized task
   assigned by the orchestrator.
2. One issue owns one repository, one branch, one isolated worktree, and one
   pull request. Split cross-repository work into producer and consumer issues
   joined by a versioned contract.
3. Respect declared file ownership and contention locks. Do not edit files
   owned by another active worker.
4. Do not fix unrelated findings. Preserve evidence, report the finding to the
   orchestrator, and continue the assigned work when safe.
5. Cadence is the durable work source. If Cadence is unavailable, do not invent
   a second queue or claim. Only explicitly owner-authorized fallback work may
   proceed, and it must be recorded in the approved local decision or handoff
   artifact for later reconciliation.
6. A missed checkpoint does not authorize duplicate work. Reconcile the worker,
   branch, worktree, process, and pull request before a new attempt starts.

### Implementation loop

1. Restate acceptance criteria and identify the smallest testable slice.
2. Write or update the failing test first. Run it and confirm the expected
   failure for the intended reason.
3. Implement only enough production behavior to pass that test.
4. Run the focused test, then the repository's current broader gate.
5. Update contracts, API documentation, ADRs, runbooks, and operator guidance
   in the same pull request when behavior changes.
6. Capture commands, results, changed paths, assumptions, and residual risk in
   the handoff. Never claim a test, review, build, or deployment that did not
   run.
7. Prefer fakes and deterministic fixtures. Tests must not require production
   credentials, private user data, live Signal state, or production Cadence.

### Repository hygiene

1. Preserve all user changes. Do not reset, discard, overwrite, or reformat
   unrelated work.
2. Do not use destructive git or filesystem commands without explicit owner
   authorization and exact target verification.
3. Keep changes focused. Do not mix refactors, dependency upgrades, generated
   churn, or opportunistic cleanup into a bounded issue.
4. Generated files must be reproducible. Change the source and generator, then
   regenerate. Do not hand-edit generated output.
5. Never add co-author, generated-by, model, bot, or similar attribution to
   commits, pull requests, code comments, documentation, or artifacts.

### Security and data handling

1. Never place secrets, tokens, credentials, private keys, approval proofs,
   biometric data, private memory, PII, or production records in prompts,
   source, tests, fixtures, logs, screenshots, or receipts.
2. Use typed operations and least privilege. Model output, prompt text, local
   confidence, and skill content are not authority.
3. Validate user-controlled input, paths, selectors, identifiers, and external
   responses at the boundary. Use parameterized queries.
4. Fail closed at authority, authentication, tenant, secret, approval, and host
   effect boundaries. Preserve an explicit unknown state for ambiguous effects.
5. Use synthetic data and dedicated test namespaces. A local test must not
   mutate production or a real user's external account.

### Durable decisions and learning

1. Durable Armel work, memory, policy, approvals, and completion receipts live
   in Cadence. Repository documents are versioned implementation evidence, not
   a competing brain or task queue.
2. Read the governing schema, taxonomy, template, and current index before
   writing structured knowledge. Do not invent a new entity type or tag in one
   file.
3. Record significant architectural or security decisions in the repository's
   ADR location. If no convention exists, propose one before creating it.
4. Record forensic learning at the checkpoint where it becomes known. Include
   absolute date, evidence, surprise, cost, rejected assumption, and follow-up.
5. Preserve history. Supersede or archive durable records instead of deleting
   or silently rewriting accepted evidence.

### Review and completion

1. Every implementation change receives independent code review. Security,
   authentication, concurrency, migration, frontend, accessibility, and
   infrastructure changes also receive the relevant specialist review.
2. Verify review findings against code and tests before adopting them. A
   reviewer assertion is evidence to investigate, not automatic truth.
3. Resolve or explicitly disposition every finding. Re-run affected tests after
   corrections.
4. Completion requires passing required tests, documentation, review evidence,
   final head revision, changed-path inventory, and honest residual risks.
5. Only the authorized orchestrator or owner merges and settles work. A worker
   does not mark its own issue complete.

### Writing style

1. Do not use emoji.
2. Do not use em dashes or en dashes. Use commas, periods, colons, semicolons,
   parentheses, or ASCII hyphens.
3. Use absolute dates for decisions and time-sensitive evidence.
4. Write concise, direct, project-specific instructions. Do not add generic
   filler, marketing language, or claims without evidence.
