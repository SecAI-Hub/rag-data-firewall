# Security audit — 2026-08-02

## Scope

The review covered policy parsing and precedence, request authentication and
identity, retrieval scope, content scanning, document persistence, audit-log
integrity, HTTP behavior, containers, and the GitHub Actions supply chain.
Policies, requests, stored state, and document content were treated as hostile.

## Remediated findings

- Daemon startup now fails closed without a strong owner-only token, a valid
  strict versioned policy, an intact audit chain, and writable durable storage.
- HTTP callers can no longer elevate themselves by declaring `system`, `user`,
  or `high` trust; identity is configured by the operator per service instance.
- Every HTTP retrieval requires explicit chunk or document IDs.
- Removed the raw-content bypass from the chunk-list endpoint. It now returns
  bounded metadata for one explicit document; content is available only through
  policy evaluation.
- Retrieval deduplicates and caps candidates at 1,000 and re-scans their content
  immediately before evaluation, preventing stale persisted scan fields or a
  scanner-policy reload from preserving a fail-open decision.
- JSON and YAML parsing is bounded and rejects unknown fields, trailing values,
  duplicate/invalid policy values, and unsafe unscoped allows.
- Replaced crash-prone two-file updates with one fsynced atomic snapshot that
  migrates legacy JSONL state and validates relationships, timestamps, security
  label inheritance, record limits, and chunk hashes.
- Corpus state and audit storage are owner-only and singly linked. Active path
  identity, size, and modification time are tracked so external snapshot
  replacement or mutation blocks subsequent writes.
- Audit verification fails on malformed or altered chains; writes are locked,
  fsynced, bounded, tied to the active file identity/size, and fail closed if
  persistence is unavailable. Mutation authorization is logged before state
  changes, so audit failure cannot create an unaudited ingest/delete/reload.
- Policy reload now rejects data, retention, and daemon changes that cannot be
  applied safely without restart.
- Added generic client errors, request/file limits, strict health readiness,
  security headers, timeouts, graceful shutdown, and bounded CLI file reads.
- TTL retention now executes at startup and hourly with fail-closed audit
  authorization. Added bounded base64 inspection, complete high-risk redaction
  aliases, a concurrent-request cap, and explicit non-loopback bind opt-in.
- Added a pre-allocation 4,096-chunk limit to defeat newline/paragraph separator
  bombs, applies query limits during indexed selection, deduplicates document
  scopes, and caps aggregate retrieval content at 32 MiB before rescanning.
- Added digest-pinned non-root containers and immutable-action CI, CodeQL,
  dependency updates, SBOM, provenance, checksum, and signing release controls.
- Gated every release publisher on a read-only check that requires a
  v-prefixed strict SemVer annotated tag resolving exactly to the workflow
  commit, with that commit contained in `origin/main`. Write, package, OIDC,
  and attestation permissions remain confined to the publishing jobs.

## Verification completed

- `go test -race -count=1 ./...`
- `go vet ./...`
- `gosec -severity medium -confidence medium ./...`: no findings
- `govulncheck ./...`: no reachable vulnerabilities
- Trivy source/config/secret and image scans: no HIGH or CRITICAL findings
- Gitleaks full-history and working-tree scans: no findings
- Actionlint and a read-only/capability-dropped daemon smoke test
- Release dependency/permission graph checks, strict SemVer positive/negative
  fixtures, and synthetic annotated/lightweight/off-main Git ancestry cases

## Residual operational risks

- Stored chunks are plaintext. Use an encrypted filesystem/volume, encrypted
  backups, strict mount permissions, and host-level access controls.
- The hash chain detects edits and interior deletion but needs an external
  immutable anchor to prove that its tail was not truncated. Export periodic
  head hashes to a trusted transparency or logging system.
- The in-process rate limit is per replica. Enforce an aggregate limit at the
  ingress when deploying more than one replica.
- Atomic JSON snapshots prioritize integrity over write throughput. Move to a
  transactional encrypted database before very large or high-write workloads.
- Authorization records precede the corresponding snapshot mutation. A later
  storage failure can therefore leave an accurate authorized-attempt record
  without a committed mutation; consumers should not interpret authorization
  records as transaction receipts.
- Local CLI operations do not join the daemon audit chain. Restrict CLI access
  to trusted operators and use OS-level command/session auditing where required.
- Pattern matching reduces known prompt-injection risk but cannot establish that
  arbitrary retrieved text is safe. Retain model-side instruction/data
  separation and least-privilege tool controls.
