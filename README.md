# rag-data-firewall

A deny-by-default policy gateway for retrieval-augmented generation. It labels,
scans, stores, and evaluates document chunks before they are returned to models
or tools, and records security decisions in a hash-chained audit log.

## Capabilities

- Prompt-injection, encoded-smuggling, exfiltration, credential, and PII checks
- Deny-first policy evaluation with allow, deny, redact, and approval outcomes
- Explicit document/chunk retrieval scoping
- Fresh content scanning at retrieval time; stored scan verdicts are non-authoritative
- Separate reader, ingester, curator and administrator credentials
- Server-controlled requester identity, upload provenance and session trust
- One immutable scanner/policy generation per retrieval, identified in response and audit
- Bounded strict JSON/YAML inputs and retention enforcement
- Per-document chunk and aggregate retrieval-byte limits against separator and selection DoS
- Atomic, crash-consistent document/chunk snapshots
- Exclusive corpus and audit writer ownership, checked during readiness and use
- Fail-closed mutation audit authorization
- Authenticated HTTP API, endpoint-wide rate/concurrency limiting, security headers, and graceful shutdown

## Build and test

Go 1.26.8 or newer is required; CI uses Go 1.27.1.

```bash
go test -race ./...
go build -trimpath -o rag-data-firewall .
```

## CLI

```bash
rag-data-firewall scan -policy policies/default-policy.yaml -file document.txt
rag-data-firewall ingest -policy policies/default-policy.yaml \
  -file document.txt -name handbook -sensitivity internal -trust verified
rag-data-firewall list -policy policies/default-policy.yaml documents
rag-data-firewall query -policy policies/default-policy.yaml -docs DOCUMENT_ID
```

CLI queries run locally and may set requester and trust flags. The HTTP daemon
does not trust identity claims supplied in a request body.

## Daemon

All `/v1/*` routes require a bearer token. Generate a different credential for
each enabled role, with at least 32 random non-whitespace bytes in an owner-only,
single-link regular file (mode `0400` or `0600`). Symlinks, hard links and shared
credentials fail startup. Configure the required reader credential:

```bash
export SERVICE_TOKEN_PATH=/run/secure-ai/service-token
export SERVICE_REQUESTER_TYPE=tool
export SERVICE_SESSION_TRUST=low
rag-data-firewall serve -policy policies/default-policy.yaml
```

`SERVICE_REQUESTER_TYPE` defaults to `tool`; `SERVICE_SESSION_TRUST` defaults to
`low`. These are deployment settings, never caller-controlled privileges. All
HTTP retrieval, including requests authenticated as a curator or administrator,
uses this configured identity and the same content policy. Run separate instances
with separate storage, tokens and policies for different trust identities or
tenants; one instance manages a shared corpus, not per-user document ownership.

Optional role credentials are loaded only when their path is configured:

| Environment variable | Role | Permissions |
| --- | --- | --- |
| `SERVICE_TOKEN_PATH` | Reader | Scoped policy-filtered retrieval and scanning |
| `INGEST_TOKEN_PATH` | Ingester | Restricted, untrusted uploads and scanning |
| `CURATOR_TOKEN_PATH` | Curator | Manual ingestion, corpus metadata, deletion, retrieval and scanning |
| `ADMIN_TOKEN_PATH` | Administrator | Curator operations, policy reload and metrics |

Missing optional credentials leave those roles disabled; an invalid configured
credential prevents startup. Restart to rotate credentials. Do not give curator
or administrator tokens to a model or an untrusted client.

| Method | Path | Required role |
| --- | --- | --- |
| `GET` | `/health` | Public readiness check; no corpus counts |
| `POST` | `/v1/ingest` | Ingester, curator or administrator |
| `POST` | `/v1/retrieve` | Reader, curator or administrator |
| `POST` | `/v1/scan` | Any authenticated role |
| `GET`, `DELETE` | `/v1/documents` | Curator or administrator |
| `GET` | `/v1/chunks` | Curator or administrator; one explicit document |
| `POST` | `/v1/reload` | Administrator |
| `GET` | `/v1/metrics` | Administrator |

HTTP ingestion binds provenance to the credential. An ingester's uploads receive
`source=upload`, `trust_level=untrusted` and `sensitivity_label=restricted`; they
cannot supply policy labels or read the corpus. Curators and administrators can
classify manual documents, with `source=manual` and `trust_level=unverified`.
Omit the provenance fields or supply these exact values. Every HTTP role is
forbidden from claiming a verified document or vault origin. Establish those
claims through the trusted local operator workflow while the daemon is stopped.

The default policy withholds all confidential content in low-trust sessions.
An explicitly configured high-trust user may receive it; other identities get
`require-approval` without content. That outcome is a refusal pending a separate
operator workflow, not an implemented approval/release endpoint. PII redaction
alone does not make confidential prose safe to release.

The default bind is `127.0.0.1:8500`. Terminate TLS and apply network policy in
front of the service before exposing it outside a trusted host or pod. A
non-loopback bind requires the explicit `ALLOW_REMOTE_BIND=true` opt-in.

The chunk-list endpoint never returns stored text. `/v1/retrieve` is the only
HTTP content-release path and accepts at most 1,000 unique candidates per
request and at most 32 MiB of aggregate candidate content. A document may
produce at most 4,096 chunks, and selection limits are applied while reading
the in-memory index rather than after copying the entire document. It re-scans
every candidate immediately before deny-first evaluation. Scanning, evaluation,
response `policy_digest`, and audit evidence use one immutable policy snapshot.
Retrieval audits contain authenticated role identity and per-chunk content/rule
hashes and verdicts, without raw document content, names, queries, or tool text.
Scanner responses expose their generation in `X-SecAI-Policy-Digest`.
Changes to the data directory, retention, or daemon settings require a restart;
hot reload rejects them rather than reporting an unapplied configuration.
Reload records durable authorization before atomically publishing a generation;
an audit failure keeps the previous generation active. Requests already running
finish under their captured generation.
TTL expiration runs before the listener starts and hourly thereafter. Each
purge is audit-authorized before the replacement snapshot is committed.

## Container

The image runs as UID/GID 65534 and includes the default policy. Mount the
service-token file at `/run/secure-ai/service-token` with mode `0400`/`0600`,
mount optional role files separately and set their path variables, and persist
`/var/lib/secure-ai` on an encrypted local volume. The container command
binds to `0.0.0.0:8500`; it is not host-accessible unless a port is explicitly
published.

For an owner-only bind-mounted token, either securely project it with ownership
65534:65534 or run the container as the token file's host UID/GID. Never make a
secret group/world-readable merely to satisfy a container UID mismatch.

Run with a read-only root filesystem, all capabilities dropped,
`no-new-privileges`, a PID limit, and writable mounts only for
`/var/lib/secure-ai` and `/run/secure-ai`.

Daemon audit records cover authorization of ingest, delete, policy reload, and
TTL purge before state changes, plus each retrieval decision before content is
returned. Corpus snapshots, audit files, and their dedicated directories are
owner-only. The daemon tracks the live snapshot/audit identities and refuses
later writes after external replacement, truncation, permission change, or
hard-linking. Readiness and protected HTTP operations fail when corpus/audit
ownership or state identity is lost. Empty `.writer.lock` and audit `.lock` files
remain after shutdown; do not delete or replace them to bypass an active writer.
Stop the daemon before using local CLI commands, taking a consistent offline
backup, or moving its state. A second process refuses to open the same corpus or
journal. This uses [Linux advisory file locks](https://man7.org/linux/man-pages/man2/flock.2.html)
on local filesystems; it is not isolation from a malicious process running as the
same user, and network-filesystem locking has not been qualified.
Local CLI operations are intended for an already trusted operator and are not
written to the daemon audit file.

Upgrade existing clients by keeping their current `SERVICE_TOKEN_PATH` for
retrieval and provisioning separate role files only for trusted management or
upload workflows. The old reader token no longer permits ingestion, metadata
enumeration, deletion, reload or metrics. Update HTTP upload provenance fields
as described above. Deploy the revised default policy explicitly if maintaining
an operator copy; existing custom policies are not rewritten. Store snapshots
remain version 1, and old complete audit records remain readable. The extended
audit format is not readable by older binaries once new fields have been logged;
preserve the upgraded journal with its matching binary for verification instead
of removing evidence to roll back. Independent rollback/deletion anchoring and
journal rotation remain deployment work; reaching the size cap fails closed.

## Security

See [SECURITY.md](SECURITY.md) and the latest [security audit](SECURITY_AUDIT.md).

## License

Apache 2.0. See [LICENSE](LICENSE).
