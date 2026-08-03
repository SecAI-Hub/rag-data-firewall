# rag-data-firewall

A deny-by-default policy gateway for retrieval-augmented generation. It labels,
scans, stores, and evaluates document chunks before they are returned to models
or tools, and records security decisions in a hash-chained audit log.

## Capabilities

- Prompt-injection, encoded-smuggling, exfiltration, credential, and PII checks
- Deny-first policy evaluation with allow, deny, redact, and approval outcomes
- Explicit document/chunk retrieval scoping
- Fresh content scanning at retrieval time; stored scan verdicts are non-authoritative
- Server-controlled requester identity and session trust
- Bounded strict JSON/YAML inputs and retention enforcement
- Per-document chunk and aggregate retrieval-byte limits against separator and selection DoS
- Atomic, crash-consistent document/chunk snapshots
- Fail-closed mutation audit authorization
- Authenticated HTTP API, endpoint-wide rate/concurrency limiting, security headers, and graceful shutdown

## Build and test

Go 1.26.5 or newer is required.

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

All `/v1/*` routes require a bearer token. Place at least 32 random,
non-whitespace bytes in an owner-only regular file (mode `0600`) and set:

```bash
export SERVICE_TOKEN_PATH=/run/secure-ai/service-token
export SERVICE_REQUESTER_TYPE=tool
export SERVICE_SESSION_TRUST=low
rag-data-firewall serve -policy policies/default-policy.yaml
```

`SERVICE_REQUESTER_TYPE` defaults to `tool`; `SERVICE_SESSION_TRUST` defaults to
`low`. Run separate instances with separate tokens and policies when different
trust identities are required.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Readiness check; no corpus counts are disclosed |
| `POST` | `/v1/ingest` | Store and scan a labeled document |
| `POST` | `/v1/retrieve` | Evaluate explicitly scoped chunks/documents |
| `POST` | `/v1/scan` | Scan content without storing it |
| `GET`, `DELETE` | `/v1/documents` | List or delete documents |
| `GET` | `/v1/chunks` | List content-free metadata for one explicit document |
| `POST` | `/v1/reload` | Strictly reload rules/scanner/rate policy |
| `GET` | `/v1/metrics` | Service counters |

The default bind is `127.0.0.1:8500`. Terminate TLS and apply network policy in
front of the service before exposing it outside a trusted host or pod. A
non-loopback bind requires the explicit `ALLOW_REMOTE_BIND=true` opt-in.

The chunk-list endpoint never returns stored text. `/v1/retrieve` is the only
HTTP content-release path and accepts at most 1,000 unique candidates per
request and at most 32 MiB of aggregate candidate content. A document may
produce at most 4,096 chunks, and selection limits are applied while reading
the in-memory index rather than after copying the entire document. It re-scans
every candidate immediately before deny-first evaluation.
Changes to the data directory, retention, or daemon settings require a restart;
hot reload rejects them rather than reporting an unapplied configuration.
TTL expiration runs before the listener starts and hourly thereafter. Each
purge is audit-authorized before the replacement snapshot is committed.

## Container

The image runs as UID/GID 65534 and includes the default policy. Mount the
service-token file at `/run/secure-ai/service-token` with mode `0400`/`0600`,
and persist `/var/lib/secure-ai` on an encrypted volume. The container command
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
hard-linking.
Local CLI operations are intended for an already trusted operator and are not
written to the daemon audit file.

## Security

See [SECURITY.md](SECURITY.md) and the latest [security audit](SECURITY_AUDIT.md).

## License

Apache 2.0. See [LICENSE](LICENSE).
