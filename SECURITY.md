# Security Design — rag-data-firewall

## Overview

The RAG Data Firewall is a policy-enforced gateway that controls which
document chunks may be returned to AI models and tools during retrieval.
It provides content scanning, PII redaction, and tamper-evident audit logging.

## Authentication

All non-health endpoints require a bearer token. The token is loaded from an
owner-only file selected by `SERVICE_TOKEN_PATH` (default
`/run/secure-ai/service-token`) and compared using
`crypto/subtle.ConstantTimeCompare` to prevent timing attacks.

Requester type and session trust are server configuration, not trusted request
claims. The defaults are `tool` and `low`.

## Policy Evaluation — Deny-First Precedence

The policy engine uses **deny-first** rule evaluation:

1. All deny rules are checked first, regardless of position in the config
2. If any deny rule matches, the chunk is blocked immediately
3. Non-deny rules (require-approval, redact, allow) are then evaluated in order
4. If no rule matches, the default action applies (deny by default)

This prevents an early allow rule from accidentally overriding a
security-critical deny rule.

## Content Scanning

The scanner detects:

- **Direct prompt injection**: 14 patterns (ignore instructions, role override, etc.)
- **Encoded injection**: Unicode bidi overrides, zero-width hiding, HTML entity tags, hex escapes
- **Instruction smuggling**: Markdown fence injection, HTML comment injection, invisible text, delimiter role switching
- **Data exfiltration**: URL fetch, file protocol, markdown exfil, DNS exfil, send-data instructions
- **Base64-encoded injection**: Decodes base64 strings and checks for embedded injection patterns
- **PII detection**: SSN, email, credit card, credentials, bearer tokens, phone numbers
- **Suspicious patterns**: eval, exec, import os, subprocess, script tags

Each finding produces a structured `RiskReason` with category, pattern,
weight, and detail for explainability.

## Retrieval Scoping

Every HTTP caller must provide explicit `chunk_ids` or `document_ids`.
Requests are deduplicated and limited to 1,000 candidates. Stored scanner
results are re-computed immediately before policy evaluation. The chunk-list
endpoint requires one document ID and returns metadata, never content.
Unscoped retrieval is available only to a local CLI operator.

## Data Protection

- **Retention limits**: Configurable max documents, max total chunks, and TTL;
  expiration is enforced at startup and hourly with audit authorization
- **Document deletion**: Documents and their chunks can be deleted via API
- **PII redaction**: Content matching PII patterns is replaced with tagged placeholders
- **Crash consistency**: Documents and chunks are committed together in one
  fsynced, atomically replaced snapshot; legacy JSONL is migrated on first open
- **State validation**: IDs, timestamps, hashes, labels, trust/sensitivity
  inheritance, relationships, counts, and hard record limits are checked at
  startup

## Tamper-Evident Audit Logging

Every trust-bearing daemon operation is audit-gated. Ingest, delete, policy
reload, and TTL purge authorization is durably recorded before state mutation; retrieval
decisions are recorded before content is returned. The JSONL audit file uses a
SHA-256 hash chain. Each entry includes:

- `hash`: SHA-256 of the entry's canonical fields
- `prev_hash`: hash of the preceding entry

The service verifies the complete chain at startup and monitors the active
file's identity and expected size before every append. Any replacement,
truncation, append, size-limit, write, or synchronization error disables audit
readiness and blocks later mutations. The chain allows detection of inserted,
deleted, or modified entries, subject to the external-anchor limitation below.

## HTTP Server Hardening

- `http.Server` with configurable read/write/idle timeouts (defaults: 30s/60s/120s)
- `MaxBytesReader` on all request bodies (10 MiB limit), strict JSON decoding,
  and a 16 KiB maximum header size
- Rate limiting on every authenticated endpoint (configurable requests per minute)
- A bounded concurrent-request pool for expensive scan/store/retrieval work
- Consistent JSON error responses on all endpoints

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Prompt injection in documents | Content scanning with 14+ injection patterns plus encoded/smuggling detection |
| PII leakage via RAG retrieval | PII detection + redaction action in policy rules |
| Unauthorized access to chunks | Bearer token auth, metadata-only listing, explicit retrieval scope, fresh scanning, and deny-by-default policy |
| Unscoped data access | Retrieval scoping (require explicit chunk/doc IDs for non-system callers) |
| Policy misconfiguration | Deny-first precedence ensures deny rules always take priority |
| Audit log tampering | Hash chain on audit entries |
| Data accumulation | Retention limits + TTL-based expiration + document deletion |

Non-loopback binding requires `ALLOW_REMOTE_BIND=true`; this is an exposure
acknowledgement, not a TLS control. Keep the service on loopback or place it
behind authenticated TLS and network policy.

Policy hot reload applies rules, scanner settings, and rate limits. Changes to
the data directory, retention settings, or HTTP server settings are rejected
until restart so the reported configuration cannot diverge from active state.
