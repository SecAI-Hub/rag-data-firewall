package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
)

const (
	roleReader   = "reader"
	roleIngester = "ingester"
	roleCurator  = "curator"
	roleAdmin    = "admin"
)

type principal struct{ role, identity string }
type principalContextKey struct{}

var adminToken, curatorToken, ingestToken string

func readRoleToken(path string) (string, error) {
	raw, info, err := readRegularFileWithInfo(path, maxServiceTokenSize)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0o077 != 0 || !hasSingleLink(info) {
		return "", fmt.Errorf("credential must be an owner-only single-link regular file")
	}
	token := strings.TrimSpace(string(raw))
	if !validServiceToken(token) {
		return "", fmt.Errorf("credential must contain at least 32 non-whitespace bytes")
	}
	return token, nil
}

// Optional management credentials only enable their explicit role. They never
// inherit the retrieval token, and a configured invalid token fails startup.
func loadRoleTokens() error {
	values := map[string]string{roleReader: serviceToken}
	for role, variable := range map[string]string{roleAdmin: "ADMIN_TOKEN_PATH", roleCurator: "CURATOR_TOKEN_PATH", roleIngester: "INGEST_TOKEN_PATH"} {
		if path := os.Getenv(variable); path != "" {
			value, err := readRoleToken(path)
			if err != nil {
				return fmt.Errorf("load %s credential: %w", role, err)
			}
			values[role] = value
		}
	}
	seen := make(map[[32]byte]bool)
	for _, value := range values {
		digest := sha256.Sum256([]byte(value))
		if seen[digest] {
			return fmt.Errorf("roles must use different credentials")
		}
		seen[digest] = true
	}
	adminToken, curatorToken, ingestToken = values[roleAdmin], values[roleCurator], values[roleIngester]
	return nil
}

func authenticateToken(token string) (principal, bool) {
	presented := sha256.Sum256([]byte(token))
	var actor principal
	// Compare fixed-length digests for every role; missing roles never match.
	for _, entry := range []struct{ role, token string }{{roleReader, serviceToken}, {roleIngester, ingestToken}, {roleCurator, curatorToken}, {roleAdmin, adminToken}} {
		configured := sha256.Sum256([]byte(entry.token))
		if subtle.ConstantTimeCompare(presented[:], configured[:]) == 1 && entry.token != "" {
			actor = principal{role: entry.role, identity: entry.role + ":" + hex.EncodeToString(configured[:16])}
		}
	}
	return actor, actor.role != ""
}

func requestPrincipal(r *http.Request) principal {
	actor, _ := r.Context().Value(principalContextKey{}).(principal)
	return actor
}

func requireRole(w http.ResponseWriter, r *http.Request, roles ...string) bool {
	actor := requestPrincipal(r)
	for _, role := range roles {
		if actor.role == role {
			return true
		}
	}
	jsonError(w, "credential is not authorized for this operation", http.StatusForbidden)
	return false
}

func withPrincipal(r *http.Request, actor principal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), principalContextKey{}, actor))
}

// HTTP uploads cannot self-assert vault origin or verified provenance. Trusted
// local CLI/adapters remain the explicit operator boundary for such assertions.
func bindIngestProvenance(r *http.Request, req *IngestRequest) error {
	actor := requestPrincipal(r)
	source, trust := "manual", "unverified"
	if actor.role == roleIngester {
		source, trust = "upload", "untrusted"
		if (req.SensitivityLabel != "" && req.SensitivityLabel != "restricted") || len(req.Labels) != 0 {
			return fmt.Errorf("ingester uploads must be restricted and cannot set policy labels")
		}
		req.SensitivityLabel = "restricted"
	}
	if (req.Source != "" && req.Source != source) || (req.TrustLevel != "" && req.TrustLevel != trust) {
		return fmt.Errorf("document provenance does not match the authenticated ingestion role")
	}
	req.Source, req.TrustLevel = source, trust
	return nil
}
