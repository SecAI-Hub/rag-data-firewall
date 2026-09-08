package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func roleRequest(t *testing.T, token, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	// A client header or a context supplied by another wrapper cannot elevate
	// the role derived from the credential at the actual HTTP boundary.
	r.Header.Set("X-Role", roleAdmin)
	r = withPrincipal(r, principal{role: roleAdmin, identity: "forged-context"})
	w := httptest.NewRecorder()
	buildMux().ServeHTTP(w, r)
	return w
}

func TestReaderCannotManageCorpusOrPolicy(t *testing.T) {
	setupTestEnv(t)
	defer docStore.Close()
	doc, _, err := docStore.Ingest(IngestRequest{Name: "private document name", Content: "Private business plan", SensitivityLabel: "restricted"}, getPolicy().Scanner)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(getDataDir(), "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	generation := getRuntime()
	for _, request := range []struct{ method, path, body string }{
		{"POST", "/v1/ingest", `{"name":"poisoned","content":"content","source":"vault","trust_level":"verified","sensitivity_label":"public"}`},
		{"GET", "/v1/documents", ""},
		{"DELETE", "/v1/documents?id=" + doc.ID, ""},
		{"GET", "/v1/chunks?document_id=" + doc.ID, ""},
		{"POST", "/v1/reload", ""},
		{"GET", "/v1/metrics", ""},
	} {
		w := roleRequest(t, serviceToken, request.method, request.path, request.body)
		if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), doc.Name) {
			t.Fatalf("%s %s: %d %s", request.method, request.path, w.Code, w.Body.String())
		}
	}
	after, err := os.ReadFile(filepath.Join(getDataDir(), "store.json"))
	if err != nil || string(before) != string(after) || getRuntime() != generation {
		t.Fatal("forbidden operations changed persisted state or policy")
	}
	w := roleRequest(t, serviceToken, "POST", "/v1/retrieve", `{"document_ids":["`+doc.ID+`"]}`)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "Private business plan") {
		t.Fatalf("restricted retrieval: %d %s", w.Code, w.Body.String())
	}
	if scan := roleRequest(t, serviceToken, "POST", "/v1/scan", `{"content":"Ordinary prose"}`); scan.Code != 200 {
		t.Fatal("reader must retain scan capability")
	}
}

func TestHTTPIngestionBindsProvenanceAndRole(t *testing.T) {
	setupTestEnv(t)
	defer docStore.Close()
	ingestToken = strings.Repeat("ingester-", 5)
	curatorToken = strings.Repeat("curator-", 5)
	adminToken = strings.Repeat("admin-", 7)
	for role, token := range map[string]string{roleIngester: ingestToken, roleCurator: curatorToken, roleAdmin: adminToken} {
		for _, claim := range []string{`"source":"vault"`, `"trust_level":"verified"`} {
			w := roleRequest(t, token, "POST", "/v1/ingest", `{"name":"test","content":"document",`+claim+`}`)
			if w.Code != http.StatusForbidden || docStore.DocumentCount() != 0 {
				t.Fatalf("%s accepted asserted provenance: %d %s", role, w.Code, w.Body.String())
			}
		}
	}
	for _, claim := range []string{`"sensitivity_label":"public"`, `"sensitivity_label":"internal"`, `"labels":{"reviewed":"true"}`} {
		w := roleRequest(t, ingestToken, "POST", "/v1/ingest", `{"name":"test","content":"document",`+claim+`}`)
		if w.Code != http.StatusForbidden || docStore.DocumentCount() != 0 {
			t.Fatalf("ingester escalated sensitivity/labels: %d %s", w.Code, w.Body.String())
		}
	}
	w := roleRequest(t, ingestToken, "POST", "/v1/ingest", `{"name":"private upload name","content":"private upload content"}`)
	var uploaded struct {
		Document Document `json:"document"`
	}
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &uploaded) != nil {
		t.Fatalf("restricted upload: %d %s", w.Code, w.Body.String())
	}
	if uploaded.Document.Source != "upload" || uploaded.Document.TrustLevel != "untrusted" || uploaded.Document.SensitivityLabel != "restricted" {
		t.Fatalf("wrong server provenance: %+v", uploaded.Document)
	}
	for _, request := range []struct{ method, path, body string }{
		{"POST", "/v1/retrieve", `{"document_ids":["` + uploaded.Document.ID + `"]}`},
		{"GET", "/v1/documents", ""},
		{"GET", "/v1/chunks?document_id=" + uploaded.Document.ID, ""},
		{"DELETE", "/v1/documents?id=" + uploaded.Document.ID, ""},
		{"POST", "/v1/reload", ""},
		{"GET", "/v1/metrics", ""},
	} {
		if response := roleRequest(t, ingestToken, request.method, request.path, request.body); response.Code != http.StatusForbidden {
			t.Fatalf("ingester can %s %s: %d", request.method, request.path, response.Code)
		}
	}
	w = roleRequest(t, curatorToken, "POST", "/v1/ingest", `{"name":"public manual name","content":"Public document text","sensitivity_label":"public"}`)
	var curated struct {
		Document Document `json:"document"`
	}
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &curated) != nil {
		t.Fatalf("curation: %d %s", w.Code, w.Body.String())
	}
	if curated.Document.Source != "manual" || curated.Document.TrustLevel != "unverified" {
		t.Fatal("curator cannot establish verified provenance")
	}
	for _, token := range []string{serviceToken, curatorToken, adminToken} {
		response := roleRequest(t, token, "POST", "/v1/retrieve", `{"document_ids":["`+curated.Document.ID+`"]}`)
		if response.Code != 200 || !strings.Contains(response.Body.String(), "Public document text") {
			t.Fatal("authorized public retrieval failed")
		}
	}
	if response := roleRequest(t, curatorToken, "GET", "/v1/chunks?document_id="+curated.Document.ID, ""); response.Code != 200 {
		t.Fatal("curator cannot review metadata")
	}
	if response := roleRequest(t, curatorToken, "GET", "/v1/documents", ""); response.Code != 200 {
		t.Fatal("curator cannot list corpus")
	}
	if response := roleRequest(t, curatorToken, "POST", "/v1/reload", ""); response.Code != http.StatusForbidden {
		t.Fatal("curator can reload policy")
	}
	if response := roleRequest(t, curatorToken, "DELETE", "/v1/documents?id="+curated.Document.ID, ""); response.Code != 200 {
		t.Fatal("curator cannot delete document")
	}
	if response := roleRequest(t, adminToken, "GET", "/v1/metrics", ""); response.Code != 200 {
		t.Fatal("admin cannot inspect metrics")
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{serviceToken, curatorToken, adminToken, ingestToken, "private upload name", "private upload content", "public manual name", "Public document text", "forged-context"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("sensitive or forged value in audit: %q", secret)
		}
	}
	for _, role := range []string{roleReader, roleIngester, roleCurator, roleAdmin} {
		if !strings.Contains(string(data), `"identity":"`+role+`:`) {
			t.Fatalf("audit lacks authenticated %s identity", role)
		}
	}
}

func TestAdminReloadAndMutationsFailClosedOnAuditLoss(t *testing.T) {
	setupTestEnv(t)
	defer docStore.Close()
	adminToken = strings.Repeat("admin-", 7)
	curatorToken = strings.Repeat("curator-", 5)
	pol := getPolicy()
	pol.Scanner.PromptInjection = false
	raw, err := yaml.Marshal(pol)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POLICY_PATH", path)
	prior := getRuntime()
	w := roleRequest(t, adminToken, "POST", "/v1/reload", "")
	if w.Code != 200 || getRuntime() == prior || !strings.Contains(w.Body.String(), getRuntime().digest) {
		t.Fatalf("admin reload failed: %d %s", w.Code, w.Body.String())
	}
	prior = getRuntime()
	doc, _, err := docStore.Ingest(IngestRequest{Name: "retain", Content: "Retain this document", SensitivityLabel: "public"}, pol.Scanner)
	if err != nil {
		t.Fatal(err)
	}
	auditMu.Lock()
	_ = auditFile.Close()
	auditFile = nil
	auditMu.Unlock()
	for _, request := range []struct{ method, path, body string }{
		{"POST", "/v1/ingest", `{"name":"new","content":"new document"}`},
		{"DELETE", "/v1/documents?id=" + doc.ID, ""},
		{"POST", "/v1/reload", ""},
		{"POST", "/v1/retrieve", `{"document_ids":["` + doc.ID + `"]}`},
	} {
		w = roleRequest(t, adminToken, request.method, request.path, request.body)
		if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), doc.Name) {
			t.Fatalf("audit-loss %s: %d %s", request.path, w.Code, w.Body.String())
		}
		if docStore.DocumentCount() != 1 || getRuntime() != prior {
			t.Fatal("failed audit changed document store or policy")
		}
	}
}

func TestRoleCredentialsMustBeDistinctAndExplicit(t *testing.T) {
	setupTestEnv(t)
	defer docStore.Close()
	for _, name := range []string{"ADMIN_TOKEN_PATH", "CURATOR_TOKEN_PATH", "INGEST_TOKEN_PATH"} {
		t.Setenv(name, "")
	}
	if err := loadRoleTokens(); err != nil || adminToken != "" || curatorToken != "" || ingestToken != "" {
		t.Fatal("missing role configuration must leave management disabled")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "role-token")
	if err := os.WriteFile(path, []byte(serviceToken), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADMIN_TOKEN_PATH", path)
	if err := loadRoleTokens(); err == nil || adminToken != "" {
		t.Fatal("reader and admin accepted the same credential")
	}
	secret := strings.Repeat("admin-", 7)
	if err := os.WriteFile(path, []byte(secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadRoleTokens(); err != nil || adminToken != secret {
		t.Fatalf("valid explicit admin failed: %v", err)
	}
	priorAdmin := adminToken
	t.Setenv("CURATOR_TOKEN_PATH", filepath.Join(dir, "missing"))
	if err := loadRoleTokens(); err == nil || adminToken != priorAdmin || curatorToken != "" {
		t.Fatal("invalid configured role did not fail transactionally")
	}
	t.Setenv("CURATOR_TOKEN_PATH", path)
	if err := loadRoleTokens(); err == nil {
		t.Fatal("management roles accepted duplicate credentials")
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := readRoleToken(path); err == nil {
		t.Fatal("group-readable credential accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked-token")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRoleToken(link); err == nil {
		t.Fatal("symlink credential accepted")
	}
	hardLink := filepath.Join(dir, "hard-token")
	if err := os.Link(path, hardLink); err != nil {
		t.Fatal(err)
	}
	if _, err := readRoleToken(path); err == nil {
		t.Fatal("hard-linked credential accepted")
	}
}

func TestDefaultPolicyWithholdsConfidentialProse(t *testing.T) {
	t.Setenv("POLICY_PATH", "policies/default-policy.yaml")
	pol, err := readPolicy()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := newPolicyRuntime(pol)
	if err != nil {
		t.Fatal(err)
	}
	content := "Confidential acquisition target and undisclosed product roadmap."
	chunk := Chunk{ID: "private-chunk", Content: content, SensitivityLabel: "confidential", TrustLevel: "verified", Scan: ScanContent(content, pol.Scanner)}
	if chunk.Scan.PIIDetected || chunk.Scan.PromptInjection || chunk.Scan.RiskScore >= 0.8 {
		t.Fatal("regression requires confidential prose without a scanner finding")
	}
	for _, tc := range []struct{ requester, trust, action string }{
		{"tool", "low", "deny"}, {"user", "low", "deny"}, {"system", "low", "deny"},
		{"tool", "high", "require-approval"}, {"user", "medium", "require-approval"}, {"system", "high", "require-approval"},
		{"user", "high", "allow"},
	} {
		decision := snapshot.engine.EvaluateChunk(chunk, "vault", RetrievalRequest{RequesterType: tc.requester, SessionTrust: tc.trust})
		if decision.Action != tc.action || (tc.action != "allow" && decision.Content != "") || (tc.action == "allow" && decision.Content != content) {
			t.Fatalf("%s/%s: %+v", tc.requester, tc.trust, decision)
		}
	}
}
