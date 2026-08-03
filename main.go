package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

type FirewallPolicy struct {
	Version       int             `yaml:"version"`
	DefaultAction string          `yaml:"default_action"`
	Rules         []Rule          `yaml:"rules"`
	Scanner       ScannerConfig   `yaml:"scanner"`
	DataDir       string          `yaml:"data_dir"`
	Daemon        DaemonConfig    `yaml:"daemon"`
	RateLimit     RateLimitCfg    `yaml:"rate_limit"`
	Retention     RetentionConfig `yaml:"retention"`
}

type DaemonConfig struct {
	BindAddr        string `yaml:"bind_addr"`
	ReadTimeoutSec  int    `yaml:"read_timeout_seconds"`
	WriteTimeoutSec int    `yaml:"write_timeout_seconds"`
	IdleTimeoutSec  int    `yaml:"idle_timeout_seconds"`
}

type RateLimitCfg struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
}

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

var (
	policyMu sync.RWMutex
	policy   FirewallPolicy
	engine   *PolicyEngine

	docStore *DocumentStore

	auditFile     *os.File
	auditMu       sync.Mutex
	auditPath     string
	auditLastHash string
	auditFileSize int64
	auditFileTime time.Time

	rateMu      sync.Mutex
	rateCounter int64
	rateWindow  time.Time

	totalRequests    atomic.Int64
	ingestRequests   atomic.Int64
	retrieveRequests atomic.Int64

	serviceToken         string
	serviceRequesterType = "tool"
	serviceSessionTrust  = "low"
	protectedSlots       = make(chan struct{}, 64)
)

const (
	defaultPolicyPath   = "/etc/secure-ai/policy/rag-firewall.yaml"
	defaultTokenPath    = "/run/secure-ai/service-token"
	defaultAuditPath    = "/var/lib/secure-ai/logs/rag-firewall-audit.jsonl"
	defaultDataDir      = "/var/lib/secure-ai/rag"
	defaultBindAddr     = "127.0.0.1:8500"
	defaultRPM          = 120
	maxRequestBodySize  = 10 << 20 // 10 MiB (documents can be large)
	maxRetrievalBytes   = 32 << 20 // bound aggregate content copied/scanned per request
	maxPolicySize       = 1 << 20
	maxAuditSize        = 512 << 20
	maxAuditLineSize    = 2 << 20
	maxServiceTokenSize = 4096
)

// ---------------------------------------------------------------------------
// Policy loading
// ---------------------------------------------------------------------------

func policyFilePath() string {
	if p := os.Getenv("POLICY_PATH"); p != "" {
		return p
	}
	return defaultPolicyPath
}

func readPolicy() (FirewallPolicy, error) {
	data, err := readRegularFile(policyFilePath(), maxPolicySize)
	if err != nil {
		return FirewallPolicy{}, fmt.Errorf("read policy: %w", err)
	}
	var p FirewallPolicy
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&p); err != nil {
		return FirewallPolicy{}, fmt.Errorf("parse policy: %w", err)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return FirewallPolicy{}, errors.New("parse policy: multiple YAML documents are not allowed")
		}
		return FirewallPolicy{}, fmt.Errorf("parse policy trailing data: %w", err)
	}
	if err := validatePolicy(p); err != nil {
		return FirewallPolicy{}, fmt.Errorf("validate policy: %w", err)
	}
	return p, nil
}

func installPolicy(p FirewallPolicy) {
	policyMu.Lock()
	policy = p
	engine = NewPolicyEngine(p.DefaultAction, p.Rules)
	policyMu.Unlock()
}

func loadPolicy() error {
	p, err := readPolicy()
	if err != nil {
		return err
	}
	installPolicy(p)

	log.Printf("policy loaded: default=%s rules=%d", p.DefaultAction, len(p.Rules))
	return nil
}

func getPolicy() FirewallPolicy {
	policyMu.RLock()
	p := policy
	policyMu.RUnlock()
	return p
}

func getEngine() *PolicyEngine {
	policyMu.RLock()
	e := engine
	policyMu.RUnlock()
	return e
}

func getDataDir() string {
	p := getPolicy()
	if p.DataDir != "" {
		return p.DataDir
	}
	return defaultDataDir
}

// ---------------------------------------------------------------------------
// Tamper-evident audit logging (hash chain)
// ---------------------------------------------------------------------------

type AuditEntry struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Allowed   int    `json:"allowed,omitempty"`
	Denied    int    `json:"denied,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Hash      string `json:"hash"`
	PrevHash  string `json:"prev_hash,omitempty"`
}

func initAuditLog() error {
	auditPath = os.Getenv("AUDIT_LOG_PATH")
	if auditPath == "" {
		auditPath = defaultAuditPath
	}
	if err := os.MkdirAll(filepath.Dir(auditPath), 0700); err != nil {
		return fmt.Errorf("create audit directory: %w", err)
	}
	if err := ensurePrivateDirectory(filepath.Dir(auditPath)); err != nil {
		return fmt.Errorf("secure audit directory: %w", err)
	}

	verifiedInfo, err := verifyExistingAuditLog(auditPath)
	if err != nil {
		return err
	}

	// #nosec G304 -- auditPath is operator configuration inside a verified
	// private directory; Lstat/Fstat/link/identity checks immediately follow.
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	pathInfo, err := os.Lstat(auditPath)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("inspect opened audit log: %w", err)
	}
	openedInfo, err := f.Stat()
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode().Perm()&0o077 != 0 ||
		!hasSingleLink(pathInfo) || !hasSingleLink(openedInfo) ||
		!os.SameFile(pathInfo, openedInfo) || openedInfo.Size() > maxAuditSize {
		_ = f.Close()
		return fmt.Errorf("opened audit log is not a bounded, protected regular file")
	}
	if verifiedInfo == nil {
		if openedInfo.Size() != 0 {
			_ = f.Close()
			return fmt.Errorf("audit log appeared during initialization")
		}
	} else if !os.SameFile(verifiedInfo, openedInfo) || verifiedInfo.Size() != openedInfo.Size() ||
		!verifiedInfo.ModTime().Equal(openedInfo.ModTime()) {
		_ = f.Close()
		return fmt.Errorf("audit log changed after verification")
	}
	auditFile = f
	auditFileSize = openedInfo.Size()
	auditFileTime = openedInfo.ModTime()
	return nil
}

// computeAuditHash returns a SHA-256 digest over all fields except Hash.
func computeAuditHash(entry AuditEntry) string {
	canonical := struct {
		Timestamp string `json:"timestamp"`
		Action    string `json:"action"`
		Allowed   int    `json:"allowed,omitempty"`
		Denied    int    `json:"denied,omitempty"`
		Detail    string `json:"detail,omitempty"`
		PrevHash  string `json:"prev_hash,omitempty"`
	}{
		Timestamp: entry.Timestamp,
		Action:    entry.Action,
		Allowed:   entry.Allowed,
		Denied:    entry.Denied,
		Detail:    entry.Detail,
		PrevHash:  entry.PrevHash,
	}
	data, _ := json.Marshal(canonical)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func writeAudit(entry AuditEntry) error {
	auditMu.Lock()
	defer auditMu.Unlock()
	if auditFile == nil {
		return fmt.Errorf("audit log is unavailable")
	}
	pathInfo, err := os.Lstat(auditPath)
	if err != nil {
		return disableAudit(fmt.Errorf("inspect audit log before append: %w", err))
	}
	openedInfo, err := auditFile.Stat()
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode().Perm()&0077 != 0 ||
		!hasSingleLink(pathInfo) || !hasSingleLink(openedInfo) || !os.SameFile(pathInfo, openedInfo) ||
		openedInfo.Size() != auditFileSize || pathInfo.Size() != auditFileSize ||
		!openedInfo.ModTime().Equal(auditFileTime) || !pathInfo.ModTime().Equal(auditFileTime) {
		return disableAudit(fmt.Errorf("audit log changed outside this process"))
	}
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	entry.PrevHash = auditLastHash
	entry.Hash = computeAuditHash(entry)

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if auditFileSize+int64(len(data))+1 > maxAuditSize {
		return disableAudit(fmt.Errorf("audit log reached its configured size limit"))
	}
	record := append(data, '\n')
	written, err := auditFile.Write(record)
	if err != nil || written != len(record) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return disableAudit(err)
	}
	if err := auditFile.Sync(); err != nil {
		return disableAudit(err)
	}
	after, err := auditFile.Stat()
	if err != nil || after.Size() != auditFileSize+int64(written) {
		return disableAudit(fmt.Errorf("audit log size did not advance atomically"))
	}
	auditLastHash = entry.Hash
	auditFileSize = after.Size()
	auditFileTime = after.ModTime()
	return nil
}

// disableAudit is called with auditMu held and makes subsequent readiness and
// mutation checks fail closed after any integrity or durability error.
func disableAudit(cause error) error {
	if auditFile != nil {
		_ = auditFile.Close()
		auditFile = nil
	}
	return cause
}

func auditIsReady() bool {
	auditMu.Lock()
	defer auditMu.Unlock()
	return auditFile != nil
}

func verifyExistingAuditLog(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		auditLastHash = ""
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect audit log: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !hasSingleLink(info) || info.Size() > maxAuditSize {
		return nil, fmt.Errorf("audit log is not a bounded regular file")
	}
	// #nosec G304 -- path is the configured audit log; the bounded chain reader
	// pins it with Lstat/Fstat and verifies identity again after the full read.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || !hasSingleLink(openedInfo) {
		return nil, fmt.Errorf("audit log changed while opening")
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), maxAuditLineSize)
	previous := ""
	line := 0
	for scanner.Scan() {
		line++
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			return nil, fmt.Errorf("audit log contains an empty record at line %d", line)
		}
		var entry AuditEntry
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&entry); err != nil {
			return nil, fmt.Errorf("audit log line %d is invalid", line)
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			return nil, fmt.Errorf("audit log line %d has trailing JSON", line)
		}
		if entry.PrevHash != previous || entry.Hash == "" || entry.Hash != computeAuditHash(entry) {
			return nil, fmt.Errorf("audit hash chain verification failed at line %d", line)
		}
		previous = entry.Hash
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(info, after) || info.Size() != after.Size() ||
		!info.ModTime().Equal(after.ModTime()) {
		return nil, fmt.Errorf("audit log changed while being verified")
	}
	auditLastHash = previous
	return after, nil
}

// ---------------------------------------------------------------------------
// Service token authentication
// ---------------------------------------------------------------------------

func loadServiceToken() error {
	tokenPath := os.Getenv("SERVICE_TOKEN_PATH")
	if tokenPath == "" {
		tokenPath = defaultTokenPath
	}
	info, err := os.Lstat(tokenPath)
	if err != nil {
		return fmt.Errorf("load service token: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("service token must be an owner-only regular file")
	}
	data, err := readRegularFile(tokenPath, maxServiceTokenSize)
	if err != nil {
		return fmt.Errorf("load service token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if !validServiceToken(token) {
		return fmt.Errorf("service token must be at least 32 bytes without whitespace or control characters")
	}
	serviceToken = token
	log.Printf("service token loaded")
	return nil
}

func validServiceToken(token string) bool {
	if len(token) < 32 {
		return false
	}
	for i := 0; i < len(token); i++ {
		if token[i] <= 0x20 || token[i] == 0x7f {
			return false
		}
	}
	return true
}

func loadServiceIdentity() error {
	requesterType := os.Getenv("SERVICE_REQUESTER_TYPE")
	if requesterType == "" {
		requesterType = "tool"
	}
	sessionTrust := os.Getenv("SERVICE_SESSION_TRUST")
	if sessionTrust == "" {
		sessionTrust = "low"
	}
	if !validRequesterTypes[requesterType] || !validSessionTrusts[sessionTrust] {
		return fmt.Errorf("invalid service requester type or session trust")
	}
	serviceRequesterType = requesterType
	serviceSessionTrust = sessionTrust
	return nil
}

func requireServiceToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if serviceToken == "" {
			jsonError(w, "service authentication unavailable", http.StatusServiceUnavailable)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || strings.Count(auth, " ") != 1 {
			jsonError(w, "forbidden: invalid service token", http.StatusForbidden)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(serviceToken)) != 1 {
			jsonError(w, "forbidden: invalid service token", http.StatusForbidden)
			return
		}
		if !checkRateLimit() {
			jsonError(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		select {
		case protectedSlots <- struct{}{}:
			defer func() { <-protectedSlots }()
		default:
			jsonError(w, "too many concurrent requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// ---------------------------------------------------------------------------
// Consistent JSON error responses
// ---------------------------------------------------------------------------

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func decodeRequest(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

func checkRateLimit() bool {
	pol := getPolicy()
	rpm := pol.RateLimit.RequestsPerMinute
	if rpm <= 0 {
		rpm = defaultRPM
	}
	rateMu.Lock()
	defer rateMu.Unlock()
	now := time.Now()
	if now.Sub(rateWindow) > time.Minute {
		rateCounter = 0
		rateWindow = now
	}
	rateCounter++
	return rateCounter <= int64(rpm)
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

func handleHealth(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if docStore == nil || getEngine() == nil || serviceToken == "" || !auditIsReady() {
		jsonError(w, "service not ready", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "rag-data-firewall"})
}

func handleIngest(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)
	ingestRequests.Add(1)

	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req IngestRequest
	if err := decodeRequest(w, r, maxRequestBodySize, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := validateIngestRequest(req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	pol := getPolicy()
	doc, chunks, err := docStore.IngestWithAudit(req, pol.Scanner, func(doc Document, chunks []Chunk) error {
		flagged := 0
		for _, chunk := range chunks {
			if chunk.Scan.PromptInjection || chunk.Scan.RiskScore >= pol.Scanner.MinRiskToFlag {
				flagged++
			}
		}
		return writeAudit(AuditEntry{
			Action: "ingest_authorized",
			Detail: fmt.Sprintf("doc=%s chunks=%d flagged=%d", doc.ID, len(chunks), flagged),
		})
	})
	if err != nil {
		log.Printf("ingest error: %v", err)
		if !auditIsReady() {
			jsonError(w, "audit persistence failed", http.StatusServiceUnavailable)
			return
		}
		jsonError(w, "document ingestion failed", http.StatusInternalServerError)
		return
	}

	// Count flagged chunks.
	flagged := 0
	for _, c := range chunks {
		if c.Scan.PromptInjection || c.Scan.RiskScore >= pol.Scanner.MinRiskToFlag {
			flagged++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"document": doc,
		"chunks":   len(chunks),
		"flagged":  flagged,
	})
}

func handleRetrieve(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)
	retrieveRequests.Add(1)

	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req RetrievalRequest
	if err := decodeRequest(w, r, maxRequestBodySize, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if (req.RequesterType != "" && req.RequesterType != serviceRequesterType) ||
		(req.SessionTrust != "" && req.SessionTrust != serviceSessionTrust) {
		jsonError(w, "request identity claims do not match the configured service identity", http.StatusBadRequest)
		return
	}
	req.RequesterType = serviceRequesterType
	req.SessionTrust = serviceSessionTrust

	if err := validateRetrievalRequest(req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Gather candidate chunks with tightened scoping.
	const maxCandidates = 1000
	var candidates []Chunk
	seenChunks := make(map[string]struct{})
	totalCandidateBytes := 0
	addCandidate := func(c Chunk) bool {
		if len(c.Content) > maxRetrievalBytes-totalCandidateBytes {
			return false
		}
		candidates = append(candidates, c)
		seenChunks[c.ID] = struct{}{}
		totalCandidateBytes += len(c.Content)
		return true
	}
	if len(req.ChunkIDs) > 0 {
		for _, cid := range req.ChunkIDs {
			if _, duplicate := seenChunks[cid]; duplicate {
				continue
			}
			if c, ok := docStore.GetChunk(cid); ok {
				if !addCandidate(c) {
					jsonError(w, "retrieval content exceeds 32 MiB", http.StatusRequestEntityTooLarge)
					return
				}
			}
		}
	} else if len(req.DocumentIDs) > 0 {
		seenDocuments := make(map[string]struct{}, len(req.DocumentIDs))
		for _, did := range req.DocumentIDs {
			if _, duplicate := seenDocuments[did]; duplicate {
				continue
			}
			seenDocuments[did] = struct{}{}
			remaining := maxCandidates - len(candidates)
			for _, chunk := range docStore.QueryChunks(ChunkFilter{DocumentID: did, Limit: remaining + 1}) {
				if _, duplicate := seenChunks[chunk.ID]; duplicate {
					continue
				}
				if len(candidates) >= maxCandidates {
					jsonError(w, "retrieval candidate set exceeds 1000 chunks", http.StatusBadRequest)
					return
				}
				if !addCandidate(chunk) {
					jsonError(w, "retrieval content exceeds 32 MiB", http.StatusRequestEntityTooLarge)
					return
				}
			}
		}
	} else {
		jsonError(w, "retrieval requires explicit chunk_ids or document_ids", http.StatusBadRequest)
		return
	}
	// Treat stored scan results as evidence, not authority. Re-scan content at
	// retrieval time so policy reloads and local state tampering cannot preserve
	// a stale fail-open verdict.
	pol := getPolicy()
	for i := range candidates {
		candidates[i].Scan = ScanContent(candidates[i].Content, pol.Scanner)
	}

	// Build doc source lookup.
	docSourceMap := make(map[string]string)
	for _, c := range candidates {
		if _, seen := docSourceMap[c.DocumentID]; !seen {
			if doc, ok := docStore.GetDocument(c.DocumentID); ok {
				docSourceMap[c.DocumentID] = doc.Source
			}
		}
	}

	eng := getEngine()
	resp := eng.Evaluate(candidates, docSourceMap, req)

	if err := writeAudit(AuditEntry{
		Action:  "retrieve",
		Allowed: resp.Summary.Allowed,
		Denied:  resp.Summary.Denied,
		Detail:  fmt.Sprintf("requester=%s tool=%s chunks=%d", req.RequesterType, req.Tool, resp.Summary.TotalChunks),
	}); err != nil {
		log.Printf("audit write failed: %v", err)
		jsonError(w, "audit persistence failed", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Content string `json:"content"`
	}
	if err := decodeRequest(w, r, maxRequestBodySize, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Content == "" {
		jsonError(w, "content is required", http.StatusBadRequest)
		return
	}

	result := ScanContent(req.Content, getPolicy().Scanner)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleDocuments(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"documents": docStore.ListDocuments(),
		})

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" || len(id) > 256 || strings.ContainsAny(id, "\r\n\x00") {
			jsonError(w, "id parameter is required", http.StatusBadRequest)
			return
		}
		if err := docStore.DeleteDocumentWithAudit(id, func(document Document) error {
			return writeAudit(AuditEntry{
				Action: "delete_authorized",
				Detail: fmt.Sprintf("doc=%s", document.ID),
			})
		}); err != nil {
			if !auditIsReady() {
				jsonError(w, "audit persistence failed", http.StatusServiceUnavailable)
				return
			}
			if errors.Is(err, ErrDocumentNotFound) {
				jsonError(w, "document not found", http.StatusNotFound)
				return
			}
			log.Printf("delete error: %v", err)
			jsonError(w, "document deletion failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "id": id})

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleListChunks(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	documentID := q.Get("document_id")
	if documentID == "" || len(documentID) > 256 || strings.ContainsAny(documentID, "\r\n\x00") {
		jsonError(w, "document_id is required", http.StatusBadRequest)
		return
	}
	filter := ChunkFilter{
		DocumentID:       documentID,
		SensitivityLabel: q.Get("sensitivity"),
		TrustLevel:       q.Get("trust"),
		Limit:            1000,
	}
	if filter.SensitivityLabel != "" && !validSensitivities[filter.SensitivityLabel] ||
		filter.TrustLevel != "" && !validTrustLevels[filter.TrustLevel] {
		jsonError(w, "invalid sensitivity or trust filter", http.StatusBadRequest)
		return
	}

	chunks := docStore.QueryChunks(filter)
	pol := getPolicy()
	type chunkMetadata struct {
		ID               string            `json:"id"`
		DocumentID       string            `json:"document_id"`
		Index            int               `json:"index"`
		SensitivityLabel string            `json:"sensitivity_label"`
		TrustLevel       string            `json:"trust_level"`
		Labels           map[string]string `json:"labels,omitempty"`
		Scan             ScanResult        `json:"scan"`
		ContentHash      string            `json:"content_hash"`
	}
	metadata := make([]chunkMetadata, 0, len(chunks))
	for _, chunk := range chunks {
		metadata = append(metadata, chunkMetadata{
			ID: chunk.ID, DocumentID: chunk.DocumentID, Index: chunk.Index,
			SensitivityLabel: chunk.SensitivityLabel, TrustLevel: chunk.TrustLevel,
			Labels: chunk.Labels, Scan: ScanContent(chunk.Content, pol.Scanner), ContentHash: chunk.ContentHash,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":  len(metadata),
		"chunks": metadata,
	})
}

func handleReload(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	nextPolicy, err := readPolicy()
	if err != nil {
		log.Printf("policy reload failed: %v", err)
		jsonError(w, "policy reload failed", http.StatusInternalServerError)
		return
	}
	currentPolicy := getPolicy()
	if nextPolicy.DataDir != currentPolicy.DataDir || nextPolicy.Retention != currentPolicy.Retention ||
		nextPolicy.Daemon != currentPolicy.Daemon {
		jsonError(w, "data, retention, and daemon settings require a restart", http.StatusConflict)
		return
	}
	if err := writeAudit(AuditEntry{Action: "policy_reload_authorized", Detail: "validated strict policy reload"}); err != nil {
		log.Printf("audit write failed: %v", err)
		jsonError(w, "audit persistence failed", http.StatusServiceUnavailable)
		return
	}
	installPolicy(nextPolicy)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "policy reloaded"})
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{
		"total_requests":    totalRequests.Load(),
		"ingest_requests":   ingestRequests.Load(),
		"retrieve_requests": retrieveRequests.Load(),
		"documents":         int64(docStore.DocumentCount()),
		"chunks":            int64(docStore.ChunkCount()),
	})
}

// ---------------------------------------------------------------------------
// Mux builder (exported for testability)
// ---------------------------------------------------------------------------

func buildMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/ingest", requireServiceToken(handleIngest))
	mux.HandleFunc("/v1/retrieve", requireServiceToken(handleRetrieve))
	mux.HandleFunc("/v1/scan", requireServiceToken(handleScan))
	mux.HandleFunc("/v1/documents", requireServiceToken(handleDocuments))
	mux.HandleFunc("/v1/chunks", requireServiceToken(handleListChunks))
	mux.HandleFunc("/v1/reload", requireServiceToken(handleReload))
	mux.HandleFunc("/v1/metrics", requireServiceToken(handleMetrics))
	return mux
}

// ---------------------------------------------------------------------------
// Daemon
// ---------------------------------------------------------------------------

func runDaemon(bindAddr string) error {
	if err := loadServiceToken(); err != nil {
		return err
	}
	if err := loadServiceIdentity(); err != nil {
		return err
	}
	if err := initAuditLog(); err != nil {
		return err
	}
	defer func() {
		if auditFile != nil {
			auditFile.Close()
			auditFile = nil
		}
	}()
	purgeExpired := func() error {
		count, err := docStore.PurgeExpiredWithAudit(func(documents []Document) error {
			return writeAudit(AuditEntry{
				Action: "retention_purge_authorized",
				Detail: fmt.Sprintf("documents=%d", len(documents)),
			})
		})
		if err != nil {
			return err
		}
		if count > 0 {
			log.Printf("retention purge removed %d expired documents", count)
		}
		return nil
	}
	if err := purgeExpired(); err != nil {
		return fmt.Errorf("startup retention purge: %w", err)
	}

	pol := getPolicy()
	readTimeout := 30
	writeTimeout := 60
	idleTimeout := 120
	if pol.Daemon.ReadTimeoutSec > 0 {
		readTimeout = pol.Daemon.ReadTimeoutSec
	}
	if pol.Daemon.WriteTimeoutSec > 0 {
		writeTimeout = pol.Daemon.WriteTimeoutSec
	}
	if pol.Daemon.IdleTimeoutSec > 0 {
		idleTimeout = pol.Daemon.IdleTimeoutSec
	}

	srv := &http.Server{
		Addr:              bindAddr,
		Handler:           securityHeaders(buildMux()),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Duration(readTimeout) * time.Second,
		WriteTimeout:      time.Duration(writeTimeout) * time.Second,
		IdleTimeout:       time.Duration(idleTimeout) * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	defer srv.Close()

	log.Printf("rag-data-firewall serving on %s (docs=%d chunks=%d)",
		bindAddr, docStore.DocumentCount(), docStore.ChunkCount())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	retentionTicker := time.NewTicker(time.Hour)
	defer retentionTicker.Stop()
	for {
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("serve: %w", err)
			}
			return nil
		case <-retentionTicker.C:
			if err := purgeExpired(); err != nil {
				return fmt.Errorf("periodic retention purge: %w", err)
			}
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			if err := srv.Shutdown(shutdownCtx); err != nil {
				cancel()
				return fmt.Errorf("graceful shutdown: %w", err)
			}
			cancel()
			err := <-errCh
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("serve: %w", err)
			}
			return nil
		}
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// CLI commands
// ---------------------------------------------------------------------------

func cmdServe(policyPath, bindAddr string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	pol := getPolicy()
	var err error
	docStore, err = NewDocumentStore(getDataDir(), pol.Retention)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening store: %v\n", err)
		return 1
	}
	defer docStore.Close()

	if bindAddr == "" {
		bindAddr = pol.Daemon.BindAddr
		if bindAddr == "" {
			bindAddr = defaultBindAddr
		}
	}
	if !isLoopbackBind(bindAddr) && os.Getenv("ALLOW_REMOTE_BIND") != "true" {
		fmt.Fprintf(os.Stderr, "error: remote bind %q requires ALLOW_REMOTE_BIND=true and a protected TLS/network boundary\n", bindAddr)
		return 1
	}

	if err := runDaemon(bindAddr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func isLoopbackBind(bindAddr string) bool {
	host, _, err := net.SplitHostPort(bindAddr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func cmdIngest(policyPath, filePath, name, sensitivity, trust, source string, labels map[string]string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	pol := getPolicy()
	var err error
	docStore, err = NewDocumentStore(getDataDir(), pol.Retention)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer docStore.Close()

	content, err := readRegularFile(filePath, maxRequestBodySize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading file: %v\n", err)
		return 1
	}

	if name == "" {
		name = filePath
	}

	req := IngestRequest{
		Name:             name,
		Content:          string(content),
		Source:           source,
		SensitivityLabel: sensitivity,
		TrustLevel:       trust,
		Labels:           labels,
	}

	doc, chunks, err := docStore.Ingest(req, pol.Scanner)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	flagged := 0
	for _, c := range chunks {
		if c.Scan.PromptInjection {
			flagged++
		}
	}

	fmt.Printf("ingested: %s\n  id:          %s\n  chunks:      %d\n  flagged:     %d\n  sensitivity: %s\n  trust:       %s\n",
		doc.Name, doc.ID, len(chunks), flagged, doc.SensitivityLabel, doc.TrustLevel)
	return 0
}

func cmdScan(policyPath, content string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	result := ScanContent(content, getPolicy().Scanner)
	data, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(data))

	if result.PromptInjection {
		return 2
	}
	return 0
}

func cmdQuery(policyPath, requesterType, sessionTrust, tool string, chunkIDs, docIDs []string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	pol := getPolicy()
	var err error
	docStore, err = NewDocumentStore(getDataDir(), pol.Retention)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer docStore.Close()

	req := RetrievalRequest{
		RequesterType: requesterType,
		SessionTrust:  sessionTrust,
		Tool:          tool,
		ChunkIDs:      chunkIDs,
		DocumentIDs:   docIDs,
	}

	var candidates []Chunk
	if len(req.ChunkIDs) > 0 {
		for _, cid := range req.ChunkIDs {
			if c, ok := docStore.GetChunk(cid); ok {
				candidates = append(candidates, c)
			}
		}
	} else if len(req.DocumentIDs) > 0 {
		for _, did := range req.DocumentIDs {
			candidates = append(candidates, docStore.QueryChunks(ChunkFilter{DocumentID: did})...)
		}
	} else if requesterType == "system" {
		// Only system-trust callers may query all chunks (unscoped).
		candidates = docStore.AllChunks()
	} else {
		fmt.Fprintf(os.Stderr, "error: unscoped query requires -requester=system (pass -chunks or -docs to scope)\n")
		return 1
	}

	docSourceMap := make(map[string]string)
	for _, c := range candidates {
		if _, seen := docSourceMap[c.DocumentID]; !seen {
			if doc, ok := docStore.GetDocument(c.DocumentID); ok {
				docSourceMap[c.DocumentID] = doc.Source
			}
		}
	}

	resp := getEngine().Evaluate(candidates, docSourceMap, req)
	data, _ := json.MarshalIndent(resp, "", "  ")
	fmt.Println(string(data))
	return 0
}

func cmdList(policyPath, what string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	pol := getPolicy()
	var err error
	docStore, err = NewDocumentStore(getDataDir(), pol.Retention)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer docStore.Close()

	switch what {
	case "documents", "docs":
		docs := docStore.ListDocuments()
		if len(docs) == 0 {
			fmt.Println("no documents ingested")
			return 0
		}
		for _, d := range docs {
			fmt.Printf("  %-30s  [%s] trust=%s  chunks=%d  source=%s\n",
				d.ID, d.SensitivityLabel, d.TrustLevel, d.ChunkCount, d.Source)
		}
	case "chunks":
		chunks := docStore.AllChunks()
		if len(chunks) == 0 {
			fmt.Println("no chunks")
			return 0
		}
		for _, c := range chunks {
			flag := " "
			if c.Scan.PromptInjection {
				flag = "!"
			}
			fmt.Printf("  %s %-30s  [%s] trust=%s  risk=%.2f  %s\n",
				flag, c.ID, c.SensitivityLabel, c.TrustLevel, c.Scan.RiskScore,
				truncate(c.Content, 60))
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown: %s (use 'documents' or 'chunks')\n", what)
		return 1
	}
	return 0
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		bind := fs.String("bind", "", "bind address (overrides policy)")
		fs.Parse(os.Args[2:])
		os.Exit(cmdServe(*policyPath, *bind))

	case "ingest":
		fs := flag.NewFlagSet("ingest", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		filePath := fs.String("file", "", "file to ingest")
		name := fs.String("name", "", "document name")
		sensitivity := fs.String("sensitivity", "internal", "sensitivity label")
		trust := fs.String("trust", "unverified", "trust level")
		source := fs.String("source", "upload", "source origin")
		fs.Parse(os.Args[2:])
		if *filePath == "" {
			fmt.Fprintf(os.Stderr, "error: -file is required\n")
			os.Exit(1)
		}
		os.Exit(cmdIngest(*policyPath, *filePath, *name, *sensitivity, *trust, *source, nil))

	case "scan":
		fs := flag.NewFlagSet("scan", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		content := fs.String("content", "", "content to scan")
		file := fs.String("file", "", "file to scan")
		fs.Parse(os.Args[2:])
		text := *content
		if *file != "" {
			data, err := readRegularFile(*file, maxRequestBodySize)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			text = string(data)
		}
		if text == "" {
			fmt.Fprintf(os.Stderr, "error: -content or -file required\n")
			os.Exit(1)
		}
		os.Exit(cmdScan(*policyPath, text))

	case "query":
		fs := flag.NewFlagSet("query", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		requesterType := fs.String("requester", "user", "requester type (user, tool, system)")
		sessionTrust := fs.String("session-trust", "medium", "session trust level")
		tool := fs.String("tool", "", "requesting tool name")
		chunks := fs.String("chunks", "", "comma-separated chunk IDs to scope retrieval")
		docs := fs.String("docs", "", "comma-separated document IDs to scope retrieval")
		fs.Parse(os.Args[2:])
		var chunkIDs, docIDs []string
		if *chunks != "" {
			chunkIDs = strings.Split(*chunks, ",")
		}
		if *docs != "" {
			docIDs = strings.Split(*docs, ",")
		}
		os.Exit(cmdQuery(*policyPath, *requesterType, *sessionTrust, *tool, chunkIDs, docIDs))

	case "list":
		fs := flag.NewFlagSet("list", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		fs.Parse(os.Args[2:])
		what := "documents"
		if fs.NArg() > 0 {
			what = fs.Arg(0)
		}
		os.Exit(cmdList(*policyPath, what))

	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `rag-data-firewall — OPA-style policy engine for secure RAG

Usage:
  rag-data-firewall <command> [options]

Commands:
  serve     Start policy engine daemon (HTTP API on :8500)
  ingest    Ingest a document with sensitivity labels and scanning
  scan      Scan content for prompt injection and PII
  query     Evaluate retrieval policy against stored chunks
  list      List documents or chunks

Policy actions: allow, deny, redact, require-approval
Every decision includes evidence explaining why a chunk was allowed or blocked.

Use "rag-data-firewall <command> -h" for command-specific options.
`)
}
