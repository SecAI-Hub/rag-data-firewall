package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Executed in a fresh process so exclusion is checked beyond Go mutexes.
func TestWriterLockProcessProbe(t *testing.T) {
	kind := os.Getenv("RAG_TEST_LOCK_KIND")
	if kind == "" {
		return
	}
	path := os.Getenv("RAG_TEST_LOCK_PATH")
	var err error
	switch kind {
	case "corpus":
		var store *DocumentStore
		store, err = NewDocumentStore(path, RetentionConfig{})
		if store != nil {
			defer store.Close()
		}
	case "audit":
		t.Setenv("AUDIT_LOG_PATH", path)
		err = initAuditLog()
		defer closeAuditLog()
	default:
		t.Fatal("invalid lock probe kind")
	}
	if os.Getenv("RAG_TEST_EXPECT_LOCK") == "deny" {
		if err == nil || !strings.Contains(err.Error(), "another process owns the writer lock") {
			t.Fatalf("did not reject competing writer: %v", err)
		}
	} else if err != nil {
		t.Fatalf("released writer lock did not reopen: %v", err)
	}
}

func probeWriterProcess(t *testing.T, kind, path, expect string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWriterLockProcessProbe$")
	cmd.Env = append(os.Environ(), "RAG_TEST_LOCK_KIND="+kind, "RAG_TEST_LOCK_PATH="+path, "RAG_TEST_EXPECT_LOCK="+expect)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s process probe: %v\n%s", kind, err, output)
	}
}

func TestIndependentProcessesCannotShareCorpusOrAudit(t *testing.T) {
	setupTestEnv(t)
	defer docStore.Close()
	probeWriterProcess(t, "corpus", getDataDir(), "deny")
	probeWriterProcess(t, "audit", auditPath, "deny")
	if err := docStore.Close(); err != nil {
		t.Fatal(err)
	}
	closeAuditLog()
	probeWriterProcess(t, "corpus", getDataDir(), "allow")
	probeWriterProcess(t, "audit", auditPath, "allow")
}

func TestCorpusOwnershipDriftFailsBeforeAuthorization(t *testing.T) {
	for _, change := range []string{"replace", "hardlink", "permissions", "content", "directory", "close"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			store, err := NewDocumentStore(dir, RetentionConfig{})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			doc, _, err := store.Ingest(IngestRequest{Name: "retain", Content: "keep", SensitivityLabel: "public"}, ScannerConfig{})
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(store.statePath)
			if err != nil {
				t.Fatal(err)
			}
			lockPath := filepath.Join(dir, ".writer.lock")
			switch change {
			case "replace":
				err = os.Remove(lockPath)
				if err == nil {
					err = os.WriteFile(lockPath, nil, 0600)
				}
			case "hardlink":
				err = os.Link(lockPath, filepath.Join(dir, "other.lock"))
			case "permissions":
				err = os.Chmod(lockPath, 0640)
			case "content":
				err = os.WriteFile(lockPath, []byte("changed"), 0600)
			case "directory":
				err = os.Chmod(dir, 0755)
			case "close":
				err = store.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			if store.Ready() == nil {
				t.Fatal("lost writer ownership still ready")
			}
			authorized := false
			_, _, err = store.IngestWithAudit(IngestRequest{Name: "new", Content: "new"}, ScannerConfig{}, func(Document, []Chunk) error { authorized = true; return nil })
			if err == nil || authorized {
				t.Fatal("lost writer ownership reached ingest authorization")
			}
			err = store.DeleteDocumentWithAudit(doc.ID, func(Document) error { authorized = true; return nil })
			if err == nil || authorized {
				t.Fatal("lost writer ownership reached delete authorization")
			}
			after, err := os.ReadFile(store.statePath)
			if err != nil || string(after) != string(before) {
				t.Fatal("lost writer ownership changed persisted corpus")
			}
		})
	}
}

func TestAuditOwnershipDriftStopsReadinessAndRelease(t *testing.T) {
	setupTestEnv(t)
	defer docStore.Close()
	doc, _, err := docStore.Ingest(IngestRequest{Name: "public", Content: "Content must stay withheld", SensitivityLabel: "public"}, ScannerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(auditPath + ".lock"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auditPath+".lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	response := roleRequest(t, serviceToken, "POST", "/v1/retrieve", `{"document_ids":["`+doc.ID+`"]}`)
	if response.Code != 503 || strings.Contains(response.Body.String(), "Content must stay withheld") || auditIsReady() {
		t.Fatal("lost audit ownership did not stop content release")
	}
	health := httptest.NewRecorder()
	handleHealth(health, httptest.NewRequest("GET", "/health", nil))
	if health.Code != 503 {
		t.Fatal("lost audit ownership reported ready")
	}
}

func TestAuditReplayRejectsIncompleteTailAndIdentityTampering(t *testing.T) {
	t.Setenv("AUDIT_LOG_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))
	if err := initAuditLog(); err != nil {
		t.Fatal(err)
	}
	defer closeAuditLog()
	if err := writeAudit(AuditEntry{Action: "retrieve", Identity: "reader:synthetic", PolicyDigest: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	closeAuditLog()
	original, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auditPath, original[:len(original)-1], 0600); err != nil {
		t.Fatal(err)
	}
	if err := initAuditLog(); err == nil || !strings.Contains(err.Error(), "incomplete final record") {
		t.Fatalf("unterminated record was accepted: %v", err)
	}
	if err := os.WriteFile(auditPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := initAuditLog(); err != nil {
		t.Fatalf("failed load retained its writer lock: %v", err)
	}
	closeAuditLog()
	var entry AuditEntry
	if err := json.Unmarshal(original, &entry); err != nil {
		t.Fatal(err)
	}
	entry.Identity = "admin:forged"
	tampered, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auditPath, append(tampered, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := initAuditLog(); err == nil {
		t.Fatal("changed audit identity passed hash-chain replay")
	}
}

func TestOversizeAuditRecordDoesNotBreakNextStartup(t *testing.T) {
	t.Setenv("AUDIT_LOG_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))
	if err := initAuditLog(); err != nil {
		t.Fatal(err)
	}
	defer closeAuditLog()
	if err := writeAudit(AuditEntry{Action: "retrieve", Detail: strings.Repeat("x", maxAuditLineSize)}); err == nil {
		t.Fatal("unreplayable audit record accepted")
	}
	if err := writeAudit(AuditEntry{Action: "retrieve", Allowed: 1}); err != nil {
		t.Fatalf("rejected oversized record harmed journal: %v", err)
	}
	closeAuditLog()
	if err := initAuditLog(); err != nil {
		t.Fatalf("journal could not restart after rejected record: %v", err)
	}
}
