package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxStoreFileSize int64 = 1024 * 1024 * 1024

const (
	hardMaxDocuments     = 100_000
	hardMaxChunks        = 1_000_000
	maxChunksPerDocument = 4096
)

var ErrDocumentNotFound = errors.New("document not found")

// ---------------------------------------------------------------------------
// Document and chunk types
// ---------------------------------------------------------------------------

// Document represents an ingested source with sensitivity metadata.
type Document struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Source           string            `json:"source"`            // vault, upload, crawl, manual
	SensitivityLabel string            `json:"sensitivity_label"` // public, internal, confidential, restricted
	TrustLevel       string            `json:"trust_level"`       // verified, unverified, untrusted
	IngestedAt       string            `json:"ingested_at"`
	Labels           map[string]string `json:"labels,omitempty"` // arbitrary key-value
	ContentHash      string            `json:"content_hash"`
	ChunkCount       int               `json:"chunk_count"`
}

// Chunk is a segment of a document, labeled and scanned.
type Chunk struct {
	ID               string            `json:"id"`
	DocumentID       string            `json:"document_id"`
	Index            int               `json:"index"`
	Content          string            `json:"content"`
	SensitivityLabel string            `json:"sensitivity_label"`
	TrustLevel       string            `json:"trust_level"`
	Labels           map[string]string `json:"labels,omitempty"`
	Scan             ScanResult        `json:"scan"`
	ContentHash      string            `json:"content_hash"`
}

// RetentionConfig controls document/chunk storage limits.
type RetentionConfig struct {
	MaxDocuments   int `yaml:"max_documents"`
	MaxTotalChunks int `yaml:"max_total_chunks"`
	TTLDays        int `yaml:"ttl_days"`
}

// ---------------------------------------------------------------------------
// ID generation
// ---------------------------------------------------------------------------

func generateID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random ID: %w", err)
	}
	return fmt.Sprintf("%d-%s", time.Now().UnixMilli(), hex.EncodeToString(b)), nil
}

func hashContent(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

// ---------------------------------------------------------------------------
// Chunking
// ---------------------------------------------------------------------------

// chunkDocument splits content into chunks by paragraphs.
// Each chunk inherits the document's sensitivity label and trust level.
func chunkDocument(doc Document, content string) []Chunk {
	paragraphs := splitParagraphs(content)
	chunks := make([]Chunk, 0, len(paragraphs))

	for i, para := range paragraphs {
		para = strings.TrimSpace(para)
		if para == "" {
			continue
		}

		chunk := Chunk{
			ID:               fmt.Sprintf("%s-c%d", doc.ID, i),
			DocumentID:       doc.ID,
			Index:            i,
			Content:          para,
			SensitivityLabel: doc.SensitivityLabel,
			TrustLevel:       doc.TrustLevel,
			Labels:           copyLabels(doc.Labels),
			ContentHash:      hashContent(para),
		}
		chunks = append(chunks, chunk)
	}
	return chunks
}

// splitParagraphs splits text by double newlines or significant breaks.
func splitParagraphs(content string) []string {
	// Normalize line endings.
	content = strings.ReplaceAll(content, "\r\n", "\n")

	// Split on double newlines.
	parts := strings.Split(content, "\n\n")

	// If only one chunk and it's long, split by single newlines with a size limit.
	if len(parts) == 1 && len(content) > 1000 {
		var result []string
		lines := strings.Split(content, "\n")
		var buf strings.Builder
		for _, line := range lines {
			if buf.Len()+len(line) > 800 && buf.Len() > 0 {
				result = append(result, buf.String())
				buf.Reset()
			}
			if buf.Len() > 0 {
				buf.WriteByte('\n')
			}
			buf.WriteString(line)
		}
		if buf.Len() > 0 {
			result = append(result, buf.String())
		}
		return result
	}

	return parts
}

// validateChunkingCost rejects separator bombs before strings.Split can
// allocate millions of substrings and before the scanner builds one result per
// fragment. The request byte limit alone does not bound the number of chunks.
func validateChunkingCost(content string) error {
	normalized := strings.ReplaceAll(content, "\r\n", "\n")
	if strings.Contains(normalized, "\n\n") {
		if strings.Count(normalized, "\n\n")+1 > maxChunksPerDocument {
			return fmt.Errorf("document would exceed %d chunks", maxChunksPerDocument)
		}
		return nil
	}
	if len(normalized) > 1000 && strings.Count(normalized, "\n")+1 > maxChunksPerDocument {
		return fmt.Errorf("document would exceed %d chunks", maxChunksPerDocument)
	}
	return nil
}

func copyLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	cp := make(map[string]string, len(labels))
	for k, v := range labels {
		cp[k] = v
	}
	return cp
}

// ---------------------------------------------------------------------------
// Document store (JSONL file-backed, in-memory indexed)
// ---------------------------------------------------------------------------

// DocumentStore manages documents and chunks with fsync durability.
type DocumentStore struct {
	mu        sync.RWMutex
	documents []Document
	chunks    []Chunk
	docIndex  map[string]int   // doc ID -> index in documents
	chunkByID map[string]int   // chunk ID -> index in chunks
	docChunks map[string][]int // doc ID -> chunk indices

	dataDir   string
	statePath string
	stateInfo os.FileInfo
	retention RetentionConfig
	writer    *writerLock
}

type persistedState struct {
	Version   int        `json:"version"`
	Documents []Document `json:"documents"`
	Chunks    []Chunk    `json:"chunks"`
}

// NewDocumentStore creates or opens a document store with retention controls.
func NewDocumentStore(dataDir string, retention RetentionConfig) (*DocumentStore, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	if err := ensurePrivateDirectory(dataDir); err != nil {
		return nil, fmt.Errorf("secure data directory: %w", err)
	}
	writer, err := acquireWriterLock(filepath.Join(dataDir, ".writer.lock"))
	if err != nil {
		return nil, fmt.Errorf("lock corpus: %w", err)
	}
	opened := false
	defer func() {
		if !opened {
			_ = writer.Close()
		}
	}()

	store := &DocumentStore{
		docIndex:  make(map[string]int),
		chunkByID: make(map[string]int),
		docChunks: make(map[string][]int),
		dataDir:   dataDir,
		statePath: filepath.Join(dataDir, "store.json"),
		retention: retention,
		writer:    writer,
	}

	data, stateInfo, err := readRegularFileWithInfo(store.statePath, maxStoreFileSize)
	if err == nil {
		if stateInfo.Mode().Perm()&0077 != 0 || !hasSingleLink(stateInfo) {
			return nil, fmt.Errorf("state file must be owner-only and have exactly one link")
		}
		store.stateInfo = stateInfo
		var state persistedState
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&state); err != nil {
			return nil, fmt.Errorf("load state: %w", err)
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			return nil, fmt.Errorf("load state: trailing JSON data")
		}
		if state.Version != 1 {
			return nil, fmt.Errorf("unsupported state version %d", state.Version)
		}
		store.documents = state.Documents
		store.chunks = state.Chunks
	} else if os.IsNotExist(err) {
		if err := store.loadLegacyState(); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("load state: %w", err)
	}
	if err := store.rebuildIndexes(); err != nil {
		return nil, err
	}
	if data == nil {
		if err := store.persistState(store.documents, store.chunks); err != nil {
			return nil, fmt.Errorf("migrate legacy state: %w", err)
		}
	}

	opened = true
	return store, nil
}

func (s *DocumentStore) loadLegacyState() error {
	docPath := filepath.Join(s.dataDir, "documents.jsonl")
	if data, info, err := readRegularFileWithInfo(docPath, maxStoreFileSize); err == nil {
		if info.Mode().Perm()&0077 != 0 || !hasSingleLink(info) {
			return fmt.Errorf("legacy documents file must be owner-only and have exactly one link")
		}
		for lineNum, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var document Document
			if err := decodeStrictJSONLine(line, &document); err != nil {
				return fmt.Errorf("invalid legacy document record at line %d", lineNum+1)
			}
			s.documents = append(s.documents, document)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("load legacy documents: %w", err)
	}

	chunkPath := filepath.Join(s.dataDir, "chunks.jsonl")
	if data, info, err := readRegularFileWithInfo(chunkPath, maxStoreFileSize); err == nil {
		if info.Mode().Perm()&0077 != 0 || !hasSingleLink(info) {
			return fmt.Errorf("legacy chunks file must be owner-only and have exactly one link")
		}
		for lineNum, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var chunk Chunk
			if err := decodeStrictJSONLine(line, &chunk); err != nil {
				return fmt.Errorf("invalid legacy chunk record at line %d", lineNum+1)
			}
			s.chunks = append(s.chunks, chunk)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("load legacy chunks: %w", err)
	}
	return nil
}

func (s *DocumentStore) rebuildIndexes() error {
	s.docIndex = make(map[string]int, len(s.documents))
	s.chunkByID = make(map[string]int, len(s.chunks))
	s.docChunks = make(map[string][]int)
	for index, document := range s.documents {
		if document.ID == "" || len(document.ID) > 256 || strings.ContainsAny(document.ID, "\r\n\x00") ||
			document.Name == "" || len(document.Name) > 1024 || document.ContentHash == "" ||
			document.ChunkCount < 0 || !validSensitivities[document.SensitivityLabel] ||
			!validTrustLevels[document.TrustLevel] || len(document.Source) > 256 ||
			validateLabels(document.Labels) != nil {
			return fmt.Errorf("invalid document record at index %d", index)
		}
		if _, err := time.Parse(time.RFC3339, document.IngestedAt); err != nil {
			return fmt.Errorf("invalid document timestamp at index %d", index)
		}
		if _, err := hex.DecodeString(document.ContentHash); err != nil || len(document.ContentHash) != sha256.Size*2 {
			return fmt.Errorf("invalid document content hash at index %d", index)
		}
		if _, duplicate := s.docIndex[document.ID]; duplicate {
			return fmt.Errorf("duplicate document ID at index %d", index)
		}
		s.docIndex[document.ID] = index
	}
	for index, chunk := range s.chunks {
		documentIndex, documentExists := s.docIndex[chunk.DocumentID]
		if chunk.ID == "" || len(chunk.ID) > 512 || strings.ContainsAny(chunk.ID, "\r\n\x00") ||
			chunk.DocumentID == "" || chunk.Index < 0 || len(chunk.Content) > maxRequestBodySize ||
			chunk.ContentHash != hashContent(chunk.Content) || !validSensitivities[chunk.SensitivityLabel] ||
			!validTrustLevels[chunk.TrustLevel] || validateLabels(chunk.Labels) != nil ||
			math.IsNaN(chunk.Scan.RiskScore) || math.IsInf(chunk.Scan.RiskScore, 0) ||
			chunk.Scan.RiskScore < 0 || chunk.Scan.RiskScore > 1 ||
			len(chunk.Scan.PIITypes) > 128 || len(chunk.Scan.SuspiciousPatterns) > 1024 ||
			len(chunk.Scan.RiskReasons) > 1024 {
			return fmt.Errorf("invalid chunk record at index %d", index)
		}
		if chunk.ID != fmt.Sprintf("%s-c%d", chunk.DocumentID, chunk.Index) {
			return fmt.Errorf("chunk ID does not match its document and index at position %d", index)
		}
		if _, duplicate := s.chunkByID[chunk.ID]; duplicate {
			return fmt.Errorf("duplicate chunk ID at index %d", index)
		}
		if !documentExists {
			return fmt.Errorf("chunk at index %d references an unknown document", index)
		}
		document := s.documents[documentIndex]
		if chunk.SensitivityLabel != document.SensitivityLabel || chunk.TrustLevel != document.TrustLevel {
			return fmt.Errorf("chunk at index %d does not inherit its document security labels", index)
		}
		s.chunkByID[chunk.ID] = index
		s.docChunks[chunk.DocumentID] = append(s.docChunks[chunk.DocumentID], index)
	}
	for _, document := range s.documents {
		if len(s.docChunks[document.ID]) != document.ChunkCount {
			return fmt.Errorf("document %q chunk count does not match persisted chunks", document.ID)
		}
	}
	if len(s.documents) > hardMaxDocuments || len(s.chunks) > hardMaxChunks {
		return fmt.Errorf("persisted state exceeds hard record limits")
	}
	if s.retention.MaxDocuments > 0 && len(s.documents) > s.retention.MaxDocuments {
		return fmt.Errorf("persisted document count exceeds retention limit")
	}
	if s.retention.MaxTotalChunks > 0 && len(s.chunks) > s.retention.MaxTotalChunks {
		return fmt.Errorf("persisted chunk count exceeds retention limit")
	}
	return nil
}

// IngestRequest is the input for document ingestion.
type IngestRequest struct {
	Name             string            `json:"name"`
	Content          string            `json:"content"`
	Source           string            `json:"source"`
	SensitivityLabel string            `json:"sensitivity_label"`
	TrustLevel       string            `json:"trust_level"`
	Labels           map[string]string `json:"labels,omitempty"`
}

// Ingest adds a document and its chunks to the store.
// Enforces retention limits (max_documents, max_total_chunks).
func (s *DocumentStore) Ingest(req IngestRequest, scanCfg ScannerConfig) (Document, []Chunk, error) {
	return s.IngestWithAudit(req, scanCfg, nil)
}

// IngestWithAudit invokes authorize after the complete new record has been
// prepared and scanned but before durable state is mutated.
func (s *DocumentStore) IngestWithAudit(req IngestRequest, scanCfg ScannerConfig, authorize func(Document, []Chunk) error) (Document, []Chunk, error) {
	return s.ingestWithScanner(req, scanCfg, ScanContent, authorize)
}

// ingestWithScanner binds the scanner implementation to the same immutable
// runtime generation that supplies the HTTP request's config and audit digest.
func (s *DocumentStore) ingestWithScanner(req IngestRequest, scanCfg ScannerConfig, scan func(string, ScannerConfig) ScanResult, authorize func(Document, []Chunk) error) (Document, []Chunk, error) {
	if err := validateIngestRequest(req); err != nil {
		return Document{}, nil, err
	}
	if err := validateChunkingCost(req.Content); err != nil {
		return Document{}, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.validateCurrentStatePath(); err != nil {
		return Document{}, nil, err
	}

	// Enforce retention: max documents.
	if s.retention.MaxDocuments > 0 && len(s.documents) >= s.retention.MaxDocuments {
		return Document{}, nil, fmt.Errorf("max documents reached (%d)", s.retention.MaxDocuments)
	}

	if req.SensitivityLabel == "" {
		req.SensitivityLabel = "internal"
	}
	if req.TrustLevel == "" {
		req.TrustLevel = "unverified"
	}
	if req.Source == "" {
		req.Source = "upload"
	}

	docID, err := generateID()
	if err != nil {
		return Document{}, nil, err
	}
	doc := Document{
		ID:               docID,
		Name:             req.Name,
		Source:           req.Source,
		SensitivityLabel: req.SensitivityLabel,
		TrustLevel:       req.TrustLevel,
		IngestedAt:       time.Now().UTC().Format(time.RFC3339),
		Labels:           copyLabels(req.Labels),
		ContentHash:      hashContent(req.Content),
	}

	// Chunk the content.
	chunks := chunkDocument(doc, req.Content)
	if len(chunks) > maxChunksPerDocument {
		return Document{}, nil, fmt.Errorf("document exceeds %d chunks", maxChunksPerDocument)
	}

	// Enforce retention: max total chunks.
	if s.retention.MaxTotalChunks > 0 && len(s.chunks)+len(chunks) > s.retention.MaxTotalChunks {
		return Document{}, nil, fmt.Errorf("max total chunks would be exceeded (%d + %d > %d)", len(s.chunks), len(chunks), s.retention.MaxTotalChunks)
	}

	// Scan each chunk.
	for i := range chunks {
		chunks[i].Scan = scan(chunks[i].Content, scanCfg)
	}

	doc.ChunkCount = len(chunks)
	if authorize != nil {
		if err := authorize(doc, chunks); err != nil {
			return Document{}, nil, fmt.Errorf("audit ingest authorization: %w", err)
		}
	}

	newDocuments := append([]Document(nil), s.documents...)
	newDocuments = append(newDocuments, doc)
	newChunks := append([]Chunk(nil), s.chunks...)
	newChunks = append(newChunks, chunks...)
	if err := s.persistState(newDocuments, newChunks); err != nil {
		return Document{}, nil, fmt.Errorf("persist document transaction: %w", err)
	}

	docIdx := len(newDocuments) - 1
	s.documents = newDocuments
	s.chunks = newChunks
	s.docIndex[doc.ID] = docIdx
	firstChunkIndex := len(newChunks) - len(chunks)
	for offset, c := range chunks {
		cIdx := firstChunkIndex + offset
		s.chunkByID[c.ID] = cIdx
		s.docChunks[doc.ID] = append(s.docChunks[doc.ID], cIdx)
	}

	return cloneDocument(doc), cloneChunks(chunks), nil
}

func decodeStrictJSONLine(line string, dst any) error {
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

// GetDocument returns a document by ID.
func (s *DocumentStore) GetDocument(id string) (Document, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.writer == nil {
		return Document{}, false
	}
	idx, ok := s.docIndex[id]
	if !ok {
		return Document{}, false
	}
	return cloneDocument(s.documents[idx]), true
}

// GetChunk returns a chunk by ID.
func (s *DocumentStore) GetChunk(id string) (Chunk, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.writer == nil {
		return Chunk{}, false
	}
	idx, ok := s.chunkByID[id]
	if !ok {
		return Chunk{}, false
	}
	return cloneChunk(s.chunks[idx]), true
}

// ChunkFilter specifies query criteria for chunks.
type ChunkFilter struct {
	DocumentID       string
	SensitivityLabel string
	TrustLevel       string
	Limit            int
}

// QueryChunks returns chunks matching the filter.
func (s *DocumentStore) QueryChunks(filter ChunkFilter) []Chunk {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.writer == nil {
		return nil
	}

	var results []Chunk
	appendMatch := func(c Chunk) bool {
		if filter.SensitivityLabel != "" && c.SensitivityLabel != filter.SensitivityLabel {
			return false
		}
		if filter.TrustLevel != "" && c.TrustLevel != filter.TrustLevel {
			return false
		}
		results = append(results, cloneChunk(c))
		return filter.Limit > 0 && len(results) >= filter.Limit
	}
	if filter.DocumentID != "" {
		indices, ok := s.docChunks[filter.DocumentID]
		if !ok {
			return nil
		}
		for _, idx := range indices {
			if appendMatch(s.chunks[idx]) {
				break
			}
		}
	} else {
		for i := range s.chunks {
			if appendMatch(s.chunks[i]) {
				break
			}
		}
	}
	return results
}

// ListDocuments returns all documents, newest first.
func (s *DocumentStore) ListDocuments() []Document {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.writer == nil {
		return nil
	}

	result := make([]Document, len(s.documents))
	for i := range s.documents {
		result[i] = cloneDocument(s.documents[i])
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].IngestedAt > result[j].IngestedAt
	})
	return result
}

// AllChunks returns every chunk (for policy evaluation).
func (s *DocumentStore) AllChunks() []Chunk {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.writer == nil {
		return nil
	}
	result := make([]Chunk, len(s.chunks))
	for i := range s.chunks {
		result[i] = cloneChunk(s.chunks[i])
	}
	return result
}

// DocumentCount returns total documents.
func (s *DocumentStore) DocumentCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.writer == nil {
		return 0
	}
	return len(s.documents)
}

// ChunkCount returns total chunks.
func (s *DocumentStore) ChunkCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.writer == nil {
		return 0
	}
	return len(s.chunks)
}

// ---------------------------------------------------------------------------
// Deletion and retention
// ---------------------------------------------------------------------------

// DeleteDocument removes a document and its chunks, rewriting JSONL files.
func (s *DocumentStore) DeleteDocument(docID string) error {
	return s.DeleteDocumentWithAudit(docID, nil)
}

// DeleteDocumentWithAudit invokes authorize before the persisted state is
// changed, ensuring an audit failure cannot produce an unaudited mutation.
func (s *DocumentStore) DeleteDocumentWithAudit(docID string, authorize func(Document) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.validateCurrentStatePath(); err != nil {
		return err
	}

	documentIndex, ok := s.docIndex[docID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrDocumentNotFound, docID)
	}
	if authorize != nil {
		if err := authorize(cloneDocument(s.documents[documentIndex])); err != nil {
			return fmt.Errorf("audit delete authorization: %w", err)
		}
	}

	// Rebuild arrays excluding the deleted document and its chunks.
	deletedChunks := make(map[int]bool)
	for _, idx := range s.docChunks[docID] {
		deletedChunks[idx] = true
	}

	var newDocs []Document
	newDocIndex := make(map[string]int)
	for _, d := range s.documents {
		if d.ID == docID {
			continue
		}
		idx := len(newDocs)
		newDocs = append(newDocs, d)
		newDocIndex[d.ID] = idx
	}

	var newChunks []Chunk
	newChunkByID := make(map[string]int)
	newDocChunks := make(map[string][]int)
	for i, c := range s.chunks {
		if deletedChunks[i] {
			continue
		}
		idx := len(newChunks)
		newChunks = append(newChunks, c)
		newChunkByID[c.ID] = idx
		newDocChunks[c.DocumentID] = append(newDocChunks[c.DocumentID], idx)
	}

	if err := s.persistState(newDocs, newChunks); err != nil {
		return fmt.Errorf("persist delete transaction: %w", err)
	}
	s.documents = newDocs
	s.docIndex = newDocIndex
	s.chunks = newChunks
	s.chunkByID = newChunkByID
	s.docChunks = newDocChunks
	return nil
}

// PurgeExpired removes documents older than the retention TTL.
// Returns the number of documents purged.
func (s *DocumentStore) PurgeExpired() (int, error) {
	return s.PurgeExpiredWithAudit(nil)
}

// PurgeExpiredWithAudit authorizes the complete deletion set before committing
// one replacement snapshot.
func (s *DocumentStore) PurgeExpiredWithAudit(authorize func([]Document) error) (int, error) {
	if s.retention.TTLDays <= 0 {
		return 0, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.validateCurrentStatePath(); err != nil {
		return 0, err
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -s.retention.TTLDays)
	var expiredIDs []string
	for _, d := range s.documents {
		ingestedAt, err := time.Parse(time.RFC3339, d.IngestedAt)
		if err != nil {
			return 0, fmt.Errorf("invalid stored ingestion timestamp for %q", d.ID)
		}
		if ingestedAt.Before(cutoff) {
			expiredIDs = append(expiredIDs, d.ID)
		}
	}

	if len(expiredIDs) == 0 {
		return 0, nil
	}
	if authorize != nil {
		expiredDocuments := make([]Document, 0, len(expiredIDs))
		for _, id := range expiredIDs {
			expiredDocuments = append(expiredDocuments, cloneDocument(s.documents[s.docIndex[id]]))
		}
		if err := authorize(expiredDocuments); err != nil {
			return 0, fmt.Errorf("audit retention purge authorization: %w", err)
		}
	}

	// Build set of deleted doc IDs and chunk indices.
	deletedDocs := make(map[string]bool)
	deletedChunks := make(map[int]bool)
	for _, id := range expiredIDs {
		deletedDocs[id] = true
		for _, idx := range s.docChunks[id] {
			deletedChunks[idx] = true
		}
	}

	// Rebuild arrays.
	var newDocs []Document
	newDocIndex := make(map[string]int)
	for _, d := range s.documents {
		if deletedDocs[d.ID] {
			continue
		}
		idx := len(newDocs)
		newDocs = append(newDocs, d)
		newDocIndex[d.ID] = idx
	}

	var newChunks []Chunk
	newChunkByID := make(map[string]int)
	newDocChunks := make(map[string][]int)
	for i, c := range s.chunks {
		if deletedChunks[i] {
			continue
		}
		idx := len(newChunks)
		newChunks = append(newChunks, c)
		newChunkByID[c.ID] = idx
		newDocChunks[c.DocumentID] = append(newDocChunks[c.DocumentID], idx)
	}

	if err := s.persistState(newDocs, newChunks); err != nil {
		return 0, fmt.Errorf("persist purge transaction: %w", err)
	}
	s.documents = newDocs
	s.docIndex = newDocIndex
	s.chunks = newChunks
	s.chunkByID = newChunkByID
	s.docChunks = newDocChunks

	return len(expiredIDs), nil
}

func (s *DocumentStore) persistState(documents []Document, chunks []Chunk) error {
	currentInfo, err := s.validateCurrentStatePath()
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(s.dataDir, ".store-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	encoder := json.NewEncoder(tmp)
	if err := encoder.Encode(persistedState{Version: 1, Documents: documents, Chunks: chunks}); err != nil {
		return err
	}
	info, err := tmp.Stat()
	if err != nil {
		return err
	}
	if info.Size() > maxStoreFileSize {
		return fmt.Errorf("state exceeds %d-byte limit", maxStoreFileSize)
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := s.requireUnchangedStatePath(currentInfo); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.statePath); err != nil {
		return err
	}
	dir, err := os.Open(s.dataDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return err
	}
	newInfo, err := os.Lstat(s.statePath)
	if err != nil || !newInfo.Mode().IsRegular() || newInfo.Mode().Perm()&0077 != 0 || !hasSingleLink(newInfo) {
		return fmt.Errorf("persisted state file failed post-write validation")
	}
	s.stateInfo = newInfo
	ok = true
	return nil
}

func (s *DocumentStore) validateCurrentStatePath() (os.FileInfo, error) {
	if err := s.writer.Validate(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(s.statePath)
	if os.IsNotExist(err) {
		if s.stateInfo != nil {
			return nil, fmt.Errorf("state file was removed outside this process")
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !hasSingleLink(info) {
		return nil, fmt.Errorf("state file must remain owner-only, regular, and singly linked")
	}
	if s.stateInfo == nil {
		return nil, fmt.Errorf("state file appeared outside this process")
	}
	if !os.SameFile(info, s.stateInfo) || info.Size() != s.stateInfo.Size() || !info.ModTime().Equal(s.stateInfo.ModTime()) {
		return nil, fmt.Errorf("state file changed outside this process")
	}
	return info, nil
}

func (s *DocumentStore) requireUnchangedStatePath(expected os.FileInfo) error {
	if err := s.writer.Validate(); err != nil {
		return err
	}
	info, err := os.Lstat(s.statePath)
	if expected == nil {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("state file appeared during persistence")
	}
	if err != nil || !os.SameFile(info, expected) || info.Size() != expected.Size() ||
		!info.ModTime().Equal(expected.ModTime()) {
		return fmt.Errorf("state file changed during persistence")
	}
	return nil
}

// Ready checks ownership and state identity without releasing any content.
func (s *DocumentStore) Ready() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, err := s.validateCurrentStatePath()
	return err
}

// Close waits for outstanding store operations and releases writer ownership.
func (s *DocumentStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.writer.Close()
	s.writer = nil
	return err
}

func validateLabels(labels map[string]string) error {
	if len(labels) > 64 {
		return fmt.Errorf("too many labels")
	}
	for key, value := range labels {
		if key == "" || len(key) > 128 || len(value) > 1024 || strings.ContainsAny(key, "\r\n\x00") || strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("invalid label")
		}
	}
	return nil
}

func cloneDocument(document Document) Document {
	document.Labels = copyLabels(document.Labels)
	return document
}

func cloneChunk(chunk Chunk) Chunk {
	chunk.Labels = copyLabels(chunk.Labels)
	chunk.Scan.PIITypes = append([]string(nil), chunk.Scan.PIITypes...)
	chunk.Scan.SuspiciousPatterns = append([]string(nil), chunk.Scan.SuspiciousPatterns...)
	chunk.Scan.RiskReasons = append([]RiskReason(nil), chunk.Scan.RiskReasons...)
	return chunk
}

func cloneChunks(chunks []Chunk) []Chunk {
	result := make([]Chunk, len(chunks))
	for i := range chunks {
		result[i] = cloneChunk(chunks[i])
	}
	return result
}
