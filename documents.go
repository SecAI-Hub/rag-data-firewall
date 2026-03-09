package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Document and chunk types
// ---------------------------------------------------------------------------

// Document represents an ingested source with sensitivity metadata.
type Document struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Source           string            `json:"source"`              // vault, upload, crawl, manual
	SensitivityLabel string            `json:"sensitivity_label"`   // public, internal, confidential, restricted
	TrustLevel       string            `json:"trust_level"`         // verified, unverified, untrusted
	IngestedAt       string            `json:"ingested_at"`
	Labels           map[string]string `json:"labels,omitempty"`    // arbitrary key-value
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

// ---------------------------------------------------------------------------
// ID generation
// ---------------------------------------------------------------------------

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%d-%s", time.Now().UnixMilli(), hex.EncodeToString(b))
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

// DocumentStore manages documents and chunks.
type DocumentStore struct {
	mu        sync.RWMutex
	documents []Document
	chunks    []Chunk
	docIndex  map[string]int   // doc ID -> index in documents
	chunkByID map[string]int   // chunk ID -> index in chunks
	docChunks map[string][]int // doc ID -> chunk indices

	docFile   *os.File
	chunkFile *os.File
}

// NewDocumentStore creates or opens a document store.
func NewDocumentStore(dataDir string) (*DocumentStore, error) {
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	store := &DocumentStore{
		docIndex:  make(map[string]int),
		chunkByID: make(map[string]int),
		docChunks: make(map[string][]int),
	}

	// Load existing documents.
	docPath := dataDir + "/documents.jsonl"
	if data, err := os.ReadFile(docPath); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var d Document
			if err := json.Unmarshal([]byte(line), &d); err != nil {
				continue
			}
			idx := len(store.documents)
			store.documents = append(store.documents, d)
			store.docIndex[d.ID] = idx
		}
	}

	// Load existing chunks.
	chunkPath := dataDir + "/chunks.jsonl"
	if data, err := os.ReadFile(chunkPath); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var c Chunk
			if err := json.Unmarshal([]byte(line), &c); err != nil {
				continue
			}
			idx := len(store.chunks)
			store.chunks = append(store.chunks, c)
			store.chunkByID[c.ID] = idx
			store.docChunks[c.DocumentID] = append(store.docChunks[c.DocumentID], idx)
		}
	}

	// Open files for appending.
	df, err := os.OpenFile(docPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open documents file: %w", err)
	}
	store.docFile = df

	cf, err := os.OpenFile(chunkPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		df.Close()
		return nil, fmt.Errorf("open chunks file: %w", err)
	}
	store.chunkFile = cf

	return store, nil
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
func (s *DocumentStore) Ingest(req IngestRequest, scanCfg ScannerConfig) (Document, []Chunk, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if req.SensitivityLabel == "" {
		req.SensitivityLabel = "internal"
	}
	if req.TrustLevel == "" {
		req.TrustLevel = "unverified"
	}
	if req.Source == "" {
		req.Source = "upload"
	}

	doc := Document{
		ID:               generateID(),
		Name:             req.Name,
		Source:           req.Source,
		SensitivityLabel: req.SensitivityLabel,
		TrustLevel:       req.TrustLevel,
		IngestedAt:       time.Now().UTC().Format(time.RFC3339),
		Labels:           req.Labels,
		ContentHash:      hashContent(req.Content),
	}

	// Chunk the content.
	chunks := chunkDocument(doc, req.Content)

	// Scan each chunk.
	for i := range chunks {
		chunks[i].Scan = ScanContent(chunks[i].Content, scanCfg)
	}

	doc.ChunkCount = len(chunks)

	// Persist document.
	docData, _ := json.Marshal(doc)
	s.docFile.Write(append(docData, '\n'))

	docIdx := len(s.documents)
	s.documents = append(s.documents, doc)
	s.docIndex[doc.ID] = docIdx

	// Persist chunks.
	for _, c := range chunks {
		chunkData, _ := json.Marshal(c)
		s.chunkFile.Write(append(chunkData, '\n'))

		cIdx := len(s.chunks)
		s.chunks = append(s.chunks, c)
		s.chunkByID[c.ID] = cIdx
		s.docChunks[doc.ID] = append(s.docChunks[doc.ID], cIdx)
	}

	return doc, chunks, nil
}

// GetDocument returns a document by ID.
func (s *DocumentStore) GetDocument(id string) (Document, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.docIndex[id]
	if !ok {
		return Document{}, false
	}
	return s.documents[idx], true
}

// GetChunk returns a chunk by ID.
func (s *DocumentStore) GetChunk(id string) (Chunk, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.chunkByID[id]
	if !ok {
		return Chunk{}, false
	}
	return s.chunks[idx], true
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

	var candidates []Chunk
	if filter.DocumentID != "" {
		indices, ok := s.docChunks[filter.DocumentID]
		if !ok {
			return nil
		}
		for _, idx := range indices {
			candidates = append(candidates, s.chunks[idx])
		}
	} else {
		candidates = s.chunks
	}

	var results []Chunk
	for _, c := range candidates {
		if filter.SensitivityLabel != "" && c.SensitivityLabel != filter.SensitivityLabel {
			continue
		}
		if filter.TrustLevel != "" && c.TrustLevel != filter.TrustLevel {
			continue
		}
		results = append(results, c)
		if filter.Limit > 0 && len(results) >= filter.Limit {
			break
		}
	}
	return results
}

// ListDocuments returns all documents, newest first.
func (s *DocumentStore) ListDocuments() []Document {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Document, len(s.documents))
	copy(result, s.documents)
	sort.Slice(result, func(i, j int) bool {
		return result[i].IngestedAt > result[j].IngestedAt
	})
	return result
}

// AllChunks returns every chunk (for policy evaluation).
func (s *DocumentStore) AllChunks() []Chunk {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Chunk, len(s.chunks))
	copy(result, s.chunks)
	return result
}

// DocumentCount returns total documents.
func (s *DocumentStore) DocumentCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.documents)
}

// ChunkCount returns total chunks.
func (s *DocumentStore) ChunkCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.chunks)
}

// Close closes the store files.
func (s *DocumentStore) Close() error {
	if s.docFile != nil {
		s.docFile.Close()
	}
	if s.chunkFile != nil {
		s.chunkFile.Close()
	}
	return nil
}
