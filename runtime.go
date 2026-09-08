package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// policyRuntime is published once and never mutated. Every operation captures
// one generation for its scanner, rule engine and audit provenance.
type policyRuntime struct {
	policy    FirewallPolicy
	engine    *PolicyEngine
	digest    string
	canonical []byte
	scan      func(string, ScannerConfig) ScanResult
}

func newPolicyRuntime(p FirewallPolicy) (*policyRuntime, error) {
	if err := validatePolicy(p); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("encode policy: %w", err)
	}
	var frozen FirewallPolicy
	if err := json.Unmarshal(canonical, &frozen); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	return &policyRuntime{policy: frozen, engine: NewPolicyEngine(frozen.DefaultAction, frozen.Rules),
		digest: hex.EncodeToString(digest[:]), canonical: canonical, scan: ScanContent}, nil
}

func getRuntime() *policyRuntime {
	policyMu.RLock()
	snapshot := activeRuntime
	policyMu.RUnlock()
	return snapshot
}

// Copies returned for configuration inspection cannot mutate a published policy.
func (snapshot *policyRuntime) copyPolicy() FirewallPolicy {
	if snapshot == nil {
		return FirewallPolicy{}
	}
	var p FirewallPolicy
	_ = json.Unmarshal(snapshot.canonical, &p) // validated during construction
	return p
}

type AuditChunkDecision struct {
	ChunkID         string `json:"chunk_id"`
	ContentHash     string `json:"content_hash"`
	RuleHash        string `json:"rule_hash"`
	Action          string `json:"action"`
	PromptInjection bool   `json:"prompt_injection,omitempty"`
	PIIDetected     bool   `json:"pii_detected,omitempty"`
}

// Evidence omits document names, sources, query/tool strings and content. It
// binds each returned decision to the re-scanned chunk and captured policy.
func decisionEvidence(chunks []Chunk, response RetrievalResponse) []AuditChunkDecision {
	byID := make(map[string]Chunk, len(chunks))
	for _, chunk := range chunks {
		byID[chunk.ID] = chunk
	}
	evidence := make([]AuditChunkDecision, 0, len(chunks))
	for _, decisions := range [][]ChunkDecision{response.Allowed, response.Denied, response.Redacted, response.PendingApproval} {
		for _, decision := range decisions {
			chunk := byID[decision.ChunkID]
			ruleHash := sha256.Sum256([]byte(decision.Rule))
			evidence = append(evidence, AuditChunkDecision{ChunkID: chunk.ID, ContentHash: chunk.ContentHash,
				RuleHash: hex.EncodeToString(ruleHash[:]), Action: decision.Action,
				PromptInjection: chunk.Scan.PromptInjection, PIIDetected: chunk.Scan.PIIDetected})
		}
	}
	return evidence
}
