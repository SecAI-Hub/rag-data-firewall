package main

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"syscall"
)

var (
	validSensitivities = map[string]bool{
		"public": true, "internal": true, "confidential": true, "restricted": true,
	}
	validTrustLevels = map[string]bool{
		"verified": true, "unverified": true, "untrusted": true,
	}
	validRequesterTypes = map[string]bool{
		"user": true, "tool": true, "system": true,
	}
	validSessionTrusts = map[string]bool{
		"high": true, "medium": true, "low": true,
	}
)

// validateIngestRequest checks structural validity before document ingestion.
func validateIngestRequest(req IngestRequest) error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}
	if len(req.Name) > 1024 || strings.ContainsAny(req.Name, "\r\n\x00") {
		return fmt.Errorf("name exceeds 1024-byte limit")
	}
	if req.Content == "" {
		return fmt.Errorf("content is required")
	}
	if len(req.Content) > maxRequestBodySize {
		return fmt.Errorf("content exceeds %d-byte limit", maxRequestBodySize)
	}
	if req.SensitivityLabel != "" && !validSensitivities[req.SensitivityLabel] {
		return fmt.Errorf("invalid sensitivity_label: %s (must be public, internal, confidential, or restricted)", req.SensitivityLabel)
	}
	if req.TrustLevel != "" && !validTrustLevels[req.TrustLevel] {
		return fmt.Errorf("invalid trust_level: %s (must be verified, unverified, or untrusted)", req.TrustLevel)
	}
	if len(req.Source) > 256 || strings.ContainsAny(req.Source, "\r\n\x00") {
		return fmt.Errorf("source exceeds 256-byte limit")
	}
	if err := validateLabels(req.Labels); err != nil {
		return err
	}
	return nil
}

// validateRetrievalRequest checks structural validity of a retrieval request.
func validateRetrievalRequest(req RetrievalRequest) error {
	if req.RequesterType != "" && !validRequesterTypes[req.RequesterType] {
		return fmt.Errorf("invalid requester_type: %s (must be user, tool, or system)", req.RequesterType)
	}
	if req.SessionTrust != "" && !validSessionTrusts[req.SessionTrust] {
		return fmt.Errorf("invalid session_trust: %s (must be high, medium, or low)", req.SessionTrust)
	}
	if len(req.Query) > 64*1024 || len(req.User) > 256 || len(req.Session) > 256 || len(req.Tool) > 256 || len(req.Model) > 256 ||
		strings.ContainsAny(req.User+req.Session+req.Tool+req.Model, "\r\n\x00") {
		return fmt.Errorf("retrieval metadata exceeds configured limits")
	}
	if req.MaxChunks < 0 || req.MaxChunks > 1000 {
		return fmt.Errorf("max_chunks must be between 0 and 1000")
	}
	if len(req.ChunkIDs) > 1000 || len(req.DocumentIDs) > 1000 {
		return fmt.Errorf("too many chunk_ids or document_ids")
	}
	for _, id := range append(append([]string(nil), req.ChunkIDs...), req.DocumentIDs...) {
		if id == "" || len(id) > 256 || strings.ContainsAny(id, "\r\n\x00") {
			return fmt.Errorf("invalid chunk or document ID")
		}
	}
	return nil
}

func validatePolicy(p FirewallPolicy) error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported policy version %d", p.Version)
	}
	if p.DefaultAction != "deny" {
		return fmt.Errorf("default_action must be deny")
	}
	if len(p.Rules) == 0 || len(p.Rules) > 1000 {
		return fmt.Errorf("policy must contain between 1 and 1000 rules")
	}
	seen := make(map[string]struct{}, len(p.Rules))
	validActions := map[string]bool{"allow": true, "deny": true, "redact": true, "require-approval": true}
	validRedactions := map[string]bool{
		"email": true, "ssn": true, "phone": true, "credential": true,
		"credit_card": true, "card": true, "bearer_token": true, "bearer": true,
	}
	for index, rule := range p.Rules {
		if rule.Name == "" || len(rule.Name) > 128 || strings.ContainsAny(rule.Name, "\r\n\x00") ||
			len(rule.Description) > 4096 || len(rule.Reason) > 4096 ||
			strings.ContainsAny(rule.Description+rule.Reason, "\x00") {
			return fmt.Errorf("rule %d has an invalid name", index)
		}
		if _, duplicate := seen[rule.Name]; duplicate {
			return fmt.Errorf("duplicate rule name %q", rule.Name)
		}
		seen[rule.Name] = struct{}{}
		if !validActions[rule.Action] {
			return fmt.Errorf("rule %q has invalid action %q", rule.Name, rule.Action)
		}
		if rule.Action == "allow" && emptyRuleMatch(rule.Match) {
			return fmt.Errorf("rule %q is an unscoped allow", rule.Name)
		}
		if len(rule.Match.Sensitivity) > 128 || len(rule.Match.TrustLevel) > 128 ||
			len(rule.Match.Source) > 128 || len(rule.Match.RequesterType) > 128 ||
			len(rule.Match.SessionTrust) > 128 || len(rule.RedactPatterns) > 16 ||
			validateLabels(rule.Match.Labels) != nil {
			return fmt.Errorf("rule %q has excessive or invalid match values", rule.Name)
		}
		for _, value := range rule.Match.Sensitivity {
			if !validSensitivities[value] {
				return fmt.Errorf("rule %q has invalid sensitivity %q", rule.Name, value)
			}
		}
		for _, value := range rule.Match.TrustLevel {
			if !validTrustLevels[value] {
				return fmt.Errorf("rule %q has invalid trust level %q", rule.Name, value)
			}
		}
		for _, value := range rule.Match.RequesterType {
			if !validRequesterTypes[value] {
				return fmt.Errorf("rule %q has invalid requester type %q", rule.Name, value)
			}
		}
		for _, value := range rule.Match.SessionTrust {
			if !validSessionTrusts[value] {
				return fmt.Errorf("rule %q has invalid session trust %q", rule.Name, value)
			}
		}
		for _, value := range rule.Match.Source {
			if value == "" || len(value) > 256 || strings.ContainsAny(value, "\r\n\x00") {
				return fmt.Errorf("rule %q has invalid source %q", rule.Name, value)
			}
		}
		if score := rule.Match.MinRiskScore; score != nil && (math.IsNaN(*score) || math.IsInf(*score, 0) || *score < 0 || *score > 1) {
			return fmt.Errorf("rule %q has invalid minimum risk score", rule.Name)
		}
		for _, pattern := range rule.RedactPatterns {
			if !validRedactions[pattern] {
				return fmt.Errorf("rule %q has unsupported redaction pattern %q", rule.Name, pattern)
			}
		}
	}
	if math.IsNaN(p.Scanner.MinRiskToFlag) || math.IsInf(p.Scanner.MinRiskToFlag, 0) || p.Scanner.MinRiskToFlag < 0 || p.Scanner.MinRiskToFlag > 1 {
		return fmt.Errorf("scanner min_risk_to_flag must be between 0 and 1")
	}
	if p.Daemon.ReadTimeoutSec < 0 || p.Daemon.ReadTimeoutSec > 300 || p.Daemon.WriteTimeoutSec < 0 || p.Daemon.WriteTimeoutSec > 300 || p.Daemon.IdleTimeoutSec < 0 || p.Daemon.IdleTimeoutSec > 600 {
		return fmt.Errorf("daemon timeout is outside the supported range")
	}
	if p.RateLimit.RequestsPerMinute < 0 || p.RateLimit.RequestsPerMinute > 100_000 {
		return fmt.Errorf("requests_per_minute is outside the supported range")
	}
	if p.Retention.MaxDocuments < 0 || p.Retention.MaxDocuments > hardMaxDocuments ||
		p.Retention.MaxTotalChunks < 0 || p.Retention.MaxTotalChunks > hardMaxChunks ||
		p.Retention.TTLDays < 0 || p.Retention.TTLDays > 36_500 {
		return fmt.Errorf("retention values are outside supported bounds")
	}
	return nil
}

func emptyRuleMatch(match RuleMatch) bool {
	return len(match.Sensitivity) == 0 && len(match.TrustLevel) == 0 && len(match.Source) == 0 &&
		len(match.RequesterType) == 0 && len(match.SessionTrust) == 0 && len(match.Labels) == 0 &&
		match.ScanPromptInjection == nil && match.ScanPIIDetected == nil && match.MinRiskScore == nil
}

func readRegularFile(path string, maxBytes int64) ([]byte, error) {
	data, _, err := readRegularFileWithInfo(path, maxBytes)
	return data, err
}

func readRegularFileWithInfo(path string, maxBytes int64) ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("refusing non-regular file: %s", info.Mode())
	}
	if info.Size() > maxBytes {
		return nil, nil, fmt.Errorf("file exceeds %d-byte limit", maxBytes)
	}
	// #nosec G304 -- this centralized bounded reader accepts explicit operator
	// paths and surrounds the open with regular-file and identity checks.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return nil, nil, fmt.Errorf("file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, nil, fmt.Errorf("file exceeds %d-byte limit", maxBytes)
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(info, after) || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return nil, nil, fmt.Errorf("file changed while reading")
	}
	pathAfter, err := os.Lstat(path)
	if err != nil || !os.SameFile(after, pathAfter) || pathAfter.Size() != after.Size() ||
		!pathAfter.ModTime().Equal(after.ModTime()) {
		return nil, nil, fmt.Errorf("file path changed while reading")
	}
	return data, after, nil
}

func hasSingleLink(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Nlink) == 1
}

// ensurePrivateDirectory tightens a newly created or empty dedicated directory.
// It refuses to chmod a non-empty shared path so a configuration mistake cannot
// unexpectedly change permissions on an unrelated directory tree.
func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("directory must be a real directory")
	}
	if info.Mode().Perm()&0077 == 0 {
		return nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("non-empty directory must already have mode 0700")
	}
	// #nosec G304 -- path is a dedicated configured state/audit directory and
	// is pinned with Lstat/Fstat before its permissions are tightened.
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	opened, err := dir.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return fmt.Errorf("directory changed while opening")
	}
	if err := dir.Chmod(0700); err != nil {
		return err
	}
	after, err := dir.Stat()
	if err != nil || after.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("directory permissions could not be secured")
	}
	return nil
}
