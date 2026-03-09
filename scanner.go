package main

import (
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// Content scanning — prompt injection, PII, suspicious patterns
// ---------------------------------------------------------------------------

// ScanResult captures all findings from content analysis.
type ScanResult struct {
	PromptInjection    bool     `json:"prompt_injection"`
	PIIDetected        bool     `json:"pii_detected"`
	PIITypes           []string `json:"pii_types,omitempty"`
	SuspiciousPatterns []string `json:"suspicious_patterns,omitempty"`
	RiskScore          float64  `json:"risk_score"` // 0.0 (clean) to 1.0 (high risk)
}

// ScannerConfig controls which scans are enabled.
type ScannerConfig struct {
	PromptInjection    bool    `yaml:"prompt_injection"`
	PIIDetection       bool    `yaml:"pii_detection"`
	SuspiciousPatterns bool    `yaml:"suspicious_patterns"`
	MinRiskToFlag      float64 `yaml:"min_risk_to_flag"`
}

// ---------------------------------------------------------------------------
// Prompt injection detection
// ---------------------------------------------------------------------------

var promptInjectionPatterns = []struct {
	Pattern *regexp.Regexp
	Name    string
}{
	{regexp.MustCompile(`(?i)ignore\s+(all\s+)?previous\s+instructions`), "ignore_previous"},
	{regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|above|prior)`), "disregard"},
	{regexp.MustCompile(`(?i)you\s+are\s+now\s+`), "role_override"},
	{regexp.MustCompile(`(?i)forget\s+(everything|all|your)\b`), "forget"},
	{regexp.MustCompile(`(?i)new\s+instructions?\s*:`), "new_instructions"},
	{regexp.MustCompile(`(?i)system\s*prompt\s*:`), "system_prompt_leak"},
	{regexp.MustCompile(`(?i)<\|im_start\|>`), "chat_delimiter"},
	{regexp.MustCompile(`(?i)\[INST\]`), "inst_delimiter"},
	{regexp.MustCompile(`(?i)\[SYSTEM\]`), "system_delimiter"},
	{regexp.MustCompile(`(?i)act\s+as\s+(if\s+you\s+are|a)\s+`), "act_as"},
	{regexp.MustCompile(`(?i)pretend\s+(you\s+are|to\s+be)\s+`), "pretend"},
	{regexp.MustCompile(`(?i)override\s+(your|the|all)\s+`), "override"},
	{regexp.MustCompile(`(?i)do\s+not\s+follow\s+(your|the|any)\s+(rules|guidelines|instructions)`), "rule_bypass"},
	{regexp.MustCompile(`(?i)output\s+(your|the)\s+(system|initial)\s+prompt`), "prompt_extraction"},
}

func detectPromptInjection(content string) (bool, []string) {
	var matched []string
	for _, p := range promptInjectionPatterns {
		if p.Pattern.MatchString(content) {
			matched = append(matched, p.Name)
		}
	}
	return len(matched) > 0, matched
}

// ---------------------------------------------------------------------------
// PII detection
// ---------------------------------------------------------------------------

var piiPatterns = []struct {
	Pattern *regexp.Regexp
	Type    string
}{
	{regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), "ssn"},
	{regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`), "email"},
	{regexp.MustCompile(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`), "credit_card"},
	{regexp.MustCompile(`(?i)(password|secret|api[_-]?key)\s*[:=]\s*\S+`), "credential"},
	{regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*`), "bearer_token"},
	{regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`), "phone"},
}

func detectPII(content string) (bool, []string) {
	typeSet := make(map[string]bool)
	for _, p := range piiPatterns {
		if p.Pattern.MatchString(content) {
			typeSet[p.Type] = true
		}
	}
	if len(typeSet) == 0 {
		return false, nil
	}
	var types []string
	for t := range typeSet {
		types = append(types, t)
	}
	return true, types
}

// ---------------------------------------------------------------------------
// Suspicious pattern detection
// ---------------------------------------------------------------------------

var suspiciousPatterns = []struct {
	Pattern *regexp.Regexp
	Name    string
}{
	{regexp.MustCompile(`(?i)\beval\s*\(`), "eval_call"},
	{regexp.MustCompile(`(?i)\bexec\s*\(`), "exec_call"},
	{regexp.MustCompile(`(?i)\bimport\s+os\b`), "import_os"},
	{regexp.MustCompile(`(?i)\bsubprocess\b`), "subprocess"},
	{regexp.MustCompile(`(?i)\b__import__\b`), "dunder_import"},
	{regexp.MustCompile(`(?i)curl\s+.+\|\s*(?:bash|sh)`), "pipe_to_shell"},
	{regexp.MustCompile(`(?i)<script\b`), "script_tag"},
	{regexp.MustCompile(`(?i)javascript\s*:`), "js_uri"},
}

func detectSuspicious(content string) []string {
	var found []string
	for _, p := range suspiciousPatterns {
		if p.Pattern.MatchString(content) {
			found = append(found, p.Name)
		}
	}
	return found
}

// ---------------------------------------------------------------------------
// Unified scanner
// ---------------------------------------------------------------------------

// ScanContent runs all enabled scans on content and returns a composite result.
func ScanContent(content string, cfg ScannerConfig) ScanResult {
	var result ScanResult
	var riskFactors int
	var riskSum float64

	if cfg.PromptInjection {
		injected, patterns := detectPromptInjection(content)
		result.PromptInjection = injected
		if injected {
			result.SuspiciousPatterns = append(result.SuspiciousPatterns, patterns...)
			riskFactors++
			riskSum += 0.9 // prompt injection is high risk
		}
	}

	if cfg.PIIDetection {
		hasPII, types := detectPII(content)
		result.PIIDetected = hasPII
		result.PIITypes = types
		if hasPII {
			riskFactors++
			riskSum += 0.4 // PII presence is moderate risk
		}
	}

	if cfg.SuspiciousPatterns {
		suspicious := detectSuspicious(content)
		if len(suspicious) > 0 {
			result.SuspiciousPatterns = append(result.SuspiciousPatterns, suspicious...)
			riskFactors++
			riskSum += 0.7 // suspicious code is high-ish risk
		}
	}

	if riskFactors > 0 {
		result.RiskScore = riskSum / float64(riskFactors)
	}

	return result
}

// ---------------------------------------------------------------------------
// PII redaction (for redact action)
// ---------------------------------------------------------------------------

var piiRedactionRules = []struct {
	Pattern *regexp.Regexp
	Tag     string
}{
	{regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), "[REDACTED:ssn]"},
	{regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`), "[REDACTED:email]"},
	{regexp.MustCompile(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`), "[REDACTED:card]"},
	{regexp.MustCompile(`(?i)(password|secret|api[_-]?key)\s*[:=]\s*\S+`), "[REDACTED:credential]"},
	{regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*`), "[REDACTED:bearer]"},
	{regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`), "[REDACTED:phone]"},
}

// RedactContent replaces PII in content with tagged placeholders.
func RedactContent(content string, patterns []string) string {
	filterSet := make(map[string]bool)
	for _, p := range patterns {
		filterSet[p] = true
	}

	for _, rule := range piiRedactionRules {
		// If specific patterns requested, only apply matching ones.
		tag := strings.TrimPrefix(strings.TrimSuffix(rule.Tag, "]"), "[REDACTED:")
		if len(filterSet) > 0 && !filterSet[tag] {
			continue
		}
		content = rule.Pattern.ReplaceAllString(content, rule.Tag)
	}
	return content
}
