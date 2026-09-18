package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Default returns the policy used when no bundle is configured: no rules, and
// the fail_closed default of DESIGN §3.6.
func Default() *Policy {
	return &Policy{Defaults: Defaults{OnError: FailClosed}, Version: "default"}
}

// Parse reads a YAML bundle. Unknown keys are an error: a policy that silently
// ignores a misspelled rule is worse than one that refuses to load.
//
// TODO(phase-3): verify the control plane's bundle signature before parsing
// (DESIGN §3.7).
func Parse(data []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: parse: %w", err)
	}
	if p.Defaults.OnError == "" {
		p.Defaults.OnError = FailClosed
	}
	sum := sha256.Sum256(data)
	p.Version = hex.EncodeToString(sum[:])[:12]
	return &p, nil
}

// LoadFile reads and parses a bundle from disk (the air-gapped path of §3.6).
func LoadFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", path, err)
	}
	return Parse(data)
}
