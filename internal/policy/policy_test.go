package policy

import (
	"testing"

	"github.com/rajesh-proddu/ai_security/internal/core"
	"github.com/rajesh-proddu/ai_security/internal/detect"
)

// The fixture is the example policy of DESIGN §3.6, verbatim. If the doc's
// example stops parsing, the loader is wrong.
func TestLoadExamplePolicy(t *testing.T) {
	p, err := LoadFile("testdata/example.yaml")
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if p.Tenant != "acme" {
		t.Errorf("tenant = %q, want acme", p.Tenant)
	}
	if p.Defaults.OnError != FailClosed {
		t.Errorf("on_error = %q, want fail_closed", p.Defaults.OnError)
	}
	if p.Version == "" {
		t.Error("loader must derive a policy version")
	}
	if len(p.Rules) != 4 {
		t.Fatalf("rules = %d, want 4", len(p.Rules))
	}

	r0 := p.Rules[0]
	if len(r0.Surface) != 2 || !r0.Surface.Contains("input") || !r0.Surface.Contains("tool_result") {
		t.Errorf("rule 0 surface = %v", r0.Surface)
	}
	// scalar form
	if len(r0.When.Detector) != 1 || r0.When.Detector[0] != detect.DetectorInjectionML {
		t.Errorf("rule 0 detector = %v, want the scalar form", r0.When.Detector)
	}
	if r0.When.ScoreGTE == nil || *r0.When.ScoreGTE != 0.9 {
		t.Errorf("rule 0 score_gte = %v, want 0.9", r0.When.ScoreGTE)
	}
	if r0.Action != core.ActionBlock {
		t.Errorf("rule 0 action = %q, want block", r0.Action)
	}

	r1 := p.Rules[1]
	if r1.Action != core.ActionFlag || !r1.TaintSession {
		t.Errorf("rule 1 = %+v, want flag with taint_session", r1)
	}

	r2 := p.Rules[2]
	// sequence form of the same field
	if len(r2.When.Detector) != 2 || !r2.When.Detector.Contains(detect.DetectorPII) ||
		!r2.When.Detector.Contains(detect.DetectorSecrets) {
		t.Errorf("rule 2 detector = %v, want the sequence form", r2.When.Detector)
	}
	for _, want := range []string{detect.TypeCard, detect.TypeAWSKey, detect.TypeAadhaar} {
		if !r2.When.TypeIn.Contains(want) {
			t.Errorf("rule 2 type_in %v is missing %q", r2.When.TypeIn, want)
		}
	}
	if r2.Action != core.ActionRedact {
		t.Errorf("rule 2 action = %q, want redact", r2.Action)
	}

	r3 := p.Rules[3]
	if r3.When.Tool != "email.send" {
		t.Errorf("rule 3 tool = %q", r3.When.Tool)
	}
	if r3.When.SessionTainted == nil || !*r3.When.SessionTainted {
		t.Errorf("rule 3 session_tainted = %v, want true", r3.When.SessionTainted)
	}
	if r3.Action != core.ActionBlock {
		t.Errorf("rule 3 action = %q, want block", r3.Action)
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
		check   func(*testing.T, *Policy)
	}{
		{
			name: "missing defaults fails closed",
			yaml: "tenant: acme\n",
			check: func(t *testing.T, p *Policy) {
				if p.Defaults.OnError != FailClosed {
					t.Errorf("on_error = %q, want fail_closed", p.Defaults.OnError)
				}
			},
		},
		{
			name: "fail_open is honoured when explicit",
			yaml: "defaults: { on_error: fail_open }\n",
			check: func(t *testing.T, p *Policy) {
				if p.Defaults.OnError != FailOpen {
					t.Errorf("on_error = %q, want fail_open", p.Defaults.OnError)
				}
			},
		},
		{
			name:    "an unknown key is an error, not a silent no-op",
			yaml:    "tenant: acme\nrulez: []\n",
			wantErr: true,
		},
		{
			name:    "a mapping where a string list belongs is an error",
			yaml:    "rules:\n  - surface: { a: b }\n",
			wantErr: true,
		},
		{
			name:    "not yaml",
			yaml:    "\tnope:\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Parse([]byte(tt.yaml))
			if tt.wantErr {
				if err == nil {
					t.Fatal("want an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			tt.check(t, p)
		})
	}
}

func TestParseVersionTracksContent(t *testing.T) {
	a, err := Parse([]byte("tenant: acme\n"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte("tenant: acme\n"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse([]byte("tenant: other\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Version != b.Version {
		t.Error("identical bundles must get the same version")
	}
	if a.Version == c.Version {
		t.Error("different bundles must get different versions")
	}
}

func TestLoadFileMissing(t *testing.T) {
	if _, err := LoadFile("testdata/does-not-exist.yaml"); err == nil {
		t.Fatal("want an error for a missing bundle")
	}
}
