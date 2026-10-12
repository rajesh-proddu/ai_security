package policy

import (
	"context"
	"testing"

	"github.com/rajesh-proddu/ai_security/internal/core"
	"github.com/rajesh-proddu/ai_security/internal/detect"
)

func finding(detector, typ string, score float64, start, end int) core.Finding {
	return core.Finding{
		Detector: detector,
		Type:     typ,
		Score:    score,
		Span:     core.Span{Start: start, End: end},
	}
}

// The example policy of DESIGN §3.6, driven end to end: the rules in the doc
// must produce the actions the doc describes.
func TestEvaluateExamplePolicy(t *testing.T) {
	p, err := LoadFile("testdata/example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEvaluator(p)

	tests := []struct {
		name      string
		in        core.EvalInput
		want      core.Action
		wantTaint bool
		wantSpans []core.Span
	}{
		{
			name: "clean input is allowed",
			in:   core.EvalInput{Request: core.Request{Surface: core.SurfaceInput}},
			want: core.ActionAllow,
		},
		{
			name: "high-scoring ml injection on input is blocked",
			in: core.EvalInput{
				Request:  core.Request{Surface: core.SurfaceInput},
				Findings: []core.Finding{finding(detect.DetectorInjectionML, "", 0.95, 0, 5)},
			},
			want: core.ActionBlock,
		},
		{
			name: "the same finding below the score threshold is allowed",
			in: core.EvalInput{
				Request:  core.Request{Surface: core.SurfaceInput},
				Findings: []core.Finding{finding(detect.DetectorInjectionML, "", 0.5, 0, 5)},
			},
			want: core.ActionAllow,
		},
		{
			name: "heuristic injection in a tool result flags and taints",
			in: core.EvalInput{
				Request:  core.Request{Surface: core.SurfaceToolResult},
				Findings: []core.Finding{finding(detect.DetectorInjectionHeuristic, detect.TypeInstructionOverride, 0.8, 0, 9)},
			},
			want:      core.ActionFlag,
			wantTaint: true,
		},
		{
			name: "the same finding on input does not taint",
			in: core.EvalInput{
				Request:  core.Request{Surface: core.SurfaceInput},
				Findings: []core.Finding{finding(detect.DetectorInjectionHeuristic, detect.TypeInstructionOverride, 0.8, 0, 9)},
			},
			want: core.ActionAllow,
		},
		{
			name: "a card in the output is redacted",
			in: core.EvalInput{
				Request:  core.Request{Surface: core.SurfaceOutput},
				Findings: []core.Finding{finding(detect.DetectorPII, detect.TypeCard, 1, 4, 20)},
			},
			want:      core.ActionRedact,
			wantSpans: []core.Span{{Start: 4, End: 20}},
		},
		{
			name: "only the listed types are redacted",
			in: core.EvalInput{
				Request: core.Request{Surface: core.SurfaceOutput},
				Findings: []core.Finding{
					finding(detect.DetectorPII, detect.TypeCard, 1, 4, 20),
					finding(detect.DetectorPII, detect.TypeEmail, 0.7, 30, 45),
				},
			},
			want:      core.ActionRedact,
			wantSpans: []core.Span{{Start: 4, End: 20}},
		},
		{
			name: "an email alone is not in the redact list",
			in: core.EvalInput{
				Request:  core.Request{Surface: core.SurfaceOutput},
				Findings: []core.Finding{finding(detect.DetectorPII, detect.TypeEmail, 0.7, 30, 45)},
			},
			want: core.ActionAllow,
		},
		{
			name: "a tainted session cannot send email",
			in: core.EvalInput{
				Request:        core.Request{Surface: core.SurfaceToolCall, Source: "email.send"},
				SessionTainted: true,
			},
			want: core.ActionBlock,
		},
		{
			name: "an untainted session can",
			in: core.EvalInput{
				Request: core.Request{Surface: core.SurfaceToolCall, Source: "email.send"},
			},
			want: core.ActionAllow,
		},
		{
			name: "a different tool is unaffected by taint",
			in: core.EvalInput{
				Request:        core.Request{Surface: core.SurfaceToolCall, Source: "calendar.read"},
				SessionTainted: true,
			},
			want: core.ActionAllow,
		},
		{
			name: "a changed tool definition is blocked",
			in: core.EvalInput{
				Request:    core.Request{Surface: core.SurfaceToolDefinition, Source: "email.send"},
				PinChanged: true,
			},
			want: core.ActionBlock,
		},
		{
			name: "an unchanged tool definition is allowed",
			in: core.EvalInput{
				Request: core.Request{Surface: core.SurfaceToolDefinition, Source: "email.send"},
			},
			want: core.ActionAllow,
		},
		{
			name: "most severe wins when rules overlap",
			in: core.EvalInput{
				Request: core.Request{Surface: core.SurfaceToolResult},
				Findings: []core.Finding{
					finding(detect.DetectorInjectionHeuristic, detect.TypeInstructionOverride, 0.8, 0, 9),
					finding(detect.DetectorInjectionML, "", 0.99, 0, 9),
				},
			},
			want:      core.ActionBlock, // block beats the flag rule
			wantTaint: true,             // but the flag rule still taints
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := e.Evaluate(context.Background(), tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if got.Action != tt.want {
				t.Errorf("action = %s, want %s", got.Action, tt.want)
			}
			if got.TaintSession != tt.wantTaint {
				t.Errorf("taint = %v, want %v", got.TaintSession, tt.wantTaint)
			}
			if len(got.Redactions) != len(tt.wantSpans) {
				t.Fatalf("redactions = %+v, want %+v", got.Redactions, tt.wantSpans)
			}
			for i := range tt.wantSpans {
				if got.Redactions[i] != tt.wantSpans[i] {
					t.Errorf("redactions = %+v, want %+v", got.Redactions, tt.wantSpans)
				}
			}
			if got.PolicyVersion != p.Version {
				t.Errorf("policy version = %q, want %q", got.PolicyVersion, p.Version)
			}
		})
	}
}

func TestRuleMatching(t *testing.T) {
	yes, no := true, false
	score := 0.9
	tests := []struct {
		name string
		rule Rule
		in   core.EvalInput
		want bool
	}{
		{
			name: "no surface list covers every surface",
			rule: Rule{Action: core.ActionFlag},
			in:   core.EvalInput{Request: core.Request{Surface: core.SurfaceOutput}},
			want: true,
		},
		{
			name: "surface must match",
			rule: Rule{Surface: StringList{"input"}},
			in:   core.EvalInput{Request: core.Request{Surface: core.SurfaceOutput}},
			want: false,
		},
		{
			name: "detector and type must both hold",
			rule: Rule{When: Condition{Detector: StringList{"pii"}, TypeIn: StringList{"card"}}},
			in: core.EvalInput{Findings: []core.Finding{
				finding("pii", "email", 1, 0, 1),
				finding("secrets", "card", 1, 0, 1),
			}},
			want: false,
		},
		{
			name: "one finding satisfying every predicate is enough",
			rule: Rule{When: Condition{Detector: StringList{"pii"}, TypeIn: StringList{"card"}}},
			in: core.EvalInput{Findings: []core.Finding{
				finding("pii", "email", 1, 0, 1),
				finding("pii", "card", 1, 0, 1),
			}},
			want: true,
		},
		{
			name: "score_gte is inclusive",
			rule: Rule{When: Condition{ScoreGTE: &score}},
			in:   core.EvalInput{Findings: []core.Finding{finding("x", "y", 0.9, 0, 1)}},
			want: true,
		},
		{
			name: "session_tainted false matches only an untainted session",
			rule: Rule{When: Condition{SessionTainted: &no}},
			in:   core.EvalInput{SessionTainted: true},
			want: false,
		},
		{
			name: "session_tainted true needs no findings",
			rule: Rule{When: Condition{SessionTainted: &yes}},
			in:   core.EvalInput{SessionTainted: true},
			want: true,
		},
		{
			name: "pin_changed false matches an unchanged definition",
			rule: Rule{When: Condition{PinChanged: &no}},
			in:   core.EvalInput{},
			want: true,
		},
		{
			name: "request and finding predicates are ANDed",
			rule: Rule{When: Condition{Tool: "email.send", Detector: StringList{"pii"}}},
			in: core.EvalInput{
				Request:  core.Request{Source: "calendar.read"},
				Findings: []core.Finding{finding("pii", "card", 1, 0, 1)},
			},
			want: false,
		},
		{
			name: "a finding predicate with no findings never matches",
			rule: Rule{When: Condition{Detector: StringList{"pii"}}},
			in:   core.EvalInput{},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := tt.rule.match(tt.in)
			if got != tt.want {
				t.Fatalf("match = %v, want %v", got, tt.want)
			}
		})
	}
}

// A rule keyed only on the hop redacts everything found on it — there is no
// other sensible reading of a redact rule with no finding predicate.
func TestRedactWithoutFindingPredicate(t *testing.T) {
	e := NewEvaluator(&Policy{Rules: []Rule{{
		Surface: StringList{"output"},
		When:    Condition{SessionTainted: boolPtr(true)},
		Action:  core.ActionRedact,
	}}})
	got, err := e.Evaluate(context.Background(), core.EvalInput{
		Request:        core.Request{Surface: core.SurfaceOutput},
		Findings:       []core.Finding{finding("pii", "email", 0.7, 1, 5)},
		SessionTainted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Action != core.ActionRedact || len(got.Redactions) != 1 {
		t.Fatalf("decision = %+v", got)
	}
}

func boolPtr(b bool) *bool { return &b }
