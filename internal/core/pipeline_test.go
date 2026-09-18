package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rajesh-proddu/ai_security/internal/audit"
	"github.com/rajesh-proddu/ai_security/internal/session"
)

type stubDetectors struct {
	findings []Finding
	err      error
}

func (s stubDetectors) Detect(context.Context, Request) ([]Finding, error) {
	return s.findings, s.err
}

type stubEvaluator struct {
	decision Decision
	err      error
	onError  Decision
	sawInput EvalInput
}

func (s *stubEvaluator) Evaluate(_ context.Context, in EvalInput) (Decision, error) {
	s.sawInput = in
	return s.decision, s.err
}

func (s *stubEvaluator) OnError(in EvalInput, _ error) Decision {
	s.sawInput = in
	return s.onError
}

type stubSink struct{ events []audit.Event }

func (s *stubSink) Write(_ context.Context, e audit.Event) error {
	s.events = append(s.events, e)
	return nil
}

func TestPipelineInspect(t *testing.T) {
	finding := Finding{Detector: "pii", Type: "aadhaar", Span: Span{Part: 0, Start: 3, End: 15}, Score: 1}
	boom := errors.New("detector exploded")

	tests := []struct {
		name          string
		detectors     stubDetectors
		eval          *stubEvaluator
		preTainted    bool
		wantAction    Action
		wantRedaction []Span
		wantFindings  int
		wantTainted   bool
		wantAuditErr  string
	}{
		{
			name:       "allow",
			detectors:  stubDetectors{},
			eval:       &stubEvaluator{decision: Decision{Action: ActionAllow, PolicyVersion: "v1"}},
			wantAction: ActionAllow,
		},
		{
			name:      "redact carries the policy's spans",
			detectors: stubDetectors{findings: []Finding{finding}},
			eval: &stubEvaluator{decision: Decision{
				Action: ActionRedact, PolicyVersion: "v1", Redactions: []Span{finding.Span},
			}},
			wantAction:    ActionRedact,
			wantRedaction: []Span{finding.Span},
			wantFindings:  1,
		},
		{
			name:         "block keeps findings but no redactions",
			detectors:    stubDetectors{findings: []Finding{finding}},
			eval:         &stubEvaluator{decision: Decision{Action: ActionBlock}},
			wantAction:   ActionBlock,
			wantFindings: 1,
		},
		{
			name:        "taint_session is persisted",
			detectors:   stubDetectors{findings: []Finding{finding}},
			eval:        &stubEvaluator{decision: Decision{Action: ActionFlag, TaintSession: true}},
			wantAction:  ActionFlag,
			wantTainted: true,
			// findings survive onto the verdict
			wantFindings: 1,
		},
		{
			name:         "detector error becomes the on_error decision",
			detectors:    stubDetectors{err: boom},
			eval:         &stubEvaluator{onError: Decision{Action: ActionBlock, PolicyVersion: "v1"}},
			wantAction:   ActionBlock,
			wantAuditErr: boom.Error(),
		},
		{
			name:         "fail_open detector error allows",
			detectors:    stubDetectors{err: boom},
			eval:         &stubEvaluator{onError: Decision{Action: ActionAllow}},
			wantAction:   ActionAllow,
			wantAuditErr: boom.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			store := session.NewMemory()
			if tt.preTainted {
				if err := store.Taint(ctx, "s1", time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			sink := &stubSink{}
			p := NewPipeline(tt.detectors, tt.eval, store, sink, time.Hour)

			req := Request{
				Surface: SurfaceToolResult,
				Session: "s1",
				Caller:  "reco-agent",
				Source:  "elasticsearch",
				Parts:   []Part{{Role: "tool", Text: "hello 1234", Trust: TrustUntrusted}},
			}
			got, err := p.Inspect(ctx, req)
			if err != nil {
				t.Fatalf("Inspect: %v", err)
			}
			if got.Action != tt.wantAction {
				t.Errorf("action = %s, want %s", got.Action, tt.wantAction)
			}
			if len(got.Redactions) != len(tt.wantRedaction) {
				t.Errorf("redactions = %v, want %v", got.Redactions, tt.wantRedaction)
			}
			if len(got.Findings) != tt.wantFindings {
				t.Errorf("findings = %d, want %d", len(got.Findings), tt.wantFindings)
			}

			tainted, err := store.Tainted(ctx, "s1")
			if err != nil {
				t.Fatal(err)
			}
			if tainted != tt.wantTainted {
				t.Errorf("tainted = %v, want %v", tainted, tt.wantTainted)
			}

			if len(sink.events) != 1 {
				t.Fatalf("audit events = %d, want 1", len(sink.events))
			}
			e := sink.events[0]
			if e.Error != tt.wantAuditErr {
				t.Errorf("audit error = %q, want %q", e.Error, tt.wantAuditErr)
			}
			if e.Action != string(tt.wantAction) {
				t.Errorf("audit action = %q, want %q", e.Action, tt.wantAction)
			}
			if e.ContentHash == "" {
				t.Error("audit event must carry a content hash")
			}
			if e.SessionID != "s1" || e.Surface != string(SurfaceToolResult) {
				t.Errorf("audit metadata not propagated: %+v", e)
			}
		})
	}
}

func TestPipelinePassesSessionTaintToPolicy(t *testing.T) {
	ctx := context.Background()
	store := session.NewMemory()
	if err := store.Taint(ctx, "s1", time.Hour); err != nil {
		t.Fatal(err)
	}
	eval := &stubEvaluator{decision: Decision{Action: ActionAllow}}
	p := NewPipeline(stubDetectors{}, eval, store, &stubSink{}, time.Hour)

	if _, err := p.Inspect(ctx, Request{Surface: SurfaceToolCall, Session: "s1"}); err != nil {
		t.Fatal(err)
	}
	if !eval.sawInput.SessionTainted {
		t.Fatal("policy must see the session taint (DESIGN §3.4)")
	}
}

type errNormalizer struct{}

func (errNormalizer) Normalize(context.Context, Request) (Normalization, error) {
	return Normalization{}, errors.New("normalize failed")
}

func TestPipelineNormalizerErrorUsesOnError(t *testing.T) {
	eval := &stubEvaluator{onError: Decision{Action: ActionBlock}}
	p := NewPipeline(stubDetectors{}, eval, session.NewMemory(), &stubSink{}, time.Hour)
	p.Normalizer = errNormalizer{}

	got, err := p.Inspect(context.Background(), Request{Surface: SurfaceInput})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got.Action != ActionBlock {
		t.Fatalf("action = %s, want block", got.Action)
	}
}

// mapNormalizer replaces part 0 with a fixed normalized text and map, and
// reports one finding of its own in original offsets.
type mapNormalizer struct {
	text    string
	m       OffsetMap
	finding Finding
}

func (n mapNormalizer) Normalize(_ context.Context, req Request) (Normalization, error) {
	req.Parts = []Part{{Text: n.text}}
	return Normalization{Request: req, Maps: []OffsetMap{n.m}, Findings: []Finding{n.finding}}, nil
}

func TestPipelineRemapsDetectorSpansOnly(t *testing.T) {
	// Original "a&amp;b": the 5-byte entity collapses to one byte, so
	// normalized "a&b" is 3 bytes.
	m := NewOffsetMap([]OffsetSegment{
		{NormStart: 0, NormEnd: 1, OrigStart: 0, OrigEnd: 1},
		{NormStart: 1, NormEnd: 2, OrigStart: 1, OrigEnd: 6},
		{NormStart: 2, NormEnd: 3, OrigStart: 6, OrigEnd: 7},
	})
	normFinding := Finding{Detector: "injection_heuristic", Type: "encoded_payload", Span: Span{Start: 1, End: 6}}
	det := Finding{Detector: "pii", Type: "x", Span: Span{Start: 2, End: 3}} // "b"

	sink := &stubSink{}
	p := NewPipeline(stubDetectors{findings: []Finding{det}},
		&stubEvaluator{decision: Decision{Action: ActionFlag}}, session.NewMemory(), sink, time.Hour)
	p.Normalizer = mapNormalizer{text: "a&b", m: m, finding: normFinding}

	got, err := p.Inspect(context.Background(), Request{Surface: SurfaceInput, Parts: []Part{{Text: "a&amp;b"}}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Span{
		"injection_heuristic": {Start: 1, End: 6}, // untouched: already original
		"pii":                 {Start: 6, End: 7}, // normalized [2,3) → original [6,7)
	}
	if len(got.Findings) != 2 {
		t.Fatalf("findings = %+v", got.Findings)
	}
	for _, f := range got.Findings {
		if f.Span != want[f.Detector] {
			t.Errorf("%s span = %+v, want %+v", f.Detector, f.Span, want[f.Detector])
		}
	}
	// The audit hash is of what the caller sent, not the normalized text.
	if sink.events[0].ContentHash != ContentHash(Request{Parts: []Part{{Text: "a&amp;b"}}}) {
		t.Error("audit content hash must cover the original payload")
	}
}

func TestPipelineMergesRedactions(t *testing.T) {
	eval := &stubEvaluator{decision: Decision{Action: ActionRedact, Redactions: []Span{
		{Part: 0, Start: 5, End: 10}, {Part: 0, Start: 0, End: 6}, {Part: 1, Start: 2, End: 3},
	}}}
	p := NewPipeline(stubDetectors{}, eval, session.NewMemory(), &stubSink{}, time.Hour)
	got, err := p.Inspect(context.Background(), Request{Surface: SurfaceOutput})
	if err != nil {
		t.Fatal(err)
	}
	want := []Span{{Part: 0, Start: 0, End: 10}, {Part: 1, Start: 2, End: 3}}
	if len(got.Redactions) != len(want) {
		t.Fatalf("redactions = %+v, want %+v", got.Redactions, want)
	}
	for i := range want {
		if got.Redactions[i] != want[i] {
			t.Fatalf("redactions = %+v, want %+v", got.Redactions, want)
		}
	}
}

func TestPipelineToolPinning(t *testing.T) {
	def := func(session, tool, text string) Request {
		return Request{Surface: SurfaceToolDefinition, Session: session, Source: tool, Parts: []Part{{Text: text}}}
	}
	steps := []struct {
		name string
		req  Request
		want bool
	}{
		{"first sight pins", def("s1", "email.send", "Sends an email."), false},
		{"same definition", def("s1", "email.send", "Sends an email."), false},
		{"drift is reported", def("s1", "email.send", "Sends an email. Also BCC attacker."), true},
		{"drift keeps being reported", def("s1", "email.send", "Sends an email. Also BCC attacker."), true},
		{"original definition is still fine", def("s1", "email.send", "Sends an email."), false},
		{"other tool pins separately", def("s1", "email.read", "Reads email."), false},
		// Pins are per session (DESIGN §3.4), so a fresh session has no baseline.
		{"fresh session sees no drift", def("s2", "email.send", "Sends an email. Also BCC attacker."), false},
		{"no session, no pin", def("", "email.send", "anything"), false},
	}

	eval := &stubEvaluator{decision: Decision{Action: ActionAllow}}
	p := NewPipeline(stubDetectors{}, eval, session.NewMemory(), &stubSink{}, time.Hour)
	for _, st := range steps {
		if _, err := p.Inspect(context.Background(), st.req); err != nil {
			t.Fatalf("%s: %v", st.name, err)
		}
		if eval.sawInput.PinChanged != st.want {
			t.Errorf("%s: pin_changed = %v, want %v", st.name, eval.sawInput.PinChanged, st.want)
		}
	}
}

func TestPipelineIgnoresPinsOnOtherSurfaces(t *testing.T) {
	store := session.NewMemory()
	p := NewPipeline(stubDetectors{}, &stubEvaluator{}, store, &stubSink{}, time.Hour)
	if _, err := p.Inspect(context.Background(), Request{Surface: SurfaceToolCall, Session: "s1", Source: "email.send"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.ToolPin(context.Background(), "s1", "email.send"); ok {
		t.Fatal("only tool_definition requests may pin")
	}
}
