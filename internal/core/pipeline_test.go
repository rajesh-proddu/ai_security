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
			name:          "redact carries finding spans",
			detectors:     stubDetectors{findings: []Finding{finding}},
			eval:          &stubEvaluator{decision: Decision{Action: ActionRedact, PolicyVersion: "v1"}},
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

func (errNormalizer) Normalize(context.Context, Request) (Request, error) {
	return Request{}, errors.New("normalize failed")
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
