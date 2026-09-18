package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/rajesh-proddu/ai_security/internal/audit"
	"github.com/rajesh-proddu/ai_security/internal/session"
)

// The pipeline of DESIGN §3.3: normalize → detectors → policy → verdict → audit.
// Each stage is an interface so Phase 1 can fill it in without touching this file.

// Normalizer decodes and canonicalises text before detection (DESIGN §3.3).
type Normalizer interface {
	Normalize(ctx context.Context, req Request) (Request, error)
}

// DetectorSet runs the configured detectors over a request.
type DetectorSet interface {
	Detect(ctx context.Context, req Request) ([]Finding, error)
}

// EvalInput is everything the policy layer decides on: the request, the
// findings, and the cross-surface session state of DESIGN §3.4.
type EvalInput struct {
	Request        Request
	Findings       []Finding
	SessionTainted bool
}

// Decision is the policy layer's output.
type Decision struct {
	Action        Action
	TaintSession  bool
	PolicyVersion string
}

// Evaluator maps findings and session state to an action (DESIGN §3.6).
type Evaluator interface {
	Evaluate(ctx context.Context, in EvalInput) (Decision, error)
	// OnError is the defaults.on_error path: a detector or ML failure becomes
	// a decision rather than an error propagated to the gateway.
	OnError(in EvalInput, err error) Decision
}

// Pipeline is the default Inspector implementation.
type Pipeline struct {
	Normalizer Normalizer // optional; skipped when nil
	Detectors  DetectorSet
	Policy     Evaluator
	Sessions   session.Store
	Audit      audit.Sink

	// TaintTTL bounds how long a taint mark survives.
	TaintTTL time.Duration

	now func() time.Time
}

// NewPipeline wires the stages. Detectors, Policy, Sessions and Audit are required.
func NewPipeline(d DetectorSet, p Evaluator, s session.Store, a audit.Sink, taintTTL time.Duration) *Pipeline {
	return &Pipeline{Detectors: d, Policy: p, Sessions: s, Audit: a, TaintTTL: taintTTL, now: time.Now}
}

var _ Inspector = (*Pipeline)(nil)

func (p *Pipeline) clock() time.Time {
	if p.now == nil {
		return time.Now()
	}
	return p.now()
}

func (p *Pipeline) Inspect(ctx context.Context, req Request) (Verdict, error) {
	start := p.clock()

	if p.Normalizer != nil {
		normalized, err := p.Normalizer.Normalize(ctx, req)
		if err != nil {
			return p.fail(ctx, req, EvalInput{Request: req}, err, start)
		}
		req = normalized
	}

	tainted := false
	if req.Session != "" {
		t, err := p.Sessions.Tainted(ctx, req.Session)
		if err != nil {
			return p.fail(ctx, req, EvalInput{Request: req}, err, start)
		}
		tainted = t
	}

	findings, err := p.Detectors.Detect(ctx, req)
	in := EvalInput{Request: req, Findings: findings, SessionTainted: tainted}
	if err != nil {
		return p.fail(ctx, req, in, err, start)
	}

	decision, err := p.Policy.Evaluate(ctx, in)
	if err != nil {
		return p.fail(ctx, req, in, err, start)
	}

	verdict := Verdict{
		Action:        decision.Action,
		Findings:      findings,
		TaintSession:  decision.TaintSession,
		PolicyVersion: decision.PolicyVersion,
	}
	if verdict.Action == ActionRedact {
		verdict.Redactions = spans(findings)
	}

	if decision.TaintSession && req.Session != "" {
		if err := p.Sessions.Taint(ctx, req.Session, p.TaintTTL); err != nil {
			return p.fail(ctx, req, in, err, start)
		}
	}

	p.emit(ctx, req, verdict, start, nil)
	return verdict, nil
}

// fail turns a stage error into the policy's on_error decision. The error is
// recorded in the audit event, not returned: the gateway gets a verdict.
func (p *Pipeline) fail(ctx context.Context, req Request, in EvalInput, cause error, start time.Time) (Verdict, error) {
	decision := p.Policy.OnError(in, cause)
	verdict := Verdict{Action: decision.Action, PolicyVersion: decision.PolicyVersion}
	p.emit(ctx, req, verdict, start, cause)
	return verdict, nil
}

func (p *Pipeline) emit(ctx context.Context, req Request, v Verdict, start time.Time, cause error) {
	e := audit.Event{
		Time:          start.UTC().Format(time.RFC3339Nano),
		SessionID:     req.Session,
		Surface:       string(req.Surface),
		Caller:        req.Caller,
		Source:        req.Source,
		Action:        string(v.Action),
		PolicyVersion: v.PolicyVersion,
		TaintSession:  v.TaintSession,
		Findings:      auditFindings(v.Findings),
		ContentHash:   ContentHash(req),
		LatencyMS:     float64(p.clock().Sub(start).Microseconds()) / 1000,
	}
	if cause != nil {
		e.Error = cause.Error()
	}
	// A sink failure must not turn a decided hop into an error for the gateway.
	_ = p.Audit.Write(ctx, e)
}

// ContentHash identifies an inspected payload without carrying it (DESIGN §3.7).
func ContentHash(req Request) string {
	h := sha256.New()
	for _, part := range req.Parts {
		h.Write([]byte(part.Text))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func spans(findings []Finding) []Span {
	if len(findings) == 0 {
		return nil
	}
	out := make([]Span, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Span)
	}
	return out
}

func auditFindings(findings []Finding) []audit.Finding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]audit.Finding, 0, len(findings))
	for _, f := range findings {
		out = append(out, audit.Finding{
			Detector: f.Detector,
			Type:     f.Type,
			Score:    f.Score,
			Part:     f.Span.Part,
			Start:    f.Span.Start,
			End:      f.Span.End,
		})
	}
	return out
}
