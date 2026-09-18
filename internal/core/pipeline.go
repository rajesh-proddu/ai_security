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
// Each stage is an interface so it can be replaced without touching this file.

// Normalization is what the normalize stage produces: the request with decoded,
// folded text; one OffsetMap per part so findings can be mapped back to the
// original bytes; and any findings the normalizer itself is the only stage able
// to make — the evasion signals it neutralises (hidden characters, encoded
// payloads) are invisible by the time detectors run. Those findings carry
// original offsets.
type Normalization struct {
	Request  Request
	Maps     []OffsetMap
	Findings []Finding
}

// Normalizer decodes and canonicalises text before detection (DESIGN §3.3).
type Normalizer interface {
	Normalize(ctx context.Context, req Request) (Normalization, error)
}

// DetectorSet runs the configured detectors over a request.
type DetectorSet interface {
	Detect(ctx context.Context, req Request) ([]Finding, error)
}

// EvalInput is everything the policy layer decides on: the request, the
// findings, and the cross-surface state of DESIGN §3.4.
type EvalInput struct {
	Request        Request
	Findings       []Finding
	SessionTainted bool
	// PinChanged reports that this tool definition's hash differs from the one
	// pinned earlier in the session — the rug pull of DESIGN §4.
	PinChanged bool
}

// Decision is the policy layer's output.
type Decision struct {
	Action       Action
	TaintSession bool
	// Redactions are the spans of the findings matched by a redact rule — not
	// every finding, only the ones a redact rule selected.
	Redactions    []Span
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

	// TaintTTL bounds how long a taint mark and a tool pin survive.
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
	original := req

	var maps []OffsetMap
	var findings []Finding
	if p.Normalizer != nil {
		n, err := p.Normalizer.Normalize(ctx, req)
		if err != nil {
			return p.fail(ctx, original, EvalInput{Request: original}, err, start)
		}
		req, maps, findings = n.Request, n.Maps, n.Findings
	}

	tainted := false
	if req.Session != "" {
		t, err := p.Sessions.Tainted(ctx, req.Session)
		if err != nil {
			return p.fail(ctx, original, EvalInput{Request: original}, err, start)
		}
		tainted = t
	}

	pinChanged, err := p.checkPin(ctx, original)
	if err != nil {
		return p.fail(ctx, original, EvalInput{Request: original}, err, start)
	}

	// Detector spans are in normalized offsets and are mapped back; normalizer
	// findings are already in original offsets.
	detected, err := p.Detectors.Detect(ctx, req)
	remapSpans(detected, maps)
	findings = append(findings, detected...)

	in := EvalInput{Request: req, Findings: findings, SessionTainted: tainted, PinChanged: pinChanged}
	if err != nil {
		return p.fail(ctx, original, in, err, start)
	}

	decision, err := p.Policy.Evaluate(ctx, in)
	if err != nil {
		return p.fail(ctx, original, in, err, start)
	}

	verdict := Verdict{
		Action:        decision.Action,
		Findings:      findings,
		TaintSession:  decision.TaintSession,
		PolicyVersion: decision.PolicyVersion,
	}
	if decision.Action == ActionRedact {
		verdict.Redactions = MergeSpans(decision.Redactions)
	}

	if decision.TaintSession && req.Session != "" {
		if err := p.Sessions.Taint(ctx, req.Session, p.TaintTTL); err != nil {
			return p.fail(ctx, original, in, err, start)
		}
	}

	p.emit(ctx, original, verdict, start, nil)
	return verdict, nil
}

// checkPin implements tool-definition pinning (DESIGN §4): the first definition
// seen for a tool in a session is recorded, and a later definition that hashes
// differently is reported as drift. The approved hash is kept, so repeated drift
// keeps being reported.
//
// Scope limit: pins are keyed by session, per §3.4, so a rug pull that arrives
// in a fresh session is not detected — that session has nothing to compare
// against.
func (p *Pipeline) checkPin(ctx context.Context, req Request) (bool, error) {
	if req.Surface != SurfaceToolDefinition || req.Session == "" || req.Source == "" {
		return false, nil
	}
	hash := ContentHash(req)
	pinned, ok, err := p.Sessions.ToolPin(ctx, req.Session, req.Source)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, p.Sessions.PinTool(ctx, req.Session, req.Source, hash, p.TaintTTL)
	}
	return pinned != hash, nil
}

// remapSpans rewrites finding spans from normalized offsets to the offsets of
// the payload the caller sent.
func remapSpans(findings []Finding, maps []OffsetMap) {
	if len(maps) == 0 {
		return
	}
	for i := range findings {
		part := findings[i].Span.Part
		if part < 0 || part >= len(maps) {
			continue
		}
		start, end := maps[part].Span(findings[i].Span.Start, findings[i].Span.End)
		findings[i].Span.Start, findings[i].Span.End = start, end
	}
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
