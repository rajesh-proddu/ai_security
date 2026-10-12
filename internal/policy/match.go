package policy

import "github.com/rajesh-proddu/ai_security/internal/core"

// Matching follows DESIGN §3.6: a rule applies when its surface list contains
// the request's surface and every condition in its `when` block holds. Within
// `when`, the finding predicates (detector, type_in, score_gte) select findings
// and the request predicates (tool, session_tainted, pin_changed) qualify the
// hop; all of them must hold.

// matchesSurface reports whether the rule covers this surface. A rule with no
// surface list covers every surface.
func (r Rule) matchesSurface(s core.Surface) bool {
	return len(r.Surface) == 0 || r.Surface.Contains(string(s))
}

// selectsFindings reports whether the condition constrains which findings match.
func (c Condition) selectsFindings() bool {
	return len(c.Detector) > 0 || len(c.TypeIn) > 0 || c.ScoreGTE != nil
}

// matchesRequest checks the predicates that describe the hop rather than a
// finding.
func (c Condition) matchesRequest(in core.EvalInput) bool {
	// DESIGN §3.1 makes Source the tool name on the tool paths. Exact match
	// only; patterns like `erp.*` are Phase 4 (ROADMAP).
	if c.Tool != "" && c.Tool != in.Request.Source {
		return false
	}
	if c.SessionTainted != nil && *c.SessionTainted != in.SessionTainted {
		return false
	}
	if c.PinChanged != nil && *c.PinChanged != in.PinChanged {
		return false
	}
	return true
}

// matchesFinding checks the predicates that select a finding.
func (c Condition) matchesFinding(f core.Finding) bool {
	if len(c.Detector) > 0 && !c.Detector.Contains(f.Detector) {
		return false
	}
	if len(c.TypeIn) > 0 && !c.TypeIn.Contains(f.Type) {
		return false
	}
	if c.ScoreGTE != nil && f.Score < *c.ScoreGTE {
		return false
	}
	return true
}

// match reports whether the rule applies, and which findings triggered it. A
// rule with no finding predicates is triggered by the hop itself, and its spans
// are every finding on it — that is what a redact rule keyed only on session
// state can mean.
func (r Rule) match(in core.EvalInput) (bool, []core.Span) {
	if !r.matchesSurface(in.Request.Surface) || !r.When.matchesRequest(in) {
		return false, nil
	}
	if !r.When.selectsFindings() {
		return true, spansOf(in.Findings)
	}
	var spans []core.Span
	for _, f := range in.Findings {
		if r.When.matchesFinding(f) {
			spans = append(spans, f.Span)
		}
	}
	return len(spans) > 0, spans
}

func spansOf(findings []core.Finding) []core.Span {
	if len(findings) == 0 {
		return nil
	}
	spans := make([]core.Span, 0, len(findings))
	for _, f := range findings {
		spans = append(spans, f.Span)
	}
	return spans
}
