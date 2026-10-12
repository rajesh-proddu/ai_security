// Package normalize is the first pipeline stage of DESIGN §3.3: it rewrites
// each part so detectors see what a model would read, not what an attacker
// typed to get past a pattern match.
//
// Passes, in order: extract values from JSON → decode HTML entities → decode
// URL percent-escapes → strip invisible characters → decode base64 → NFKC.
//
// Every pass records where each output byte came from, and the maps are
// composed, so a finding in normalized text redacts the right original bytes.
//
// Known limits, stated rather than papered over:
//   - Decoding is single pass. `&amp;#105;` decodes to `&#105;`, not `i`, and a
//     percent-encoded base64 payload is decoded once, not twice.
//   - Text decoded from base64 is not re-run through the earlier passes.
//   - Only readable base64 is expanded; binary payloads are left alone.
//
// The normalizer is one of several signals, as §3.3 says of the injection
// heuristic; it narrows evasion, it does not close it.
package normalize

import (
	"context"

	"github.com/rajesh-proddu/ai_security/internal/core"
	"github.com/rajesh-proddu/ai_security/internal/detect"
)

// Finding types the normalizer reports. They are injection_heuristic findings
// (DESIGN §3.3 lists hidden text and encoded payloads under it) raised here
// because detectors only ever see the text after these are removed.
const (
	TypeHiddenText     = detect.TypeHiddenText
	TypeEncodedPayload = detect.TypeEncodedPayload
)

var passes = []pass{extractJSON, decodeEntities, decodePercent, stripInvisible, expandBase64, nfkc}

// Normalizer implements core.Normalizer.
type Normalizer struct{}

var _ core.Normalizer = Normalizer{}

func (Normalizer) Normalize(_ context.Context, req core.Request) (core.Normalization, error) {
	n := core.Normalization{Request: req, Maps: make([]core.OffsetMap, len(req.Parts))}
	n.Request.Parts = make([]core.Part, len(req.Parts))
	for i, part := range req.Parts {
		text, m, findings := Text(part.Text)
		part.Text = text
		n.Request.Parts[i] = part
		n.Maps[i] = m
		for _, f := range findings {
			f.Span.Part = i
			n.Findings = append(n.Findings, f)
		}
	}
	return n, nil
}

// Text normalizes one string. It returns the normalized text, the map from
// normalized to original offsets, and evasion findings in original offsets.
func Text(in string) (string, core.OffsetMap, []core.Finding) {
	var acc core.OffsetMap // normalized → original, so far
	var findings []core.Finding
	text := in
	for _, p := range passes {
		out, m, ev := p(text)
		for _, e := range ev {
			// Evidence is in this pass's input offsets; map it to the original.
			start, end := acc.Span(e.start, e.end)
			findings = append(findings, core.Finding{
				Detector: detect.DetectorInjectionHeuristic,
				Type:     e.typ,
				Span:     core.Span{Start: start, End: end},
				Score:    e.score,
			})
		}
		acc = core.ComposeOffsets(m, acc)
		text = out
	}
	return text, acc, findings
}
