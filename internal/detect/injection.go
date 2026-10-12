package detect

import (
	"context"
	"regexp"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

// InjectionHeuristic looks for instruction-override phrasing, role and
// delimiter spoofing, and text hidden from a human reader (DESIGN §3.3).
//
// Honest limitation, in the doc's own words: **easily bypassed by paraphrase.**
// It is a signal, never the sole protection. Scores stay below 1 for that
// reason, and DESIGN §3.4's session taint — not this detector — is what makes
// indirect injection expensive to exploit.
//
// Hidden characters and encoded payloads are reported by the normalizer, which
// is the only stage that still sees them; this detector covers what survives
// normalization.
type InjectionHeuristic struct{}

func (InjectionHeuristic) Name() string { return DetectorInjectionHeuristic }

var _ Detector = InjectionHeuristic{}

// overrideRe matches attempts to cancel or replace the instructions already in
// context. Kept as phrases rather than single keywords: "ignore" alone is
// ordinary English.
var overrideRe = regexp.MustCompile(`(?i)\b(?:` +
	`(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|the\s+|your\s+|these\s+|those\s+)*` +
	`(?:previous|prior|earlier|above|preceding|initial|original|system)?\s*` +
	`(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions|context|guardrail|guardrails)` +
	`|new\s+instructions?\s*:` +
	`|instead\s+of\s+(?:the\s+)?(?:above|previous|your)\s+(?:instructions?|rules?)` +
	`|you\s+are\s+now\s+(?:a|an|in|no\s+longer|unrestricted|jailbroken|free|allowed)\b` +
	`|(?:act|behave)\s+as\s+(?:if\s+you\s+are\s+)?(?:a|an)?\s*(?:developer|dan|jailbroken|unrestricted)` +
	`|(?:do\s+not|don't|never)\s+(?:tell|mention|reveal|inform)\s+(?:the\s+)?user` +
	`|reveal\s+(?:your\s+)?(?:system\s+prompt|instructions|prompt)` +
	`|print\s+(?:your\s+)?(?:system\s+prompt|instructions)` +
	`)`)

// spoofRe matches chat-template and role markers. Content that carries them is
// trying to look like the transcript rather than a message inside it.
var spoofRe = regexp.MustCompile(`(?i)(?:` +
	`<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>` +
	`|\[/?INST\]|<<\s*SYS\s*>>` +
	`|(?m)^\s*(?:###\s*)?(?:system|assistant|human)\s*:` +
	`|</?(?:system|assistant)>` +
	`)`)

// hiddenRe matches text a reader would not see but a model would read.
var hiddenRe = regexp.MustCompile(`(?is)<!--.*?-->|<[^>]*style\s*=\s*["'][^"']*(?:display\s*:\s*none|font-size\s*:\s*0)`)

const (
	scoreOverride = 0.8
	scoreSpoof    = 0.6
	scoreHidden   = 0.6
)

func (d InjectionHeuristic) Detect(_ context.Context, req core.Request) ([]core.Finding, error) {
	var out []core.Finding
	for i, part := range req.Parts {
		for _, r := range []struct {
			re    *regexp.Regexp
			typ   string
			score float64
		}{
			{overrideRe, TypeInstructionOverride, scoreOverride},
			{spoofRe, TypeRoleSpoof, scoreSpoof},
			{hiddenRe, TypeHiddenText, scoreHidden},
		} {
			for _, loc := range r.re.FindAllStringIndex(part.Text, -1) {
				out = append(out, core.Finding{
					Detector: DetectorInjectionHeuristic,
					Type:     r.typ,
					Span:     core.Span{Part: i, Start: loc[0], End: loc[1]},
					Score:    r.score,
				})
			}
		}
	}
	return out, nil
}
