package detect

import (
	"context"
	"math"
	"regexp"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

// Secrets finds provider credentials by pattern, plus an entropy check for
// credentials whose format we do not know (DESIGN §3.3).
//
// Honest limitation: an unknown key format with low entropy slips through, and
// the entropy check is the noisiest thing in the v1 set — it is scored below
// the pattern matches so policy can act on one without the other.
type Secrets struct{}

func (Secrets) Name() string { return DetectorSecrets }

var _ Detector = Secrets{}

// providerKeys are patterns specific enough to report on their own.
var providerKeys = []struct {
	typ string
	re  *regexp.Regexp
}{
	// AWS access key ids: a fixed prefix and 16 base32 characters.
	{TypeAWSKey, regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA)[A-Z0-9]{16}\b`)},
	// GitHub tokens: ghp_ (personal), gho_, ghu_, ghs_, ghr_ (app/refresh).
	{TypeGitHubToken, regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`)},
	{TypeSlackToken, regexp.MustCompile(`\bxox[baprse]-[A-Za-z0-9-]{10,}\b`)},
	{TypeOpenAIKey, regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b`)},
}

// entropyCandidate is what the entropy check considers at all: a long,
// unbroken token. Requiring length and a mixed alphabet keeps prose out.
var entropyCandidate = regexp.MustCompile(`[A-Za-z0-9+/_\-=]{24,}`)

// entropyThreshold is in bits per character. English prose sits near 2-3;
// base64-encoded random bytes approach 6.
const entropyThreshold = 4.2

func (s Secrets) Detect(_ context.Context, req core.Request) ([]core.Finding, error) {
	var findings []core.Finding
	for i, part := range req.Parts {
		findings = append(findings, s.scan(i, part.Text)...)
	}
	return findings, nil
}

func (Secrets) scan(part int, text string) []core.Finding {
	var out []core.Finding
	for _, p := range providerKeys {
		for _, loc := range p.re.FindAllStringIndex(text, -1) {
			out = append(out, core.Finding{
				Detector: DetectorSecrets,
				Type:     p.typ,
				Span:     core.Span{Part: part, Start: loc[0], End: loc[1]},
				Score:    scoreChecksum,
			})
		}
	}
	for _, loc := range entropyCandidate.FindAllStringIndex(text, -1) {
		tok := text[loc[0]:loc[1]]
		if !mixedAlphabet(tok) || ShannonEntropy(tok) < entropyThreshold {
			continue
		}
		out = append(out, core.Finding{
			Detector: DetectorSecrets,
			Type:     TypeHighEntropy,
			Span:     core.Span{Part: part, Start: loc[0], End: loc[1]},
			Score:    0.5,
		})
	}
	// A provider key is also a high-entropy token; report it once, as the
	// specific type.
	return suppressContained(out)
}

// mixedAlphabet requires digits and letters of both cases, which a hex digest
// or a long word does not have.
func mixedAlphabet(s string) bool {
	var lower, upper, digit bool
	for i := range len(s) {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	return lower && upper && digit
}

// ShannonEntropy returns the entropy of s in bits per character.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := range len(s) {
		counts[s[i]]++
	}
	n := float64(len(s))
	e := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}
