package detect

import (
	"context"
	"fmt"
	"regexp"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

// CustomDict matches a tenant's own keyword and regex lists — project
// codenames, customer identifiers (DESIGN §3.3). Keywords go through one
// Aho-Corasick pass; regexes are applied in order.
//
// Honest limitation, per DESIGN §3.3: exact match only. A codename someone
// abbreviates or misspells is not found.
//
// Where the lists come from is an open gap: DESIGN §3.6's policy YAML has a
// `tenant` field but no slot for tenant dictionaries, so for now they are
// supplied by whoever constructs the detector.
type CustomDict struct {
	ac       *ahoCorasick
	keywords []string
	regexes  []*regexp.Regexp
}

// NewCustomDict compiles a tenant's keyword and regex lists.
func NewCustomDict(keywords, patterns []string) (*CustomDict, error) {
	d := &CustomDict{ac: newAhoCorasick(keywords), keywords: keywords}
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("custom_dict: pattern %q: %w", p, err)
		}
		d.regexes = append(d.regexes, re)
	}
	return d, nil
}

func (*CustomDict) Name() string { return DetectorCustomDict }

var _ Detector = (*CustomDict)(nil)

// Empty reports whether the dictionary would never match.
func (d *CustomDict) Empty() bool { return len(d.ac.terms) == 0 && len(d.regexes) == 0 }

func (d *CustomDict) Detect(_ context.Context, req core.Request) ([]core.Finding, error) {
	if d.Empty() {
		return nil, nil
	}
	var out []core.Finding
	for i, part := range req.Parts {
		for _, m := range d.ac.find(part.Text) {
			out = append(out, core.Finding{
				Detector: DetectorCustomDict,
				Type:     TypeCustomTerm,
				Span:     core.Span{Part: i, Start: m.start, End: m.end},
				Score:    scoreChecksum,
			})
		}
		for _, re := range d.regexes {
			for _, loc := range re.FindAllStringIndex(part.Text, -1) {
				out = append(out, core.Finding{
					Detector: DetectorCustomDict,
					Type:     TypeCustomTerm,
					Span:     core.Span{Part: i, Start: loc[0], End: loc[1]},
					Score:    scoreChecksum,
				})
			}
		}
	}
	return suppressContained(out), nil
}
