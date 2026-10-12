package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/rajesh-proddu/ai_security/internal/core"
	"github.com/rajesh-proddu/ai_security/internal/detect"
	"github.com/rajesh-proddu/ai_security/internal/normalize"
)

// Label is one expected finding: which detector should fire, and with what
// finding type. Spans are asserted in the detector unit tests, not here — the
// eval measures whether the right things are found, not where.
type Label struct {
	Detector string `json:"detector"`
	Type     string `json:"type"`
}

func (l Label) String() string { return l.Detector + "/" + l.Type }

// Case is one labelled input.
type Case struct {
	ID      string  `json:"id"`
	Note    string  `json:"note"`
	Surface string  `json:"surface"`
	Text    string  `json:"text"`
	Expect  []Label `json:"expect"`
	// Synthetic marks a case that was written by hand rather than observed in
	// real traffic. Every case in this repo is synthetic today; see the README
	// note in main.go's doc comment for what that does and does not prove.
	Synthetic bool `json:"synthetic"`
	// Dict and AllowedDomains configure the tenant-specific detectors, which
	// have no default.
	Dict           []string `json:"dict,omitempty"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
}

// Result is one scored case.
type Result struct {
	ID       string   `json:"id"`
	Expected []string `json:"expected"`
	Produced []string `json:"produced"`
	Missing  []string `json:"missing"`
	Extra    []string `json:"extra"`
	Pass     bool     `json:"pass"`
}

// Counts are the confusion-matrix cells for one detector.
type Counts struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	FN int `json:"fn"`
}

// Score is precision, recall and F1 for one detector.
type Score struct {
	Counts
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

// Summary is what the baseline stores and the gate compares.
type Summary struct {
	Cases int `json:"cases"`
	// Negatives are the cases that expect nothing; FPRate is the fraction of
	// them that produced any finding at all. It is the number that decides
	// whether anyone leaves the detectors switched on.
	Negatives   int              `json:"negatives"`
	FPRate      float64          `json:"fp_rate"`
	PerDetector map[string]Score `json:"per_detector"`
	PerCase     map[string]bool  `json:"per_case"`
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 1
	}
	return round(float64(num) / float64(den))
}

func round(f float64) float64 {
	return float64(int(f*10000+0.5)) / 10000
}

// LoadCases reads every .json file in dir and rejects duplicate ids.
func LoadCases(dir string) ([]Case, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var cases []Case
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var batch []Case
		if err := json.Unmarshal(data, &batch); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		cases = append(cases, batch...)
	}
	seen := map[string]bool{}
	for _, c := range cases {
		if seen[c.ID] {
			return nil, fmt.Errorf("duplicate case id: %s", c.ID)
		}
		seen[c.ID] = true
	}
	return cases, nil
}

// Run scores one case by comparing the set of (detector, type) pairs the
// pipeline produced against the labels.
func Run(ctx context.Context, c Case) (Result, error) {
	dict, err := detect.NewCustomDict(c.Dict, nil)
	if err != nil {
		return Result{}, err
	}
	registry, err := detect.V1(dict, c.AllowedDomains)
	if err != nil {
		return Result{}, err
	}

	req := core.Request{
		Surface: core.Surface(c.Surface),
		Parts:   []core.Part{{Text: c.Text}},
	}
	n, err := normalize.Normalizer{}.Normalize(ctx, req)
	if err != nil {
		return Result{}, err
	}
	findings, err := registry.Detect(ctx, n.Request)
	if err != nil {
		return Result{}, err
	}
	findings = append(findings, n.Findings...)

	produced := map[string]bool{}
	for _, f := range findings {
		produced[Label{Detector: f.Detector, Type: f.Type}.String()] = true
	}
	expected := map[string]bool{}
	for _, l := range c.Expect {
		expected[l.String()] = true
	}

	r := Result{ID: c.ID, Expected: keys(expected), Produced: keys(produced)}
	for l := range expected {
		if !produced[l] {
			r.Missing = append(r.Missing, l)
		}
	}
	for l := range produced {
		if !expected[l] {
			r.Extra = append(r.Extra, l)
		}
	}
	sort.Strings(r.Missing)
	sort.Strings(r.Extra)
	r.Pass = len(r.Missing) == 0 && len(r.Extra) == 0
	return r, nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func detectorOf(label string) string {
	for i := range len(label) {
		if label[i] == '/' {
			return label[:i]
		}
	}
	return label
}

// Summarize builds per-detector scores and the false-positive rate.
func Summarize(cases []Case, results []Result) Summary {
	s := Summary{
		Cases:       len(results),
		PerDetector: map[string]Score{},
		PerCase:     map[string]bool{},
	}
	counts := map[string]*Counts{}
	at := func(detector string) *Counts {
		if counts[detector] == nil {
			counts[detector] = &Counts{}
		}
		return counts[detector]
	}

	expectNothing := map[string]bool{}
	for _, c := range cases {
		expectNothing[c.ID] = len(c.Expect) == 0
	}

	for _, r := range results {
		s.PerCase[r.ID] = r.Pass
		for _, l := range r.Produced {
			if contains(r.Extra, l) {
				at(detectorOf(l)).FP++
			} else {
				at(detectorOf(l)).TP++
			}
		}
		for _, l := range r.Missing {
			at(detectorOf(l)).FN++
		}
		if expectNothing[r.ID] {
			s.Negatives++
			if len(r.Produced) > 0 {
				s.FPRate++
			}
		}
	}

	if s.Negatives > 0 {
		s.FPRate = round(s.FPRate / float64(s.Negatives))
	}
	for name, c := range counts {
		p := ratio(c.TP, c.TP+c.FP)
		rec := ratio(c.TP, c.TP+c.FN)
		f1 := 0.0
		if p+rec > 0 {
			f1 = round(2 * p * rec / (p + rec))
		}
		s.PerDetector[name] = Score{Counts: *c, Precision: p, Recall: rec, F1: f1}
	}
	return s
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Tolerance is the slack the gate allows on a mean score: float noise, not
// room to regress.
const Tolerance = 0.005

// Check compares a summary against a baseline and returns the failures. A case
// that used to pass may not start failing, even if the aggregate improves — a
// mean-only gate hides a fix for one case that breaks another.
func Check(s Summary, baseline Summary) []string {
	var failures []string
	if s.Cases != baseline.Cases {
		failures = append(failures,
			fmt.Sprintf("case count %d != baseline %d — rerun with -write-baseline", s.Cases, baseline.Cases))
	}
	if s.FPRate > baseline.FPRate+Tolerance {
		failures = append(failures,
			fmt.Sprintf("false-positive rate regressed: %.4f > baseline %.4f", s.FPRate, baseline.FPRate))
	}
	for name, want := range baseline.PerDetector {
		got, ok := s.PerDetector[name]
		if !ok {
			failures = append(failures, fmt.Sprintf("detector %s is in the baseline but reported nothing", name))
			continue
		}
		if got.Precision < want.Precision-Tolerance {
			failures = append(failures,
				fmt.Sprintf("%s precision regressed: %.4f < baseline %.4f", name, got.Precision, want.Precision))
		}
		if got.Recall < want.Recall-Tolerance {
			failures = append(failures,
				fmt.Sprintf("%s recall regressed: %.4f < baseline %.4f", name, got.Recall, want.Recall))
		}
	}
	for id, passed := range baseline.PerCase {
		now, ran := s.PerCase[id]
		switch {
		case !ran:
			failures = append(failures, fmt.Sprintf("case %s is in the baseline but was not run", id))
		case passed && !now:
			failures = append(failures, fmt.Sprintf("case %s regressed: it passed in the baseline and now fails", id))
		}
	}
	sort.Strings(failures)
	return failures
}
