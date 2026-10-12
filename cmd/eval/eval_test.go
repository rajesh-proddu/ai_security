package main

import (
	"context"
	"testing"
)

func TestSummarize(t *testing.T) {
	cases := []Case{
		{ID: "pos", Expect: []Label{{Detector: "pii", Type: "card"}}},
		{ID: "neg"},
		{ID: "miss", Expect: []Label{{Detector: "pii", Type: "aadhaar"}}},
	}
	results := []Result{
		{ID: "pos", Produced: []string{"pii/card"}, Pass: true},
		{ID: "neg", Produced: []string{"secrets/high_entropy"}, Extra: []string{"secrets/high_entropy"}},
		{ID: "miss", Missing: []string{"pii/aadhaar"}},
	}
	got := Summarize(cases, results)

	if got.Cases != 3 || got.Negatives != 1 {
		t.Fatalf("cases=%d negatives=%d", got.Cases, got.Negatives)
	}
	if got.FPRate != 1 {
		t.Errorf("fp_rate = %v, want 1 (the only negative produced a finding)", got.FPRate)
	}
	pii := got.PerDetector["pii"]
	if pii.TP != 1 || pii.FN != 1 || pii.FP != 0 {
		t.Errorf("pii counts = %+v", pii.Counts)
	}
	if pii.Precision != 1 || pii.Recall != 0.5 {
		t.Errorf("pii precision=%v recall=%v, want 1 and 0.5", pii.Precision, pii.Recall)
	}
	secrets := got.PerDetector["secrets"]
	if secrets.FP != 1 || secrets.Precision != 0 {
		t.Errorf("secrets = %+v precision=%v", secrets.Counts, secrets.Precision)
	}
	if got.PerCase["pos"] != true || got.PerCase["neg"] != false {
		t.Errorf("per-case = %v", got.PerCase)
	}
}

func TestCheck(t *testing.T) {
	baseline := Summary{
		Cases:       2,
		FPRate:      0.1,
		PerDetector: map[string]Score{"pii": {Precision: 0.9, Recall: 0.8}},
		PerCase:     map[string]bool{"a": true, "b": false},
	}
	tests := []struct {
		name string
		got  Summary
		want int // number of failures
	}{
		{
			name: "identical passes",
			got:  baseline,
		},
		{
			name: "improvement passes",
			got: Summary{Cases: 2, FPRate: 0.0,
				PerDetector: map[string]Score{"pii": {Precision: 1, Recall: 1}},
				PerCase:     map[string]bool{"a": true, "b": true}},
		},
		{
			name: "precision regression fails",
			got: Summary{Cases: 2, FPRate: 0.1,
				PerDetector: map[string]Score{"pii": {Precision: 0.5, Recall: 0.8}},
				PerCase:     map[string]bool{"a": true, "b": false}},
			want: 1,
		},
		{
			name: "recall regression fails",
			got: Summary{Cases: 2, FPRate: 0.1,
				PerDetector: map[string]Score{"pii": {Precision: 0.9, Recall: 0.1}},
				PerCase:     map[string]bool{"a": true, "b": false}},
			want: 1,
		},
		{
			name: "more false positives fails",
			got: Summary{Cases: 2, FPRate: 0.5,
				PerDetector: map[string]Score{"pii": {Precision: 0.9, Recall: 0.8}},
				PerCase:     map[string]bool{"a": true, "b": false}},
			want: 1,
		},
		{
			name: "a case count change fails",
			got: Summary{Cases: 3, FPRate: 0.1,
				PerDetector: map[string]Score{"pii": {Precision: 0.9, Recall: 0.8}},
				PerCase:     map[string]bool{"a": true, "b": false}},
			want: 1,
		},
		{
			// The gate the mean would hide: aggregate scores are unchanged but
			// a case that used to pass now fails.
			name: "a passing case regressing fails even when the aggregate holds",
			got: Summary{Cases: 2, FPRate: 0.1,
				PerDetector: map[string]Score{"pii": {Precision: 0.9, Recall: 0.8}},
				PerCase:     map[string]bool{"a": false, "b": false}},
			want: 1,
		},
		{
			name: "a missing case fails",
			got: Summary{Cases: 2, FPRate: 0.1,
				PerDetector: map[string]Score{"pii": {Precision: 0.9, Recall: 0.8}},
				PerCase:     map[string]bool{"b": false}},
			want: 1,
		},
		{
			name: "a detector going silent fails",
			got: Summary{Cases: 2, FPRate: 0.1,
				PerDetector: map[string]Score{},
				PerCase:     map[string]bool{"a": true, "b": false}},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Check(tt.got, baseline)
			if len(got) != tt.want {
				t.Fatalf("failures = %v, want %d", got, tt.want)
			}
		})
	}
}

// The corpus must stay loadable, uniquely identified and honestly labelled.
func TestCorpusIsWellFormed(t *testing.T) {
	cases, err := LoadCases("../../evals/cases")
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	negatives := 0
	for _, c := range cases {
		if c.ID == "" || c.Text == "" || c.Surface == "" {
			t.Errorf("case %q is incomplete", c.ID)
		}
		if !c.Synthetic {
			t.Errorf("case %q is not marked synthetic; every case in this repo is", c.ID)
		}
		if len(c.Expect) == 0 {
			negatives++
		}
	}
	// Without negatives the false-positive rate is unmeasurable, and a
	// detector that fires on everything would score perfectly.
	if negatives < len(cases)/5 {
		t.Errorf("only %d negative cases out of %d; the corpus cannot measure false positives", negatives, len(cases))
	}
}

func TestRunScoresACase(t *testing.T) {
	got, err := Run(context.Background(), Case{
		ID:      "t",
		Surface: "output",
		Text:    "card 4111111111111111",
		Expect:  []Label{{Detector: "pii", Type: "card"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Pass {
		t.Fatalf("result = %+v", got)
	}
}
