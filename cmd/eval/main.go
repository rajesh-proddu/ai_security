// Command eval scores the detectors against the labelled corpus in evals/.
//
//	go run ./cmd/eval                                  # score and print
//	go run ./cmd/eval -check evals/baseline.json       # what CI runs
//	go run ./cmd/eval -write-baseline evals/baseline.json
//
// The corpus is labelled `synthetic`: every case was written by hand to
// exercise a detector, not observed in traffic. That means the scores below
// prove that a known evasion still gets caught and that a change did not
// silently break a detector. They do **not** estimate how the detectors perform
// on real prompts — synthetic positives are the ones we already thought of, and
// synthetic negatives are far cleaner than production text. Treat the numbers
// as a regression gate, not as detection quality. DESIGN §5 makes real labelled
// data an opt-in, later-phase input, and the public injection benchmarks of
// ROADMAP Phase 2 are what will give a comparable number.
//
// The subset is `fast`: the DESIGN §3.3 detectors that run in-process.
// injection_ml is a Phase 2 sidecar and is not scored here.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
)

// Subset names the detector set these scores describe, so a baseline written
// for the fast path is never compared against one that includes the ML model.
const Subset = "fast"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "eval:", err)
		os.Exit(1)
	}
}

func run() error {
	casesDir := flag.String("cases", "evals/cases", "directory of labelled case files")
	check := flag.String("check", "", "fail if scores regress below this baseline")
	write := flag.String("write-baseline", "", "write the current scores as the baseline")
	report := flag.String("report", "", "write per-case results as JSON")
	flag.Parse()

	cases, err := LoadCases(*casesDir)
	if err != nil {
		return err
	}
	if len(cases) == 0 {
		return fmt.Errorf("no cases in %s", *casesDir)
	}

	ctx := context.Background()
	results := make([]Result, 0, len(cases))
	for _, c := range cases {
		r, err := Run(ctx, c)
		if err != nil {
			return fmt.Errorf("case %s: %w", c.ID, err)
		}
		results = append(results, r)
	}
	summary := Summarize(cases, results)

	for _, r := range results {
		status := "pass"
		if !r.Pass {
			status = "FAIL"
		}
		fmt.Printf("%-44s %s", r.ID, status)
		if len(r.Missing) > 0 {
			fmt.Printf("  missing=%v", r.Missing)
		}
		if len(r.Extra) > 0 {
			fmt.Printf("  extra=%v", r.Extra)
		}
		fmt.Println()
	}

	names := make([]string, 0, len(summary.PerDetector))
	for name := range summary.PerDetector {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Printf("\n[%s] cases=%d negatives=%d fp_rate=%.4f\n", Subset, summary.Cases, summary.Negatives, summary.FPRate)
	for _, name := range names {
		s := summary.PerDetector[name]
		fmt.Printf("  %-22s precision=%.4f recall=%.4f f1=%.4f  (tp=%d fp=%d fn=%d)\n",
			name, s.Precision, s.Recall, s.F1, s.TP, s.FP, s.FN)
	}

	if *report != "" {
		if err := writeJSON(*report, map[string]any{
			"subset": Subset, "summary": summary, "results": results,
		}); err != nil {
			return err
		}
	}

	if *write != "" {
		all := map[string]Summary{}
		if data, err := os.ReadFile(*write); err == nil {
			if err := json.Unmarshal(data, &all); err != nil {
				return err
			}
		}
		all[Subset] = summary
		if err := writeJSON(*write, all); err != nil {
			return err
		}
		fmt.Printf("wrote baseline [%s] to %s\n", Subset, *write)
	}

	if *check != "" {
		data, err := os.ReadFile(*check)
		if err != nil {
			return err
		}
		var all map[string]Summary
		if err := json.Unmarshal(data, &all); err != nil {
			return err
		}
		baseline, ok := all[Subset]
		if !ok {
			return fmt.Errorf("no baseline for [%s] in %s", Subset, *check)
		}
		failures := Check(summary, baseline)
		for _, f := range failures {
			fmt.Fprintln(os.Stderr, "FAIL:", f)
		}
		if len(failures) > 0 {
			return fmt.Errorf("%d eval gate failure(s)", len(failures))
		}
		fmt.Println("eval gate passed")
	}
	return nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
