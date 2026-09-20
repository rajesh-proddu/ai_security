// Package detect holds the detector contract, the registry the pipeline runs,
// and the v1 detector set of DESIGN §3.3: pii (the India pack of decision 4),
// secrets, custom_dict, injection_heuristic and exfil_url. injection_ml is a
// Python sidecar and belongs to Phase 2.
package detect

import (
	"context"
	"fmt"
	"sync"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

// Detector inspects a request and returns findings. Implementations must be
// safe for concurrent use: Phase 1 runs the fast set in parallel.
type Detector interface {
	// Name is one of the Detector* constants; it is copied onto every finding.
	Name() string
	Detect(ctx context.Context, req core.Request) ([]core.Finding, error)
}

// Registry is the set of detectors the pipeline runs. It implements
// core.DetectorSet.
type Registry struct {
	byName map[string]Detector
	order  []Detector
}

// NewRegistry returns a registry holding the given detectors.
func NewRegistry(ds ...Detector) (*Registry, error) {
	r := &Registry{byName: make(map[string]Detector, len(ds))}
	for _, d := range ds {
		if err := r.Register(d); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Register adds a detector. Names must be unique.
func (r *Registry) Register(d Detector) error {
	if r.byName == nil {
		r.byName = map[string]Detector{}
	}
	name := d.Name()
	if _, dup := r.byName[name]; dup {
		return fmt.Errorf("detect: duplicate detector %q", name)
	}
	r.byName[name] = d
	r.order = append(r.order, d)
	return nil
}

// Names lists the registered detectors in registration order.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.order))
	for _, d := range r.order {
		out = append(out, d.Name())
	}
	return out
}

// Detect runs every registered detector in parallel and concatenates their
// findings in registration order, so a verdict does not depend on which
// goroutine finished first. The first error aborts: the pipeline turns it into
// the policy's on_error action.
//
// TODO(phase-2): run the ML set per route rather than with the fast set
// (DESIGN §3.3) — it has its own, larger latency budget.
func (r *Registry) Detect(ctx context.Context, req core.Request) ([]core.Finding, error) {
	switch len(r.order) {
	case 0:
		return nil, nil
	case 1:
		return r.one(ctx, r.order[0], req)
	}

	results := make([][]core.Finding, len(r.order))
	errs := make([]error, len(r.order))
	var wg sync.WaitGroup
	for i, d := range r.order {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = r.one(ctx, d, req)
		}()
	}
	wg.Wait()

	var findings []core.Finding
	for i := range results {
		if errs[i] != nil {
			return nil, errs[i]
		}
		findings = append(findings, results[i]...)
	}
	return findings, nil
}

func (r *Registry) one(ctx context.Context, d Detector, req core.Request) ([]core.Finding, error) {
	got, err := d.Detect(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("detect %s: %w", d.Name(), err)
	}
	for i := range got {
		if got[i].Detector == "" {
			got[i].Detector = d.Name()
		}
	}
	return got, nil
}

var _ core.DetectorSet = (*Registry)(nil)
