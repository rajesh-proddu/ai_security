// Package detect holds the detector contract and the registry the pipeline runs.
// The v1 detectors themselves (DESIGN §3.3) land in Phase 1; this package ships
// the interface, the registry and the vocabulary they share.
package detect

import (
	"context"
	"fmt"

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

// Detect runs every registered detector and concatenates their findings. The
// first error aborts: the pipeline turns it into the policy's on_error action.
//
// TODO(phase-1): run the fast set in parallel to hold the p99 ≤ 20 ms budget
// (DESIGN §2), and run the ML set per route.
func (r *Registry) Detect(ctx context.Context, req core.Request) ([]core.Finding, error) {
	var findings []core.Finding
	for _, d := range r.order {
		got, err := d.Detect(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("detect %s: %w", d.Name(), err)
		}
		for i := range got {
			if got[i].Detector == "" {
				got[i].Detector = d.Name()
			}
		}
		findings = append(findings, got...)
	}
	return findings, nil
}

var _ core.DetectorSet = (*Registry)(nil)
