package detect

import (
	"context"
	"errors"
	"testing"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

type stub struct {
	name     string
	findings []core.Finding
	err      error
}

func (s stub) Name() string { return s.name }

func (s stub) Detect(context.Context, core.Request) ([]core.Finding, error) {
	return s.findings, s.err
}

func TestRegistryDetect(t *testing.T) {
	boom := errors.New("boom")

	tests := []struct {
		name         string
		detectors    []Detector
		wantFindings []core.Finding
		wantErr      bool
	}{
		{
			name:      "no detectors",
			detectors: nil,
		},
		{
			name:      "noop finds nothing",
			detectors: []Detector{Noop{}},
		},
		{
			name: "findings are concatenated and stamped with the detector name",
			detectors: []Detector{
				stub{name: DetectorPII, findings: []core.Finding{{Type: TypeAadhaar}}},
				stub{name: DetectorSecrets, findings: []core.Finding{{Type: TypeAWSKey}}},
			},
			wantFindings: []core.Finding{
				{Detector: DetectorPII, Type: TypeAadhaar},
				{Detector: DetectorSecrets, Type: TypeAWSKey},
			},
		},
		{
			name: "an explicit detector name is kept",
			detectors: []Detector{
				stub{name: DetectorPII, findings: []core.Finding{{Detector: "pii_ner", Type: TypeEmail}}},
			},
			wantFindings: []core.Finding{{Detector: "pii_ner", Type: TypeEmail}},
		},
		{
			name:      "a detector error aborts",
			detectors: []Detector{stub{name: DetectorExfilURL, err: boom}},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewRegistry(tt.detectors...)
			if err != nil {
				t.Fatalf("NewRegistry: %v", err)
			}
			got, err := r.Detect(context.Background(), core.Request{Surface: core.SurfaceInput})
			if tt.wantErr {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				if !errors.Is(err, boom) {
					t.Fatalf("error must wrap the detector's: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if len(got) != len(tt.wantFindings) {
				t.Fatalf("findings = %+v, want %+v", got, tt.wantFindings)
			}
			for i := range got {
				if got[i] != tt.wantFindings[i] {
					t.Errorf("finding %d = %+v, want %+v", i, got[i], tt.wantFindings[i])
				}
			}
		})
	}
}

func TestRegistryRejectsDuplicateNames(t *testing.T) {
	if _, err := NewRegistry(Noop{}, Noop{}); err == nil {
		t.Fatal("want a duplicate-name error")
	}
}

func TestRegistryNamesKeepsRegistrationOrder(t *testing.T) {
	r, err := NewRegistry(stub{name: DetectorPII}, stub{name: DetectorSecrets}, Noop{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{DetectorPII, DetectorSecrets, "noop"}
	got := r.Names()
	if len(got) != len(want) {
		t.Fatalf("names = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("names = %v, want %v", got, want)
		}
	}
}
