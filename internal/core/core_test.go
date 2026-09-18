package core

import "testing"

func TestActionSeverityOrder(t *testing.T) {
	ordered := []Action{ActionAllow, ActionFlag, ActionRedact, ActionBlock}
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1].Severity() >= ordered[i].Severity() {
			t.Fatalf("%s should be less severe than %s", ordered[i-1], ordered[i])
		}
	}
	if Action("nonsense").Severity() >= ActionAllow.Severity() {
		t.Fatal("unknown action must not outrank allow")
	}
}

func TestMostSevere(t *testing.T) {
	tests := []struct {
		name string
		in   []Action
		want Action
	}{
		{"none", nil, ActionAllow},
		{"single", []Action{ActionFlag}, ActionFlag},
		{"block wins", []Action{ActionFlag, ActionBlock, ActionRedact}, ActionBlock},
		{"redact over flag", []Action{ActionFlag, ActionRedact}, ActionRedact},
		{"all allow", []Action{ActionAllow, ActionAllow}, ActionAllow},
		{"unknown ignored", []Action{Action("weird"), ActionFlag}, ActionFlag},
		{"unknown only", []Action{Action("weird")}, ActionAllow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MostSevere(tt.in...); got != tt.want {
				t.Fatalf("MostSevere(%v) = %s, want %s", tt.in, got, tt.want)
			}
		})
	}
}

func TestContentHash(t *testing.T) {
	a := Request{Parts: []Part{{Text: "ab"}, {Text: "c"}}}
	b := Request{Parts: []Part{{Text: "abc"}}}
	if ContentHash(a) == ContentHash(b) {
		t.Error("parts must not be hashed as one flat string")
	}

	// The hash identifies content only: metadata must not change it, or the
	// same payload could not be correlated across surfaces.
	sameContent := Request{Surface: SurfaceOutput, Session: "s2", Parts: a.Parts}
	if ContentHash(a) != ContentHash(sameContent) {
		t.Error("hash must cover part text only")
	}
}
