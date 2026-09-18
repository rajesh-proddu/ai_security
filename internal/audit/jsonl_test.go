package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONLSinkWritesOneLinePerEvent(t *testing.T) {
	var buf bytes.Buffer
	s := NewJSONLSink(&buf)
	ctx := context.Background()

	for _, e := range []Event{
		{Time: "2026-01-01T00:00:00Z", Surface: "input", Action: "allow"},
		{Time: "2026-01-01T00:00:01Z", Surface: "output", Action: "redact"},
	} {
		if err := s.Write(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	for _, line := range lines {
		var got map[string]any
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("line %q is not JSON: %v", line, err)
		}
	}
}

// DESIGN §3.7: metadata and hashes only. The event type must have no field that
// could carry a prompt or response body.
func TestEventCarriesNoContent(t *testing.T) {
	var buf bytes.Buffer
	s := NewJSONLSink(&buf)
	err := s.Write(context.Background(), Event{
		Time:        "2026-01-01T00:00:00Z",
		Surface:     "tool_result",
		Action:      "flag",
		SessionID:   "s1",
		ContentHash: "deadbeef",
		Findings:    []Finding{{Detector: "pii", Type: "aadhaar", Part: 0, Start: 3, End: 15}},
	})
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"text", "body", "content", "prompt", "response", "parts"} {
		if _, present := got[banned]; present {
			t.Errorf("audit event must not carry %q", banned)
		}
	}
	if got["content_hash"] != "deadbeef" {
		t.Errorf("content_hash = %v", got["content_hash"])
	}
}
