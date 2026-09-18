package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

type stubInspector struct {
	saw     core.Request
	verdict core.Verdict
}

func (s *stubInspector) Inspect(_ context.Context, req core.Request) (core.Verdict, error) {
	s.saw = req
	return s.verdict, nil
}

func TestHandlerRequests(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		body       string
		wantStatus int
	}{
		{"happy path", http.MethodPost, `{"surface":"input","parts":[{"role":"user","text":"hi"}]}`, http.StatusOK},
		{"GET is rejected", http.MethodGet, "", http.StatusMethodNotAllowed},
		{"malformed JSON", http.MethodPost, `{`, http.StatusBadRequest},
		{"unknown surface", http.MethodPost, `{"surface":"telepathy","parts":[]}`, http.StatusBadRequest},
		{"empty surface", http.MethodPost, `{"parts":[]}`, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHandler(&stubInspector{verdict: core.Verdict{Action: core.ActionAllow}})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tt.method, InspectPath, strings.NewReader(tt.body)))
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("content-type = %q", ct)
			}
		})
	}
}

func TestHandlerMapsBothWays(t *testing.T) {
	in := &stubInspector{verdict: core.Verdict{
		Action:        core.ActionRedact,
		Findings:      []core.Finding{{Detector: "pii", Type: "aadhaar", Score: 1, Span: core.Span{Part: 0, Start: 3, End: 15}}},
		Redactions:    []core.Span{{Part: 0, Start: 3, End: 15}},
		TaintSession:  true,
		PolicyVersion: "abc123",
	}}
	h := NewHandler(in)

	body := `{"surface":"tool_result","session":"s1","caller":"reco","source":"es",
	          "parts":[{"role":"tool","text":"x","trust":"untrusted"},{"role":"user","text":"y"}]}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, InspectPath, strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}

	// request → core
	if in.saw.Surface != core.SurfaceToolResult || in.saw.Session != "s1" ||
		in.saw.Caller != "reco" || in.saw.Source != "es" {
		t.Errorf("request not mapped: %+v", in.saw)
	}
	if len(in.saw.Parts) != 2 {
		t.Fatalf("parts = %d, want 2", len(in.saw.Parts))
	}
	if in.saw.Parts[0].Trust != core.TrustUntrusted {
		t.Errorf("part 0 trust = %q", in.saw.Parts[0].Trust)
	}
	if in.saw.Parts[1].Trust != core.TrustTrusted {
		t.Errorf("an unset trust must default to trusted, got %q", in.saw.Parts[1].Trust)
	}

	// core → response
	var got verdictDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Action != string(core.ActionRedact) || got.PolicyVersion != "abc123" || !got.TaintSession {
		t.Errorf("verdict not mapped: %+v", got)
	}
	if len(got.Redactions) != 1 || got.Redactions[0] != (spanDTO{Part: 0, Start: 3, End: 15}) {
		t.Errorf("redactions = %+v", got.Redactions)
	}
	if len(got.Findings) != 1 || got.Findings[0].Detector != "pii" {
		t.Errorf("findings = %+v", got.Findings)
	}
}
