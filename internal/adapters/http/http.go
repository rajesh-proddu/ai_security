// Package http is the plain-JSON adapter of DESIGN §3.2: for agents with no
// gateway, and the reference mapping between a wire format and core.
package http

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

// InspectPath is the one route this adapter serves.
const InspectPath = "/v1/inspect"

type partDTO struct {
	Role  string `json:"role,omitempty"`
	Text  string `json:"text"`
	Trust string `json:"trust,omitempty"`
}

type requestDTO struct {
	Surface string    `json:"surface"`
	Session string    `json:"session,omitempty"`
	Caller  string    `json:"caller,omitempty"`
	Source  string    `json:"source,omitempty"`
	Parts   []partDTO `json:"parts"`
}

type spanDTO struct {
	Part  int `json:"part"`
	Start int `json:"start"`
	End   int `json:"end"`
}

type findingDTO struct {
	Detector string  `json:"detector"`
	Type     string  `json:"type,omitempty"`
	Score    float64 `json:"score,omitempty"`
	Span     spanDTO `json:"span"`
}

type verdictDTO struct {
	Action        string       `json:"action"`
	Findings      []findingDTO `json:"findings,omitempty"`
	Redactions    []spanDTO    `json:"redactions,omitempty"`
	TaintSession  bool         `json:"taint_session,omitempty"`
	PolicyVersion string       `json:"policy_version,omitempty"`
}

type errorDTO struct {
	Error string `json:"error"`
}

var errUnknownSurface = errors.New("unknown surface")

func (r requestDTO) toCore() (core.Request, error) {
	surface := core.Surface(r.Surface)
	if !surface.Valid() {
		return core.Request{}, errUnknownSurface
	}
	req := core.Request{
		Surface: surface,
		Session: r.Session,
		Caller:  r.Caller,
		Source:  r.Source,
		Parts:   make([]core.Part, 0, len(r.Parts)),
	}
	for _, p := range r.Parts {
		trust := core.Trust(p.Trust)
		if trust == "" {
			trust = core.TrustTrusted
		}
		req.Parts = append(req.Parts, core.Part{Role: p.Role, Text: p.Text, Trust: trust})
	}
	return req, nil
}

func fromCore(v core.Verdict) verdictDTO {
	out := verdictDTO{
		Action:        string(v.Action),
		TaintSession:  v.TaintSession,
		PolicyVersion: v.PolicyVersion,
	}
	for _, f := range v.Findings {
		out.Findings = append(out.Findings, findingDTO{
			Detector: f.Detector,
			Type:     f.Type,
			Score:    f.Score,
			Span:     spanDTO{Part: f.Span.Part, Start: f.Span.Start, End: f.Span.End},
		})
	}
	for _, s := range v.Redactions {
		out.Redactions = append(out.Redactions, spanDTO{Part: s.Part, Start: s.Start, End: s.End})
	}
	return out
}

// Handler serves InspectPath.
type Handler struct {
	Inspector core.Inspector
}

// NewHandler returns a handler over the given inspector.
func NewHandler(in core.Inspector) *Handler { return &Handler{Inspector: in} }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorDTO{Error: "POST only"})
		return
	}
	var dto requestDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		writeJSON(w, http.StatusBadRequest, errorDTO{Error: "malformed JSON body"})
		return
	}
	req, err := dto.toCore()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorDTO{Error: err.Error()})
		return
	}
	verdict, err := h.Inspector.Inspect(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorDTO{Error: "inspection failed"})
		return
	}
	writeJSON(w, http.StatusOK, fromCore(verdict))
}

// Register mounts the adapter on mux.
func (h *Handler) Register(mux *http.ServeMux) { mux.Handle(InspectPath, h) }

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
