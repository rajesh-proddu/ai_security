package agentgateway

import (
	"bytes"
	"encoding/json"
	"sort"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

// Both protocols hand us JSON. The pipeline inspects text, so a payload is
// decoded into generic values, its text fields are collected as core parts, and
// a redact verdict is written back into those same fields before re-encoding.
// Working on decoded strings rather than raw JSON bytes means a redaction can
// never cut through an escape sequence or a quote.

// replacement is what a redacted span becomes.
const replacement = "[REDACTED]"

// textField is one string inside a decoded payload, with a way to replace it.
type textField struct {
	text string
	set  func(string)
}

// decodeJSON decodes with UseNumber, so numbers survive a re-encode unchanged.
func decodeJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// encodeJSON re-encodes without HTML escaping, so `<`, `>` and `&` in text are
// not rewritten as < and friends.
func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// stringLeaves collects every string value under v, visiting object keys in
// sorted order. The order matters: tool-definition pins hash the parts in
// sequence, so an unstable order would report drift on an unchanged definition.
func stringLeaves(v any, out *[]textField) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if s, ok := t[k].(string); ok {
				*out = append(*out, textField{text: s, set: func(n string) { t[k] = n }})
				continue
			}
			stringLeaves(t[k], out)
		}
	case []any:
		for i := range t {
			if s, ok := t[i].(string); ok {
				*out = append(*out, textField{text: s, set: func(n string) { t[i] = n }})
				continue
			}
			stringLeaves(t[i], out)
		}
	}
}

// stringField returns the string at m[key] as a field, if there is one.
func stringField(m map[string]any, key string) (textField, bool) {
	s, ok := m[key].(string)
	if !ok {
		return textField{}, false
	}
	return textField{text: s, set: func(n string) { m[key] = n }}, true
}

// parts turns fields into core parts, one per field, in order.
func parts(fields []textField, role string, trust core.Trust) []core.Part {
	out := make([]core.Part, len(fields))
	for i, f := range fields {
		out[i] = core.Part{Role: role, Text: f.text, Trust: trust}
	}
	return out
}

// redactFields applies a verdict's redaction spans to the fields the parts were
// built from. It reports whether anything changed.
func redactFields(fields []textField, spans []core.Span) bool {
	byPart := map[int][]core.Span{}
	for _, s := range spans {
		if s.Part >= 0 && s.Part < len(fields) {
			byPart[s.Part] = append(byPart[s.Part], s)
		}
	}
	for i, ss := range byPart {
		fields[i].set(redact(fields[i].text, ss))
	}
	return len(byPart) > 0
}

// redact replaces each span of text with the replacement marker. Spans arrive
// merged from the pipeline; they are applied from the end so earlier offsets
// stay valid, and clamped so a bad span cannot panic.
func redact(text string, spans []core.Span) string {
	sort.Slice(spans, func(i, j int) bool { return spans[i].Start > spans[j].Start })
	for _, s := range spans {
		start, end := clamp(s.Start, len(text)), clamp(s.End, len(text))
		if end <= start {
			continue
		}
		text = text[:start] + replacement + text[end:]
	}
	return text
}

func clamp(n, limit int) int {
	return min(max(n, 0), limit)
}
