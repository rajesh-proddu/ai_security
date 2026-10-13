package agentgateway

import (
	"bytes"
	"context"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

// Streaming output (DESIGN §3.5). A streamed (SSE) response is held back as a
// sliding window: text is inspected as it arrives, and only text that can no
// longer be part of a finding is released, with any redactions applied.
//
// agentgateway accepts held chunks with no reply and a later reply carrying
// several chunks' bytes (checked live), so release points are ours to choose.
//
// Release rules, per text stream (one per chat choice):
//   - Text inside the last windowSize characters is held, so a finding that
//     straddles the release point is seen whole on a later round.
//   - The trailing unbroken run of non-space characters is neither inspected
//     nor released before end of stream: a key or digit run cut short can match
//     a pattern the complete token would not (`{16}\b`, a Luhn hit on a prefix),
//     and keys have no upper length. A run longer than maxRun is inspected and
//     partly released anyway, because model output can legitimately contain
//     long unbroken text (minified JSON).
//   - A finding that crosses the release point moves it back to the finding's
//     start.
//   - Only whole SSE events are released, in order. Events that carry no text
//     (finish_reason, usage, [DONE]) wait behind the text before them. An event
//     that is not changed is released as its original bytes.
//
// Chat completions chunks are windowed this way. Any other SSE format
// (Anthropic messages, OpenAI responses, ...) is held to end of stream and
// inspected whole: those formats repeat the full text in their final events,
// so windowing only the deltas would leak it.
//
// Known limits: a pattern with an unbounded part (a long HTML comment or
// markdown image alt text, an injection phrase padded with whitespace) longer
// than the window can straddle a release point. Each inspection is one audit
// event, so a finding in the held tail can appear in two consecutive events.
// Streamed tool_calls arguments are not inspected.
const (
	windowSize = 256  // characters held back; covers the bounded v1 patterns
	evalEvery  = 64   // inspect after this many new characters, not on every chunk
	maxRun     = 4096 // longest unbroken run held before releasing part of it
	runKeep    = 512  // characters of an over-long run that stay held
)

// sseEvent is one server-sent event, as received.
type sseEvent struct {
	raw    []byte // original bytes, including the blank-line terminator
	lines  []string
	data   any // the decoded JSON of the data lines, if any
	fields []streamField
	dirty  bool // a field was changed; re-encode on release
}

// streamField is one piece of text in an event, in a text stream.
type streamField struct {
	key string // the text stream: "c0", "c1", ... per chat choice; "" otherwise
	ev  *sseEvent
	textField
}

// bytes returns what to send for the event: the original bytes, or the event
// rebuilt with its data re-encoded if a field changed.
func (e *sseEvent) bytes() []byte {
	if !e.dirty || e.data == nil {
		return e.raw
	}
	b, err := encodeJSON(e.data)
	if err != nil {
		return e.raw
	}
	var out bytes.Buffer
	wroteData := false
	for _, l := range e.lines {
		if strings.HasPrefix(l, "data:") {
			if !wroteData {
				out.WriteString("data: ")
				out.Write(b)
				out.WriteString("\n")
				wroteData = true
			}
			continue
		}
		out.WriteString(l)
		out.WriteString("\n")
	}
	out.WriteString("\n")
	return out.Bytes()
}

// streamWindow is the state of one streamed response.
type streamWindow struct {
	inspect func(ctx context.Context, text string) (core.Verdict, error)

	pending  []byte // bytes not yet framed into an event
	held     []*sseEvent
	buffered bool // not chat completions: hold everything to end of stream
	format   bool // the format has been decided
	lastEval map[string]int
	blocked  bool
}

func newStreamWindow(inspect func(context.Context, string) (core.Verdict, error)) *streamWindow {
	return &streamWindow{inspect: inspect, lastEval: map[string]int{}}
}

// blockedStream is what the client receives when a stream is blocked: an error
// event in the OpenAI shape, then [DONE].
var blockedStream = []byte("data: " + blockBody + "\n\ndata: [DONE]\n\n")

// chunk takes one response body chunk and returns the bytes to release now,
// whether to reply at all, and whether this is the end of the stream for the
// client.
func (w *streamWindow) chunk(ctx context.Context, b []byte, eos bool) (out []byte, reply, end bool, err error) {
	if w.blocked {
		// After a block the gateway still sends the rest of the upstream
		// stream; each chunk gets an empty, final reply.
		return nil, true, true, nil
	}
	w.pending = append(w.pending, b...)
	for {
		ev, rest, ok := nextEvent(w.pending)
		if !ok {
			break
		}
		w.pending = rest
		w.add(ev)
	}
	if eos && len(w.pending) > 0 {
		// An unterminated last event: release it as it came, after inspection.
		w.add(parseEvent(w.pending))
		w.pending = nil
	}

	release, blocked, err := w.evaluate(ctx, eos)
	if err != nil {
		return nil, false, false, err
	}
	if blocked {
		w.blocked = true
		w.held = nil
		return blockedStream, true, true, nil
	}
	if len(release) == 0 && !eos {
		return nil, false, false, nil
	}
	return release, true, eos, nil
}

func (w *streamWindow) add(ev *sseEvent) {
	if !w.format && ev.data != nil {
		w.format = true
		w.buffered = !isChatChunk(ev.data)
	}
	if ev.data != nil {
		if w.buffered {
			var fs []textField
			textLeaves(ev.data, &fs)
			for _, f := range fs {
				ev.fields = append(ev.fields, streamField{key: "", textField: f})
			}
		} else {
			ev.fields = chatChunkFields(ev.data)
		}
		for i := range ev.fields {
			ev.fields[i].ev = ev
		}
	}
	w.held = append(w.held, ev)
}

// textStream is one key's held text, with where each field sits in it.
type textStream struct {
	text   strings.Builder
	fields []*streamField
	starts []int
	// ends are the fields' end offsets before any redaction this round.
	// Release decisions use them: a redaction shortens a field, and judging
	// it by its new length would release an event that still reaches past
	// the release point.
	ends []int
}

func (w *streamWindow) streams() map[string]*textStream {
	out := map[string]*textStream{}
	for _, ev := range w.held {
		for i := range ev.fields {
			f := &ev.fields[i]
			s := out[f.key]
			if s == nil {
				s = &textStream{}
				out[f.key] = s
			}
			s.fields = append(s.fields, f)
			s.starts = append(s.starts, s.text.Len())
			s.text.WriteString(f.text)
			s.ends = append(s.ends, s.text.Len())
		}
	}
	return out
}

// evaluate inspects what is due and returns the bytes that can be released.
func (w *streamWindow) evaluate(ctx context.Context, final bool) ([]byte, bool, error) {
	if w.buffered && !final {
		return nil, false, nil
	}
	streams := w.streams()
	keys := make([]string, 0, len(streams))
	for k := range streams {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	releaseTo := map[string]int{} // per key: text offset up to which events may go
	for _, k := range keys {
		s := streams[k]
		text := s.text.String()
		scanEnd := len(text)
		if !final {
			scanEnd = trailingRunStart(text)
			if len(text)-scanEnd > maxRun {
				scanEnd = runeStart(text, len(text)-runKeep)
			}
			if scanEnd-w.lastEval[k] < evalEvery || scanEnd <= windowSize {
				releaseTo[k] = 0
				continue
			}
		}
		v, err := w.inspect(ctx, text[:scanEnd])
		if err != nil {
			return nil, false, err
		}
		p := scanEnd
		if !final {
			p = max(scanEnd-windowSize, 0)
		}
		// Merged redaction spans can cover two adjacent findings, so they are
		// checked as well as the findings themselves.
		spans := append([]core.Span(nil), v.Redactions...)
		for _, f := range v.Findings {
			spans = append(spans, f.Span)
		}
		p = backOff(p, spans)
		if v.Action == core.ActionBlock {
			// A block acts on the whole verdict, and a pattern with internal
			// spaces can match a prefix of something longer that is still
			// arriving (a spaced card held up to its third group has an
			// Aadhaar-shaped run). So before end of stream, the block must
			// hold for the settled text alone: up to the release point, moved
			// back to a word boundary so no token is cut. Anything that
			// crossed the release point was backed off above, so the settled
			// text is complete. If it does not block, keep holding: nothing
			// past p is released, and a later round or the final inspection
			// decides.
			if final {
				return nil, true, nil
			}
			if q := wordStart(text, p); q > 0 {
				sv, err := w.inspect(ctx, text[:q])
				if err != nil {
					return nil, false, err
				}
				if sv.Action == core.ActionBlock {
					return nil, true, nil
				}
			}
			releaseTo[k] = 0
			continue
		}
		if v.Action == core.ActionRedact {
			var spans []core.Span
			for _, r := range v.Redactions {
				if r.End <= p {
					spans = append(spans, r)
				}
			}
			s.redact(spans)
		}
		releaseTo[k] = p
		w.lastEval[k] = scanEnd
	}
	return w.release(streams, releaseTo, final), false, nil
}

// wordStart moves p back to the start of the word it falls in, so text[:p]
// does not end in a cut token.
func wordStart(text string, p int) int {
	if p <= 0 || p >= len(text) || unicode.IsSpace(rune(text[p-1])) || unicode.IsSpace(rune(text[p])) {
		return p
	}
	return trailingRunStart(text[:p])
}

// backOff moves a release point back to the start of any span that crosses it.
func backOff(p int, spans []core.Span) int {
	for moved := true; moved; {
		moved = false
		for _, s := range spans {
			if s.Start < p && s.End > p {
				p = s.Start
				moved = true
			}
		}
	}
	return p
}

// release pops held events from the front while every text field in them
// ends at or before its stream's release point.
func (w *streamWindow) release(streams map[string]*textStream, releaseTo map[string]int, final bool) []byte {
	end := map[*streamField]int{}
	for _, s := range streams {
		for i, f := range s.fields {
			end[f] = s.ends[i]
		}
	}
	var out []byte
	n := 0
	released := map[string]int{}
	for _, ev := range w.held {
		if !final {
			ok := true
			for i := range ev.fields {
				f := &ev.fields[i]
				if end[f] > releaseTo[f.key] {
					ok = false
					break
				}
			}
			if !ok {
				break
			}
		}
		for i := range ev.fields {
			f := &ev.fields[i]
			released[f.key] = max(released[f.key], end[f])
		}
		out = append(out, ev.bytes()...)
		n++
	}
	w.held = w.held[n:]
	// Offsets are into the held text, so the last inspection point moves back
	// by what was released.
	for k, r := range released {
		w.lastEval[k] = max(w.lastEval[k]-r, 0)
	}
	return out
}

// redact applies spans (offsets into the stream's text) to the fields they
// cover. The marker goes into the field where a span starts; the covered text
// in later fields is removed, so every event stays valid on its own.
func (s *textStream) redact(spans []core.Span) {
	sort.Slice(spans, func(i, j int) bool { return spans[i].Start > spans[j].Start })
	for _, sp := range spans {
		for i, f := range s.fields {
			off := s.starts[i]
			ls, le := max(sp.Start, off)-off, min(sp.End, off+len(f.text))-off
			if le <= ls || ls > len(f.text) {
				continue
			}
			marker := ""
			if sp.Start >= off && sp.Start < off+len(f.text) {
				marker = replacement
			}
			f.text = f.text[:ls] + marker + f.text[le:]
			f.set(f.text)
			f.ev.dirty = true
		}
	}
}

// trailingRunStart returns where the text's final unbroken run of non-space
// characters begins (len(text) if it ends in whitespace).
func trailingRunStart(text string) int {
	i := strings.LastIndexFunc(text, unicode.IsSpace)
	if i < 0 {
		return 0
	}
	_, size := utf8.DecodeRuneInString(text[i:])
	return i + size
}

// runeStart moves i back to the start of the rune it falls in.
func runeStart(text string, i int) int {
	for i > 0 && i < len(text) && !utf8.RuneStart(text[i]) {
		i--
	}
	return i
}

// nextEvent splits the first complete event (terminated by a blank line) off
// b. Line endings may be \n or \r\n.
func nextEvent(b []byte) (*sseEvent, []byte, bool) {
	start := 0
	for {
		i := bytes.IndexByte(b[start:], '\n')
		if i < 0 {
			return nil, b, false
		}
		line := bytes.TrimSuffix(b[start:start+i], []byte("\r"))
		next := start + i + 1
		if len(line) == 0 {
			return parseEvent(b[:next]), b[next:], true
		}
		start = next
	}
}

// parseEvent reads an event's lines and decodes its data as JSON, if it is.
func parseEvent(raw []byte) *sseEvent {
	ev := &sseEvent{raw: append([]byte(nil), raw...)}
	var data []string
	for _, l := range strings.Split(strings.TrimRight(string(raw), "\r\n"), "\n") {
		l = strings.TrimSuffix(l, "\r")
		ev.lines = append(ev.lines, l)
		if d, ok := strings.CutPrefix(l, "data:"); ok {
			data = append(data, strings.TrimPrefix(d, " "))
		}
	}
	if len(data) == 0 {
		return ev
	}
	payload := strings.Join(data, "\n")
	if payload == "[DONE]" {
		return ev
	}
	if v, err := decodeJSON([]byte(payload)); err == nil {
		ev.data = v
	}
	return ev
}

func isChatChunk(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	if obj, _ := m["object"].(string); obj == "chat.completion.chunk" {
		return true
	}
	_, hasChoices := m["choices"]
	return hasChoices
}

// chatChunkFields returns choices[].delta.content, one text stream per choice
// index.
func chatChunkFields(v any) []streamField {
	m, _ := v.(map[string]any)
	choices, _ := m["choices"].([]any)
	var out []streamField
	for _, c := range choices {
		choice, _ := c.(map[string]any)
		delta, _ := choice["delta"].(map[string]any)
		f, ok := stringField(delta, "content")
		if !ok {
			continue
		}
		idx := "0"
		if n, ok := choice["index"]; ok {
			if s, ok := n.(interface{ String() string }); ok {
				idx = s.String()
			}
		}
		out = append(out, streamField{key: "c" + idx, textField: f})
	}
	return out
}
