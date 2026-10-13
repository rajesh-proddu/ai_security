package agentgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand"
	"strconv"
	"strings"
	"testing"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

const streamPolicy = `
tenant: test
defaults: { on_error: fail_closed }
rules:
  - surface: [output]
    when: { detector: pii, type_in: [card] }
    action: redact
  - surface: [output]
    when: { detector: secrets, type_in: [aws_key] }
    action: block
`

func outputInspector(t *testing.T, policyYAML string) func(context.Context, string) (core.Verdict, error) {
	t.Helper()
	p := pipeline(t, policyYAML)
	return func(ctx context.Context, text string) (core.Verdict, error) {
		return p.Inspect(ctx, core.Request{Surface: core.SurfaceOutput, Session: "s1",
			Parts: []core.Part{{Role: "assistant", Text: text, Trust: core.TrustTrusted}}})
	}
}

// chatSSE builds a chat completions stream with one delta event per piece,
// then a finish event and [DONE].
func chatSSE(pieces ...string) []byte {
	var b bytes.Buffer
	for _, p := range pieces {
		ev, _ := json.Marshal(map[string]any{"id": "c1", "object": "chat.completion.chunk", "model": "m",
			"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": p}, "finish_reason": nil}}})
		b.WriteString("data: " + string(ev) + "\n\n")
	}
	b.WriteString(`data: {"id":"c1","object":"chat.completion.chunk","model":"m","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n")
	b.WriteString("data: [DONE]\n\n")
	return b.Bytes()
}

// feed sends chunks through a fresh window and returns everything released,
// whether the stream was blocked, and the released bytes per reply.
func feed(t *testing.T, inspect func(context.Context, string) (core.Verdict, error), chunks [][]byte) ([]byte, bool, [][]byte) {
	t.Helper()
	w := newStreamWindow(inspect)
	var out []byte
	var replies [][]byte
	blocked := false
	for i, c := range chunks {
		b, reply, end, err := w.chunk(context.Background(), c, i == len(chunks)-1)
		if err != nil {
			t.Fatal(err)
		}
		if reply {
			replies = append(replies, b)
			out = append(out, b...)
		}
		if end && i < len(chunks)-1 {
			blocked = true
		}
	}
	return out, blocked || w.blocked, replies
}

// deltaText concatenates the delta content of a released chat stream, and
// checks every event is valid SSE carrying valid JSON.
func deltaText(t *testing.T, sse []byte) string {
	t.Helper()
	var text strings.Builder
	rest := sse
	for len(rest) > 0 {
		ev, r, ok := nextEvent(rest)
		if !ok {
			t.Fatalf("released bytes end in a partial event: %q", rest)
		}
		rest = r
		for _, l := range ev.lines {
			d, ok := strings.CutPrefix(l, "data: ")
			if !ok || d == "[DONE]" {
				continue
			}
			var m struct {
				Choices []struct {
					Delta struct {
						Content string `json:"content"`
					} `json:"delta"`
				} `json:"choices"`
			}
			if err := json.Unmarshal([]byte(d), &m); err != nil {
				t.Fatalf("released event is not JSON: %v: %s", err, d)
			}
			for _, c := range m.Choices {
				text.WriteString(c.Delta.Content)
			}
		}
	}
	return text.String()
}

func split(b []byte, at ...int) [][]byte {
	var out [][]byte
	prev := 0
	for _, a := range at {
		out = append(out, b[prev:a])
		prev = a
	}
	return append(out, b[prev:])
}

var prose = strings.Repeat("The biryani class covers rice, spices and timing in detail. ", 8)

// The test that matters: wherever the gateway cuts the stream into chunks, the
// client receives exactly the same bytes.
func TestStreamChunkBoundaryInvariance(t *testing.T) {
	inspect := outputInspector(t, streamPolicy)
	src := chatSSE(words(prose + "card 4111 1111 1111 1111 on file. " + prose + "end.")...)
	whole, _, _ := feed(t, inspect, [][]byte{src})
	want := prose + "card " + replacement + " on file. " + prose + "end."
	if got := deltaText(t, whole); got != want {
		t.Fatalf("one-chunk stream: %s", firstDiff(got, want))
	}
	// Every offset near the card, where a split can change what is found; every
	// eleventh elsewhere, where it can only change framing. (Every offset
	// everywhere takes minutes under -race.)
	card := bytes.Index(src, []byte("4111"))
	for i := 1; i < len(src); i++ {
		if (i < card-300 || i > card+300) && i%11 != 0 {
			continue
		}
		got, blocked, _ := feed(t, inspect, split(src, i))
		if blocked || !bytes.Equal(got, whole) {
			t.Fatalf("split at byte %d: output differs (blocked=%v)", i, blocked)
		}
	}
	rng := rand.New(rand.NewSource(1))
	for range 200 {
		var cuts []int
		for c := rng.Intn(40); c < len(src); c += 1 + rng.Intn(60) {
			cuts = append(cuts, c)
		}
		got, _, _ := feed(t, inspect, split(src, cuts...))
		if !bytes.Equal(got, whole) {
			t.Fatalf("random chunking %v: output differs", cuts)
		}
	}
}

// For random text, random card placement and random chunking, the client
// receives what inspecting the whole text at once would produce: windowing
// changes when text is released, never what is found. (The oracle is the
// pipeline itself, so a detector limitation, e.g. two cards one space apart,
// shows up on both sides.)
func TestStreamRedactionProperty(t *testing.T) {
	inspect := outputInspector(t, streamPolicy)
	vocab := strings.Fields(prose)
	cards := []string{"4111 1111 1111 1111", "5500 0000 0000 0004", "4012888888881881"}
	for trial := range 300 {
		rng := rand.New(rand.NewSource(int64(trial)))
		var src []string
		lastWasCard := false
		for i := range 40 + rng.Intn(120) {
			w := vocab[rng.Intn(len(vocab))]
			// Never two cards side by side: the card detector misses adjacent
			// cards, and which ones it finds depends on where its scan starts,
			// so the whole-text oracle and the window would legitimately
			// disagree. That is a detector bug, not a window one.
			isCard := i > 0 && !lastWasCard && rng.Intn(25) == 0
			if isCard {
				w = cards[rng.Intn(len(cards))]
			}
			lastWasCard = isCard
			if i > 0 {
				w = " " + w
			}
			src = append(src, w)
		}
		want := wholeText(t, inspect, strings.Join(src, ""))
		// Pieces are re-cut at random so a card spans several events.
		joined := strings.Join(src, "")
		var pieces []string
		for len(joined) > 0 {
			n := min(1+rng.Intn(9), len(joined))
			pieces = append(pieces, joined[:n])
			joined = joined[n:]
		}
		stream := chatSSE(pieces...)
		var cuts []int
		for c := 1 + rng.Intn(30); c < len(stream); c += 1 + rng.Intn(120) {
			cuts = append(cuts, c)
		}
		out, blocked, _ := feed(t, inspect, split(stream, cuts...))
		if blocked {
			t.Fatalf("trial %d: blocked", trial)
		}
		if got := deltaText(t, out); got != want {
			t.Fatalf("trial %d: %s", trial, firstDiff(got, want))
		}
	}
}

func TestStreamCardSplitAcrossEvents(t *testing.T) {
	inspect := outputInspector(t, streamPolicy)
	out, _, _ := feed(t, inspect, [][]byte{chatSSE(prose, "card 4111 11", "11 1111 ", "1111 thanks")})
	if got := deltaText(t, out); got != prose+"card "+replacement+" thanks" {
		t.Errorf("got %q", got)
	}
}

// Text is released in pieces as the stream goes, not all at the end, and the
// first release comes once the held text passes the window. That hold is the
// latency the window adds before the client's first token.
func TestStreamReleasesIncrementally(t *testing.T) {
	inspect := outputInspector(t, streamPolicy)
	pieces := words(prose + prose + prose)
	w := newStreamWindow(inspect)
	sent, firstAt, releases := 0, -1, 0
	for _, p := range pieces {
		ev := chatSSE(p)
		ev = ev[:len(ev)-len(chatSSE())] // just the delta event
		sent += len(p)
		b, reply, _, err := w.chunk(context.Background(), ev, false)
		if err != nil {
			t.Fatal(err)
		}
		if reply && len(b) > 0 {
			releases++
			if firstAt < 0 {
				firstAt = sent
			}
		}
	}
	t.Logf("first release after %d characters of text; %d releases before end of stream", firstAt, releases)
	if firstAt < windowSize || firstAt > windowSize+evalEvery+64 {
		t.Errorf("first release after %d characters, want about %d", firstAt, windowSize+evalEvery)
	}
	if releases < 3 {
		t.Errorf("%d releases before end of stream, want several", releases)
	}
}

// A block mid-stream: what was released stays released, the client then gets an
// error event and [DONE], and every later chunk gets an empty final reply.
func TestStreamBlockMidStream(t *testing.T) {
	inspect := outputInspector(t, streamPolicy)
	src := chatSSE(append(strings.Fields(prose+prose), " use AKIAIOSFODNN7EXAMPLE now", " more", " text")...)
	chunks := split(src, len(src)/4, len(src)/2, 3*len(src)/4)
	w := newStreamWindow(inspect)
	var out []byte
	sawBlock := false
	for i, c := range chunks {
		b, reply, end, err := w.chunk(context.Background(), c, i == len(chunks)-1)
		if err != nil {
			t.Fatal(err)
		}
		if sawBlock {
			if !reply || !end || len(b) != 0 {
				t.Errorf("chunk after block: reply=%v end=%v body=%q, want an empty final reply", reply, end, b)
			}
			continue
		}
		out = append(out, b...)
		if bytes.Contains(b, []byte("ai_security_block")) {
			sawBlock = true
			if !end || !bytes.HasSuffix(b, []byte("data: [DONE]\n\n")) {
				t.Errorf("block reply: end=%v body=%q", end, b)
			}
		}
	}
	if !sawBlock {
		t.Fatal("stream with an AWS key was not blocked")
	}
	if bytes.Contains(out, []byte("AKIA")) {
		t.Error("the key reached the client")
	}
}

// A token cut short at the held boundary can match a pattern the complete
// token does not: AWS's 16 characters then \b. The trailing run is not
// inspected before it ends, so this must not block.
func TestStreamTruncatedTokenIsNotActedOn(t *testing.T) {
	inspect := outputInspector(t, streamPolicy)
	token := "AKIAIOSFODNN7EXAMPLEXYZQ" // longer than an AWS key id, so not one
	pieces := strings.Fields(prose + prose)
	for _, r := range token {
		pieces = append(pieces, string(r))
	}
	pieces = append(pieces, " done.")
	for _, cut := range []int{1, 7, 64} {
		stream := chatSSE(pieces...)
		var cuts []int
		for c := cut; c < len(stream); c += cut * 13 {
			cuts = append(cuts, c)
		}
		out, blocked, _ := feed(t, inspect, split(stream, cuts...))
		if blocked {
			t.Fatalf("cut every %d: blocked on a truncated token", cut)
		}
		if !strings.Contains(deltaText(t, out), token) {
			t.Errorf("cut every %d: token missing from output", cut)
		}
	}
}

// Streams in other formats are held to the end and inspected whole, including
// events that repeat the full text.
func TestStreamOtherFormatHeldToEnd(t *testing.T) {
	inspect := outputInspector(t, streamPolicy)
	ev := func(typ string, v map[string]any) string {
		v["type"] = typ
		b, _ := json.Marshal(v)
		return "event: " + typ + "\ndata: " + string(b) + "\n\n"
	}
	src := ev("message_start", map[string]any{"message": map[string]any{"id": "msg_01", "role": "assistant"}}) +
		ev("content_block_delta", map[string]any{"index": 0, "delta": map[string]any{"type": "text_delta", "text": prose + "card 4111 11"}}) +
		ev("content_block_delta", map[string]any{"index": 0, "delta": map[string]any{"type": "text_delta", "text": "11 1111 1111 ok"}}) +
		ev("message_stop", map[string]any{})
	chunks := split([]byte(src), 100, 400, 700)
	w := newStreamWindow(inspect)
	var out []byte
	for i, c := range chunks {
		b, reply, _, err := w.chunk(context.Background(), c, i == len(chunks)-1)
		if err != nil {
			t.Fatal(err)
		}
		if reply && i < len(chunks)-1 {
			t.Fatalf("chunk %d released before end of stream", i)
		}
		out = append(out, b...)
	}
	if bytes.Contains(out, []byte("4111")) || !bytes.Contains(out, []byte(replacement)) {
		t.Errorf("card not redacted: %s", out)
	}
	if !bytes.Contains(out, []byte("event: content_block_delta\n")) || !bytes.Contains(out, []byte("event: message_stop\n")) {
		t.Errorf("event lines lost: %s", out)
	}
}

// Two choices interleaved: each is its own text stream, so a card in one does
// not disturb the other, and pieces of the two never join into a false match.
func TestStreamChoicesAreSeparate(t *testing.T) {
	inspect := outputInspector(t, streamPolicy)
	var b bytes.Buffer
	emit := func(idx int, s string) {
		ev, _ := json.Marshal(map[string]any{"object": "chat.completion.chunk",
			"choices": []any{map[string]any{"index": idx, "delta": map[string]any{"content": s}}}})
		b.WriteString("data: " + string(ev) + "\n\n")
	}
	for _, w := range strings.Fields(prose) {
		emit(0, w+" ")
		emit(1, w+" ")
	}
	emit(0, "4111 1111 ")
	emit(1, "1111 1111 ") // would complete a card only if the choices were joined
	emit(0, "1111 1111 done")
	emit(1, "done")
	b.WriteString("data: [DONE]\n\n")
	out, _, _ := feed(t, inspect, split(b.Bytes(), b.Len()/3, 2*b.Len()/3))
	var c0, c1 strings.Builder
	rest := out
	for len(rest) > 0 {
		ev, r, ok := nextEvent(rest)
		if !ok {
			break
		}
		rest = r
		m, _ := ev.data.(map[string]any)
		for _, c := range chatChunkFields(m) {
			if c.key == "c0" {
				c0.WriteString(c.text)
			} else {
				c1.WriteString(c.text)
			}
		}
	}
	if !strings.HasSuffix(c0.String(), replacement+" done") {
		t.Errorf("choice 0 = %q, want the card redacted", c0.String()[len(c0.String())-40:])
	}
	if !strings.HasSuffix(c1.String(), "1111 1111 done") {
		t.Errorf("choice 1 = %q, want it untouched", c1.String()[len(c1.String())-40:])
	}
}

func TestParseEventForms(t *testing.T) {
	raw := []byte(": keepalive\r\n\r\nevent: x\r\ndata: {\"a\":\r\ndata: 1}\r\n\r\ndata: [DONE]\n\npartial")
	var evs []*sseEvent
	for {
		ev, rest, ok := nextEvent(raw)
		if !ok {
			break
		}
		evs = append(evs, ev)
		raw = rest
	}
	if len(evs) != 3 || string(raw) != "partial" {
		t.Fatalf("events = %d, rest = %q", len(evs), raw)
	}
	if evs[0].data != nil || evs[2].data != nil {
		t.Error("comment and [DONE] carry no JSON")
	}
	if m, ok := evs[1].data.(map[string]any); !ok || m["a"] == nil {
		t.Errorf("multi-line data not joined: %v", evs[1].data)
	}
}

// firstDiff shows where two long strings first differ.
func firstDiff(got, want string) string {
	i := 0
	for i < len(got) && i < len(want) && got[i] == want[i] {
		i++
	}
	from := max(i-40, 0)
	return "first difference at byte " + strconv.Itoa(i) + ":\n got …" + got[from:min(i+60, len(got))] + "\nwant …" + want[from:min(i+60, len(want))]
}

// words splits text into pieces that keep their trailing space, so joining
// them gives the text back.
func words(text string) []string {
	var out []string
	for len(text) > 0 {
		i := strings.IndexByte(text, ' ')
		if i < 0 {
			return append(out, text)
		}
		out = append(out, text[:i+1])
		text = text[i+1:]
	}
	return out
}

// wholeText is the oracle: the text inspected in one piece, redactions applied.
func wholeText(t *testing.T, inspect func(context.Context, string) (core.Verdict, error), text string) string {
	t.Helper()
	v, err := inspect(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if v.Action != core.ActionRedact {
		return text
	}
	return redact(text, append([]core.Span(nil), v.Redactions...))
}

const blockAadhaarPolicy = `
tenant: test
defaults: { on_error: fail_closed }
rules:
  - surface: [output]
    when: { detector: pii, type_in: [card] }
    action: redact
  - surface: [output]
    when: { detector: pii, type_in: [aadhaar] }
    action: block
`

// A streamed response is blocked exactly when the whole text would be. Spaced
// cards matter here: a card held up to its third group has an Aadhaar-shaped
// run, and a block on that prefix would cut off a stream that is fine.
func TestStreamBlockParity(t *testing.T) {
	inspect := outputInspector(t, blockAadhaarPolicy)
	vocab := strings.Fields(prose)
	// 4000 0000 0005 0007 is a card whose first three groups pass the Aadhaar
	// checksum: the case that matters.
	values := []string{"4000 0000 0005 0007", "4000 0000 0014 0006", "4111 1111 1111 1111", "2345 6789 0124", "4567 8901 2346"}
	blocks := 0
	for trial := range 300 {
		rng := rand.New(rand.NewSource(int64(trial)))
		var src []string
		lastWasValue := false
		for i := range 40 + rng.Intn(120) {
			w := vocab[rng.Intn(len(vocab))]
			isValue := i > 0 && !lastWasValue && rng.Intn(20) == 0 // no adjacent values; see above
			if isValue {
				w = values[rng.Intn(len(values))]
			}
			lastWasValue = isValue
			if i > 0 {
				w = " " + w
			}
			src = append(src, w)
		}
		text := strings.Join(src, "")
		v, err := inspect(context.Background(), text)
		if err != nil {
			t.Fatal(err)
		}
		wantBlock := v.Action == core.ActionBlock
		var pieces []string
		for rest := text; len(rest) > 0; {
			n := min(1+rng.Intn(9), len(rest))
			pieces = append(pieces, rest[:n])
			rest = rest[n:]
		}
		stream := chatSSE(pieces...)
		var cuts []int
		for c := 1 + rng.Intn(30); c < len(stream); c += 1 + rng.Intn(120) {
			cuts = append(cuts, c)
		}
		out, blocked, _ := feed(t, inspect, split(stream, cuts...))
		gotBlock := blocked || bytes.Contains(out, []byte("ai_security_block"))
		if gotBlock != wantBlock {
			t.Fatalf("trial %d: streamed blocked=%v, whole text blocked=%v", trial, gotBlock, wantBlock)
		}
		if gotBlock {
			blocks++
		}
	}
	t.Logf("%d of %d trials blocked", blocks, 300)
}

// A round that ends just after a spaced card's third group sees an
// Aadhaar-shaped run (4000 0000 0005 passes Verhoeff). Under a policy that
// blocks Aadhaar, that must not block: the card completes in the next event.
func TestStreamSpacedCardPrefixDoesNotBlock(t *testing.T) {
	inspect := outputInspector(t, blockAadhaarPolicy)
	stream := chatSSE(prose, strings.Repeat("timing ", 12)+"card 4000 0000 0005 ", "0007 is on file.")
	out, blocked, _ := feed(t, inspect, split(stream, len(chatSSE(prose))-len(chatSSE()), len(chatSSE(prose, strings.Repeat("timing ", 12)+"card 4000 0000 0005 "))-len(chatSSE())))
	if blocked || bytes.Contains(out, []byte("ai_security_block")) {
		t.Fatalf("blocked on the prefix of a card: %s", out)
	}
	if got := deltaText(t, out); !strings.HasSuffix(got, "card "+replacement+" is on file.") {
		t.Errorf("card not redacted: %q", got[max(len(got)-60, 0):])
	}
}
