package normalize

import (
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/rajesh-proddu/ai_security/internal/core"
	"github.com/rajesh-proddu/ai_security/internal/detect"
	"golang.org/x/text/unicode/norm"
)

// A pass rewrites text and reports spans (in its own input offsets) that are
// evidence of evasion — the characters or encodings it just neutralised.
type pass func(in string) (out string, m core.OffsetMap, evidence []evidence)

type evidence struct {
	typ        string
	start, end int
	score      float64
}

// extractJSON replaces a JSON document with its string and number values, one
// per line. Tool-call arguments and MCP payloads are JSON; keys and punctuation
// only add noise for detectors. Anything that is not a whole JSON object or
// array passes through untouched.
func extractJSON(in string) (string, core.OffsetMap, []evidence) {
	trimmed := strings.TrimSpace(in)
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') || !json.Valid([]byte(in)) {
		return in, core.OffsetMap{}, nil
	}

	dec := json.NewDecoder(strings.NewReader(in))
	dec.UseNumber()
	var b builder
	b.changed = true
	var stack []byte // '{' or '['; in an object, even positions are keys
	var count []int
	for {
		before := int(dec.InputOffset())
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// json.Valid passed, so this is unreachable; be conservative anyway.
			return in, core.OffsetMap{}, nil
		}
		after := int(dec.InputOffset())

		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				// The container is itself an element of its parent.
				markValue(count)
				stack = append(stack, byte(t))
				count = append(count, 0)
			default:
				stack, count = stack[:len(stack)-1], count[:len(count)-1]
			}
			continue
		case string, json.Number:
			// Inside an object, tokens alternate key, value, key, value.
			isKey := len(stack) > 0 && stack[len(stack)-1] == '{' && count[len(count)-1]%2 == 0
			markValue(count)
			if isKey {
				continue
			}
			start := tokenStart(in, before)
			if b.out.Len() > 0 {
				// The separator belongs to no input byte; map it to an empty
				// range so a span ending on it stays inside the last value.
				b.replace("\n", start, start)
			}
			if s, ok := t.(string); ok {
				raw := in[start+1 : after-1] // between the quotes
				if raw == s {
					b.keep(in, start+1, after-1)
				} else {
					b.replace(s, start, after)
				}
			} else {
				b.keep(in, start, after)
			}
		default: // bool, nil
			markValue(count)
		}
	}
	out, m := b.result(in)
	return out, m, nil
}

// markValue counts one more token in the innermost container.
func markValue(count []int) {
	if len(count) > 0 {
		count[len(count)-1]++
	}
}

// tokenStart skips the whitespace and separators json.Decoder consumed before
// the token itself.
func tokenStart(in string, from int) int {
	for from < len(in) {
		switch in[from] {
		case ' ', '\t', '\n', '\r', ',', ':':
			from++
		default:
			return from
		}
	}
	return from
}

var entityRe = regexp.MustCompile(`&(?:#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[a-zA-Z][a-zA-Z0-9]{1,31});`)

// decodeEntities decodes HTML character references. Single pass: `&amp;#105;`
// becomes `&#105;`, not `i`.
func decodeEntities(in string) (string, core.OffsetMap, []evidence) {
	if !strings.Contains(in, "&") {
		return in, core.OffsetMap{}, nil
	}
	return substitute(in, entityRe, func(match string) (string, bool) {
		out := html.UnescapeString(match)
		return out, out != match
	})
}

var percentRe = regexp.MustCompile(`(?:%[0-9a-fA-F]{2})+`)

// decodePercent decodes runs of URL percent-escapes that form valid UTF-8.
// Single pass, like decodeEntities.
func decodePercent(in string) (string, core.OffsetMap, []evidence) {
	if !strings.Contains(in, "%") {
		return in, core.OffsetMap{}, nil
	}
	return substitute(in, percentRe, func(match string) (string, bool) {
		out, err := url.PathUnescape(match)
		if err != nil || !utf8.ValidString(out) {
			return "", false
		}
		return out, true
	})
}

// substitute replaces each regexp match for which fn reports ok.
func substitute(in string, re *regexp.Regexp, fn func(string) (string, bool)) (string, core.OffsetMap, []evidence) {
	var b builder
	prev := 0
	for _, loc := range re.FindAllStringIndex(in, -1) {
		repl, ok := fn(in[loc[0]:loc[1]])
		if !ok {
			continue
		}
		b.keep(in, prev, loc[0])
		b.replace(repl, loc[0], loc[1])
		prev = loc[1]
	}
	b.keep(in, prev, len(in))
	out, m := b.result(in)
	return out, m, nil
}

// invisible reports characters that render as nothing or reorder text: zero
// width characters, bidi controls, the BOM and the soft hyphen. Attackers use
// them to split a phrase so it slips past matching, or to hide text from a
// human reviewer (DESIGN §3.3).
func invisible(r rune) bool {
	switch {
	case r >= 0x200B && r <= 0x200F, // zero width space/joiners, LRM, RLM
		r >= 0x202A && r <= 0x202E, // bidi embeddings and overrides
		r >= 0x2060 && r <= 0x2064, // word joiner, invisible operators
		r >= 0x2066 && r <= 0x2069, // bidi isolates
		r == 0xFEFF,                // BOM / zero width no-break space
		r == 0x00AD,                // soft hyphen
		r == 0x180E:                // Mongolian vowel separator
		return true
	}
	return false
}

// stripInvisible removes invisible characters, reporting each contiguous run.
func stripInvisible(in string) (string, core.OffsetMap, []evidence) {
	var b builder
	var ev []evidence
	prev, runStart := 0, -1
	for i, r := range in {
		if invisible(r) {
			if runStart < 0 {
				runStart = i
				b.keep(in, prev, i)
			}
			continue
		}
		if runStart >= 0 {
			b.replace("", runStart, i)
			ev = append(ev, evidence{typ: TypeHiddenText, start: runStart, end: i, score: 1})
			runStart, prev = -1, i
		}
	}
	if runStart >= 0 {
		b.replace("", runStart, len(in))
		ev = append(ev, evidence{typ: TypeHiddenText, start: runStart, end: len(in), score: 1})
		prev = len(in)
	}
	b.keep(in, prev, len(in))
	out, m := b.result(in)
	return out, m, ev
}

// nfkc applies Unicode NFKC, which folds compatibility forms — fullwidth
// letters, ligatures, circled and styled characters — onto plain ones. It works
// segment by segment between normalization boundaries, so each changed segment
// maps back to exactly the input it came from.
func nfkc(in string) (string, core.OffsetMap, []evidence) {
	if norm.NFKC.IsNormalString(in) {
		return in, core.OffsetMap{}, nil
	}
	var b builder
	for i := 0; i < len(in); {
		n := norm.NFKC.NextBoundaryInString(in[i:], true)
		if n <= 0 {
			n = len(in) - i
		}
		chunk := in[i : i+n]
		if out := norm.NFKC.String(chunk); out != chunk {
			b.replace(out, i, i+n)
		} else {
			b.keep(in, i, i+n)
		}
		i += n
	}
	out, m := b.result(in)
	return out, m, nil
}

var base64Re = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)

// expandBase64 appends the text of any base64 token that decodes to readable
// content, after the original text rather than inside it. Inline expansion
// would break the structures detectors match on — a markdown image whose URL
// carries a base64 payload stops looking like a markdown image. The token
// itself is untouched, and every appended payload maps back to its token.
func expandBase64(in string) (string, core.OffsetMap, []evidence) {
	type payload struct {
		text       string
		start, end int
	}
	var payloads []payload
	var ev []evidence
	for _, loc := range base64Re.FindAllStringIndex(in, -1) {
		decoded, ok := detect.DecodeReadableBase64(in[loc[0]:loc[1]])
		if !ok {
			continue
		}
		payloads = append(payloads, payload{text: decoded, start: loc[0], end: loc[1]})
		ev = append(ev, evidence{typ: TypeEncodedPayload, start: loc[0], end: loc[1], score: 0.5})
	}
	if len(payloads) == 0 {
		return in, core.OffsetMap{}, nil
	}

	var b builder
	b.keep(in, 0, len(in))
	for _, p := range payloads {
		b.replace("\n"+p.text, p.start, p.end)
	}
	out, m := b.result(in)
	return out, m, ev
}
