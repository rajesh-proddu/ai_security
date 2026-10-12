package detect

import (
	"bytes"
	"encoding/base64"
	"unicode"
	"unicode/utf8"
)

var base64Encodings = []*base64.Encoding{
	base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
}

// DecodeReadableBase64 decodes a token only if the result is text a person
// could read: valid UTF-8, of some length, and almost entirely printable.
// Identifiers that happen to be valid base64 decode to binary and are rejected.
//
// Two callers need the same answer: the normalizer expands readable payloads so
// detectors can see them, and the secrets entropy check skips them — a base64
// blob that decodes to English prose is not a credential.
func DecodeReadableBase64(tok string) (string, bool) {
	for _, enc := range base64Encodings {
		raw, err := enc.DecodeString(tok)
		if err != nil || len(raw) < 8 || !utf8.Valid(raw) {
			continue
		}
		printable := 0
		for _, r := range string(raw) {
			if unicode.IsPrint(r) || r == '\n' || r == '\t' {
				printable++
			}
		}
		if printable*10 >= utf8.RuneCount(raw)*9 {
			return string(bytes.TrimSpace(raw)), true
		}
	}
	return "", false
}
