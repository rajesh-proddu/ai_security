package detect

import (
	"context"
	"testing"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

// All values below are synthetic. The Aadhaar and GSTIN numbers were generated
// to satisfy their checksums; the card numbers are the publicly documented test
// numbers. None identifies a real person or account.
const (
	fixtureAadhaar = "234567890124"
	fixtureGSTIN   = "27ABCDE1234F1Z0"
	fixtureCard    = "4111111111111111"
)

func findingTypes(findings []core.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Type)
	}
	return out
}

func detectText(t *testing.T, d Detector, text string) []core.Finding {
	t.Helper()
	got, err := d.Detect(context.Background(), core.Request{
		Surface: core.SurfaceInput,
		Parts:   []core.Part{{Text: text}},
	})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	return got
}

func hasType(findings []core.Finding, typ string) bool {
	for _, f := range findings {
		if f.Type == typ {
			return true
		}
	}
	return false
}

func TestPIIDetect(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		want    []string // types that must be present
		notWant []string
	}{
		{"aadhaar", "aadhaar " + fixtureAadhaar, []string{TypeAadhaar}, nil},
		{"aadhaar spaced", "2345 6789 0124", []string{TypeAadhaar}, nil},
		{"aadhaar bad checksum", "234567890123", nil, []string{TypeAadhaar}},
		{"twelve digits are not an aadhaar", "order 100000000001", nil, []string{TypeAadhaar}},
		{"card", "card " + fixtureCard, []string{TypeCard}, nil},
		{"card spaced", "4111 1111 1111 1111", []string{TypeCard}, nil},
		{"card bad luhn", "4111111111111112", nil, []string{TypeCard}},
		{"gstin", "gstin " + fixtureGSTIN, []string{TypeGSTIN}, nil},
		{"gstin bad checksum", "27ABCDE1234F1ZA", nil, []string{TypeGSTIN}},
		{"pan", "PAN ABCDE1234F", []string{TypePAN}, nil},
		{"ifsc", "IFSC HDFC0001234", []string{TypeIFSC}, nil},
		{"ifsc with account", "IFSC HDFC0001234 acct 123456789012", []string{TypeIFSC, TypeBankAccount}, nil},
		{"account without ifsc is not reported", "ref 123456789012345", nil, []string{TypeBankAccount}},
		{"mobile", "call 9876543210", []string{TypeIndianMobile}, nil},
		{"mobile with country code", "call +91 9876543210", []string{TypeIndianMobile}, nil},
		{"landline-looking number is not a mobile", "call 1234567890", nil, []string{TypeIndianMobile}},
		{"passport", "passport M1234567", []string{TypeIndianPassport}, nil},
		{"email", "mail a.b+c@example.com", []string{TypeEmail}, nil},
		{"upi vpa", "pay rajesh@okhdfcbank", []string{TypeUPIVPA}, nil},
		{"unknown handle is not a vpa", "pay rajesh@notabank", nil, []string{TypeUPIVPA}},
		{"an email is not a vpa", "mail rajesh@paytm.com", []string{TypeEmail}, []string{TypeUPIVPA}},
		{"clean text", "the quick brown fox jumps over the lazy dog", nil, []string{
			TypeAadhaar, TypeCard, TypePAN, TypeEmail, TypeIndianMobile, TypeGSTIN,
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectText(t, PII{}, tt.text)
			for _, want := range tt.want {
				if !hasType(got, want) {
					t.Errorf("missing %q; got %v", want, findingTypes(got))
				}
			}
			for _, bad := range tt.notWant {
				if hasType(got, bad) {
					t.Errorf("unexpected %q; got %v", bad, findingTypes(got))
				}
			}
		})
	}
}

// A card and an Aadhaar both contain a ten-digit run starting 6-9, so the
// mobile pattern fires inside them. The longer, checksum-backed match must win.
func TestPIISuppressesContainedMatches(t *testing.T) {
	for _, text := range []string{fixtureCard, fixtureAadhaar, "4111 1111 1111 1111"} {
		got := detectText(t, PII{}, text)
		if hasType(got, TypeIndianMobile) {
			t.Errorf("%q: mobile reported inside a longer match: %v", text, findingTypes(got))
		}
		if len(got) != 1 {
			t.Errorf("%q: findings = %v, want exactly one", text, findingTypes(got))
		}
	}
}

func TestPIISpansCoverTheValue(t *testing.T) {
	text := "my card is " + fixtureCard + " ok"
	got := detectText(t, PII{}, text)
	if len(got) != 1 {
		t.Fatalf("findings = %v", findingTypes(got))
	}
	if covered := text[got[0].Span.Start:got[0].Span.End]; covered != fixtureCard {
		t.Fatalf("span covers %q, want %q", covered, fixtureCard)
	}
}

func TestPIIReportsPerPart(t *testing.T) {
	got, err := PII{}.Detect(context.Background(), core.Request{
		Parts: []core.Part{{Text: "clean"}, {Text: "card " + fixtureCard}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Span.Part != 1 {
		t.Fatalf("findings = %+v, want one on part 1", got)
	}
}

func TestValidators(t *testing.T) {
	tests := []struct {
		name string
		fn   func(string) bool
		in   string
		want bool
	}{
		{"verhoeff valid", Verhoeff, fixtureAadhaar, true},
		{"verhoeff wrong check digit", Verhoeff, "234567890123", false},
		{"verhoeff transposition is caught", Verhoeff, "234567890214", false},
		{"verhoeff non-digit", Verhoeff, "23456789012a", false},
		{"luhn valid", Luhn, fixtureCard, true},
		{"luhn invalid", Luhn, "4111111111111112", false},
		{"luhn empty", Luhn, "", false},
		{"luhn non-digit", Luhn, "41111111111111x1", false},
		{"gstin valid", GSTIN, fixtureGSTIN, true},
		{"gstin wrong check char", GSTIN, "27ABCDE1234F1ZA", false},
		{"gstin too short", GSTIN, "27ABCDE1234F1Z", false},
		{"gstin bad alphabet", GSTIN, "27ABCDE1234F1Z!", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fn(tt.in); got != tt.want {
				t.Fatalf("%s(%q) = %v, want %v", tt.name, tt.in, got, tt.want)
			}
		})
	}
}
