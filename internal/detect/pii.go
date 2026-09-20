package detect

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

// PII is the India pack of DESIGN decision 4, framed against DPDP Act 2023
// categories, plus email. Where a checksum exists it is required, so the
// detector reports an Aadhaar rather than any twelve digits.
//
// Honest limitation, per DESIGN §3.3: these are patterns. Unstructured PII —
// names, addresses — is invisible to them and waits for the Phase 5 NER model.
type PII struct{}

func (PII) Name() string { return DetectorPII }

var _ Detector = PII{}

// Scores separate a checksum-backed match from a shape-only one, so policy can
// require `score_gte` before acting.
const (
	scoreChecksum = 1.0
	scoreShape    = 0.7
)

var (
	aadhaarRe  = regexp.MustCompile(`\b[2-9][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}\b`)
	panRe      = regexp.MustCompile(`\b[A-Z]{5}[0-9]{4}[A-Z]\b`)
	gstinRe    = regexp.MustCompile(`\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][0-9A-Z]Z[0-9A-Z]\b`)
	ifscRe     = regexp.MustCompile(`\b[A-Z]{4}0[A-Z0-9]{6}\b`)
	accountRe  = regexp.MustCompile(`\b[0-9]{9,18}\b`)
	mobileRe   = regexp.MustCompile(`(?:\+91[ -]?|\b0)?[6-9][0-9]{9}\b`)
	passportRe = regexp.MustCompile(`\b[A-PR-WY][1-9][0-9][ ]?[0-9]{4}[1-9]\b`)
	cardRe     = regexp.MustCompile(`\b[0-9](?:[0-9 -]{11,21})[0-9]\b`)
	emailRe    = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+\b`)
	vpaRe      = regexp.MustCompile(`\b[A-Za-z0-9.\-_]{2,64}@([A-Za-z]{2,64})\b`)
)

// upiHandles is the closed set of provider handles a VPA may use. A VPA and an
// email differ only by the handle, so matching any `name@word` would flag every
// intranet address. Precision over recall, and the list is the thing to extend.
var upiHandles = map[string]bool{
	"okhdfcbank": true, "okicici": true, "oksbi": true, "okaxis": true,
	"ybl": true, "ibl": true, "axl": true, "apl": true, "yapl": true,
	"paytm": true, "upi": true, "airtel": true, "freecharge": true,
	"jupiteraxis": true, "fam": true, "naviaxis": true, "superyes": true,
}

// bankAccountWindow is how far from an IFSC a number may sit and still be read
// as the account it belongs to (DESIGN §3.3 pairs the two).
const bankAccountWindow = 120

func (p PII) Detect(_ context.Context, req core.Request) ([]core.Finding, error) {
	var findings []core.Finding
	for i, part := range req.Parts {
		findings = append(findings, p.scan(i, part.Text)...)
	}
	return findings, nil
}

func (PII) scan(part int, text string) []core.Finding {
	var out []core.Finding
	add := func(typ string, loc []int, score float64) {
		out = append(out, core.Finding{
			Detector: DetectorPII,
			Type:     typ,
			Span:     core.Span{Part: part, Start: loc[0], End: loc[1]},
			Score:    score,
		})
	}

	for _, loc := range aadhaarRe.FindAllStringIndex(text, -1) {
		if d := digitsOnly(text[loc[0]:loc[1]]); len(d) == 12 && Verhoeff(d) {
			add(TypeAadhaar, loc, scoreChecksum)
		}
	}
	for _, loc := range cardRe.FindAllStringIndex(text, -1) {
		d := digitsOnly(text[loc[0]:loc[1]])
		if len(d) >= 13 && len(d) <= 19 && Luhn(d) {
			add(TypeCard, loc, scoreChecksum)
		}
	}
	for _, loc := range gstinRe.FindAllStringIndex(text, -1) {
		if GSTIN(text[loc[0]:loc[1]]) {
			add(TypeGSTIN, loc, scoreChecksum)
		}
	}
	for _, loc := range panRe.FindAllStringIndex(text, -1) {
		add(TypePAN, loc, scoreShape)
	}
	for _, loc := range passportRe.FindAllStringIndex(text, -1) {
		add(TypeIndianPassport, loc, scoreShape)
	}
	for _, loc := range mobileRe.FindAllStringIndex(text, -1) {
		add(TypeIndianMobile, loc, scoreShape)
	}
	for _, loc := range emailRe.FindAllStringIndex(text, -1) {
		add(TypeEmail, loc, scoreShape)
	}
	for _, m := range vpaRe.FindAllStringSubmatchIndex(text, -1) {
		handle := text[m[2]:m[3]]
		// A trailing dot means this is the first label of an email domain.
		if m[1] < len(text) && text[m[1]] == '.' {
			continue
		}
		if upiHandles[strings.ToLower(handle)] {
			add(TypeUPIVPA, []int{m[0], m[1]}, scoreShape)
		}
	}

	ifscs := ifscRe.FindAllStringIndex(text, -1)
	for _, loc := range ifscs {
		add(TypeIFSC, loc, scoreShape)
	}
	if len(ifscs) > 0 {
		for _, loc := range accountRe.FindAllStringIndex(text, -1) {
			if nearAny(loc, ifscs, bankAccountWindow) {
				add(TypeBankAccount, loc, scoreShape)
			}
		}
	}

	return suppressContained(out)
}

// nearAny reports whether loc sits within window bytes of any of the anchors.
func nearAny(loc []int, anchors [][]int, window int) bool {
	for _, a := range anchors {
		if loc[0] < a[1]+window && a[0] < loc[1]+window {
			return true
		}
	}
	return false
}

// suppressContained drops a finding whose span sits inside another's. A card
// number contains a ten-digit run starting 6-9, so the mobile pattern fires
// inside every card and Aadhaar; the longer, checksum-backed match wins.
func suppressContained(findings []core.Finding) []core.Finding {
	if len(findings) < 2 {
		return findings
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i].Span, findings[j].Span
		if a.Part != b.Part {
			return a.Part < b.Part
		}
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		if a.End != b.End {
			return a.End > b.End // longer first
		}
		return findings[i].Score > findings[j].Score
	})

	kept := findings[:0]
	for _, f := range findings {
		contained := false
		for _, k := range kept {
			if k.Span.Part == f.Span.Part && k.Span.Start <= f.Span.Start && f.Span.End <= k.Span.End {
				contained = true
				break
			}
		}
		if !contained {
			kept = append(kept, f)
		}
	}
	return kept
}
