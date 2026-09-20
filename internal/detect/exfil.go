package detect

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

// ExfilURL finds URLs that carry data out in their query string, and markdown
// images, which a client fetches without the user clicking anything — the
// classic silent exfiltration channel (DESIGN §3.3).
//
// Honest limitation, per DESIGN §3.3: covert channels that are not URLs are not
// covered, and data split across several calls is not reassembled.
type ExfilURL struct {
	// allowed is the domain allow-list. When empty, no domain is reported as
	// disallowed — an allow-list nobody configured must not block everything.
	allowed map[string]bool
}

// NewExfilURL builds the detector. Domains match themselves and their
// subdomains.
func NewExfilURL(allowedDomains []string) *ExfilURL {
	d := &ExfilURL{}
	if len(allowedDomains) > 0 {
		d.allowed = make(map[string]bool, len(allowedDomains))
		for _, domain := range allowedDomains {
			d.allowed[strings.ToLower(strings.TrimPrefix(domain, "."))] = true
		}
	}
	return d
}

func (*ExfilURL) Name() string { return DetectorExfilURL }

var _ Detector = (*ExfilURL)(nil)

var (
	urlRe      = regexp.MustCompile(`https?://[^\s<>"')\]]+`)
	mdImageRe  = regexp.MustCompile(`!\[[^\]]*\]\((https?://[^\s)]+)\)`)
	dataParamB = 24 // a query value at least this long is carrying data, not a flag
)

func (d *ExfilURL) Detect(_ context.Context, req core.Request) ([]core.Finding, error) {
	var out []core.Finding
	for i, part := range req.Parts {
		add := func(typ string, start, end int, score float64) {
			out = append(out, core.Finding{
				Detector: DetectorExfilURL,
				Type:     typ,
				Span:     core.Span{Part: i, Start: start, End: end},
				Score:    score,
			})
		}

		for _, m := range mdImageRe.FindAllStringSubmatchIndex(part.Text, -1) {
			add(TypeMarkdownImage, m[0], m[1], scoreOverride)
		}
		for _, loc := range urlRe.FindAllStringIndex(part.Text, -1) {
			raw := part.Text[loc[0]:loc[1]]
			u, err := url.Parse(raw)
			if err != nil {
				continue
			}
			if d.allowed != nil && !d.permitted(u.Hostname()) {
				add(TypeDisallowedDomain, loc[0], loc[1], scoreOverride)
			}
			if carriesData(u) {
				add(TypeDataBearingURL, loc[0], loc[1], scoreSpoof)
			}
		}
	}
	return out, nil
}

// permitted reports whether host is on the allow-list, or is a subdomain of
// something on it.
func (d *ExfilURL) permitted(host string) bool {
	host = strings.ToLower(host)
	for {
		if d.allowed[host] {
			return true
		}
		i := strings.IndexByte(host, '.')
		if i < 0 {
			return false
		}
		host = host[i+1:]
	}
}

// carriesData reports whether a URL's query or fragment looks like a payload
// rather than parameters: a long value, or one holding an @ or a space.
func carriesData(u *url.URL) bool {
	for _, values := range u.Query() {
		for _, v := range values {
			if len(v) >= dataParamB || strings.ContainsAny(v, "@ \n") {
				return true
			}
		}
	}
	return len(u.Fragment) >= dataParamB
}
