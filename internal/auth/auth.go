// Package auth verifies SPF, DKIM and DMARC itself instead of believing an
// Authentication-Results header, which any sender can write.
//
// Every DNS query goes through Resolver, so tests run against a fake DNS
// with no network, and production can point at whichever resolver it trusts.
package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"

	"github.com/GligorcoGligorov/inspekt/internal/email"
)

// Resolver is the DNS surface SPF, DKIM and DMARC need. *net.Resolver
// satisfies it.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Result uses the RFC 8601 result names, so a verified result and one read
// from a header mean the same thing.
type Result string

const (
	Pass      Result = "pass"
	Fail      Result = "fail"
	SoftFail  Result = "softfail"
	Neutral   Result = "neutral"
	None      Result = "none"
	TempError Result = "temperror"
	PermError Result = "permerror"
)

// Results is the outcome of verifying one message.
type Results struct {
	SPF       Result `json:"spf"`
	SPFDomain string `json:"spf_domain,omitempty"` // domain SPF was checked for
	ClientIP  string `json:"client_ip,omitempty"`

	DKIM        Result   `json:"dkim"`
	DKIMDomains []string `json:"dkim_domains,omitempty"` // d= of valid signatures

	DMARC       Result `json:"dmarc"`
	DMARCPolicy string `json:"dmarc_policy,omitempty"` // policy that applies to From

	// Notes explain results that are not a plain pass/fail, for the analyst.
	Notes []string `json:"notes,omitempty"`
}

// maxSignatures bounds DKIM work per message: each signature costs a DNS
// query and a public-key operation, and the sender controls how many exist.
const maxSignatures = 5

// Verifier checks a message against the sender's published DNS policy.
type Verifier struct {
	Resolver Resolver
	// OrgDomain maps a host to its organisational domain for DMARC relaxed
	// alignment ("mail.example.co.uk" -> "example.co.uk"). Nil means exact
	// match only, which is stricter than RFC 7489.
	OrgDomain func(string) string
	// Timeout bounds all DNS work for one message. Zero means 5 s.
	Timeout time.Duration
}

// Verify runs SPF, DKIM and DMARC. It never returns an error: DNS trouble
// becomes temperror, so a resolver outage can never make mail look forged.
func (v *Verifier) Verify(ctx context.Context, msg *email.Message) Results {
	timeout := v.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var r Results
	v.checkSPF(ctx, msg, &r)
	v.checkDKIM(ctx, msg, &r)
	v.checkDMARC(ctx, msg, &r)
	return r
}

// ---------------------------------------------------------------------------
// SPF

func (v *Verifier) checkSPF(ctx context.Context, msg *email.Message, r *Results) {
	ip, helo, ok := ConnectingHost(msg.Received)
	if !ok {
		r.SPF = None
		r.Notes = append(r.Notes, "spf: no client IP in the topmost Received header")
		return
	}
	// The final MTA writes the SMTP MAIL FROM into Return-Path. An empty
	// one (bounces) means SPF is checked for the HELO name instead.
	sender := "postmaster@" + helo
	if msg.ReturnPath != nil && msg.ReturnPath.Email != "" {
		sender = msg.ReturnPath.Email
	}
	r.ClientIP = ip.String()
	r.SPFDomain = sender[strings.LastIndexByte(sender, '@')+1:]

	res, err := spf.CheckHostWithSender(ip, helo, sender,
		spf.WithContext(ctx), spf.WithResolver(v.Resolver))
	r.SPF = Result(res)
	if err != nil && r.SPF != Pass {
		r.Notes = append(r.Notes, "spf: "+err.Error())
	}
}

// receivedFrom matches the "from" clause an MTA writes, e.g.
//
//	from mail.example.org (mail.example.org [192.0.2.10]) by mx.example.com ...
//	from [IPv6:2001:db8::1] (unknown) by mx.example.com ...
var (
	receivedFrom = regexp.MustCompile(`(?is)^\s*from\s+(\S+).*?\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]`)
	receivedBy   = regexp.MustCompile(`(?i)\sby\s`)
)

// ConnectingHost returns the client IP and HELO name from the topmost
// Received header.
//
// Assumption: the topmost Received header was written by our own MTA, the
// one that accepted the SMTP connection. That holds when Inspekt receives
// mail straight from that MTA. Any header below it may be forged by the
// sender, so it is never consulted.
func ConnectingHost(received []string) (ip net.IP, helo string, ok bool) {
	if len(received) == 0 {
		return nil, "", false
	}
	h := received[0]
	// Only look at the "from" clause; "by" and "for" describe our side.
	if loc := receivedBy.FindStringIndex(h); loc != nil {
		h = h[:loc[0]]
	}
	m := receivedFrom.FindStringSubmatch(h)
	if m == nil {
		return nil, "", false
	}
	ip = net.ParseIP(m[2])
	if ip == nil {
		return nil, "", false
	}
	helo = strings.Trim(m[1], "[]")
	return ip, helo, true
}

// ---------------------------------------------------------------------------
// DKIM

func (v *Verifier) checkDKIM(ctx context.Context, msg *email.Message, r *Results) {
	opts := &dkim.VerifyOptions{
		LookupTXT:        func(name string) ([]string, error) { return v.Resolver.LookupTXT(ctx, name) },
		MaxVerifications: maxSignatures,
	}
	verifs, err := dkim.VerifyWithOptions(bytes.NewReader(msg.Raw), opts)
	if errors.Is(err, dkim.ErrTooManySignatures) {
		r.Notes = append(r.Notes, fmt.Sprintf("dkim: only the first %d signatures were checked", maxSignatures))
	} else if err != nil {
		r.DKIM = PermError
		r.Notes = append(r.Notes, "dkim: "+err.Error())
		return
	}
	if len(verifs) == 0 {
		r.DKIM = None
		return
	}

	// One valid signature is enough. Otherwise report the most hopeful
	// failure: a DNS hiccup (temperror) must not read as forgery (fail).
	var temp, perm, bad bool
	for _, vf := range verifs {
		switch {
		case vf.Err == nil:
			r.DKIMDomains = append(r.DKIMDomains, strings.ToLower(vf.Domain))
		case dkim.IsTempFail(vf.Err):
			temp = true
		case dkim.IsPermFail(vf.Err):
			perm = true
		default:
			bad = true
		}
		if vf.Err != nil {
			r.Notes = append(r.Notes, fmt.Sprintf("dkim d=%s: %v", vf.Domain, vf.Err))
		}
	}
	switch {
	case len(r.DKIMDomains) > 0:
		r.DKIM = Pass
	case temp:
		r.DKIM = TempError
	case bad:
		r.DKIM = Fail
	case perm:
		r.DKIM = PermError
	}
}

// ---------------------------------------------------------------------------
// DMARC

func (v *Verifier) checkDMARC(ctx context.Context, msg *email.Message, r *Results) {
	if msg.From == nil || msg.From.Domain == "" {
		r.DMARC = None
		r.Notes = append(r.Notes, "dmarc: no From domain")
		return
	}
	from := msg.From.Domain
	org := v.org(from)
	lookup := &dmarc.LookupOptions{
		LookupTXT: func(name string) ([]string, error) { return v.Resolver.LookupTXT(ctx, name) },
	}

	// RFC 7489 6.6.3: try the From domain, then its organisational domain,
	// where the subdomain policy (sp=) applies if set.
	rec, err := dmarc.LookupWithOptions(from, lookup)
	policy := Result("")
	if errors.Is(err, dmarc.ErrNoPolicy) && org != from {
		rec, err = dmarc.LookupWithOptions(org, lookup)
		if err == nil && rec.SubdomainPolicy != "" {
			policy = Result(rec.SubdomainPolicy)
		}
	}
	switch {
	case errors.Is(err, dmarc.ErrNoPolicy):
		r.DMARC = None
		return
	case dmarc.IsTempFail(err):
		r.DMARC = TempError
		r.Notes = append(r.Notes, "dmarc: "+err.Error())
		return
	case err != nil:
		r.DMARC = PermError
		r.Notes = append(r.Notes, "dmarc: "+err.Error())
		return
	}
	if policy == "" {
		policy = Result(rec.Policy)
	}
	r.DMARCPolicy = string(policy)

	// DMARC passes if SPF or DKIM passed for a domain aligned with From.
	if r.SPF == Pass && v.aligned(r.SPFDomain, from, rec.SPFAlignment) {
		r.DMARC = Pass
		return
	}
	for _, d := range r.DKIMDomains {
		if v.aligned(d, from, rec.DKIMAlignment) {
			r.DMARC = Pass
			return
		}
	}
	r.DMARC = Fail
	r.Notes = append(r.Notes, fmt.Sprintf("dmarc: no pass aligned with %s (spf %s for %q, dkim d=%v)",
		from, r.SPF, r.SPFDomain, r.DKIMDomains))
}

func (v *Verifier) aligned(domain, from string, mode dmarc.AlignmentMode) bool {
	if domain == "" {
		return false
	}
	if mode == dmarc.AlignmentStrict {
		return strings.EqualFold(domain, from)
	}
	return v.org(domain) == v.org(from)
}

func (v *Verifier) org(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if v.OrgDomain == nil {
		return domain
	}
	return v.OrgDomain(domain)
}
