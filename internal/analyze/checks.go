package analyze

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/GligorcoGligorov/inspekt/internal/auth"
	"github.com/GligorcoGligorov/inspekt/internal/email"
	"github.com/GligorcoGligorov/inspekt/internal/extract"
)

// ---------------------------------------------------------------------------
// AuthCheck turns SPF / DKIM / DMARC results into signals. In "headers" mode
// it reads Authentication-Results stamped by a trusted upstream MTA. In
// "verify" mode (Verifier set) it ignores those headers and does its own DNS
// checks. Both modes share signal IDs and weights, so eval runs compare.

type AuthCheck struct {
	Trusted  []string
	Verifier *auth.Verifier
}

func (AuthCheck) Name() string { return "auth" }

var authResult = regexp.MustCompile(`(?i)\b(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none|temperror|permerror)\b`)

func (c AuthCheck) Run(in *Input) []Signal {
	if c.Verifier != nil {
		return c.verified(in.Msg)
	}
	var out []Signal
	for _, h := range in.Msg.AuthResults {
		if !c.trusted(h) {
			continue
		}
		for _, m := range authResult.FindAllStringSubmatch(h, -1) {
			mech, res := strings.ToLower(m[1]), strings.ToLower(m[2])
			if s, ok := authSignal(mech, res, fmt.Sprintf("%s=%s", mech, res)); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func (c AuthCheck) verified(msg *email.Message) []Signal {
	r := c.Verifier.Verify(context.Background(), msg)
	var out []Signal
	add := func(mech string, res auth.Result, ev string) {
		if s, ok := authSignal(mech, string(res), ev); ok {
			out = append(out, s)
		}
	}
	add("spf", r.SPF, fmt.Sprintf("spf=%s for %s from %s (verified)", r.SPF, r.SPFDomain, r.ClientIP))
	add("dkim", r.DKIM, fmt.Sprintf("dkim=%s (verified)", r.DKIM))
	add("dmarc", r.DMARC, fmt.Sprintf("dmarc=%s, policy %s (verified)", r.DMARC, r.DMARCPolicy))

	// DNS errors carry no points: an outage must not make mail look forged.
	// The analyst still sees that a check could not run.
	for _, res := range []auth.Result{r.SPF, r.DKIM, r.DMARC} {
		if res == auth.TempError || res == auth.PermError {
			out = append(out, Signal{ID: "auth_unverified", Severity: SevInfo, Score: 0, Evidence: r.Notes})
			break
		}
	}
	return out
}

// authSignal maps one mechanism result to a signal. Results not listed
// (pass, none, neutral, errors) score nothing.
func authSignal(mech, res, ev string) (Signal, bool) {
	switch {
	case mech == "dmarc" && res == "fail":
		return Signal{ID: "dmarc_fail", Severity: SevHigh, Score: 35, Evidence: []string{ev}}, true
	case mech == "spf" && res == "fail":
		return Signal{ID: "spf_fail", Severity: SevMedium, Score: 15, Evidence: []string{ev}}, true
	case mech == "spf" && res == "softfail":
		return Signal{ID: "spf_softfail", Severity: SevLow, Score: 8, Evidence: []string{ev}}, true
	case mech == "dkim" && res == "fail":
		return Signal{ID: "dkim_fail", Severity: SevMedium, Score: 15, Evidence: []string{ev}}, true
	}
	return Signal{}, false
}

// trusted reports whether header h was written by an authserv-id we trust.
// The authserv-id is the first token of the header (RFC 8601).
func (c AuthCheck) trusted(h string) bool {
	if len(c.Trusted) == 0 {
		return true
	}
	id := strings.TrimSpace(strings.SplitN(h, ";", 2)[0])
	for _, t := range c.Trusted {
		if strings.EqualFold(id, t) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// SenderCheck looks for inconsistencies between the identities a message
// presents. Weights are low where legitimate mail commonly differs (ESPs
// set their own Return-Path), higher where it rarely does.

type SenderCheck struct{}

func (SenderCheck) Name() string { return "sender" }

var emailInText = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})`)

func (SenderCheck) Run(in *Input) []Signal {
	m := in.Msg
	if m.From == nil {
		return []Signal{{ID: "missing_from", Severity: SevMedium, Score: 20,
			Evidence: []string{"no parseable From header"}}}
	}
	var out []Signal
	from := RegistrableDomain(m.From.Domain)

	if m.ReplyTo != nil && RegistrableDomain(m.ReplyTo.Domain) != from {
		out = append(out, Signal{ID: "reply_to_mismatch", Severity: SevMedium, Score: 20,
			Evidence: []string{fmt.Sprintf("From %s, replies go to %s", m.From.Domain, m.ReplyTo.Domain)}})
	}
	if m.ReturnPath != nil && RegistrableDomain(m.ReturnPath.Domain) != from {
		out = append(out, Signal{ID: "return_path_mismatch", Severity: SevLow, Score: 5,
			Evidence: []string{fmt.Sprintf("From %s, envelope sender %s", m.From.Domain, m.ReturnPath.Domain)}})
	}
	// "PayPal Support <support@paypal.com>" <x@evil.example>
	if mm := emailInText.FindStringSubmatch(m.From.Name); mm != nil &&
		RegistrableDomain(strings.ToLower(mm[1])) != from {
		out = append(out, Signal{ID: "display_name_spoof", Severity: SevHigh, Score: 30,
			Evidence: []string{fmt.Sprintf("display name shows %s, real sender is %s", mm[0], m.From.Email)}})
	}
	return out
}

// ---------------------------------------------------------------------------
// LookalikeCheck flags sender and link domains that imitate protected brands.

type LookalikeCheck struct{ Protected []string }

func (LookalikeCheck) Name() string { return "lookalike" }

func (c LookalikeCheck) Run(in *Input) []Signal {
	var out []Signal
	check := func(where, host string) {
		if strings.Contains(host, "xn--") {
			out = append(out, Signal{ID: "punycode_domain", Severity: SevMedium, Score: 20,
				Evidence: []string{fmt.Sprintf("%s uses punycode: %s", where, host)}})
		}
		if target, kind, ok := Lookalike(host, c.Protected); ok {
			score := 40
			if kind == KindEmbedded {
				score = 30 // brand-in-domain has more legitimate uses (resellers)
			}
			out = append(out, Signal{ID: "lookalike_" + where, Severity: SevHigh, Score: score,
				Evidence: []string{fmt.Sprintf("%s imitates %s (%s)", host, target, kind)}})
		}
	}
	if in.Msg.From != nil {
		check("sender", in.Msg.From.Domain)
	}
	for _, l := range in.Links {
		check("link", l.Host)
	}
	return out
}

// ---------------------------------------------------------------------------
// LinkCheck inspects URLs for deceptive presentation.

type LinkCheck struct{}

func (LinkCheck) Name() string { return "links" }

// looksLikeURL is true for anchor text a reader would take as an address.
var looksLikeURL = regexp.MustCompile(`(?i)^(https?://)?(www\.)?[a-z0-9\-]+(\.[a-z0-9\-]+)+(/\S*)?$`)

func (LinkCheck) Run(in *Input) []Signal {
	var out []Signal
	from := ""
	if in.Msg.From != nil {
		from = RegistrableDomain(in.Msg.From.Domain)
	}
	for _, l := range in.Links {
		// A QR code pointing off the sender's own domain: the reader is asked
		// to open it on a phone, outside any protected browser.
		if l.Source == extract.SourceQR && RegistrableDomain(l.Host) != from {
			out = append(out, Signal{ID: "qr_code_link", Severity: SevMedium, Score: 20,
				Evidence: []string{"QR code in an image opens " + l.URL}})
		}
		if l.IsIP {
			out = append(out, Signal{ID: "ip_literal_url", Severity: SevMedium, Score: 25,
				Evidence: []string{l.URL}})
		}
		if urlShorteners[RegistrableDomain(l.Host)] {
			out = append(out, Signal{ID: "url_shortener", Severity: SevLow, Score: 10,
				Evidence: []string{l.URL + " (real destination hidden)"}})
		}
		if l.Source == "html_form" {
			out = append(out, Signal{ID: "html_form_in_email", Severity: SevHigh, Score: 30,
				Evidence: []string{"form submits to " + l.Host}})
		}
		if l.Text != "" && looksLikeURL.MatchString(l.Text) {
			shown := l.Text
			if !strings.Contains(shown, "://") {
				shown = "http://" + shown
			}
			shownHost := hostOf(shown)
			if shownHost != "" && RegistrableDomain(shownHost) != RegistrableDomain(l.Host) {
				out = append(out, Signal{ID: "link_text_mismatch", Severity: SevHigh, Score: 35,
					Evidence: []string{fmt.Sprintf("shows %q, goes to %s", l.Text, l.Host)}})
			}
		}
	}
	return out
}

// urlShorteners hide where a link really goes, so the other link checks
// cannot see the destination. Low weight: legitimate mail uses them too
// (t.co is in every Twitter/X notification). Keys are registrable domains.
var urlShorteners = set("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
	"buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id")

func hostOf(u string) string {
	u = u[strings.Index(u, "://")+3:]
	if i := strings.IndexAny(u, "/?#:"); i >= 0 {
		u = u[:i]
	}
	return strings.ToLower(u)
}

// ---------------------------------------------------------------------------
// AttachmentCheck flags file types used to deliver malware or phishing pages.

type AttachmentCheck struct{}

func (AttachmentCheck) Name() string { return "attachments" }

var (
	executableExt = set(".exe", ".scr", ".com", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe",
		".wsf", ".hta", ".ps1", ".msi", ".lnk", ".jar", ".cpl")
	smugglingExt = set(".html", ".htm", ".shtml", ".svg", ".xhtml")
	macroExt     = set(".docm", ".xlsm", ".pptm", ".xlam", ".dotm")
	containerExt = set(".iso", ".img", ".vhd", ".zip", ".rar", ".7z", ".gz", ".cab")
	documentExt  = set(".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt")
)

func (AttachmentCheck) Run(in *Input) []Signal {
	var out []Signal
	for _, a := range in.Msg.Attachments {
		name := strings.ToLower(a.Filename)
		if name == "" {
			continue
		}
		ext := path.Ext(name)
		inner := path.Ext(strings.TrimSuffix(name, ext))
		switch {
		case executableExt[ext] && documentExt[inner]:
			out = append(out, Signal{ID: "double_extension", Severity: SevHigh, Score: 50,
				Evidence: []string{a.Filename}})
		case executableExt[ext]:
			out = append(out, Signal{ID: "executable_attachment", Severity: SevHigh, Score: 45,
				Evidence: []string{a.Filename}})
		case smugglingExt[ext]:
			out = append(out, Signal{ID: "html_attachment", Severity: SevMedium, Score: 30,
				Evidence: []string{a.Filename + " (HTML/SVG can carry a full phishing page)"}})
		case macroExt[ext]:
			out = append(out, Signal{ID: "macro_document", Severity: SevMedium, Score: 30,
				Evidence: []string{a.Filename}})
		case containerExt[ext]:
			out = append(out, Signal{ID: "container_attachment", Severity: SevLow, Score: 10,
				Evidence: []string{a.Filename + " (contents not inspected yet)"}})
		}
	}
	return out
}

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// ---------------------------------------------------------------------------
// LureCheck is a deliberately weak content signal: credential-themed wording
// together with a link. It never decides a verdict on its own (max 10 pts);
// it only tips borderline cases. Wording-based rules are exactly what
// LLM-written phishing evades, which is why they carry little weight.

type LureCheck struct{}

func (LureCheck) Name() string { return "lure" }

var lurePhrases = []string{
	"verify your account", "confirm your identity", "password will expire",
	"unusual sign-in", "account has been suspended", "update your payment",
	"your mailbox is full", "shared a document with you", "invoice attached",
}

func (LureCheck) Run(in *Input) []Signal {
	if len(in.Links) == 0 {
		return nil
	}
	body := strings.ToLower(in.Msg.Subject + " " + in.Msg.TextBody + " " + in.Msg.HTMLBody)
	for _, p := range lurePhrases {
		if strings.Contains(body, p) {
			return []Signal{{ID: "credential_lure", Severity: SevLow, Score: 10,
				Evidence: []string{fmt.Sprintf("phrase %q with a link", p)}}}
		}
	}
	return nil
}
