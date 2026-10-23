package analyze

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// AuthCheck reads SPF / DKIM / DMARC results stamped by an upstream MTA.
// Saturday's work adds our own verification (see docs/WEEKEND_PLAN.md);
// this check stays as the cheap first signal.

type AuthCheck struct{ Trusted []string }

func (AuthCheck) Name() string { return "auth" }

var authResult = regexp.MustCompile(`(?i)\b(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none|temperror|permerror)\b`)

func (c AuthCheck) Run(in *Input) []Signal {
	var out []Signal
	for _, h := range in.Msg.AuthResults {
		if !c.trusted(h) {
			continue
		}
		for _, m := range authResult.FindAllStringSubmatch(h, -1) {
			mech, res := strings.ToLower(m[1]), strings.ToLower(m[2])
			ev := fmt.Sprintf("%s=%s", mech, res)
			switch {
			case mech == "dmarc" && res == "fail":
				out = append(out, Signal{ID: "dmarc_fail", Severity: SevHigh, Score: 35, Evidence: []string{ev}})
			case mech == "spf" && res == "fail":
				out = append(out, Signal{ID: "spf_fail", Severity: SevMedium, Score: 15, Evidence: []string{ev}})
			case mech == "spf" && res == "softfail":
				out = append(out, Signal{ID: "spf_softfail", Severity: SevLow, Score: 8, Evidence: []string{ev}})
			case mech == "dkim" && res == "fail":
				out = append(out, Signal{ID: "dkim_fail", Severity: SevMedium, Score: 15, Evidence: []string{ev}})
			}
		}
	}
	return out
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
	for _, l := range in.Links {
		if l.IsIP {
			out = append(out, Signal{ID: "ip_literal_url", Severity: SevMedium, Score: 25,
				Evidence: []string{l.URL}})
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
