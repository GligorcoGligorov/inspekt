// Package campaign correlates scans that come from the same attack.
//
// Each finished scan yields indicators (link hosts, attachment hashes, the
// sending IP, a fingerprint of the subject). Scans that share an indicator
// belong to the same campaign. This is a correlation layer only: nothing
// here reads or changes a score or a verdict.
package campaign

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/email"
)

// Indicator kinds. Strong kinds link two scans on their own; weak kinds
// only together with a second, different weak kind (see Cluster).
const (
	AttachmentSHA  = "attachment_sha256" // strong: the same file
	FullURL        = "full_url"          // strong: the same page on a shortener or shared hosting
	LinkHost       = "link_host"         // weak
	SenderIP       = "sender_ip"         // weak
	SubjectFP      = "subject_fp"        // weak
	maxIndicators  = 100                 // per scan; a 500-link newsletter must not write 500 rows
	maxValueLength = 255                 // the column size
	minSubjectLen  = 8                   // characters after normalising
)

// Indicator is one correlatable value of a scan.
type Indicator struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// Allowlist holds registrable domains so common in legitimate mail that a
// shared link to them says nothing about a common sender: big platforms and
// standards bodies. Hosts attackers abuse for phishing pages (cloud storage,
// serverless hosting, form builders) are deliberately not here.
var Allowlist = map[string]bool{
	"google.com": true, "microsoft.com": true, "apple.com": true, "facebook.com": true,
	"linkedin.com": true, "youtube.com": true, "w3.org": true, "twitter.com": true, "x.com": true,
	"instagram.com": true, "amazon.com": true, "office.com": true, "outlook.com": true,
	"live.com": true, "wikipedia.org": true, "mozilla.org": true, "gstatic.com": true,
	"youtu.be": true, "whatsapp.com": true, "bing.com": true, "yahoo.com": true,
}

// Strong reports whether one shared value of this kind links two scans.
func Strong(kind string) bool { return kind == AttachmentSHA || kind == FullURL }

// Domain is the registrable domain by the full Public Suffix List
// (golang.org/x/net/publicsuffix), so "shop.co.za" and "bank.co.za" are
// different domains. Campaign extraction only: the scoring checks keep
// analyze.RegistrableDomain, so this cannot move a verdict.
func Domain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return ""
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return host
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return "" // a public suffix itself (co.za) identifies nobody
	}
	return d
}

// fullURL is scheme://host/path with the query, fragment and user info
// dropped: the same phishing page, whatever tracking parameters it carries.
func fullURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	v := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + u.EscapedPath()
	if len(v) > maxValueLength {
		sum := sha256.Sum256([]byte(v))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	return v
}

// Extract returns the de-duplicated, sorted indicators of one analysed message.
func Extract(rep *analyze.Report) []Indicator {
	seen := map[Indicator]bool{}
	var out []Indicator
	add := func(kind, value string) {
		if value == "" || len(value) > maxValueLength || len(out) >= maxIndicators {
			return
		}
		ind := Indicator{kind, value}
		if !seen[ind] {
			seen[ind] = true
			out = append(out, ind)
		}
	}
	// The recipient's own domain shows up in links (unsubscribe pages,
	// personalised URLs); it says who received the mail, not who sent it.
	recipient := map[string]bool{}
	if msg := rep.Message; msg != nil {
		for _, a := range append(append([]email.Address{}, msg.To...), msg.DeliveredTo...) {
			if d := Domain(a.Domain); d != "" {
				recipient[d] = true
			}
		}
	}
	for _, l := range rep.Links {
		// On shorteners and shared hosting the host is shared by everyone;
		// the page is what identifies the campaign.
		if analyze.IsShortener(l.Host) || analyze.AbusedHosting(l) != "" {
			add(FullURL, fullURL(l.URL))
			continue
		}
		if d := Domain(l.Host); d != "" && !Allowlist[d] && !recipient[d] {
			add(LinkHost, d)
		}
	}
	if msg := rep.Message; msg != nil {
		for _, a := range msg.Attachments {
			add(AttachmentSHA, a.SHA256)
		}
		add(SenderIP, FirstExternalIP(msg.Received))
		if n := NormalizeSubject(msg.Subject); len([]rune(n)) >= minSubjectLen {
			sum := sha256.Sum256([]byte(n))
			add(SubjectFP, hex.EncodeToString(sum[:]))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Value < out[j].Value
	})
	return out
}

var (
	replyPrefix = regexp.MustCompile(`^(re|fw|fwd)\s*:\s*`)
	digits      = regexp.MustCompile(`[0-9]+`)
)

// NormalizeSubject makes subjects from one campaign compare equal:
// lowercase, reply/forward prefixes removed, every run of digits replaced
// by "#", spaces collapsed. "RE: Invoice 4471 overdue" and
// "invoice 12 overdue" both become "invoice # overdue".
func NormalizeSubject(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	for {
		t := replyPrefix.ReplaceAllString(s, "")
		if t == s {
			break
		}
		s = strings.TrimSpace(t)
	}
	s = digits.ReplaceAllString(s, "#")
	return strings.Join(strings.Fields(s), " ")
}

var (
	fromBy     = regexp.MustCompile(`(?i)\sby\s`)
	bracketIP  = regexp.MustCompile(`\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]`)
	bareIPv4   = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)
	cgnat      = netip.MustParsePrefix("100.64.0.0/10")
	docNets    = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	benchmark  = netip.MustParsePrefix("198.18.0.0/15")
	sharedNets = append([]netip.Prefix{cgnat, benchmark}, docNets...)
)

// FirstExternalIP returns the first public IP in the "from" part of the
// Received headers, read top-down (the newest hop first). Private,
// loopback, link-local, CGNAT and documentation addresses are skipped:
// they are someone's internal network, not a sender.
func FirstExternalIP(received []string) string {
	for _, h := range received {
		if loc := fromBy.FindStringIndex(h); loc != nil {
			h = h[:loc[0]]
		}
		cands := bracketIP.FindAllStringSubmatch(h, -1)
		for _, m := range bareIPv4.FindAllStringSubmatch(h, -1) {
			cands = append(cands, m)
		}
		for _, m := range cands {
			ip, err := netip.ParseAddr(m[1])
			if err != nil {
				continue
			}
			ip = ip.Unmap()
			if public(ip) {
				return ip.String()
			}
		}
	}
	return ""
}

func public(ip netip.Addr) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, p := range sharedNets {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
