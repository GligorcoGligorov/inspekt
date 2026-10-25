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
	"regexp"
	"sort"
	"strings"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
)

// Indicator kinds.
const (
	LinkHost       = "link_host"
	AttachmentSHA  = "attachment_sha256"
	SenderIP       = "sender_ip"
	SubjectFP      = "subject_fp"
	maxIndicators  = 100 // per scan; a 500-link newsletter must not write 500 rows
	maxValueLength = 255 // the column size
	minSubjectLen  = 8   // characters after normalising
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
	for _, l := range rep.Links {
		if d := analyze.RegistrableDomain(l.Host); d != "" && !Allowlist[d] {
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
