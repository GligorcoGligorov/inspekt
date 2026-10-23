package analyze

import (
	"net"
	"strings"
)

// multiLabelSuffixes is a deliberately small stand-in for the Public Suffix
// List. It covers the suffixes that appear in the test corpora. On a machine
// with network access, swap RegistrableDomain for
// golang.org/x/net/publicsuffix.EffectiveTLDPlusOne.
var multiLabelSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true,
	"com.au": true, "co.jp": true, "co.nz": true, "co.in": true,
	"com.br": true, "com.mx": true, "com.tr": true,
	"com.mk": true, "org.mk": true, "edu.mk": true, "gov.mk": true,
}

// RegistrableDomain returns the part of host an organisation actually
// registers: "login.secure.example.co.uk" -> "example.co.uk".
func RegistrableDomain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || net.ParseIP(host) != nil {
		return host
	}
	labels := strings.Split(host, ".")
	n := len(labels)
	if n <= 2 {
		return host
	}
	if multiLabelSuffixes[labels[n-2]+"."+labels[n-1]] {
		return strings.Join(labels[n-3:], ".")
	}
	return strings.Join(labels[n-2:], ".")
}

// brandLabel is the registrable domain without its public suffix:
// "paypal.com" -> "paypal", "example.co.uk" -> "example".
func brandLabel(registrable string) string {
	if i := strings.IndexByte(registrable, '.'); i > 0 {
		return registrable[:i]
	}
	return registrable
}

// homoglyphs folds characters attackers commonly swap in for one another.
// Multi-character sequences are replaced first.
var homoglyphs = strings.NewReplacer(
	"rn", "m", "vv", "w", "cl", "d",
	"0", "o", "1", "l", "3", "e", "5", "s", "7", "t", "@", "a",
	"i", "l", // capital I vs lower l are indistinguishable in many fonts
	"-", "",
)

// skeleton maps a label to a canonical form so that visually confusable
// labels collide: "paypa1" and "paypal" share a skeleton.
func skeleton(label string) string { return homoglyphs.Replace(strings.ToLower(label)) }

// levenshtein is the classic edit distance, O(len(a)*len(b)) time and
// O(len(b)) space. Labels are short, so this is cheap.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}

// LookalikeKind describes how a domain imitates a protected one.
type LookalikeKind string

const (
	KindHomoglyph LookalikeKind = "homoglyph" // paypa1.com, rnicrosoft.com
	KindTypo      LookalikeKind = "typo"      // micosoft.com
	KindEmbedded  LookalikeKind = "embedded"  // microsoft-account-verify.com
)

// Lookalike reports whether registrable domain d imitates any protected
// domain, and which one. An exact match is not a lookalike.
func Lookalike(d string, protected []string) (target string, kind LookalikeKind, ok bool) {
	d = RegistrableDomain(d)
	label := brandLabel(d)
	for _, p := range protected {
		p = RegistrableDomain(p)
		if d == p {
			return "", "", false // the real thing; stop looking
		}
	}
	for _, p := range protected {
		p = RegistrableDomain(p)
		pl := brandLabel(p)
		if len(pl) < 4 {
			continue // short brands produce too many false positives
		}
		switch {
		case label != pl && skeleton(label) == skeleton(pl):
			return p, KindHomoglyph, true
		case levenshtein(label, pl) <= typoBudget(pl):
			return p, KindTypo, true
		}
		// Brand used as one hyphen-separated token: "login-micros0ft",
		// "paypal-secure". Matching whole tokens (not substrings) keeps
		// "pineapple" from matching "apple" and leaves the real
		// "microsoftonline.com" alone.
		if strings.Contains(label, "-") {
			for _, tok := range strings.Split(label, "-") {
				if tok == pl || (len(tok) >= 4 && skeleton(tok) == skeleton(pl)) {
					return p, KindEmbedded, true
				}
			}
		}
	}
	return "", "", false
}

func typoBudget(brand string) int {
	switch {
	case len(brand) >= 9:
		return 2
	case len(brand) >= 5:
		return 1
	default:
		return 0
	}
}
