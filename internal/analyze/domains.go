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
	if host == "" || (mayBeIP(host) && net.ParseIP(host) != nil) {
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

// mayBeIP is a cheap pre-check before net.ParseIP, which allocates. It never
// rejects a real IP literal (IPv4 ends in a digit, IPv6 contains a colon);
// it only spares the call for ordinary names, which end in a letter.
func mayBeIP(host string) bool {
	c := host[len(host)-1]
	return strings.IndexByte(host, ':') >= 0 || ('0' <= c && c <= '9')
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
	return newBrands(protected).match(d)
}

// brand is a protected domain with its derived forms computed once, not
// once per link (profiling showed that repeated work was ~90 % of the
// engine's allocations on link-heavy mail).
type brand struct{ domain, label, skel string }

type brands []brand

func newBrands(protected []string) brands {
	out := make(brands, 0, len(protected))
	for _, p := range protected {
		d := RegistrableDomain(p)
		l := brandLabel(d)
		out = append(out, brand{domain: d, label: l, skel: skeleton(l)})
	}
	return out
}

func (bs brands) match(host string) (target string, kind LookalikeKind, ok bool) {
	d := RegistrableDomain(host)
	for _, b := range bs {
		if d == b.domain {
			return "", "", false // the real thing; stop looking
		}
	}
	label := brandLabel(d)
	skel := skeleton(label)
	// Brand used as one hyphen-separated token: "login-micros0ft",
	// "paypal-secure". Matching whole tokens (not substrings) keeps
	// "pineapple" from matching "apple" and leaves the real
	// "microsoftonline.com" alone.
	var toks, tokSkels []string
	if strings.Contains(label, "-") {
		toks = strings.Split(label, "-")
		tokSkels = make([]string, len(toks))
		for i, t := range toks {
			if len(t) >= 4 {
				tokSkels[i] = skeleton(t)
			}
		}
	}
	for _, b := range bs {
		if len(b.label) < 4 {
			continue // short brands produce too many false positives
		}
		switch {
		case label != b.label && skel == b.skel:
			return b.domain, KindHomoglyph, true
		case withinEdits(label, b.label, typoBudget(b.label)):
			return b.domain, KindTypo, true
		}
		for i, tok := range toks {
			if tok == b.label || (tokSkels[i] != "" && tokSkels[i] == b.skel) {
				return b.domain, KindEmbedded, true
			}
		}
	}
	return "", "", false
}

// withinEdits is levenshtein(a, b) <= budget, skipping the O(n·m) work when
// the length difference alone already exceeds the budget.
func withinEdits(a, b string, budget int) bool {
	if d := len(a) - len(b); d > budget || -d > budget {
		return false
	}
	return levenshtein(a, b) <= budget
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
