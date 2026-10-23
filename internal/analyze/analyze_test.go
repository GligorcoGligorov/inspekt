package analyze

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/GligorcoGligorov/inspekt/internal/email"
)

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"login.secure.example.com": "example.com",
		"example.com":              "example.com",
		"mail.example.co.uk":       "example.co.uk",
		"www.finki.ukim.edu.mk":    "ukim.edu.mk",
		"198.51.100.23":            "198.51.100.23",
		"Example.COM.":             "example.com",
	}
	for in, want := range cases {
		if got := RegistrableDomain(in); got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLookalike(t *testing.T) {
	protected := DefaultConfig.ProtectedDomains
	cases := []struct {
		domain string
		hit    bool
		kind   LookalikeKind
	}{
		{"paypa1.com", true, KindHomoglyph},
		{"rnicrosoft.com", true, KindHomoglyph},
		{"micosoft.com", true, KindTypo},
		{"login-micros0ft.com", true, KindEmbedded},
		{"paypal-secure-login.com", true, KindEmbedded},
		// Must NOT fire:
		{"paypal.com", false, ""},
		{"www.paypal.com", false, ""},
		{"microsoftonline.com", false, ""}, // real Microsoft domain
		{"pineapple.com", false, ""},
		{"example.org", false, ""},
	}
	for _, c := range cases {
		_, kind, hit := Lookalike(c.domain, protected)
		if hit != c.hit || kind != c.kind {
			t.Errorf("Lookalike(%q) = (%v, %q), want (%v, %q)", c.domain, hit, kind, c.hit, c.kind)
		}
	}
}

func TestLevenshtein(t *testing.T) {
	for _, c := range []struct {
		a, b string
		d    int
	}{{"", "", 0}, {"abc", "abc", 0}, {"kitten", "sitting", 3}, {"paypal", "paypa1", 1}} {
		if got := levenshtein(c.a, c.b); got != c.d {
			t.Errorf("levenshtein(%q,%q)=%d want %d", c.a, c.b, got, c.d)
		}
	}
}

func TestAuthCheckTrustsOnlyOwnMTA(t *testing.T) {
	msg := &email.Message{AuthResults: []string{
		"evil.example; dmarc=fail", // forged by the sender: ignored
		"mx.inspekt.local; spf=pass; dmarc=pass",
	}}
	sigs := AuthCheck{Trusted: []string{"mx.inspekt.local"}}.Run(&Input{Msg: msg})
	if len(sigs) != 0 {
		t.Fatalf("forged Authentication-Results was trusted: %+v", sigs)
	}
}

func TestMergeKeepsHighestScoreOnce(t *testing.T) {
	out := merge([]Signal{
		{ID: "x", Score: 10, Evidence: []string{"a"}},
		{ID: "x", Score: 30, Evidence: []string{"b"}},
		{ID: "y", Score: 5, Evidence: []string{"c"}},
	})
	if len(out) != 2 || out[0].ID != "x" || out[0].Score != 30 || len(out[0].Evidence) != 2 {
		t.Fatalf("unexpected merge result: %+v", out)
	}
}

// TestSamples is an end-to-end golden test over testdata/.
func TestSamples(t *testing.T) {
	cases := []struct {
		file        string
		want        Verdict
		mustContain []string
	}{
		{"clean_newsletter.eml", VerdictClean, nil},
		{"phish_lookalike.eml", VerdictMalicious,
			[]string{"dmarc_fail", "link_text_mismatch", "display_name_spoof", "lookalike_sender", "lookalike_link"}},
		{"malware_attachment.eml", VerdictMalicious, []string{"double_extension", "html_attachment"}},
		// Known gap: a text-only BEC from a correctly authenticated domain
		// has almost no technical signals. Rules alone cannot catch it;
		// this is what the LLM stage (WEEKEND_PLAN step 6) is for.
		{"bec_reply_to.eml", VerdictClean, []string{"reply_to_mismatch"}},
	}
	eng := New(DefaultConfig)
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			f, err := os.Open(filepath.Join("..", "..", "testdata", c.file))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			msg, err := email.Parse(f, email.DefaultLimits)
			if err != nil {
				t.Fatal(err)
			}
			rep := eng.Analyze(msg)
			if rep.Verdict != c.want {
				t.Errorf("verdict %s (score %d), want %s; signals: %+v", rep.Verdict, rep.Score, c.want, rep.Signals)
			}
			got := map[string]bool{}
			for _, s := range rep.Signals {
				got[s.ID] = true
			}
			for _, id := range c.mustContain {
				if !got[id] {
					t.Errorf("missing signal %s", id)
				}
			}
		})
	}
}
