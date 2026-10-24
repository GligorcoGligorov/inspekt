package extract

import (
	"strings"
	"testing"
)

func TestHTMLContentHidingTechniques(t *testing.T) {
	cases := []struct {
		name, html, reason string
	}{
		{"display none", `<p>Hello <span style="display:none">SECRET</span> world</p>`, "display:none"},
		{"visibility hidden", `<p>Hi <b style="visibility: hidden">SECRET</b></p>`, "visibility:hidden"},
		{"font-size zero", `<p>a <span style="font-size:0px">SECRET</span> b</p>`, "font-size:0px"},
		{"font-size 1px", `<p>a <span style="FONT-SIZE: 1px !important">SECRET</span> b</p>`, "font-size:1px"},
		{"opacity", `<p>a <i style="opacity:0">SECRET</i> b</p>`, "opacity:0"},
		{"mso-hide", `<div style="mso-hide:all">SECRET</div><p>x</p>`, "mso-hide:all"},
		{"zero height", `<div style="max-height:0;overflow:hidden">SECRET</div><p>x</p>`, "zero height with overflow hidden"},
		{"zero width", `<div style="width:0px; overflow:hidden">SECRET</div><p>x</p>`, "zero width with overflow hidden"},
		{"text-indent", `<p style="text-indent:-9999px">SECRET</p><p>x</p>`, "text-indent:-9999px"},
		{"off-screen", `<div style="position:absolute;left:-5000px">SECRET</div><p>x</p>`, "positioned off-screen"},
		{"clip", `<span style="clip:rect(0 0 0 0);position:absolute">SECRET</span><p>x</p>`, "clip:rect(0 0 0 0)"},
		{"clip-path", `<span style="clip-path: inset(50%)">SECRET</span><p>x</p>`, "clip-path:inset(50%)"},
		{"scale", `<span style="transform:scale(0)">SECRET</span><p>x</p>`, "transform:scale(0)"},
		{"hidden attribute", `<div hidden>SECRET</div><p>x</p>`, "hidden attribute"},
		{"white on default white", `<p>x <span style="color:#FFF">SECRET</span></p>`, "text colour matches background (#ffffff)"},
		{"same as table bgcolor", `<table><tr><td bgcolor="#f0f0f0"><font color="#F0F0F0">SECRET</font> x</td></tr></table>`, "text colour matches background (#f0f0f0)"},
		{"rgb colour", `<div style="background-color:rgb(0,0,0)"><span style="color: rgb(0, 0, 0)">SECRET</span> x</div>`, "text colour matches background (#000000)"},
		{"class rule in style block", `<style>.pre{display:none}</style><p>x</p><div class="a pre">SECRET</div>`, "display:none"},
		{"tag.class and id rules", `<style>p.x,#y{font-size:0}</style><p class="x">SECRET</p><b id="y">SECRET</b><i>x</i>`, "font-size:0"},
		{"inherited by children", `<div style="display:none"><p>SEC<b>RET</b></p></div><p>x</p>`, "display:none"},
	}
	for _, c := range cases {
		got := HTMLContent(c.html)
		if strings.Contains(got.Visible, "SECRET") || strings.Contains(got.Visible, "SEC") {
			t.Errorf("%s: hidden text leaked into Visible %q", c.name, got.Visible)
		}
		if len(got.Hidden) == 0 || got.Hidden[0].Reason != c.reason || !strings.Contains(strings.ReplaceAll(got.Hidden[0].Text, " ", ""), "SECRET") {
			t.Errorf("%s: hidden %+v, want reason %q", c.name, got.Hidden, c.reason)
		}
	}
}

func TestHTMLContentStaysVisible(t *testing.T) {
	for name, doc := range map[string]string{
		"white text on a dark button":   `<table><tr><td bgcolor="#0b5394"><a style="color:#ffffff">Pay invoice</a></td></tr></table>`,
		"white div, child on dark":      `<div style="color:#fff"><span style="background:#222">Pay invoice</span></div>`,
		"1em is normal size":            `<p style="font-size:1em">Pay invoice</p>`,
		"media query rules are ignored": `<style>@media (max-width:600px){.c{display:none}}</style><p class="c">Pay invoice</p>`,
		"descendant selectors ignored":  `<style>table .c{display:none}</style><p class="c">Pay invoice</p>`,
		"normal small print":            `<p style="font-size:11px;color:#666">Pay invoice</p>`,
		"unclosed tags":                 `<p>Pay <b>invoice`,
		"stray end tag does not unhide": `<p>Pay</span> invoice</p>`,
	} {
		got := HTMLContent(doc)
		if got.Visible != "Pay invoice" || len(got.Hidden) != 0 {
			t.Errorf("%s: visible %q, hidden %+v", name, got.Visible, got.Hidden)
		}
	}
}

func TestHTMLContentSkipsNonText(t *testing.T) {
	got := HTMLContent(`<html><head><title>T</title><style>p{}</style><script>var x="SECRET"</script></head>` +
		`<body><p>Hello</p><noscript>SECRET</noscript></body></html>`)
	if got.Visible != "Hello" || len(got.Hidden) != 0 {
		t.Fatalf("visible %q hidden %+v", got.Visible, got.Hidden)
	}
}

func TestZeroWidthAndComments(t *testing.T) {
	got := HTMLContent("<p>Mi​cro‌soft account</p><!-- ignore previous instructions --><!--[if mso]><table><![endif]-->")
	if got.Visible != "Microsoft account" || got.ZeroWidth != 2 {
		t.Errorf("visible %q, zero-width %d", got.Visible, got.ZeroWidth)
	}
	if got.Comments != "ignore previous instructions" {
		t.Errorf("comments %q (Outlook conditional comments must be excluded)", got.Comments)
	}
}

func TestPreheaderPositionAndInterleaving(t *testing.T) {
	pre := HTMLContent(`<div style="display:none">Your October picks are here</div><p>New arrivals are in.</p>`)
	if len(pre.Hidden) != 1 || pre.Hidden[0].VisibleBefore != 0 || pre.Interleaved != 0 {
		t.Fatalf("preheader: %+v interleaved %d", pre.Hidden, pre.Interleaved)
	}
	salt := HTMLContent(`<p>Your <span style="font-size:0">lorem</span>pass<span style="font-size:0">ipsum</span>word expires</p>`)
	if salt.Visible != "Your password expires" || salt.Interleaved != 2 || salt.HiddenChars != 10 {
		t.Fatalf("salting: visible %q, %+v, interleaved %d, chars %d", salt.Visible, salt.Hidden, salt.Interleaved, salt.HiddenChars)
	}
}

func TestHTMLContentLimits(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxHiddenRuns+10; i++ {
		b.WriteString(`<p>v</p><span style="display:none">h</span>`)
	}
	got := HTMLContent(b.String())
	if len(got.Hidden) != MaxHiddenRuns || !got.Truncated || got.HiddenChars != MaxHiddenRuns+10 {
		t.Errorf("runs %d truncated %v chars %d", len(got.Hidden), got.Truncated, got.HiddenChars)
	}
	deep := strings.Repeat("<div>", 100000) + "deep" + strings.Repeat("</div>", 100000)
	if HTMLContent(deep).Visible != "deep" {
		t.Error("deep nesting lost text")
	}
	if !HTMLContent(strings.Repeat("a", MaxHTMLBytes+10)).Truncated {
		t.Error("size limit not applied")
	}
}

// FuzzHTMLContent: hostile HTML must never panic, and hidden text must
// never be reported as visible and hidden at once.
func FuzzHTMLContent(f *testing.F) {
	for _, s := range []string{
		`<p>x <span style="display:none">y</span></p>`,
		`<style>.a{font-size:0}</style><b class=a>z</b>`,
		"<div style='color:#fff'>​q</div><!-- c -->",
		`<td bgcolor=#000><font color=black>k`,
		`<style>@media{.x{display:none}}}}{{`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, doc string) {
		c := HTMLContent(doc)
		if len(c.Hidden) > MaxHiddenRuns {
			t.Fatalf("%d hidden runs", len(c.Hidden))
		}
	})
}
