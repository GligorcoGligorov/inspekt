package extract

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// Content is an HTML body split by what a reader can actually see.
//
// Attackers hide text with CSS ("hidden text salting", Cisco Talos) to
// dilute or fake what content filters read, and hide instructions for AI
// email assistants (EchoLeak). The checks therefore read Visible, and
// Hidden is evidence in its own right.
//
// This is not a CSS engine. It understands inline styles, the hidden
// attribute, and simple <style> rules (.class, #id, tag, tag.class) outside
// @media/@supports blocks; anything else (descendant selectors, external
// stylesheets, computed layout, images of text) is out of scope and counts
// as visible.
type Content struct {
	Visible     string      // text a reader sees, whitespace collapsed, invisible characters removed
	Hidden      []HiddenRun // hidden text in document order (capped at MaxHiddenRuns)
	HiddenChars int         // letters and digits in all hidden text, stored or not
	Interleaved int         // hidden runs with visible text both before and after them
	ZeroWidth   int         // invisible format characters (zero-width space, joiner, ...)
	Comments    string      // HTML comment text, Outlook conditional comments excluded (capped)
	Truncated   bool        // a limit was hit; the rest of the input was not read
}

// HiddenRun is one stretch of hidden text and why it is hidden.
type HiddenRun struct {
	Text   string `json:"text"`
	Reason string `json:"reason"`
	// VisibleBefore is how many visible characters precede the run: a
	// preheader sits at 0, salting is scattered through the text.
	VisibleBefore int `json:"visible_before"`
}

// Limits on work per message. The parser streams; nothing builds a tree.
const (
	MaxHTMLBytes   = 2 << 20 // bytes of HTML read
	MaxDepth       = 512     // open elements tracked; deeper ones inherit their parent's state
	MaxHiddenRuns  = 64
	MaxRunChars    = 2000
	MaxVisibleRune = 1 << 20
	MaxCommentRune = 4000
	maxStyleRules  = 2000
)

// Elements whose content is never rendered as body text.
var nonText = map[string]bool{"script": true, "style": true, "head": true, "title": true,
	"noscript": true, "template": true, "object": true, "iframe": true}

var voidElements = map[string]bool{"area": true, "base": true, "br": true, "col": true, "embed": true,
	"hr": true, "img": true, "input": true, "link": true, "meta": true, "source": true, "track": true, "wbr": true}

type frame struct {
	tag    string
	hidden string // reason, "" if visible
	bg     string // background colour in effect (normalised); "" or unknownBg if not known
	color  string // text colour in effect (inherited separately from bg)
	skip   bool   // inside script/style/head...
}

// HTMLContent splits doc into visible and hidden text.
func HTMLContent(doc string) Content {
	var c Content
	if len(doc) > MaxHTMLBytes {
		doc, c.Truncated = doc[:MaxHTMLBytes], true
	}
	rules := styleRules(doc)
	var vis, comments strings.Builder
	visRunes := 0
	stack := []frame{{tag: "#root"}}
	var cur *HiddenRun // run being extended by adjacent hidden text

	z := html.NewTokenizer(strings.NewReader(doc))
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			c.Visible = strings.Join(strings.Fields(vis.String()), " ")
			c.Comments = strings.TrimSpace(comments.String())
			for i := range c.Hidden {
				c.Hidden[i].Text = strings.Join(strings.Fields(c.Hidden[i].Text), " ")
			}
			c.Interleaved = countInterleaved(c.Hidden, utf8.RuneCountInString(c.Visible))
			return c

		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := string(name)
			parent := stack[len(stack)-1]
			f := frame{tag: tag, hidden: parent.hidden, bg: parent.bg, color: parent.color, skip: parent.skip || nonText[tag]}
			var style, class, id string
			var hiddenAttr bool
			for hasAttr {
				var k, v []byte
				k, v, hasAttr = z.TagAttr()
				switch string(k) {
				case "style":
					style = string(v)
				case "class":
					class = string(v)
				case "id":
					id = string(v)
				case "bgcolor":
					if bg := normColor(string(v)); bg != "" {
						f.bg = bg
					}
				case "background": // an image: the colour behind the text is unknown
					f.bg = unknownBg
				case "color": // <font color=...>
					if col := normColor(string(v)); col != "" {
						f.color = col
					}
				case "hidden":
					hiddenAttr = true
				}
			}
			decls := rules.match(tag, class, id) + ";" + style
			why, bg, col := hiddenBy(decls)
			if bg != "" {
				f.bg = bg
			}
			if col != "" {
				f.color = col
			}
			if f.hidden == "" {
				if hiddenAttr {
					f.hidden = "hidden attribute"
				} else {
					f.hidden = why
				}
			}
			if tt == html.StartTagToken && !voidElements[tag] && len(stack) < MaxDepth {
				stack = append(stack, f)
			}

		case html.EndTagToken:
			name, _ := z.TagName()
			for i := len(stack) - 1; i > 0; i-- { // close up to the matching element, if open
				if stack[i].tag == string(name) {
					stack = stack[:i]
					break
				}
			}

		case html.CommentToken:
			text := string(z.Text())
			if t := strings.TrimSpace(text); strings.HasPrefix(t, "[if") || strings.HasPrefix(t, "<![endif]") || strings.HasPrefix(t, "[endif]") {
				continue // Outlook conditional comments: markup, not prose
			}
			if utf8.RuneCountInString(comments.String()) < MaxCommentRune {
				comments.WriteString(text)
				comments.WriteByte(' ')
			}

		case html.TextToken:
			top := stack[len(stack)-1]
			if top.skip {
				continue
			}
			if top.hidden == "" && top.color != "" && top.color == top.bg && top.bg != unknownBg {
				top.hidden = "text colour matches background (" + top.color + ")"
			}
			raw := string(z.Text())
			text, zw := stripInvisible(raw)
			c.ZeroWidth += zw
			if strings.TrimSpace(text) == "" {
				if top.hidden == "" && text != "" {
					vis.WriteByte(' ')
				}
				continue
			}
			if top.hidden == "" {
				cur = nil
				if visRunes < MaxVisibleRune {
					vis.WriteString(text)
					visRunes += utf8.RuneCountInString(text)
				} else {
					c.Truncated = true
				}
				continue
			}
			c.HiddenChars += alnum(text)
			if cur != nil && cur.Reason == top.hidden {
				if utf8.RuneCountInString(cur.Text) < MaxRunChars {
					cur.Text += " " + text
				}
				continue
			}
			if len(c.Hidden) >= MaxHiddenRuns {
				c.Truncated = true
				continue
			}
			c.Hidden = append(c.Hidden, HiddenRun{Text: truncateRunes(text, MaxRunChars), Reason: top.hidden,
				VisibleBefore: utf8.RuneCountInString(strings.Join(strings.Fields(vis.String()), " "))})
			cur = &c.Hidden[len(c.Hidden)-1]
		}
	}
}

func countInterleaved(runs []HiddenRun, visible int) int {
	n := 0
	for _, r := range runs {
		if r.VisibleBefore > 0 && r.VisibleBefore < visible {
			n++
		}
	}
	return n
}

// Invisible format characters used to split words without a visible trace.
func isInvisible(r rune) bool {
	switch r {
	case 0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, 0x00ad, 0x034f, 0x180e, // zero-width space/joiners, word joiner, BOM, soft hyphen, CGJ, MVS
		0x2061, 0x2062, 0x2063, 0x2064, // invisible math operators
		0x206a, 0x206b, 0x206c, 0x206d, 0x206e, 0x206f: // deprecated format characters
		return true
	}
	return false
}

// StripInvisible removes invisible format characters and counts them.
func StripInvisible(s string) (string, int) { return stripInvisible(s) }

func stripInvisible(s string) (string, int) {
	n := 0
	for _, r := range s {
		if isInvisible(r) {
			n++
		}
	}
	if n == 0 {
		return s, 0
	}
	return strings.Map(func(r rune) rune {
		if isInvisible(r) {
			return -1
		}
		return r
	}, s), n
}

func alnum(s string) int {
	n := 0
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			n++
		}
	}
	return n
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// ---------------------------------------------------------------------------
// CSS: just enough to see what is hidden.

var (
	declRe   = regexp.MustCompile(`(?i)([a-z-]+)\s*:\s*([^;]+)`)
	pxRe     = regexp.MustCompile(`^(-?[0-9.]+)\s*(px|pt|em|rem|%|)$`)
	styleTag = regexp.MustCompile(`(?is)<style[^>]*>(.*?)</style>`)
	cssComm  = regexp.MustCompile(`(?s)/\*.*?\*/`)
)

// hiddenBy reports why declarations hide an element ("" if they don't),
// plus the background and text colours they set ("" if not set). Colour
// matching is decided per text node, from the inherited values.
func hiddenBy(decls string) (reason, bg, color string) {
	props := map[string]string{}
	for _, m := range declRe.FindAllStringSubmatch(decls, -1) {
		v := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(m[2]), "!important"))
		props[strings.ToLower(m[1])] = strings.ToLower(v)
	}
	switch {
	case strings.Contains(props["background"], "url(") || strings.Contains(props["background"], "gradient") ||
		strings.Contains(props["background-image"], "url(") || strings.Contains(props["background-image"], "gradient"):
		bg = unknownBg // an image or gradient: the colour behind the text is unknown
	case props["background-color"] != "":
		bg = normColor(props["background-color"])
	default:
		if f := strings.Fields(props["background"]); len(f) > 0 {
			bg = normColor(f[0])
		}
	}
	color = normColor(props["color"])
	overflowHidden := props["overflow"] == "hidden"
	switch {
	case props["display"] == "none":
		return "display:none", bg, color
	case props["visibility"] == "hidden" || props["visibility"] == "collapse":
		return "visibility:hidden", bg, color
	case props["mso-hide"] == "all":
		return "mso-hide:all", bg, color
	case tinyFont(props["font-size"]):
		return "font-size:" + props["font-size"], bg, color
	case numberAtMost(props["opacity"], 0.1):
		return "opacity:" + props["opacity"], bg, color
	case overflowHidden && (zeroLength(props["max-height"]) || zeroLength(props["height"])):
		return "zero height with overflow hidden", bg, color
	case overflowHidden && (zeroLength(props["max-width"]) || zeroLength(props["width"])):
		return "zero width with overflow hidden", bg, color
	case farNegative(props["text-indent"]):
		return "text-indent:" + props["text-indent"], bg, color
	case (props["position"] == "absolute" || props["position"] == "fixed") &&
		(farNegative(props["left"]) || farNegative(props["top"])):
		return "positioned off-screen", bg, color
	case strings.HasPrefix(props["clip"], "rect(0") || strings.HasPrefix(props["clip"], "rect(1px"):
		return "clip:" + props["clip"], bg, color
	case strings.Contains(props["clip-path"], "inset(50%") || strings.Contains(props["clip-path"], "inset(100%") ||
		strings.Contains(props["clip-path"], "circle(0"):
		return "clip-path:" + props["clip-path"], bg, color
	case strings.Contains(props["transform"], "scale(0)"):
		return "transform:scale(0)", bg, color
	case props["color"] == "transparent":
		return "color:transparent", bg, color
	}
	return "", bg, color
}

// length parses "12px", "-9999pt", "0.1em", "50%", "0" into a number and
// unit; ok is false for anything else (calc(), var(), keywords).
func length(v string) (n float64, unit string, ok bool) {
	m := pxRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return 0, "", false
	}
	f, err := strconv.ParseFloat(m[1], 64)
	return f, m[2], err == nil
}

// tinyFont: text too small to read. Thresholds per unit, so 1em is normal.
func tinyFont(v string) bool {
	n, unit, ok := length(v)
	if !ok {
		return false
	}
	switch unit {
	case "", "px", "pt":
		return n <= 1
	case "em", "rem":
		return n <= 0.1
	case "%":
		return n <= 10
	}
	return false
}

func zeroLength(v string) bool {
	n, _, ok := length(v)
	return ok && n <= 0
}

// farNegative: pushed at least ~500px off-screen.
func farNegative(v string) bool {
	n, unit, ok := length(v)
	if !ok {
		return false
	}
	switch unit {
	case "em", "rem":
		n *= 16
	case "%":
		return n <= -100
	}
	return n <= -500
}

func numberAtMost(v string, limit float64) bool {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	return err == nil && f <= limit
}

// unknownBg marks a background whose colour cannot be known (an image or a
// gradient). The root starts with no known background either: white text
// counts as hidden only against a background the email itself declares.
const unknownBg = "?"

var namedColors = map[string]string{"white": "#ffffff", "black": "#000000", "red": "#ff0000",
	"blue": "#0000ff", "green": "#008000", "gray": "#808080", "grey": "#808080", "silver": "#c0c0c0"}

// normColor turns #fff, #FFFFFF, white and rgb(255,255,255) into "#ffffff";
// anything else (gradients, images, var()) is "" (unknown).
func normColor(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if c, ok := namedColors[v]; ok {
		return c
	}
	if strings.HasPrefix(v, "#") {
		h := v[1:]
		if len(h) == 3 {
			h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
		}
		if len(h) == 6 {
			if _, err := strconv.ParseUint(h, 16, 32); err == nil {
				return "#" + h
			}
		}
		return ""
	}
	if strings.HasPrefix(v, "rgb(") && strings.HasSuffix(v, ")") {
		parts := strings.Split(v[4:len(v)-1], ",")
		if len(parts) != 3 {
			return ""
		}
		var b strings.Builder
		b.WriteByte('#')
		for _, p := range parts {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || n < 0 || n > 255 {
				return ""
			}
			b.WriteString(strconv.FormatInt(int64(n)|0x100, 16)[1:])
		}
		return b.String()
	}
	return ""
}

type cssRule struct {
	tag, class, id string
	decls          string
}

type cssRules []cssRule

// styleRules reads simple rules from <style> blocks: .class, #id, tag,
// tag.class, tag#id. Rules inside @media/@supports are skipped on purpose:
// responsive emails hide columns there for small screens.
func styleRules(doc string) cssRules {
	var out cssRules
	for _, m := range styleTag.FindAllStringSubmatch(doc, -1) {
		css := cssComm.ReplaceAllString(m[1], "")
		depth, start := 0, 0
		var selectors string
		for i := 0; i < len(css) && len(out) < maxStyleRules; i++ {
			switch css[i] {
			case '{':
				if depth == 0 {
					selectors = strings.TrimSpace(css[start:i])
					start = i + 1
				}
				depth++
			case '}':
				depth--
				if depth == 0 {
					body := css[start:i]
					if !strings.HasPrefix(selectors, "@") && !strings.Contains(body, "{") {
						for _, sel := range strings.Split(selectors, ",") {
							if r, ok := parseSelector(strings.TrimSpace(sel)); ok {
								r.decls = body
								out = append(out, r)
							}
						}
					}
					start = i + 1
				}
				if depth < 0 {
					depth = 0
				}
			}
		}
	}
	return out
}

var simpleSel = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9]*)?(?:([.#])([a-zA-Z0-9_-]+))?$`)

func parseSelector(s string) (cssRule, bool) {
	m := simpleSel.FindStringSubmatch(s)
	if m == nil || (m[1] == "" && m[2] == "") {
		return cssRule{}, false
	}
	r := cssRule{tag: strings.ToLower(m[1])}
	switch m[2] {
	case ".":
		r.class = m[3]
	case "#":
		r.id = m[3]
	}
	return r, true
}

func (rs cssRules) match(tag, class, id string) string {
	if len(rs) == 0 {
		return ""
	}
	classes := strings.Fields(class)
	var b strings.Builder
	for _, r := range rs {
		if r.tag != "" && r.tag != tag {
			continue
		}
		if r.class != "" && !containsStr(classes, r.class) {
			continue
		}
		if r.id != "" && r.id != id {
			continue
		}
		b.WriteString(r.decls)
		b.WriteByte(';')
	}
	return b.String()
}

func containsStr(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
