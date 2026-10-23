package analyze

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GligorcoGligorov/inspekt/internal/email"
)

// benchInputs are the sample messages plus one stress case: an HTML
// newsletter with 300 links, the shape that makes link extraction work.
func benchInputs(b *testing.B) map[string][]byte {
	b.Helper()
	files, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "*.eml"))
	in := map[string][]byte{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			b.Fatal(err)
		}
		in[strings.TrimSuffix(filepath.Base(f), ".eml")] = raw
	}
	var html strings.Builder
	for i := range 300 {
		fmt.Fprintf(&html, `<p><a href="https://shop%d.example.com/p/%d?utm_source=nl">Product %d</a></p>`+"\n", i%20, i, i)
	}
	in["newsletter_300_links"] = []byte("From: News <news@shop.example.com>\r\nSubject: Deals\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + html.String())
	return in
}

// BenchmarkParse measures MIME parsing alone.
func BenchmarkParse(b *testing.B) {
	for name, raw := range benchInputs(b) {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := email.Parse(bytes.NewReader(raw), email.DefaultLimits); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkAnalyze measures everything after parsing: link extraction,
// QR decoding and all checks (headers auth mode, no network).
func BenchmarkAnalyze(b *testing.B) {
	eng := New(DefaultConfig)
	for name, raw := range benchInputs(b) {
		msg, err := email.Parse(bytes.NewReader(raw), email.DefaultLimits)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				eng.Analyze(msg)
			}
		})
	}
}
