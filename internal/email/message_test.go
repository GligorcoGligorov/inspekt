package email

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func parse(t *testing.T, raw string) *Message {
	t.Helper()
	m, err := Parse(strings.NewReader(raw), DefaultLimits)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return m
}

func TestParseHeadersAndEncodedSubject(t *testing.T) {
	m := parse(t, "From: \"Ana\" <Ana@Example.COM>\r\n"+
		"Reply-To: other@elsewhere.net\r\n"+
		"Subject: =?utf-8?B?0JfQtNGA0LDQstC+?=\r\n\r\nhi\r\n")
	if m.From == nil || m.From.Email != "ana@example.com" || m.From.Domain != "example.com" {
		t.Fatalf("From = %+v", m.From)
	}
	if m.ReplyTo == nil || m.ReplyTo.Domain != "elsewhere.net" {
		t.Fatalf("ReplyTo = %+v", m.ReplyTo)
	}
	if m.Subject != "Здраво" {
		t.Fatalf("Subject = %q", m.Subject)
	}
}

func TestParseMultipartWithAttachment(t *testing.T) {
	raw := "From: a@b.com\r\nContent-Type: multipart/mixed; boundary=X\r\n\r\n" +
		"--X\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nhello=20world\r\n" +
		"--X\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"../../etc/a.pdf\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\naGVs\r\nbG8=\r\n--X--\r\n"
	m := parse(t, raw)
	if !strings.Contains(m.TextBody, "hello world") {
		t.Errorf("TextBody = %q", m.TextBody)
	}
	if len(m.Attachments) != 1 {
		t.Fatalf("attachments = %d", len(m.Attachments))
	}
	a := m.Attachments[0]
	if a.Filename != "a.pdf" { // path traversal stripped
		t.Errorf("Filename = %q", a.Filename)
	}
	if string(a.Data) != "hello" || a.Size != 5 {
		t.Errorf("Data = %q size %d", a.Data, a.Size)
	}
	if a.SHA256 != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Errorf("SHA256 = %s", a.SHA256)
	}
}

func TestLimits(t *testing.T) {
	t.Run("size", func(t *testing.T) {
		_, err := Parse(strings.NewReader("Subject: x\r\n\r\n"+strings.Repeat("a", 200)), Limits{MaxBytes: 100, MaxParts: 10, MaxDepth: 5})
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("depth", func(t *testing.T) {
		// Build multipart nested 20 levels deep.
		var b bytes.Buffer
		b.WriteString("Content-Type: multipart/mixed; boundary=b0\r\n\r\n")
		for i := 0; i < 20; i++ {
			fmt.Fprintf(&b, "--b%d\r\nContent-Type: multipart/mixed; boundary=b%d\r\n\r\n", i, i+1)
		}
		_, err := Parse(&b, DefaultLimits)
		if !errors.Is(err, ErrTooDeep) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("parts", func(t *testing.T) {
		var b bytes.Buffer
		b.WriteString("Content-Type: multipart/mixed; boundary=X\r\n\r\n")
		for i := 0; i < 50; i++ {
			b.WriteString("--X\r\nContent-Type: text/plain\r\n\r\nx\r\n")
		}
		b.WriteString("--X--\r\n")
		_, err := Parse(&b, Limits{MaxBytes: 1 << 20, MaxParts: 10, MaxDepth: 5})
		if !errors.Is(err, ErrTooManyParts) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestMalformedInputDoesNotFail(t *testing.T) {
	// Broken boundary and garbage Content-Type: we warn and keep going.
	m := parse(t, "From: a@b.com\r\nContent-Type: multipart/mixed\r\n\r\nbody")
	if len(m.Warnings) == 0 {
		t.Fatal("expected a parse warning")
	}
}

// FuzzParse checks that no input can panic the parser. Run locally with:
//
//	go test ./internal/email -fuzz=FuzzParse -fuzztime=60s
func FuzzParse(f *testing.F) {
	f.Add("From: a@b.com\r\nSubject: x\r\n\r\nbody")
	f.Add("Content-Type: multipart/mixed; boundary=X\r\n\r\n--X\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!\r\n--X--")
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = Parse(strings.NewReader(raw), Limits{MaxBytes: 1 << 16, MaxParts: 20, MaxDepth: 5})
	})
}

func TestDeliveredTo(t *testing.T) {
	m, err := Parse(strings.NewReader("Delivered-To: jose@monkey.org\r\nDelivered-To: not an address\r\nTo: x@example.org\r\nSubject: s\r\n\r\nb"), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.DeliveredTo) != 1 || m.DeliveredTo[0].Domain != "monkey.org" {
		t.Fatalf("delivered-to %+v", m.DeliveredTo)
	}
}
