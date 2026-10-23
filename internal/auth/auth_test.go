package auth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/GligorcoGligorov/inspekt/internal/auth/authtest"
	"github.com/GligorcoGligorov/inspekt/internal/email"
)

// A fixed seed keeps the key, and so every signature, reproducible.
var testKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))

const dkimSelector = "s1"

func dkimRecord() string {
	return "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(testKey.Public().(ed25519.PublicKey))
}

// message builds a raw CRLF message received from ip / helo.
func message(from, returnPath, ip, helo, body string) []byte {
	lines := []string{
		"Received: from " + helo + " (" + helo + " [" + ip + "]) by mx.inspekt.local with ESMTPS id 4XyZ; Thu, 22 Oct 2026 10:00:00 +0000",
		"Return-Path: <" + returnPath + ">",
		"From: Sender <" + from + ">",
		"To: user@inspekt.local",
		"Subject: Test",
		"Date: Thu, 22 Oct 2026 10:00:00 +0000",
		"Message-ID: <t1@example.org>",
		"",
		body,
	}
	return []byte(strings.Join(lines, "\r\n"))
}

func sign(t *testing.T, raw []byte, domain string) []byte {
	t.Helper()
	var out bytes.Buffer
	err := dkim.Sign(&out, bytes.NewReader(raw), &dkim.SignOptions{
		Domain: domain, Selector: dkimSelector, Signer: testKey,
		HeaderKeys: []string{"From", "To", "Subject", "Date", "Message-ID"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func parse(t *testing.T, raw []byte) *email.Message {
	t.Helper()
	msg, err := email.Parse(bytes.NewReader(raw), email.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// orgDomain is a two-label stand-in for analyze.RegistrableDomain, which
// this package cannot import.
func orgDomain(d string) string {
	l := strings.Split(d, ".")
	if len(l) <= 2 {
		return d
	}
	return strings.Join(l[len(l)-2:], ".")
}

// baseDNS publishes SPF, DKIM and DMARC for example.org, plus SPF for an
// unrelated bulk sender (esp.example) that relays for it.
func baseDNS() *authtest.DNS {
	return &authtest.DNS{TXT: map[string][]string{
		"example.org":                            {"v=spf1 ip4:192.0.2.10 -all"},
		dkimSelector + "._domainkey.example.org": {dkimRecord()},
		"_dmarc.example.org":                     {"v=DMARC1; p=reject; sp=quarantine"},
		"esp.example":                            {"v=spf1 ip4:198.51.100.0/24 -all"},
	}}
}

func TestVerify(t *testing.T) {
	const body = "Hello,\r\nthe report is attached.\r\n"
	cases := []struct {
		name  string
		raw   func(t *testing.T) []byte
		dns   func(*authtest.DNS)
		spf   Result
		dkim  Result
		dmarc Result
		pol   string
	}{
		{
			name: "aligned SPF and DKIM pass",
			raw: func(t *testing.T) []byte {
				return sign(t, message("ceo@example.org", "bounce@example.org", "192.0.2.10", "mail.example.org", body), "example.org")
			},
			spf: Pass, dkim: Pass, dmarc: Pass, pol: "reject",
		},
		{
			name: "ESP relays: SPF passes for the ESP, aligned DKIM carries DMARC",
			raw: func(t *testing.T) []byte {
				return sign(t, message("news@example.org", "b-1@esp.example", "198.51.100.7", "out.esp.example", body), "example.org")
			},
			spf: Pass, dkim: Pass, dmarc: Pass, pol: "reject",
		},
		{
			name: "body changed after signing",
			raw: func(t *testing.T) []byte {
				signed := sign(t, message("news@example.org", "b-1@esp.example", "198.51.100.7", "out.esp.example", body), "example.org")
				return bytes.Replace(signed, []byte("the report"), []byte("the invoice"), 1)
			},
			spf: Pass, dkim: Fail, dmarc: Fail, pol: "reject",
		},
		{
			name: "spoofed From from an unlisted IP",
			raw: func(t *testing.T) []byte {
				return message("ceo@example.org", "ceo@example.org", "203.0.113.66", "attacker.example", body)
			},
			spf: Fail, dkim: None, dmarc: Fail, pol: "reject",
		},
		{
			name: "subdomain From falls back to the org record and its sp= policy",
			raw: func(t *testing.T) []byte {
				return message("alerts@billing.example.org", "alerts@billing.example.org", "203.0.113.66", "attacker.example", body)
			},
			spf: None, dkim: None, dmarc: Fail, pol: "quarantine",
		},
		{
			name: "no DMARC record",
			raw: func(t *testing.T) []byte {
				return message("a@nodmarc.example", "a@nodmarc.example", "203.0.113.66", "x.example", body)
			},
			spf: None, dkim: None, dmarc: None,
		},
		{
			name: "DNS outage is temperror, never fail",
			raw: func(t *testing.T) []byte {
				return sign(t, message("ceo@example.org", "bounce@example.org", "192.0.2.10", "mail.example.org", body), "example.org")
			},
			dns: func(d *authtest.DNS) {
				d.Temp = map[string]bool{"example.org": true, dkimSelector + "._domainkey.example.org": true, "_dmarc.example.org": true}
			},
			spf: TempError, dkim: TempError, dmarc: TempError,
		},
		{
			name: "DKIM key no longer published (old corpus message)",
			raw: func(t *testing.T) []byte {
				return sign(t, message("ceo@example.org", "bounce@esp.example", "203.0.113.66", "x.example", body), "example.org")
			},
			dns: func(d *authtest.DNS) { delete(d.TXT, dkimSelector+"._domainkey.example.org") },
			spf: Fail, dkim: PermError, dmarc: Fail, pol: "reject",
		},
		{
			// go-msgauth canonicalizes bare LF itself; this guards that behaviour.
			name: "signed message saved with LF line endings still verifies",
			raw: func(t *testing.T) []byte {
				signed := sign(t, message("ceo@example.org", "bounce@example.org", "192.0.2.10", "mail.example.org", body), "example.org")
				return bytes.ReplaceAll(signed, []byte("\r\n"), []byte("\n"))
			},
			spf: Pass, dkim: Pass, dmarc: Pass, pol: "reject",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dns := baseDNS()
			if c.dns != nil {
				c.dns(dns)
			}
			v := &Verifier{Resolver: dns, OrgDomain: orgDomain}
			r := v.Verify(context.Background(), parse(t, c.raw(t)))
			if r.SPF != c.spf || r.DKIM != c.dkim || r.DMARC != c.dmarc || r.DMARCPolicy != c.pol {
				t.Errorf("got spf=%s dkim=%s dmarc=%s policy=%q, want spf=%s dkim=%s dmarc=%s policy=%q\nnotes: %v",
					r.SPF, r.DKIM, r.DMARC, r.DMARCPolicy, c.spf, c.dkim, c.dmarc, c.pol, r.Notes)
			}
		})
	}
}

func TestStrictAlignment(t *testing.T) {
	dns := baseDNS()
	dns.TXT["_dmarc.example.org"] = []string{"v=DMARC1; p=reject; adkim=s; aspf=s"}
	// Signed by the parent domain, From is a subdomain: relaxed passes, strict must not.
	raw := sign(t, message("a@mail.example.org", "b@esp.example", "198.51.100.7", "out.esp.example", "hi\r\n"), "example.org")
	v := &Verifier{Resolver: dns, OrgDomain: orgDomain}
	if r := v.Verify(context.Background(), parse(t, raw)); r.DMARC != Fail {
		t.Fatalf("strict alignment: dmarc=%s, want fail (notes %v)", r.DMARC, r.Notes)
	}
}

func TestConnectingHost(t *testing.T) {
	cases := []struct {
		name     string
		received []string
		ip, helo string
		ok       bool
	}{
		{"postfix", []string{"from mail.example.org (mail.example.org [192.0.2.10])\r\n\tby mx.inspekt.local (Postfix) with ESMTPS id 4XyZ"}, "192.0.2.10", "mail.example.org", true},
		{"ipv6 literal helo", []string{"from [IPv6:2001:db8::1] (unknown [IPv6:2001:db8::1]) by mx.inspekt.local"}, "2001:db8::1", "IPv6:2001:db8::1", true},
		{"only the topmost header counts", []string{"by mx.inspekt.local with LMTP", "from evil.example (evil.example [203.0.113.9]) by relay"}, "", "", false},
		{"IP in the by clause is ours, not the client's", []string{"from mail.example.org (unknown) by mx [10.0.0.1]"}, "", "", false},
		{"none", nil, "", "", false},
	}
	for _, c := range cases {
		ip, helo, ok := ConnectingHost(c.received)
		if ok != c.ok || helo != c.helo || (c.ok && !ip.Equal(net.ParseIP(c.ip))) {
			t.Errorf("%s: got (%v, %q, %v), want (%s, %q, %v)", c.name, ip, helo, ok, c.ip, c.helo, c.ok)
		}
	}
}
