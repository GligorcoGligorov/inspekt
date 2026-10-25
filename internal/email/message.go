// Package email parses raw RFC 5322 / MIME messages into a structure that
// the analysis stages can work with.
//
// The parser treats every input as hostile: it enforces limits on total size,
// number of MIME parts and nesting depth, so a crafted message cannot exhaust
// memory or CPU in a worker. It uses only the Go standard library.
package email

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"path"
	"strings"
	"time"
)

// Limits bound the resources a single message may consume while parsing.
type Limits struct {
	MaxBytes int64 // maximum raw message size
	MaxParts int   // maximum number of MIME leaf parts
	MaxDepth int   // maximum multipart nesting depth
}

// DefaultLimits are conservative values suitable for an inbound scanner.
var DefaultLimits = Limits{
	MaxBytes: 25 << 20, // 25 MiB, a common MTA ceiling
	MaxParts: 200,
	MaxDepth: 10,
}

// Errors returned when a message breaks a limit. Callers can treat these
// as a signal in their own right: legitimate mail rarely trips them.
var (
	ErrTooLarge     = errors.New("email: message exceeds size limit")
	ErrTooManyParts = errors.New("email: message exceeds MIME part limit")
	ErrTooDeep      = errors.New("email: MIME nesting exceeds depth limit")
)

// Address is a parsed mailbox. Domain is lower-cased.
type Address struct {
	Name   string `json:"name,omitempty"`
	Email  string `json:"email"`
	Domain string `json:"domain"`
}

// Attachment is a non-body MIME part. Data is kept for downstream stages
// (QR decoding, hashing) but never serialised.
type Attachment struct {
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"content_type"`
	Size        int    `json:"size"`
	SHA256      string `json:"sha256"`
	Inline      bool   `json:"inline"`
	Data        []byte `json:"-"`
}

// Message is the parsed form of one email.
type Message struct {
	MessageID   string       `json:"message_id,omitempty"`
	Subject     string       `json:"subject"`
	Date        time.Time    `json:"date,omitzero"`
	From        *Address     `json:"from,omitempty"`
	ReplyTo     *Address     `json:"reply_to,omitempty"`
	ReturnPath  *Address     `json:"return_path,omitempty"`
	To          []Address    `json:"to,omitempty"`
	DeliveredTo []Address    `json:"delivered_to,omitempty"` // the mailbox the final MTA delivered to
	AuthResults []string     `json:"authentication_results,omitempty"`
	Received    []string     `json:"received,omitempty"`
	TextBody    string       `json:"-"`
	HTMLBody    string       `json:"-"`
	Attachments []Attachment `json:"attachments,omitempty"`
	Size        int64        `json:"size"`
	Warnings    []string     `json:"parse_warnings,omitempty"`
	// Raw is the message exactly as received. DKIM verification hashes
	// these bytes, so they must not be re-serialised from the parsed form.
	Raw []byte `json:"-"`
}

var wordDecoder = &mime.WordDecoder{
	// Unknown charsets are passed through rather than failing the whole
	// message; a scanner must never drop mail because of an exotic charset.
	CharsetReader: func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	},
}

// Parse reads one message from r, enforcing lim.
func Parse(r io.Reader, lim Limits) (*Message, error) {
	raw, err := io.ReadAll(io.LimitReader(r, lim.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("email: read: %w", err)
	}
	if int64(len(raw)) > lim.MaxBytes {
		return nil, ErrTooLarge
	}

	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("email: headers: %w", err)
	}

	msg := &Message{Size: int64(len(raw)), Raw: raw}
	h := m.Header
	msg.MessageID = strings.Trim(h.Get("Message-Id"), "<> ")
	msg.Subject = decodeHeader(h.Get("Subject"))
	if d, err := h.Date(); err == nil {
		msg.Date = d
	}
	msg.From = parseAddress(h.Get("From"), msg)
	msg.ReplyTo = parseAddress(h.Get("Reply-To"), msg)
	msg.ReturnPath = parseAddress(h.Get("Return-Path"), msg)
	if list, err := (&mail.AddressParser{WordDecoder: wordDecoder}).ParseList(h.Get("To")); err == nil {
		for _, a := range list {
			msg.To = append(msg.To, toAddress(a))
		}
	}
	msg.AuthResults = h["Authentication-Results"]
	msg.Received = h["Received"]
	for _, v := range h["Delivered-To"] {
		if a, err := (&mail.AddressParser{WordDecoder: wordDecoder}).Parse(strings.TrimSpace(v)); err == nil {
			msg.DeliveredTo = append(msg.DeliveredTo, toAddress(a))
		}
	}

	p := &walker{lim: lim, msg: msg}
	err = p.walk(h, m.Body, 0)
	return msg, err
}

// header is satisfied by both mail.Header and textproto.MIMEHeader.
type header interface{ Get(string) string }

type walker struct {
	lim   Limits
	msg   *Message
	parts int
}

func (w *walker) walk(h header, body io.Reader, depth int) error {
	if depth > w.lim.MaxDepth {
		return ErrTooDeep
	}

	ctype, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil {
		// RFC 2045: missing or broken Content-Type means text/plain.
		ctype, params = "text/plain", map[string]string{}
		if h.Get("Content-Type") != "" {
			w.warn("unparseable Content-Type, treated as text/plain")
		}
	}

	if strings.HasPrefix(ctype, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			w.warn("multipart without boundary")
			return nil
		}
		mr := multipart.NewReader(body, boundary)
		for {
			part, err := mr.NextRawPart() // raw: we decode transfer encoding ourselves
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				// Truncated or malformed multipart: keep what we have.
				w.warn("malformed multipart: " + err.Error())
				return nil
			}
			if err := w.walk(part.Header, part, depth+1); err != nil {
				return err
			}
		}
	}

	w.parts++
	if w.parts > w.lim.MaxParts {
		return ErrTooManyParts
	}

	data, err := io.ReadAll(decodeTransfer(h.Get("Content-Transfer-Encoding"), body))
	if err != nil {
		w.warn("body decode: " + err.Error())
	}

	disp, dparams, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	filename := decodeHeader(dparams["filename"])
	if filename == "" {
		filename = decodeHeader(params["name"])
	}
	isAttachment := disp == "attachment" || filename != ""

	switch {
	case ctype == "text/plain" && !isAttachment:
		w.msg.TextBody += string(data)
	case ctype == "text/html" && !isAttachment:
		w.msg.HTMLBody += string(data)
	case ctype == "message/rfc822":
		// Forwarded or wrapped message: record it as an attachment. A later
		// stage can recurse into it with its own depth budget.
		w.addAttachment(filename, ctype, disp, data)
	default:
		w.addAttachment(filename, ctype, disp, data)
	}
	return nil
}

func (w *walker) addAttachment(name, ctype, disp string, data []byte) {
	sum := sha256.Sum256(data)
	if name != "" {
		name = path.Base(strings.ReplaceAll(name, `\`, "/")) // strip any path the sender smuggled in
	}
	w.msg.Attachments = append(w.msg.Attachments, Attachment{
		Filename:    name,
		ContentType: ctype,
		Size:        len(data),
		SHA256:      hex.EncodeToString(sum[:]),
		Inline:      disp == "inline" || disp == "",
		Data:        data,
	})
}

func (w *walker) warn(s string) { w.msg.Warnings = append(w.msg.Warnings, s) }

func decodeTransfer(enc string, r io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "base64":
		// Senders often wrap base64 with CRLFs; the decoder ignores newlines.
		return base64.NewDecoder(base64.StdEncoding, &stripSpace{r: r})
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	default:
		return r
	}
}

// stripSpace removes whitespace that would otherwise break base64 decoding.
type stripSpace struct{ r io.Reader }

func (s *stripSpace) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	j := 0
	for i := 0; i < n; i++ {
		switch p[i] {
		case ' ', '\t', '\r', '\n':
		default:
			p[j] = p[i]
			j++
		}
	}
	return j, err
}

func decodeHeader(s string) string {
	if out, err := wordDecoder.DecodeHeader(s); err == nil {
		return out
	}
	return s
}

func parseAddress(s string, msg *Message) *Address {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	a, err := (&mail.AddressParser{WordDecoder: wordDecoder}).Parse(s)
	if err != nil {
		// Return-Path "<>" (bounces) and badly formed From headers both land
		// here. Keep the raw value so heuristics can still look at it.
		if s != "<>" {
			msg.Warnings = append(msg.Warnings, "unparseable address: "+s)
		}
		return nil
	}
	out := toAddress(a)
	return &out
}

func toAddress(a *mail.Address) Address {
	addr := strings.ToLower(a.Address)
	domain := ""
	if i := strings.LastIndexByte(addr, '@'); i >= 0 {
		domain = addr[i+1:]
	}
	return Address{Name: a.Name, Email: addr, Domain: domain}
}
