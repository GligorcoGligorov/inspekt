// Package qr finds URLs hidden in QR codes in image attachments
// ("quishing"): a link in a picture is invisible to text-based link checks,
// and phones scan it outside the company's protected browser.
//
// Images are attacker-controlled, so every step is bounded: the number of
// images per message, bytes per image, pixel dimensions (read from the
// header before any pixel is decoded, which stops decompression bombs) and
// wall time per image.
package qr

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	_ "image/gif" // register decoders
	_ "image/jpeg"
	_ "image/png"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"

	"github.com/GligorcoGligorov/inspekt/internal/email"
	"github.com/GligorcoGligorov/inspekt/internal/extract"
)

// Limits bound the work spent on images in one message.
type Limits struct {
	MaxImages    int           // images decoded per message
	MaxBytes     int           // encoded size per image
	MaxDimension int           // width and height, in pixels
	Timeout      time.Duration // per image, including waiting for a decode slot
	// MaxConcurrent caps decodes running at once in this process. A decode
	// that timed out keeps its slot until it really ends, so this bounds
	// both memory (~85 MB per 4000×4000 colour image) and leftover work.
	MaxConcurrent int
}

// DefaultLimits keep worst-case work per message to a few hundred ms of CPU
// and ~64 MB of pixels per image (4000×4000 RGBA).
var DefaultLimits = Limits{
	MaxImages:     10,
	MaxBytes:      5 << 20,
	MaxDimension:  4000,
	Timeout:       2 * time.Second,
	MaxConcurrent: 2,
}

// Errors explaining why an image was skipped, for the analyst.
var (
	ErrTooLarge   = errors.New("qr: image file too large")
	ErrDimensions = errors.New("qr: image dimensions exceed limit")
	ErrTimeout    = errors.New("qr: decoding timed out")
)

// Decoder turns an image into the text of the QR code in it. It is a
// variable so tests can replace it.
type Decoder func(image.Image) (string, error)

// Scanner decodes QR codes within Limits. Share one Scanner per process so
// MaxConcurrent applies across all messages being analysed.
type Scanner struct {
	Limits Limits
	Decode Decoder // nil means gozxing

	once  sync.Once
	slots chan struct{}
}

// Result is what scanning a message's attachments produced.
type Result struct {
	Links   []extract.Link
	Skipped []string // images not decoded and why, for the analyst
}

// Scan decodes QR codes in msg's image attachments and returns the http(s)
// links they contain.
func (s *Scanner) Scan(ctx context.Context, msg *email.Message) Result {
	var res Result
	lim := s.Limits
	images := 0
	for _, a := range msg.Attachments {
		// Sniff the format from the bytes rather than trusting the declared
		// Content-Type or file name, which the sender controls.
		cfg, _, err := image.DecodeConfig(bytes.NewReader(a.Data))
		if err != nil {
			continue // not an image we can read
		}
		name := a.Filename
		if name == "" {
			name = a.ContentType
		}
		if images++; images > lim.MaxImages {
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s: more than %d images, not scanned", name, lim.MaxImages))
			continue
		}
		text, err := s.decodeOne(ctx, a.Data, cfg)
		switch {
		case errors.Is(err, ErrTooLarge), errors.Is(err, ErrDimensions), errors.Is(err, ErrTimeout):
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s: %v", name, err))
		case err != nil: // decodes as an image but holds no QR code: the common case
		default:
			if l, ok := extract.NewLink(normalize(text), extract.SourceQR); ok {
				res.Links = append(res.Links, l)
			}
		}
	}
	return res
}

func (s *Scanner) decodeOne(ctx context.Context, data []byte, cfg image.Config) (string, error) {
	lim := s.Limits
	if len(data) > lim.MaxBytes {
		return "", fmt.Errorf("%w (%d bytes)", ErrTooLarge, len(data))
	}
	// The header is a claim, but it is the claim the decoder allocates for:
	// a 100 KB PNG can declare 50000×50000 pixels (10 GB of RGBA).
	if cfg.Width > lim.MaxDimension || cfg.Height > lim.MaxDimension {
		return "", fmt.Errorf("%w (%d×%d)", ErrDimensions, cfg.Width, cfg.Height)
	}

	ctx, cancel := context.WithTimeout(ctx, lim.Timeout)
	defer cancel()
	s.once.Do(func() { s.slots = make(chan struct{}, max(lim.MaxConcurrent, 1)) })
	select {
	case s.slots <- struct{}{}:
	case <-ctx.Done():
		return "", ErrTimeout
	}
	type out struct {
		text string
		err  error
	}
	ch := make(chan out, 1) // buffered: a late decoder must not block forever
	go func() {
		defer func() { <-s.slots }() // released when the decode really ends
		img, _, err := image.Decode(bytes.NewReader(data))
		if err != nil {
			ch <- out{err: err}
			return
		}
		decode := s.Decode
		if decode == nil {
			decode = zxing
		}
		text, err := decode(img)
		ch <- out{text, err}
	}()
	select {
	case r := <-ch:
		return r.text, r.err
	case <-ctx.Done():
		// Go cannot kill the goroutine; it finishes in the background. The
		// dimension limit above bounds how long and how much it can use.
		return "", ErrTimeout
	}
}

func zxing(img image.Image) (string, error) {
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", err
	}
	r, err := qrcode.NewQRCodeReader().Decode(bmp, map[gozxing.DecodeHintType]any{
		gozxing.DecodeHintType_TRY_HARDER: true,
	})
	if err != nil {
		return "", err
	}
	return r.GetText(), nil
}

// bareHost matches QR payloads like "login-micros0ft.com/x" that phones open
// as web addresses even without a scheme.
var bareHost = regexp.MustCompile(`(?i)^(www\.)?[a-z0-9\-]+(\.[a-z0-9\-]+)+(/\S*)?$`)

func normalize(text string) string {
	text = strings.TrimSpace(text)
	if !strings.Contains(text, "://") && bareHost.MatchString(text) {
		return "http://" + text
	}
	return text
}
