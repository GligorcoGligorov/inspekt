package qr

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/png"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"

	"github.com/GligorcoGligorov/inspekt/internal/email"
)

func qrPNG(t *testing.T, content string) []byte {
	t.Helper()
	m, err := qrcode.NewQRCodeWriter().Encode(content, gozxing.BarcodeFormat_QR_CODE, 200, 200, nil)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := png.Encode(&b, m); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func msgWith(data ...[]byte) *email.Message {
	m := &email.Message{}
	for i, d := range data {
		m.Attachments = append(m.Attachments, email.Attachment{
			Filename: "img" + string(rune('a'+i)) + ".png", ContentType: "image/png", Data: d})
	}
	return m
}

func TestScanDecodesQRLinks(t *testing.T) {
	sample, err := os.ReadFile("../../testdata/qr.png") // made with qrencode, not gozxing
	if err != nil {
		t.Fatal(err)
	}
	notImage := []byte("%PDF-1.7 not an image")
	var plain bytes.Buffer
	png.Encode(&plain, image.NewGray(image.Rect(0, 0, 50, 50))) // an image without a QR code

	res := (&Scanner{Limits: DefaultLimits}).Scan(context.Background(), msgWith(
		sample, notImage, plain.Bytes(),
		qrPNG(t, "evil.example/pay"),          // bare host: phones open it as a URL
		qrPNG(t, "WIFI:S:office;T:WPA;P:x;;"), // not a link
	))
	var got []string
	for _, l := range res.Links {
		got = append(got, l.URL+" "+string(l.Source))
	}
	want := []string{"http://login-micros0ft.com/x qr_code", "http://evil.example/pay qr_code"}
	if strings.Join(got, ",") != strings.Join(want, ",") || len(res.Skipped) != 0 {
		t.Fatalf("links %v (want %v), skipped %v", got, want, res.Skipped)
	}
}

func spy(calls *atomic.Int32) Decoder {
	return func(image.Image) (string, error) {
		calls.Add(1)
		return "https://example.org/", nil
	}
}

func TestMaxImages(t *testing.T) {
	img := qrPNG(t, "https://example.org/")
	var imgs [][]byte
	for range 12 {
		imgs = append(imgs, img)
	}
	var calls atomic.Int32
	lim := DefaultLimits
	lim.MaxImages = 10
	res := (&Scanner{Limits: lim, Decode: spy(&calls)}).Scan(context.Background(), msgWith(imgs...))
	if calls.Load() != 10 || len(res.Links) != 10 || len(res.Skipped) != 2 {
		t.Fatalf("decoded %d, links %d, skipped %v", calls.Load(), len(res.Links), res.Skipped)
	}
}

func TestMaxBytes(t *testing.T) {
	img := qrPNG(t, "https://example.org/")
	var calls atomic.Int32
	lim := DefaultLimits
	lim.MaxBytes = len(img) - 1
	res := (&Scanner{Limits: lim, Decode: spy(&calls)}).Scan(context.Background(), msgWith(img))
	if calls.Load() != 0 || len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0], ErrTooLarge.Error()) {
		t.Fatalf("decoded %d, skipped %v", calls.Load(), res.Skipped)
	}
}

// bomb returns a PNG of a few dozen bytes whose header declares w×h pixels.
// Decoding it would allocate w*h bytes or more before noticing the pixel
// data is missing; at 50000×50000 that is gigabytes.
func bomb(t *testing.T, w, h uint32) []byte {
	t.Helper()
	var b bytes.Buffer
	png.Encode(&b, image.NewGray(image.Rect(0, 0, 1, 1)))
	p := b.Bytes()
	// Signature (8) + IHDR length (4) + "IHDR" (4), then width and height.
	binary.BigEndian.PutUint32(p[16:], w)
	binary.BigEndian.PutUint32(p[20:], h)
	binary.BigEndian.PutUint32(p[29:], crc32.ChecksumIEEE(p[12:29]))
	return p
}

func TestDecompressionBombRejectedFromHeader(t *testing.T) {
	b := bomb(t, 50000, 50000)
	if cfg, _, err := image.DecodeConfig(bytes.NewReader(b)); err != nil || cfg.Width != 50000 {
		t.Fatalf("test bomb is not a valid PNG header: %+v %v", cfg, err)
	}
	var calls atomic.Int32
	start := time.Now()
	res := (&Scanner{Limits: DefaultLimits, Decode: spy(&calls)}).Scan(context.Background(), msgWith(b))
	if calls.Load() != 0 || len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0], "50000×50000") {
		t.Fatalf("decoded %d, skipped %v", calls.Load(), res.Skipped)
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("rejecting a %d-byte bomb took %v: pixels were decoded", len(b), d)
	}
	// One dimension over the limit is enough.
	if res := (&Scanner{Limits: DefaultLimits, Decode: spy(&calls)}).Scan(context.Background(), msgWith(bomb(t, 1, 4001))); len(res.Skipped) != 1 {
		t.Fatalf("4001 px tall image not rejected: %v", res.Skipped)
	}
}

func TestPerImageTimeout(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	slow := func(image.Image) (string, error) {
		<-release
		return "", errors.New("released")
	}
	lim := DefaultLimits
	lim.Timeout = 50 * time.Millisecond
	img := qrPNG(t, "https://example.org/")
	start := time.Now()
	res := (&Scanner{Limits: lim, Decode: slow}).Scan(context.Background(), msgWith(img, img))
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Scan took %v with a 50 ms per-image timeout", d)
	}
	if len(res.Skipped) != 2 || !strings.Contains(res.Skipped[0], ErrTimeout.Error()) {
		t.Fatalf("skipped %v", res.Skipped)
	}
}

// Timed-out decodes keep their slot, so a flood of slow images cannot pile
// up unbounded work or memory in the background.
func TestMaxConcurrentHoldsSlotsUntilDecodeEnds(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	var stuck atomic.Bool
	stuck.Store(true)
	dec := func(image.Image) (string, error) {
		calls.Add(1)
		if stuck.Load() {
			<-release
			return "", errors.New("released")
		}
		return "https://example.org/", nil
	}
	lim := DefaultLimits
	lim.Timeout = 30 * time.Millisecond
	lim.MaxConcurrent = 1
	sc := &Scanner{Limits: lim, Decode: dec}
	img := qrPNG(t, "https://example.org/")

	res := sc.Scan(context.Background(), msgWith(img, img, img))
	if calls.Load() != 1 || len(res.Skipped) != 3 {
		t.Fatalf("decoder started %d times (want 1), skipped %v", calls.Load(), res.Skipped)
	}

	stuck.Store(false)
	close(release) // the stuck decode ends and frees its slot
	deadline := time.Now().Add(2 * time.Second)
	for len(sc.Scan(context.Background(), msgWith(img)).Links) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("slot never released after the decode ended")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
