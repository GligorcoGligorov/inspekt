// Command inspekt-load measures the async pipeline end to end: it posts N
// messages with C concurrent clients and polls each scan until it is done.
//
//	go run ./cmd/inspekt-load -n 5000 -c 32 -files 'testdata/*.eml'
//
// Every message gets a unique X-Inspekt-Load header, so idempotency does not
// collapse the run into a handful of scans. Two latencies are reported:
// accept (POST until 202) and end-to-end (POST until the result can be read),
// the latter measured by polling every -poll, which bounds its resolution.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	base := flag.String("url", "http://localhost:8080", "API base URL")
	n := flag.Int("n", 2000, "messages to send")
	c := flag.Int("c", 32, "concurrent clients")
	globs := flag.String("files", "testdata/*.eml", "comma-separated globs of .eml files to cycle through")
	poll := flag.Duration("poll", 10*time.Millisecond, "result polling interval")
	timeout := flag.Duration("timeout", 60*time.Second, "give up on one scan after this long")
	flag.Parse()

	var msgs [][]byte
	for _, g := range strings.Split(*globs, ",") {
		files, _ := filepath.Glob(strings.TrimSpace(g))
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				fatal(err)
			}
			msgs = append(msgs, b)
		}
	}
	if len(msgs) == 0 {
		fatal(fmt.Errorf("no files match %q", *globs))
	}

	run := time.Now().UnixNano()
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: *c}}
	var (
		mu               sync.Mutex
		accept, e2e      []time.Duration
		next             atomic.Int64
		failed, rejected atomic.Int64
	)
	worker := func() {
		for {
			i := next.Add(1) - 1
			if i >= int64(*n) {
				return
			}
			body := append([]byte(fmt.Sprintf("X-Inspekt-Load: %d-%d\r\n", run, i)), msgs[i%int64(len(msgs))]...)
			start := time.Now()
			res, err := client.Post(*base+"/v1/scans", "message/rfc822", bytes.NewReader(body))
			if err != nil {
				failed.Add(1)
				continue
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if res.StatusCode != http.StatusAccepted {
				rejected.Add(1) // 503 when Redis is full, 413 when too large
				continue
			}
			acc := time.Since(start)
			loc := res.Header.Get("Location")
			done := false
			for time.Since(start) < *timeout {
				r, err := client.Get(*base + loc)
				if err == nil {
					var s struct{ Status string }
					json.NewDecoder(r.Body).Decode(&s)
					r.Body.Close()
					if s.Status == "done" || s.Status == "failed" {
						done = true
						break
					}
				}
				time.Sleep(*poll)
			}
			if !done {
				failed.Add(1)
				continue
			}
			total := time.Since(start)
			mu.Lock()
			accept, e2e = append(accept, acc), append(e2e, total)
			mu.Unlock()
		}
	}

	start := time.Now()
	var wg sync.WaitGroup
	for range *c {
		wg.Go(worker)
	}
	wg.Wait()
	wall := time.Since(start)

	fmt.Printf("messages: %d sent, %d completed, %d rejected, %d failed (clients %d, %d distinct files)\n",
		*n, len(e2e), rejected.Load(), failed.Load(), *c, len(msgs))
	fmt.Printf("wall time: %v, throughput: %.1f completed scans/s\n", wall.Round(time.Millisecond), float64(len(e2e))/wall.Seconds())
	fmt.Printf("accept   (POST -> 202):     %s\n", percentiles(accept))
	fmt.Printf("end-to-end (POST -> done):  %s  (polled every %v)\n", percentiles(e2e), *poll)
}

func percentiles(d []time.Duration) string {
	if len(d) == 0 {
		return "n/a"
	}
	slices.Sort(d)
	p := func(q float64) time.Duration { return d[int(q*float64(len(d)-1))].Round(100 * time.Microsecond) }
	return fmt.Sprintf("p50 %v  p95 %v  p99 %v  max %v", p(0.50), p(0.95), p(0.99), d[len(d)-1].Round(100*time.Microsecond))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
