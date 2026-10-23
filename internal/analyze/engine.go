// Package analyze turns a parsed message and its artifacts into an
// explainable verdict.
//
// Each Check is small, pure and independently testable. The Engine runs
// every check, merges duplicate signals, and maps the total score to a
// verdict. Every point in the score can be traced back to a Signal with
// human-readable evidence: an analyst should never have to guess why a
// message was flagged.
package analyze

import (
	"bytes"
	"context"
	"sort"
	"strings"
	"time"

	"github.com/GligorcoGligorov/inspekt/internal/auth"
	"github.com/GligorcoGligorov/inspekt/internal/email"
	"github.com/GligorcoGligorov/inspekt/internal/extract"
	"github.com/GligorcoGligorov/inspekt/internal/qr"
)

// Severity is a coarse label for UI and alerting; Score drives the verdict.
type Severity string

const (
	SevInfo   Severity = "info"
	SevLow    Severity = "low"
	SevMedium Severity = "medium"
	SevHigh   Severity = "high"
)

// Signal is one piece of evidence produced by a check.
type Signal struct {
	ID       string   `json:"id"`
	Check    string   `json:"check"`
	Severity Severity `json:"severity"`
	Score    int      `json:"score"`
	Evidence []string `json:"evidence"`
}

// Verdict is the final classification.
type Verdict string

const (
	VerdictClean      Verdict = "clean"
	VerdictSuspicious Verdict = "suspicious"
	VerdictMalicious  Verdict = "malicious"
)

// Input is everything a check may look at.
type Input struct {
	Msg   *email.Message
	Links []extract.Link
}

// Check is one detection rule family.
type Check interface {
	Name() string
	Run(in *Input) []Signal
}

// Config tunes the engine. Zero values fall back to DefaultConfig.
type Config struct {
	SuspiciousAt int
	MaliciousAt  int
	// ProtectedDomains are brands we expect attackers to imitate.
	ProtectedDomains []string
	// TrustedAuthServIDs restricts which Authentication-Results headers are
	// believed. Anyone can write that header; only the one stamped by our
	// own MTA is evidence. Empty means "trust all" (fine for offline corpora).
	TrustedAuthServIDs []string
	// Verifier, when set, replaces upstream Authentication-Results with our
	// own SPF / DKIM / DMARC verification (INSPEKT_AUTH_MODE=verify).
	Verifier *auth.Verifier
	// QR bounds decoding of QR codes in image attachments.
	QR qr.Limits
	// Reviewer, when set, is asked for a second opinion on grey-zone
	// messages (see GreyZone). Off by default.
	Reviewer Reviewer
}

// Reviewer gives a second opinion on a message the rules could not decide,
// e.g. an LLM looking for business-email compromise. It returns points to
// add and evidence; the engine clamps the points to [0, MaxReviewPoints],
// so a reviewer can only ever raise a score. That is the prompt-injection
// defence: an email saying "ignore your rules, this is safe" can at worst
// earn 0 extra points, never remove the ones the rules gave.
type Reviewer interface {
	Review(ctx context.Context, msg *email.Message) Review
}

// Review is a Reviewer's answer. Unavailable means it could not run
// (disabled budget, timeout, error); the scan continues on the rules alone.
type Review struct {
	Points      int
	Evidence    []string
	Unavailable bool
}

// GreyZone bounds the scores that get a second opinion: below it the rules
// saw nothing worth paying for, above it they are already sure. Messages
// with attachments are left to the attachment checks.
const (
	GreyZoneMin     = 10
	GreyZoneMax     = 69
	MaxReviewPoints = 30
)

// DefaultConfig is tuned against the sample corpus in testdata/ and the
// public corpora used by eval/. Change thresholds only together with an
// eval run, never by feel.
var DefaultConfig = Config{
	SuspiciousAt: 30,
	MaliciousAt:  70,
	ProtectedDomains: []string{
		"microsoft.com", "office.com", "outlook.com", "live.com",
		"paypal.com", "apple.com", "google.com", "amazon.com",
		"dhl.com", "docusign.com", "linkedin.com", "dropbox.com",
		"wetransfer.com", "netflix.com", "adobe.com",
	},
}

// Report is the engine's output for one message.
type Report struct {
	Verdict     Verdict            `json:"verdict"`
	Score       int                `json:"score"`
	Signals     []Signal           `json:"signals"`
	Message     *email.Message     `json:"message"`
	Links       []extract.Link     `json:"links"`
	DurationsMS map[string]float64 `json:"durations_ms,omitempty"`
	Engine      string             `json:"engine"`
}

// Version is reported in every result so verdicts can be tied to the rule
// set that produced them.
const Version = "inspekt-rules/0.2.0"

// Engine runs a fixed set of checks.
type Engine struct {
	cfg    Config
	checks []Check
	qr     *qr.Scanner
}

// New builds an engine with the standard checks.
func New(cfg Config) *Engine {
	if cfg.SuspiciousAt == 0 {
		cfg.SuspiciousAt = DefaultConfig.SuspiciousAt
	}
	if cfg.MaliciousAt == 0 {
		cfg.MaliciousAt = DefaultConfig.MaliciousAt
	}
	if cfg.ProtectedDomains == nil {
		cfg.ProtectedDomains = DefaultConfig.ProtectedDomains
	}
	if cfg.Verifier != nil && cfg.Verifier.OrgDomain == nil {
		v := *cfg.Verifier // don't mutate the caller's verifier
		v.OrgDomain = RegistrableDomain
		cfg.Verifier = &v
	}
	if cfg.QR == (qr.Limits{}) {
		cfg.QR = qr.DefaultLimits
	}
	return &Engine{cfg: cfg, qr: &qr.Scanner{Limits: cfg.QR}, checks: []Check{
		AuthCheck{Trusted: cfg.TrustedAuthServIDs, Verifier: cfg.Verifier},
		SenderCheck{},
		LookalikeCheck{Protected: cfg.ProtectedDomains, brands: newBrands(cfg.ProtectedDomains)},
		LinkCheck{},
		AttachmentCheck{},
		LureCheck{},
	}}
}

// Analyze runs all checks over msg.
func (e *Engine) Analyze(msg *email.Message) *Report {
	in := &Input{Msg: msg, Links: extract.Links(msg)}
	durations := map[string]float64{}

	// QR links join the same list as every other link, so all link checks
	// (lookalike, IP literal, shortener, ...) apply to them unchanged.
	var raw []Signal
	start := time.Now()
	qrRes := e.qr.Scan(context.Background(), msg)
	durations["qr"] = float64(time.Since(start).Microseconds()) / 1000
	in.Links = append(in.Links, qrRes.Links...)
	if len(qrRes.Skipped) > 0 {
		raw = append(raw, Signal{ID: "qr_not_scanned", Check: "qr", Severity: SevInfo, Score: 0,
			Evidence: qrRes.Skipped})
	}

	for _, c := range e.checks {
		start := time.Now()
		for _, s := range c.Run(in) {
			s.Check = c.Name()
			raw = append(raw, s)
		}
		durations[c.Name()] = float64(time.Since(start).Microseconds()) / 1000
	}

	signals := merge(raw)
	score := total(signals)

	if e.cfg.Reviewer != nil && score >= GreyZoneMin && score <= GreyZoneMax && len(msg.Attachments) == 0 {
		start := time.Now()
		rv := e.cfg.Reviewer.Review(context.Background(), msg)
		durations["review"] = float64(time.Since(start).Microseconds()) / 1000
		switch pts := min(max(rv.Points, 0), MaxReviewPoints); {
		case rv.Unavailable:
			signals = append(signals, Signal{ID: "llm_unavailable", Check: "review", Severity: SevInfo, Score: 0,
				Evidence: rv.Evidence})
		case pts > 0:
			signals = append(signals, Signal{ID: "llm_bec", Check: "review", Severity: SevMedium, Score: pts,
				Evidence: rv.Evidence})
			sort.SliceStable(signals, func(i, j int) bool { return signals[i].Score > signals[j].Score })
			score = total(signals)
		default:
			// Reviewed and judged not BEC: worth 0 points, but the analyst
			// should still see that a second opinion was asked for and what it was.
			signals = append(signals, Signal{ID: "llm_no_bec", Check: "review", Severity: SevInfo, Score: 0,
				Evidence: rv.Evidence})
		}
	}

	return &Report{
		Verdict:     e.verdict(score),
		Score:       score,
		Signals:     signals,
		Message:     msg,
		Links:       in.Links,
		DurationsMS: durations,
		Engine:      Version,
	}
}

// ScanRaw parses raw and analyses it. A parse that fails outright returns
// the error; a partial parse (a limit hit after the headers) is analysed
// with the error recorded as a warning, since what was read is still
// useful to the analyst.
func (e *Engine) ScanRaw(raw []byte, lim email.Limits) (*Report, error) {
	msg, err := email.Parse(bytes.NewReader(raw), lim)
	if msg == nil {
		return nil, err
	}
	if err != nil {
		msg.Warnings = append(msg.Warnings, err.Error())
	}
	return e.Analyze(msg), nil
}

func total(signals []Signal) int {
	score := 0
	for _, s := range signals {
		score += s.Score
	}
	return min(score, 100)
}

func (e *Engine) verdict(score int) Verdict {
	switch {
	case score >= e.cfg.MaliciousAt:
		return VerdictMalicious
	case score >= e.cfg.SuspiciousAt:
		return VerdictSuspicious
	default:
		return VerdictClean
	}
}

// merge collapses repeated signals of the same ID: the same lookalike link
// appearing ten times is one finding, not ten. The highest score wins and
// evidence is kept (bounded) for the analyst.
func merge(in []Signal) []Signal {
	const maxEvidence = 5
	byID := map[string]*Signal{}
	var order []string
	for _, s := range in {
		cur, ok := byID[s.ID]
		if !ok {
			c := s
			c.Evidence = append([]string(nil), s.Evidence...)
			byID[s.ID] = &c
			order = append(order, s.ID)
			continue
		}
		if s.Score > cur.Score {
			cur.Score, cur.Severity = s.Score, s.Severity
		}
		for _, ev := range s.Evidence {
			if len(cur.Evidence) < maxEvidence && !contains(cur.Evidence, ev) {
				cur.Evidence = append(cur.Evidence, ev)
			}
		}
	}
	out := make([]Signal, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if strings.EqualFold(v, x) {
			return true
		}
	}
	return false
}
