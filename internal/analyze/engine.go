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
	"sort"
	"strings"
	"time"

	"github.com/GligorcoGligorov/inspekt/internal/email"
	"github.com/GligorcoGligorov/inspekt/internal/extract"
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
}

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
const Version = "inspekt-rules/0.1.0"

// Engine runs a fixed set of checks.
type Engine struct {
	cfg    Config
	checks []Check
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
	return &Engine{cfg: cfg, checks: []Check{
		AuthCheck{Trusted: cfg.TrustedAuthServIDs},
		SenderCheck{},
		LookalikeCheck{Protected: cfg.ProtectedDomains},
		LinkCheck{},
		AttachmentCheck{},
		LureCheck{},
	}}
}

// Analyze runs all checks over msg.
func (e *Engine) Analyze(msg *email.Message) *Report {
	in := &Input{Msg: msg, Links: extract.Links(msg)}
	durations := map[string]float64{}

	var raw []Signal
	for _, c := range e.checks {
		start := time.Now()
		for _, s := range c.Run(in) {
			s.Check = c.Name()
			raw = append(raw, s)
		}
		durations[c.Name()] = float64(time.Since(start).Microseconds()) / 1000
	}

	signals := merge(raw)
	score := 0
	for _, s := range signals {
		score += s.Score
	}
	score = min(score, 100)

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
