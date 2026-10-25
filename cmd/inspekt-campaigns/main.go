// Command inspekt-campaigns clusters a labelled corpus offline with the
// same code the API uses (internal/campaign), for measurement only.
//
//	python3 eval/campaigns.py      (drives it; see docs/EVAL.md)
//
// Input on stdin, one JSON object per line: {"file": "...", "split": "dev"}.
// Each split is clustered as one window. Output: one JSON object with, per
// split, the guard limit, the indicator values it dropped per kind, and
// every campaign of 2+ scans with all its members (scan id = file path).
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/campaign"
	"github.com/GligorcoGligorov/inspekt/internal/email"
)

type splitResult struct {
	Scans     int                 `json:"scans"`
	Limit     int                 `json:"guard_limit"`
	Dropped   map[string]int      `json:"guard_dropped"`
	ByKind    map[string]int      `json:"indicators_by_kind"` // distinct values seen per kind
	Campaigns []campaign.Campaign `json:"campaigns"`
}

func main() {
	maxShared := flag.Int("max-shared", 20, "giant-cluster guard: absolute limit")
	maxShare := flag.Float64("max-share", 0.05, "giant-cluster guard: share of scans in the window")
	maxSize := flag.Int("max-size", 500, "clusters above this size are marked oversized")
	flag.Parse()

	// The scoring engine with the default rules (no LLM): verdicts here are
	// the same as evaluate.py's.
	eng := analyze.New(analyze.DefaultConfig)
	members := map[string][]campaign.Member{}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var in struct{ File, Split string }
		if err := json.Unmarshal(sc.Bytes(), &in); err != nil {
			fatal(err)
		}
		raw, err := os.ReadFile(in.File)
		if err != nil {
			fatal(err)
		}
		rep, err := eng.ScanRaw(raw, email.DefaultLimits)
		if err != nil {
			continue // unparseable: evaluate.py counts these as parse errors
		}
		members[in.Split] = append(members[in.Split], campaign.Member{
			ScanID: in.File, Verdict: rep.Verdict, Subject: rep.Message.Subject, Indicators: campaign.Extract(rep)})
	}
	if err := sc.Err(); err != nil {
		fatal(err)
	}

	out := map[string]splitResult{}
	splits := make([]string, 0, len(members))
	for s := range members {
		splits = append(splits, s)
	}
	sort.Strings(splits)
	for _, s := range splits {
		ms := members[s]
		res := campaign.Cluster(ms, campaign.Options{MaxShared: *maxShared, MaxShare: *maxShare,
			MaxSize: *maxSize, MinSize: 2, MinVerdict: analyze.VerdictClean})
		distinct := map[campaign.Indicator]bool{}
		byKind := map[string]int{}
		for _, m := range ms {
			for _, ind := range m.Indicators {
				if !distinct[ind] {
					distinct[ind] = true
					byKind[ind.Kind]++
				}
			}
		}
		out[s] = splitResult{Scans: res.Scans, Limit: res.Limit, Dropped: res.Dropped, ByKind: byKind, Campaigns: res.Campaigns}
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
