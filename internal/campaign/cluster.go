package campaign

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
)

// Member is one scan as clustering sees it.
type Member struct {
	ScanID     string
	ReceivedAt time.Time
	Verdict    analyze.Verdict
	Subject    string
	Indicators []Indicator
}

// Options tune clustering. Zero values take the defaults.
type Options struct {
	// The giant-cluster guard: an indicator value shared by more than
	// max(MaxShared, MaxShare × scans in the window) scans is ignored. Such a
	// value is infrastructure (a big sender's IP, a common link host), not a
	// campaign, and would chain unrelated mail into one giant cluster.
	MaxShared int     // default 20
	MaxShare  float64 // default 0.05
	// Filters applied after clustering, so a missed phish still joins its
	// caught siblings.
	MinSize    int             // default 2
	MinVerdict analyze.Verdict // keep campaigns whose highest verdict is at least this; default clean (all)
	MaxScanIDs int             // scan ids listed per campaign; 0 = all
}

// Shared is an indicator and how many of the campaign's scans carry it.
type Shared struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
	Scans int    `json:"scans"`
}

// Campaign is a group of scans linked by shared indicators.
type Campaign struct {
	ID         string                  `json:"id"`
	Size       int                     `json:"size"`
	FirstSeen  time.Time               `json:"first_seen"`
	LastSeen   time.Time               `json:"last_seen"`
	Verdicts   map[analyze.Verdict]int `json:"verdicts"`
	MaxVerdict analyze.Verdict         `json:"max_verdict"`
	Indicators []Shared                `json:"indicators"` // top shared, most common first
	Subjects   []string                `json:"subjects"`   // up to 3 examples
	ScanIDs    []string                `json:"scan_ids"`   // smallest first
	MoreScans  int                     `json:"more_scans,omitempty"`
}

// Result is a clustering of one window.
type Result struct {
	Scans     int            // scans in the window
	Limit     int            // values shared by more scans than this were ignored
	Dropped   map[string]int // values ignored by the guard, per kind
	Campaigns []Campaign     // sorted: largest first
}

var verdictRank = map[analyze.Verdict]int{analyze.VerdictClean: 0, analyze.VerdictSuspicious: 1, analyze.VerdictMalicious: 2}

const (
	topIndicators   = 5
	exampleSubjects = 3
	subjectChars    = 80
)

// Cluster groups members into campaigns: two scans are in the same campaign
// if they share an indicator, directly or through other scans (union-find).
func Cluster(members []Member, opt Options) Result {
	if opt.MaxShared == 0 {
		opt.MaxShared = 20
	}
	if opt.MaxShare == 0 {
		opt.MaxShare = 0.05
	}
	if opt.MinSize < 2 {
		opt.MinSize = 2
	}
	if opt.MinVerdict == "" {
		opt.MinVerdict = analyze.VerdictClean
	}
	res := Result{Scans: len(members), Dropped: map[string]int{}}
	res.Limit = max(opt.MaxShared, int(opt.MaxShare*float64(len(members))))

	// Which scans carry each indicator value.
	carriers := map[Indicator][]int{}
	for i, m := range members {
		for _, ind := range m.Indicators {
			carriers[ind] = append(carriers[ind], i)
		}
	}
	uf := newUnionFind(len(members))
	kept := map[Indicator]bool{}
	for ind, scans := range carriers {
		switch {
		case len(scans) > res.Limit:
			res.Dropped[ind.Kind]++
		case len(scans) > 1:
			kept[ind] = true
			for _, s := range scans[1:] {
				uf.union(scans[0], s)
			}
		}
	}

	groups := map[int][]int{}
	for i := range members {
		r := uf.find(i)
		groups[r] = append(groups[r], i)
	}
	for _, g := range groups {
		if len(g) < opt.MinSize {
			continue
		}
		c := summarise(members, g, kept, opt.MaxScanIDs)
		if verdictRank[c.MaxVerdict] >= verdictRank[opt.MinVerdict] {
			res.Campaigns = append(res.Campaigns, c)
		}
	}
	sort.Slice(res.Campaigns, func(i, j int) bool {
		a, b := res.Campaigns[i], res.Campaigns[j]
		if a.Size != b.Size {
			return a.Size > b.Size
		}
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return a.ID < b.ID
	})
	return res
}

func summarise(members []Member, g []int, kept map[Indicator]bool, maxIDs int) Campaign {
	c := Campaign{Size: len(g), Verdicts: map[analyze.Verdict]int{}, MaxVerdict: analyze.VerdictClean}
	ids := make([]string, 0, len(g))
	counts := map[Indicator]int{}
	seenSubject := map[string]bool{}
	for k, i := range g {
		m := members[i]
		ids = append(ids, m.ScanID)
		if k == 0 || m.ReceivedAt.Before(c.FirstSeen) {
			c.FirstSeen = m.ReceivedAt
		}
		if k == 0 || m.ReceivedAt.After(c.LastSeen) {
			c.LastSeen = m.ReceivedAt
		}
		c.Verdicts[m.Verdict]++
		if verdictRank[m.Verdict] > verdictRank[c.MaxVerdict] {
			c.MaxVerdict = m.Verdict
		}
		for _, ind := range m.Indicators {
			if kept[ind] {
				counts[ind]++
			}
		}
		if s := truncate(m.Subject, subjectChars); s != "" && !seenSubject[s] && len(c.Subjects) < exampleSubjects {
			seenSubject[s] = true
			c.Subjects = append(c.Subjects, s)
		}
	}
	sort.Strings(ids)
	sum := sha256.Sum256([]byte(ids[0]))
	c.ID = hex.EncodeToString(sum[:])[:12]
	if maxIDs > 0 && len(ids) > maxIDs {
		c.MoreScans, ids = len(ids)-maxIDs, ids[:maxIDs]
	}
	c.ScanIDs = ids

	for ind, n := range counts {
		if n > 1 {
			c.Indicators = append(c.Indicators, Shared{Kind: ind.Kind, Value: Display(ind), Scans: n})
		}
	}
	sort.Slice(c.Indicators, func(i, j int) bool {
		a, b := c.Indicators[i], c.Indicators[j]
		if a.Scans != b.Scans {
			return a.Scans > b.Scans
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Value < b.Value
	})
	if len(c.Indicators) > topIndicators {
		c.Indicators = c.Indicators[:topIndicators]
	}
	return c
}

// Display shortens subject fingerprints: the hash identifies, it does not
// need to be read.
func Display(ind Indicator) string {
	if ind.Kind == SubjectFP && len(ind.Value) > 12 {
		return ind.Value[:12]
	}
	return ind.Value
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// unionFind is a disjoint-set forest with path compression and union by
// size: near-constant time per operation, so clustering is linear in the
// number of (scan, indicator) pairs.
type unionFind struct{ parent, size []int }

func newUnionFind(n int) *unionFind {
	u := &unionFind{parent: make([]int, n), size: make([]int, n)}
	for i := range u.parent {
		u.parent[i], u.size[i] = i, 1
	}
	return u
}

func (u *unionFind) find(x int) int {
	for u.parent[x] != x {
		u.parent[x] = u.parent[u.parent[x]] // path halving
		x = u.parent[x]
	}
	return x
}

func (u *unionFind) union(a, b int) {
	ra, rb := u.find(a), u.find(b)
	if ra == rb {
		return
	}
	if u.size[ra] < u.size[rb] {
		ra, rb = rb, ra
	}
	u.parent[rb] = ra
	u.size[ra] += u.size[rb]
}
