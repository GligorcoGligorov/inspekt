package campaign

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
)

var t0 = time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)

func m(id string, v analyze.Verdict, minute int, inds ...Indicator) Member {
	return Member{ScanID: id, ReceivedAt: t0.Add(time.Duration(minute) * time.Minute), Verdict: v, Subject: "subject " + id, Indicators: inds}
}

func host(h string) Indicator { return Indicator{LinkHost, h} }
func ip(a string) Indicator   { return Indicator{SenderIP, a} }

const (
	clean = analyze.VerdictClean
	susp  = analyze.VerdictSuspicious
	mal   = analyze.VerdictMalicious
)

func TestClusterIsTransitive(t *testing.T) {
	// a-b share a host, b-c share an IP: one campaign of 3; d is alone.
	res := Cluster([]Member{
		m("c", mal, 3, ip("151.101.1.69")),
		m("a", mal, 1, host("evil-login.xyz")),
		m("b", clean, 2, host("evil-login.xyz"), ip("151.101.1.69")),
		m("d", mal, 4, host("other.example")),
	}, Options{})
	if len(res.Campaigns) != 1 {
		t.Fatalf("campaigns %+v", res.Campaigns)
	}
	c := res.Campaigns[0]
	if c.Size != 3 || strings.Join(c.ScanIDs, ",") != "a,b,c" || !c.FirstSeen.Equal(t0.Add(time.Minute)) || !c.LastSeen.Equal(t0.Add(3*time.Minute)) {
		t.Errorf("campaign %+v", c)
	}
	if c.Verdicts[mal] != 2 || c.Verdicts[clean] != 1 || c.MaxVerdict != mal {
		t.Errorf("verdicts %v max %s", c.Verdicts, c.MaxVerdict)
	}
	if c.ID != Cluster([]Member{m("a", mal, 0, host("x.example")), m("zzz", mal, 0, host("x.example"))}, Options{}).Campaigns[0].ID {
		t.Error("campaign id must depend only on the smallest scan id")
	}
}

// A missed phish (clean) joins its caught sibling, and the campaign passes
// a min_verdict filter because of its highest member.
func TestMinVerdictUsesHighestMember(t *testing.T) {
	ms := []Member{m("a", clean, 1, host("evil.example")), m("b", mal, 2, host("evil.example")),
		m("c", clean, 3, host("benign.example")), m("d", clean, 4, host("benign.example"))}
	res := Cluster(ms, Options{MinVerdict: susp})
	if len(res.Campaigns) != 1 || res.Campaigns[0].Size != 2 || res.Campaigns[0].ScanIDs[0] != "a" {
		t.Fatalf("got %+v", res.Campaigns)
	}
	if n := len(Cluster(ms, Options{MinVerdict: clean}).Campaigns); n != 2 {
		t.Errorf("min_verdict=clean returned %d campaigns, want 2", n)
	}
	if n := len(Cluster(ms, Options{MinSize: 3}).Campaigns); n != 0 {
		t.Errorf("min_size=3 returned %d campaigns", n)
	}
}

// One value carried by too many scans is infrastructure, not a campaign:
// it must not chain everything together.
func TestGiantClusterGuard(t *testing.T) {
	var ms []Member
	for i := range 30 { // 30 unrelated scans all relayed through one IP
		ms = append(ms, m(fmt.Sprintf("s%02d", i), mal, i, ip("8.8.4.4"), host(fmt.Sprintf("h%d.example", i))))
	}
	ms = append(ms, m("x1", mal, 40, host("h1.example"))) // a real 2-scan pair
	res := Cluster(ms, Options{})                         // limit max(20, 5% of 31) = 20
	if res.Limit != 20 || res.Dropped[SenderIP] != 1 {
		t.Fatalf("limit %d dropped %v", res.Limit, res.Dropped)
	}
	if len(res.Campaigns) != 1 || res.Campaigns[0].Size != 2 {
		t.Fatalf("campaigns %+v", res.Campaigns)
	}
	// Raising the limit lets the shared IP chain all 30 into one.
	if big := Cluster(ms, Options{MaxShared: 100}); big.Campaigns[0].Size != 31 {
		t.Errorf("with the guard off: %+v", big.Campaigns[0].Size)
	}
	// The 5 % share wins once the window is large.
	var many []Member
	for i := range 1000 {
		many = append(many, m(fmt.Sprintf("m%04d", i), clean, 0))
	}
	if l := Cluster(many, Options{}).Limit; l != 50 {
		t.Errorf("limit for 1000 scans %d, want 50", l)
	}
}

func TestSummaryDetails(t *testing.T) {
	long := strings.Repeat("Ü", 100)
	var ms []Member
	for i := range 60 {
		mm := m(fmt.Sprintf("s%02d", i), mal, i, host("evil.example"), Indicator{SubjectFP, strings.Repeat("ab", 32)})
		mm.Subject = fmt.Sprintf("%d %s", i%5, long)
		ms = append(ms, mm)
	}
	c := Cluster(ms, Options{MaxScanIDs: 50, MaxShared: 100}).Campaigns[0]
	if len(c.ScanIDs) != 50 || c.MoreScans != 10 {
		t.Errorf("scan ids %d more %d", len(c.ScanIDs), c.MoreScans)
	}
	if len(c.Subjects) != 3 || len([]rune(c.Subjects[0])) != 81 {
		t.Errorf("subjects %d, first %d runes", len(c.Subjects), len([]rune(c.Subjects[0])))
	}
	if len(c.Indicators) != 2 || c.Indicators[0].Scans != 60 {
		t.Fatalf("indicators %+v", c.Indicators)
	}
	for _, s := range c.Indicators {
		if s.Kind == SubjectFP && s.Value != strings.Repeat("ab", 6) {
			t.Errorf("subject fingerprint not shortened: %q", s.Value)
		}
	}
}

func TestUnionFind(t *testing.T) {
	u := newUnionFind(6)
	u.union(0, 1)
	u.union(2, 3)
	u.union(1, 3)
	if u.find(0) != u.find(2) || u.find(4) == u.find(0) || u.find(5) == u.find(4) {
		t.Error("wrong sets")
	}
	if u.size[u.find(0)] != 4 {
		t.Errorf("size %d", u.size[u.find(0)])
	}
}
