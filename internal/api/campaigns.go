package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/campaign"
	"github.com/GligorcoGligorov/inspekt/internal/metrics"
)

const (
	defaultSince = 24 * time.Hour
	maxSince     = 30 * 24 * time.Hour
	maxMinSize   = 10000
	maxListedIDs = 50
)

// campaignsResponse is the GET /v1/campaigns body.
type campaignsResponse struct {
	Window    campaignWindow      `json:"window"`
	Campaigns []campaign.Campaign `json:"campaigns"`
}

type campaignWindow struct {
	Since     string         `json:"since"` // effective window, after the 30d cap
	From      time.Time      `json:"from"`
	Scans     int            `json:"scans"`
	Limit     int            `json:"guard_limit"`   // values shared by more scans were ignored
	Dropped   map[string]int `json:"guard_dropped"` // ignored values per kind
	Oversized int            `json:"oversized"`     // clusters above the size cap (returned, flagged)
	Capped    bool           `json:"since_capped,omitempty"`
}

// campaigns clusters the scans of a recent window into campaigns. It is a
// correlation view only: it reads stored results and never changes them.
func (s *Server) campaigns(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "campaigns need the result store (INSPEKT_MARIADB_DSN)"})
		return
	}
	q := r.URL.Query()
	since, capped, err := parseSince(q.Get("since"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	minSize := 2
	if v := q.Get("min_size"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 2 || n > maxMinSize {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "min_size must be an integer from 2 to 10000"})
			return
		}
		minSize = n
	}
	minVerdict := analyze.VerdictSuspicious
	if v := q.Get("min_verdict"); v != "" {
		switch analyze.Verdict(v) {
		case analyze.VerdictClean, analyze.VerdictSuspicious, analyze.VerdictMalicious:
			minVerdict = analyze.Verdict(v)
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "min_verdict must be clean, suspicious or malicious"})
			return
		}
	}

	start := time.Now()
	from := start.Add(-since)
	members, err := s.Store.Members(r.Context(), from)
	if err != nil {
		s.Log.Error("campaigns: read members", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "store unavailable"})
		return
	}
	opt := s.Campaign
	opt.MinSize, opt.MinVerdict, opt.MaxScanIDs = minSize, minVerdict, maxListedIDs
	res := campaign.Cluster(members, opt)
	metrics.CampaignQueryDuration.Observe(time.Since(start).Seconds())
	metrics.CampaignsReturned.Observe(float64(len(res.Campaigns)))

	if res.Campaigns == nil {
		res.Campaigns = []campaign.Campaign{}
	}
	writeJSON(w, http.StatusOK, campaignsResponse{
		Window: campaignWindow{Since: since.String(), From: from.UTC(), Scans: res.Scans,
			Limit: res.Limit, Dropped: res.Dropped, Oversized: res.Oversized, Capped: capped},
		Campaigns: res.Campaigns,
	})
}

// parseSince accepts Go durations ("90m", "24h") and days ("7d"). Windows
// longer than 30 days are capped, not rejected, and the response says so.
func parseSince(v string) (d time.Duration, capped bool, err error) {
	if v == "" {
		return defaultSince, false, nil
	}
	if days, ok := strings.CutSuffix(v, "d"); ok {
		n, perr := strconv.Atoi(days)
		if perr != nil {
			return 0, false, errors.New("since must be a duration like 24h, 90m or 7d")
		}
		d = time.Duration(n) * 24 * time.Hour
	} else if d, err = time.ParseDuration(v); err != nil {
		return 0, false, errors.New("since must be a duration like 24h, 90m or 7d")
	}
	if d <= 0 {
		return 0, false, errors.New("since must be positive")
	}
	if d > maxSince {
		return maxSince, true, nil
	}
	return d, false, nil
}
