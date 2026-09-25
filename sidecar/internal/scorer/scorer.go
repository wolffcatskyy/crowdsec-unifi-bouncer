// Package scorer implements decision scoring and prioritization logic.
package scorer

import (
	"net"
	"sort"
	"strings"
	"time"

	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/config"
	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/feed"
	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/lapi"
)

// Scorer calculates priority scores for CrowdSec decisions.
type Scorer struct {
	config *config.ScoringConfig
	feeds  *feed.Parser
}

// New creates a new Scorer with the given configuration.
func New(cfg *config.ScoringConfig) *Scorer {
	s := &Scorer{
		config: cfg,
	}
	if cfg.FeedScoring.Enabled {
		s.feeds = feed.NewParser(cfg.FeedScoring.Prefixes, cfg.FeedScoring.LegacyPrefixes)
	}
	return s
}

// Score calculates the priority score for a single decision.
// Higher scores indicate higher priority (should be kept when truncating).
//
// Scoring factors:
//   - Scenario score * multiplier (pattern-matched)
//   - Origin score (CAPI, crowdsec, cscli)
//   - TTL bonus (longer bans = higher priority)
//   - Decision type bonus (ban vs captcha)
//   - Freshness bonus (recently created = higher priority)
//   - CIDR bonus (broader ranges = higher priority)
//   - Feed confidence penalty (blocklist-import decisions from low-confidence
//     feeds rank lower; see config.FeedScoringConfig)
//
// Recidivism bonus is applied separately in ScoreAndSort.
func (s *Scorer) Score(d *lapi.Decision) int {
	score := 0

	// Scenario score with multiplier
	scenarioBase := s.config.GetScenarioScore(d.Scenario)
	multiplier := s.config.GetScenarioMultiplier()
	score += int(float64(scenarioBase) * multiplier)

	// Origin score
	score += s.config.GetOriginScore(d.Origin)

	// TTL bonus
	if s.config.TTLScoring.Enabled && d.ParsedDuration > 0 {
		score += s.calculateTTLBonus(d.ParsedDuration)
	}

	// Decision type bonus
	score += s.config.GetDecisionTypeScore(d.Type)

	// Freshness bonus (based on created_at)
	if !d.ParsedCreated.IsZero() {
		age := time.Since(d.ParsedCreated)
		score += s.config.GetFreshnessBonus(age)
	}

	// CIDR bonus (based on IP/CIDR prefix length)
	if d.Scope == "range" || strings.Contains(d.Value, "/") {
		prefixLen := parsePrefixLen(d.Value)
		score += s.config.GetCIDRBonus(prefixLen)
	} else if d.Scope == "ip" || d.Scope == "Ip" || d.Scope == "" {
		// Single IP = /32
		score += s.config.GetCIDRBonus(32)
	}

	// Feed confidence penalty (blocklist-import provenance in scenario name)
	score -= s.feedPenalty(d)

	return score
}

// feedPenalty parses blocklist-import provenance from the scenario name,
// records the feed slug on the decision, and returns the points to subtract.
// Returns 0 for non-import decisions and for feeds with unknown confidence.
func (s *Scorer) feedPenalty(d *lapi.Decision) int {
	d.Feed = ""
	if s.feeds == nil {
		return 0
	}
	info, ok := s.feeds.Parse(d.Scenario)
	if !ok {
		return 0
	}
	d.Feed = info.Slug

	fc := &s.config.FeedScoring
	if conf, ok := fc.Feeds[info.Slug]; ok {
		return fc.Penalty(conf)
	}
	if info.HasConfidence {
		return fc.Penalty(info.Confidence)
	}
	return 0
}

// calculateTTLBonus returns bonus points based on remaining TTL.
// Longer bans get more points, up to MaxBonus for bans >= MaxTTL.
func (s *Scorer) calculateTTLBonus(duration time.Duration) int {
	if duration <= 0 {
		return 0
	}

	maxTTL := s.config.TTLScoring.MaxTTL
	maxBonus := s.config.TTLScoring.MaxBonus

	if duration >= maxTTL {
		return maxBonus
	}

	// Linear scaling: (duration / maxTTL) * maxBonus
	ratio := float64(duration) / float64(maxTTL)
	return int(ratio * float64(maxBonus))
}

// parsePrefixLen extracts the prefix length from a CIDR string.
// Returns 32 for single IPs or unparseable values.
func parsePrefixLen(value string) int {
	if strings.Contains(value, "/") {
		_, ipNet, err := net.ParseCIDR(value)
		if err == nil {
			ones, _ := ipNet.Mask.Size()
			return ones
		}
	}
	return 32
}

// ScoreAndSort scores all decisions and returns them sorted by score (descending).
// Applies recidivism bonus: IPs with multiple decisions get extra points per occurrence.
func (s *Scorer) ScoreAndSort(decisions []lapi.Decision) []lapi.Decision {
	// Recidivism pre-pass: count decisions per IP
	ipCounts := make(map[string]int)
	if s.config.RecidivismBonus > 0 {
		for _, d := range decisions {
			ipCounts[d.Value]++
		}
	}

	// Score each decision
	for i := range decisions {
		decisions[i].Score = s.Score(&decisions[i])

		// Add recidivism bonus: bonus * (count - 1) for repeat offenders
		if s.config.RecidivismBonus > 0 {
			count := ipCounts[decisions[i].Value]
			if count > 1 {
				decisions[i].Score += s.config.RecidivismBonus * (count - 1)
			}
		}
	}

	// Sort by score descending, then by ID for stability
	sort.Slice(decisions, func(i, j int) bool {
		if decisions[i].Score != decisions[j].Score {
			return decisions[i].Score > decisions[j].Score
		}
		return decisions[i].ID < decisions[j].ID
	})

	return decisions
}

// ScoreAndTruncate scores decisions, sorts them, and returns the top N.
func (s *Scorer) ScoreAndTruncate(decisions []lapi.Decision, maxDecisions int) []lapi.Decision {
	sorted := s.ScoreAndSort(decisions)

	if len(sorted) <= maxDecisions {
		return sorted
	}

	return sorted[:maxDecisions]
}

// ScoreBucketThresholds defines the histogram bucket boundaries for score distribution.
var ScoreBucketThresholds = []int{25, 50, 75, 100, 150, 200}

// Stats contains statistics about the scoring operation.
type Stats struct {
	TotalDecisions    int
	ReturnedDecisions int
	DroppedDecisions  int
	MinScore          int
	MaxScore          int
	AvgScore          float64
	ScoreDistribution map[string]int // scenario -> count (all decisions)

	// Effectiveness metrics (v2.2.0)
	OriginKept      map[string]int         // origin -> count of kept decisions
	OriginDropped   map[string]int         // origin -> count of dropped decisions
	ScenarioKept    map[string]int         // scenario -> count of kept decisions
	ScenarioDropped map[string]int         // scenario -> count of dropped decisions
	MedianScore     int                    // median score across all decisions
	ScoreCutoff     int                    // lowest score that survived truncation
	ScoreBuckets    map[int]int            // threshold -> cumulative count of decisions with score <= threshold
	RecidivismIPs   int                    // unique IPs that received recidivism bonus
	RecidivismBoosts int                   // total recidivism bonus points applied across all decisions
	DroppedIPs      map[string]struct{}    // set of IP values that were dropped (for false-negative checking)

	// Feed metrics (blocklist-import decisions only, keyed by feed slug)
	FeedKept    map[string]int
	FeedDropped map[string]int
}

// ScoreAndTruncateWithStats is like ScoreAndTruncate but also returns stats.
func (s *Scorer) ScoreAndTruncateWithStats(decisions []lapi.Decision, maxDecisions int) ([]lapi.Decision, Stats) {
	stats := Stats{
		TotalDecisions:    len(decisions),
		ScoreDistribution: make(map[string]int),
		OriginKept:        make(map[string]int),
		OriginDropped:     make(map[string]int),
		ScenarioKept:      make(map[string]int),
		ScenarioDropped:   make(map[string]int),
		ScoreBuckets:      make(map[int]int),
		DroppedIPs:        make(map[string]struct{}),
		FeedKept:          make(map[string]int),
		FeedDropped:       make(map[string]int),
	}

	if len(decisions) == 0 {
		return decisions, stats
	}

	// Score and sort (includes recidivism bonus)
	sorted := s.ScoreAndSort(decisions)

	// Recidivism stats: count unique IPs with bonus and total bonus applied
	if s.config.RecidivismBonus > 0 {
		ipCounts := make(map[string]int)
		for _, d := range sorted {
			ipCounts[d.Value]++
		}
		for _, count := range ipCounts {
			if count > 1 {
				stats.RecidivismIPs++
				// Each of the `count` decisions gets bonus*(count-1)
				stats.RecidivismBoosts += s.config.RecidivismBonus * (count - 1) * count
			}
		}
	}

	// Single pass over all sorted decisions: stats, distribution, buckets
	totalScore := 0
	stats.MaxScore = sorted[0].Score
	stats.MinScore = sorted[len(sorted)-1].Score

	for _, d := range sorted {
		totalScore += d.Score
		stats.ScoreDistribution[d.Scenario]++

		// Score buckets (cumulative: le=T counts all decisions with score <= T)
		for _, threshold := range ScoreBucketThresholds {
			if d.Score <= threshold {
				stats.ScoreBuckets[threshold]++
			}
		}
	}
	stats.AvgScore = float64(totalScore) / float64(len(sorted))

	// Median score (sorted is descending)
	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		stats.MedianScore = (sorted[mid-1].Score + sorted[mid].Score) / 2
	} else {
		stats.MedianScore = sorted[mid].Score
	}

	// Truncate
	result := sorted
	if len(sorted) > maxDecisions {
		result = sorted[:maxDecisions]
	}

	stats.ReturnedDecisions = len(result)
	stats.DroppedDecisions = stats.TotalDecisions - stats.ReturnedDecisions

	// Score cutoff: lowest score that survived truncation
	if len(result) > 0 {
		stats.ScoreCutoff = result[len(result)-1].Score
	}

	// Per-origin and per-scenario kept counts
	for _, d := range result {
		stats.OriginKept[d.Origin]++
		stats.ScenarioKept[d.Scenario]++
		if d.Feed != "" {
			stats.FeedKept[d.Feed]++
		}
	}

	// Dropped counts and dropped IP set
	if len(sorted) > maxDecisions {
		for _, d := range sorted[maxDecisions:] {
			stats.OriginDropped[d.Origin]++
			stats.ScenarioDropped[d.Scenario]++
			stats.DroppedIPs[d.Value] = struct{}{}
			if d.Feed != "" {
				stats.FeedDropped[d.Feed]++
			}
		}
	}

	return result, stats
}
