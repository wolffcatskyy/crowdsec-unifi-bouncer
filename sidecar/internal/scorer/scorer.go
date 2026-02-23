// Package scorer implements decision scoring and prioritization logic.
package scorer

import (
	"net"
	"sort"
	"strings"
	"time"

	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/config"
	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/lapi"
)

// Scorer calculates priority scores for CrowdSec decisions.
type Scorer struct {
	config *config.ScoringConfig
}

// New creates a new Scorer with the given configuration.
func New(cfg *config.ScoringConfig) *Scorer {
	return &Scorer{
		config: cfg,
	}
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

	return score
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

// Stats contains statistics about the scoring operation.
type Stats struct {
	TotalDecisions    int
	ReturnedDecisions int
	DroppedDecisions  int
	MinScore          int
	MaxScore          int
	AvgScore          float64
	ScoreDistribution map[string]int // scenario -> count
}

// ScoreAndTruncateWithStats is like ScoreAndTruncate but also returns stats.
func (s *Scorer) ScoreAndTruncateWithStats(decisions []lapi.Decision, maxDecisions int) ([]lapi.Decision, Stats) {
	stats := Stats{
		TotalDecisions:    len(decisions),
		ScoreDistribution: make(map[string]int),
	}

	if len(decisions) == 0 {
		return decisions, stats
	}

	// Score and sort
	sorted := s.ScoreAndSort(decisions)

	// Calculate stats
	totalScore := 0
	stats.MinScore = sorted[len(sorted)-1].Score
	stats.MaxScore = sorted[0].Score

	for _, d := range sorted {
		totalScore += d.Score
		stats.ScoreDistribution[d.Scenario]++
	}
	stats.AvgScore = float64(totalScore) / float64(len(sorted))

	// Truncate
	result := sorted
	if len(sorted) > maxDecisions {
		result = sorted[:maxDecisions]
	}

	stats.ReturnedDecisions = len(result)
	stats.DroppedDecisions = stats.TotalDecisions - stats.ReturnedDecisions

	return result, stats
}
