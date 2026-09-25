package proxy

import (
	"strings"

	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/lapi"
	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/scorer"
)

// Address-family helpers for per-family decision capping.
//
// The device keeps two independent ipsets - crowdsec-blacklists (inet) and
// crowdsec6-blacklists (inet6) - each with its own maxelem, so the sidecar
// caps IPv4 and IPv6 decisions separately (max_decisions / max_decisions_v6).
// A combined cap would let a flood of one family evict the other.

// IsV6 reports whether a decision targets an IPv6 address or CIDR.
// Decision values are IPs or CIDRs; only v6 forms contain a colon.
func IsV6(d lapi.Decision) bool {
	return strings.Contains(d.Value, ":")
}

// SplitByFamily partitions decisions into IPv4 and IPv6 lists, preserving order.
func SplitByFamily(decisions []lapi.Decision) (v4, v6 []lapi.Decision) {
	for _, d := range decisions {
		if IsV6(d) {
			v6 = append(v6, d)
		} else {
			v4 = append(v4, d)
		}
	}
	return v4, v6
}

// mergeStats combines the per-family scoring stats into one report.
// Counts and maps are summed; min/max scores are the extremes; averages are
// weighted by the number of decisions each stats block describes.
func mergeStats(a, b scorer.Stats) scorer.Stats {
	out := scorer.Stats{
		TotalDecisions:    a.TotalDecisions + b.TotalDecisions,
		ReturnedDecisions: a.ReturnedDecisions + b.ReturnedDecisions,
		DroppedDecisions:  a.DroppedDecisions + b.DroppedDecisions,
		ScoreDistribution: mergeCountMap(a.ScoreDistribution, b.ScoreDistribution),
		OriginKept:        mergeCountMap(a.OriginKept, b.OriginKept),
		OriginDropped:     mergeCountMap(a.OriginDropped, b.OriginDropped),
		ScenarioKept:      mergeCountMap(a.ScenarioKept, b.ScenarioKept),
		ScenarioDropped:   mergeCountMap(a.ScenarioDropped, b.ScenarioDropped),
		ScoreBuckets:      mergeBucketMap(a.ScoreBuckets, b.ScoreBuckets),
		DroppedIPs:        map[string]struct{}{},
		RecidivismIPs:     a.RecidivismIPs + b.RecidivismIPs,
		RecidivismBoosts:  a.RecidivismBoosts + b.RecidivismBoosts,
	}
	for ip := range a.DroppedIPs {
		out.DroppedIPs[ip] = struct{}{}
	}
	for ip := range b.DroppedIPs {
		out.DroppedIPs[ip] = struct{}{}
	}

	// Min/Max over non-empty inputs only (an empty family reports zeros).
	out.MinScore = a.MinScore
	if a.TotalDecisions == 0 || (b.TotalDecisions > 0 && b.MinScore < out.MinScore) {
		out.MinScore = b.MinScore
	}
	out.MaxScore = a.MaxScore
	if b.MaxScore > out.MaxScore {
		out.MaxScore = b.MaxScore
	}
	if out.TotalDecisions > 0 {
		out.AvgScore = (a.AvgScore*float64(a.TotalDecisions) + b.AvgScore*float64(b.TotalDecisions)) / float64(out.TotalDecisions)
	}
	// Median/cutoff cannot be merged exactly; the cutoff is the lowest score
	// that survived in either family, and the median is approximated by the
	// weighted mean of the two medians. Both are effectiveness-reporting
	// fields, not enforcement logic.
	if a.ReturnedDecisions == 0 {
		out.ScoreCutoff = b.ScoreCutoff
	} else if b.ReturnedDecisions == 0 {
		out.ScoreCutoff = a.ScoreCutoff
	} else if b.ScoreCutoff < a.ScoreCutoff {
		out.ScoreCutoff = b.ScoreCutoff
	} else {
		out.ScoreCutoff = a.ScoreCutoff
	}
	if out.TotalDecisions > 0 {
		out.MedianScore = (a.MedianScore*a.TotalDecisions + b.MedianScore*b.TotalDecisions) / out.TotalDecisions
	}
	return out
}

func mergeCountMap(a, b map[string]int) map[string]int {
	out := make(map[string]int, len(a)+len(b))
	for k, v := range a {
		out[k] += v
	}
	for k, v := range b {
		out[k] += v
	}
	return out
}

func mergeBucketMap(a, b map[int]int) map[int]int {
	out := make(map[int]int, len(a)+len(b))
	for k, v := range a {
		out[k] += v
	}
	for k, v := range b {
		out[k] += v
	}
	return out
}
