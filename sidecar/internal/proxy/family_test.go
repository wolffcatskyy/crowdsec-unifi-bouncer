package proxy

import (
	"testing"

	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/lapi"
	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/scorer"
)

func dec(value string) lapi.Decision {
	return lapi.Decision{Value: value, Origin: "CAPI", Type: "ban", Scenario: "test"}
}

func TestIsV6(t *testing.T) {
	cases := map[string]bool{
		"1.2.3.4":         false,
		"1.2.3.0/24":      false,
		"2001:db8::1":     true,
		"2001:db8::/32":   true,
		"::1":             true,
		"fe80::dead:beef": true,
	}
	for value, want := range cases {
		if got := IsV6(dec(value)); got != want {
			t.Errorf("IsV6(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestSplitByFamily(t *testing.T) {
	in := []lapi.Decision{dec("1.1.1.1"), dec("2001:db8::1"), dec("2.2.2.0/24"), dec("2001:db8::/32")}
	v4, v6 := SplitByFamily(in)
	if len(v4) != 2 || len(v6) != 2 {
		t.Fatalf("split = %d v4, %d v6; want 2/2", len(v4), len(v6))
	}
	if v4[0].Value != "1.1.1.1" || v4[1].Value != "2.2.2.0/24" {
		t.Errorf("v4 order not preserved: %v", v4)
	}
	if v6[0].Value != "2001:db8::1" || v6[1].Value != "2001:db8::/32" {
		t.Errorf("v6 order not preserved: %v", v6)
	}
}

func TestSplitByFamilyEmpty(t *testing.T) {
	v4, v6 := SplitByFamily(nil)
	if len(v4) != 0 || len(v6) != 0 {
		t.Errorf("nil input should give empty outputs, got %d/%d", len(v4), len(v6))
	}
}

func TestMergeStatsSumsAndUnions(t *testing.T) {
	a := scorer.Stats{
		TotalDecisions:    10,
		ReturnedDecisions: 8,
		DroppedDecisions:  2,
		MinScore:          5,
		MaxScore:          90,
		AvgScore:          40,
		MedianScore:       35,
		ScoreCutoff:       20,
		ScoreDistribution: map[string]int{"ssh-bf": 6, "http-xss": 4},
		OriginKept:        map[string]int{"CAPI": 8},
		OriginDropped:     map[string]int{"CAPI": 2},
		ScoreBuckets:      map[int]int{50: 7, 100: 10},
		DroppedIPs:        map[string]struct{}{"9.9.9.9": {}},
	}
	b := scorer.Stats{
		TotalDecisions:    4,
		ReturnedDecisions: 3,
		DroppedDecisions:  1,
		MinScore:          10,
		MaxScore:          70,
		AvgScore:          30,
		MedianScore:       25,
		ScoreCutoff:       15,
		ScoreDistribution: map[string]int{"ssh-bf": 4},
		OriginKept:        map[string]int{"CAPI": 3},
		OriginDropped:     map[string]int{"CAPI": 1},
		ScoreBuckets:      map[int]int{50: 4, 100: 4},
		DroppedIPs:        map[string]struct{}{"2001:db8::9": {}},
	}
	m := mergeStats(a, b)
	if m.TotalDecisions != 14 || m.ReturnedDecisions != 11 || m.DroppedDecisions != 3 {
		t.Errorf("totals = %d/%d/%d, want 14/11/3", m.TotalDecisions, m.ReturnedDecisions, m.DroppedDecisions)
	}
	if m.MinScore != 5 || m.MaxScore != 90 {
		t.Errorf("min/max = %d/%d, want 5/90", m.MinScore, m.MaxScore)
	}
	if m.ScoreDistribution["ssh-bf"] != 10 || m.ScoreDistribution["http-xss"] != 4 {
		t.Errorf("distribution merge wrong: %v", m.ScoreDistribution)
	}
	if m.ScoreBuckets[50] != 11 || m.ScoreBuckets[100] != 14 {
		t.Errorf("bucket merge wrong: %v", m.ScoreBuckets)
	}
	if len(m.DroppedIPs) != 2 {
		t.Errorf("DroppedIPs union = %d, want 2", len(m.DroppedIPs))
	}
	// Cutoff = lowest score that survived in either family
	if m.ScoreCutoff != 15 {
		t.Errorf("ScoreCutoff = %d, want 15", m.ScoreCutoff)
	}
	// Weighted average: (40*10 + 30*4) / 14 = 37.14...
	wantAvg := (40.0*10 + 30.0*4) / 14
	if m.AvgScore < wantAvg-0.001 || m.AvgScore > wantAvg+0.001 {
		t.Errorf("AvgScore = %f, want ~%f", m.AvgScore, wantAvg)
	}
}

func TestMergeStatsWithEmptyFamily(t *testing.T) {
	a := scorer.Stats{TotalDecisions: 5, ReturnedDecisions: 5, MinScore: 3, MaxScore: 50, AvgScore: 20, ScoreCutoff: 3}
	b := scorer.Stats{} // empty family: all zeros
	m := mergeStats(a, b)
	if m.TotalDecisions != 5 || m.MinScore != 3 || m.MaxScore != 50 || m.ScoreCutoff != 3 {
		t.Errorf("merge with empty family = %+v", m)
	}
}
