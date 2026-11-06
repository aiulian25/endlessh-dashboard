package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestSummaryAndChartUseSameMinuteRange(t *testing.T) {
	s, _ := newStore(t)
	m := createMachine(t, s, "edges")
	for i, value := range []float64{10, 20, 30} {
		applyScrape(t, s, ScrapeDelta{MachineID: m.ID, At: baseTime.Add(time.Duration(i) * time.Minute), Opens: int64(value), BytesSent: int64(value), TrappedSeconds: value})
	}
	from, to := baseTime.Add(90*time.Second), baseTime.Add(3*time.Minute)
	summary, err := s.Overview(context.Background(), []int64{m.ID}, from, from, to)
	if err != nil {
		t.Fatal(err)
	}
	chart, err := s.TimeSeries(context.Background(), []Machine{m}, from, to, 3600)
	if err != nil {
		t.Fatal(err)
	}
	var sum float64
	for _, p := range chart[0].Points {
		sum += p.TrappedSeconds
	}
	if summary.TimeWastedDeltaSeconds != sum {
		t.Fatalf("summary=%g chart=%g", summary.TimeWastedDeltaSeconds, sum)
	}
	if sum != 30 {
		t.Fatalf("included outside rows: %g", sum)
	}
}

func TestRangeEdgesAndPartialDisplayBuckets(t *testing.T) {
	s, _ := newStore(t)
	m := createMachine(t, s, "bins")
	ctx := context.Background()
	origin := time.Date(2024, 3, 31, 23, 0, 0, 0, time.UTC)
	for i := 0; i < 182; i++ {
		applyScrape(t, s, ScrapeDelta{MachineID: m.ID, At: origin.Add(time.Duration(i) * time.Minute), Opens: 1, BytesSent: 1, TrappedSeconds: 1})
	}
	for _, bucket := range []int{300, 3600, 86400} {
		t.Run(fmt.Sprint(bucket), func(t *testing.T) {
			from, to := origin.Add(90*time.Second), origin.Add(121*time.Minute)
			series, err := s.TimeSeries(ctx, []Machine{m}, from, to, bucket)
			if err != nil {
				t.Fatal(err)
			}
			summary, err := s.Overview(ctx, []int64{m.ID}, from, from, to)
			if err != nil {
				t.Fatal(err)
			}
			var opens int64
			var seconds float64
			span := NewTimeRange(from, to)
			for _, p := range series[0].Points {
				if p.At.Before(span.From) || p.To.After(span.To) || !p.At.Before(p.To) {
					t.Fatal("point interval widened selection")
				}
				opens += p.Opens
				seconds += p.TrappedSeconds
			}
			if opens != 119 || seconds != 119 || summary.TimeWastedDeltaSeconds != seconds || summary.BytesSentDelta != opens {
				t.Fatalf("range totals differ: %d %g %+v", opens, seconds, summary)
			}
			if !series[0].Points[0].Partial || !series[0].Points[len(series[0].Points)-1].Partial {
				t.Fatal("partial edge buckets unlabeled")
			}
		})
	}
	empty := origin.Add(30 * time.Second)
	series, err := s.TimeSeries(ctx, []Machine{m}, empty, empty, 3600)
	if err != nil || len(series) != 1 || len(series[0].Points) != 0 {
		t.Fatal("empty range was widened")
	}
	overview, err := s.Overview(ctx, []int64{m.ID}, empty, empty, empty)
	if err != nil || overview.TimeWastedDeltaSeconds != 0 {
		t.Fatal("empty summary not empty")
	}
	if _, err = s.TimeSeries(ctx, []Machine{m}, origin.Add(time.Hour), origin, 3600); err == nil {
		t.Fatal("reversed range accepted")
	}
}

func TestMinuteBoundaryKeepsExactEdgesAndRoundsSubsecondsForward(t *testing.T) {
	if got := MinuteBoundary(baseTime); !got.Equal(baseTime) {
		t.Fatal("exact minute moved")
	}
	if got := MinuteBoundary(baseTime.Add(time.Nanosecond)); !got.Equal(baseTime.Add(time.Minute)) {
		t.Fatal("subsecond start was rounded backward")
	}
	span := NewTimeRange(baseTime.Add(time.Nanosecond), baseTime.Add(90*time.Second))
	if !span.From.Equal(baseTime.Add(time.Minute)) || !span.To.Equal(baseTime.Add(2*time.Minute)) {
		t.Fatal("range edges use different rounding")
	}
}
