package scrape

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"endlessh-dashboard/internal/geo"
	"endlessh-dashboard/internal/registry"
	"endlessh-dashboard/internal/store"
)

// This bounded collection experiment isolates concurrent fetch/parse/SQLite
// work before selecting a scheduler default. Padding exercises the response-size
// boundary, not worst-case label cardinality. Each case should run in its own
// process when comparing VmHWM; it is a process-lifetime high-water mark.
func BenchmarkFleetCollection(b *testing.B) {
	for _, size := range []string{"small", "near-limit"} {
		for _, fleet := range []int{1, 10, 100} {
			for _, workers := range []int{1, 2, 4} {
				b.Run(fmt.Sprintf("%s/machines=%d/workers=%d", size, fleet, workers), func(b *testing.B) { benchmarkCollection(b, size, fleet, workers, false) })
			}
		}
	}
}

// Includes the actual scheduler and observes committed last-success timestamps
// every 2ms. Reported first-success latency therefore includes that sampling
// overhead, also included in allocations; it is not a network-only latency
// or a capacity guarantee.
func BenchmarkFleetScheduling(b *testing.B) {
	for _, size := range []string{"small", "near-limit"} {
		for _, fleet := range []int{1, 10, 100} {
			for _, workers := range []int{1, 2, 4} {
				b.Run(fmt.Sprintf("%s/machines=%d/workers=%d", size, fleet, workers), func(b *testing.B) { benchmarkCollection(b, size, fleet, workers, true) })
			}
		}
	}
}

func benchmarkCollection(b *testing.B, size string, fleet, workers int, scheduled bool) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(b.TempDir(), "metrics.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(ctx); err != nil {
		b.Fatal(err)
	}
	local, err := geo.Open("")
	if err != nil {
		b.Fatal(err)
	}
	defer local.Close()
	p := NewPoller(db, registry.NewValidator(nil, false), local, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour, 5*time.Second, workers)
	payload := "endlessh_client_open_count_total{local_port=\"22\"} 1\nendlessh_client_closed_count_total{local_port=\"22\"} 0\nendlessh_sent_bytes_total{local_port=\"22\"} 0\nendlessh_trapped_time_seconds_total{local_port=\"22\"} 0\n"
	if size == "near-limit" {
		padding := "# response padding for bounded input experiment\n"
		payload += strings.Repeat(padding, (maxResponseBytes-len(payload)-1024)/len(padding))
	}
	if len(payload) > maxResponseBytes {
		b.Fatal("fixture exceeds limit")
	}
	var active, peak atomic.Int64
	var began []time.Time
	p.httpClient.Transport = limitTransport(func(r *http.Request) (*http.Response, error) {
		if scheduled {
			id, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/metrics/"))
			began[id] = time.Now()
		}
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		timer := time.NewTimer(2 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(payload)), Header: http.Header{}}, nil
	})
	machines := make([]store.Machine, fleet)
	for i := range machines {
		machines[i], err = db.CreateMachine(ctx, store.Machine{Name: fmt.Sprintf("mock-%03d", i), Host: "203.0.113.1", Port: 2112, MetricsPath: fmt.Sprintf("/metrics/%d", i), Enabled: true})
		if err != nil {
			b.Fatal(err)
		}
	}
	var first, age []float64
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		b.StopTimer()
		if scheduled {
			if _, err := db.DB().Exec("UPDATE machines SET last_ok_at=NULL"); err != nil {
				b.Fatal(err)
			}
		}
		b.StartTimer()
		started := time.Now()
		began = make([]time.Time, fleet)
		finished := make([]time.Time, fleet)
		if scheduled {
			func() {
				runCtx, cancel := context.WithCancel(ctx)
				done := make(chan struct{})
				go func() { defer close(done); p.Run(runCtx) }()
				defer func() { cancel(); <-done }()
				ticker := time.NewTicker(2 * time.Millisecond)
				defer ticker.Stop()
				deadline := time.NewTimer(30 * time.Second)
				defer deadline.Stop()
				for {
					rows, err := db.ListMachines(runCtx)
					if err != nil {
						b.Fatal(err)
					}
					count := 0
					now := time.Now()
					for i, m := range rows {
						if m.LastOKAt != nil {
							count++
							if finished[i].IsZero() {
								finished[i] = now
							}
						}
					}
					if count == fleet {
						break
					}
					select {
					case <-ticker.C:
					case <-deadline.C:
						b.Fatal("scheduler did not complete benchmark fleet")
					}
				}
			}()
		} else {

			jobs := make(chan int)
			var group sync.WaitGroup
			for w := 0; w < workers; w++ {
				group.Add(1)
				go func() {
					defer group.Done()
					for i := range jobs {
						began[i] = time.Now()
						p.pollOne(ctx, machines[i])
						finished[i] = time.Now()
					}
				}()
			}
			for i := range machines {
				jobs <- i
			}
			close(jobs)
			group.Wait()
		}

		end := time.Now()
		first = nil
		age = nil
		for i := range machines {
			first = append(first, float64(finished[i].Sub(started))/float64(time.Millisecond))
			age = append(age, float64(end.Sub(began[i]))/float64(time.Millisecond))
		}
	}
	b.StopTimer()
	sort.Float64s(first)
	sort.Float64s(age)
	percentile := func(values []float64, p int) float64 { return values[(len(values)-1)*p/100] }
	b.ReportMetric(percentile(first, 50), "p50-success-ms")
	b.ReportMetric(percentile(first, 95), "p95-success-ms")
	b.ReportMetric(percentile(age, 95), "p95-age-ms")
	b.ReportMetric(float64(peak.Load()), "peak-fetches")
	raw, _ := os.ReadFile("/proc/self/status")
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && (fields[0] == "VmRSS:" || fields[0] == "VmHWM:") {
			value, _ := strconv.ParseFloat(fields[1], 64)
			b.ReportMetric(value, strings.TrimSuffix(fields[0], ":")+"-KiB")
		}
	}
	b.ReportMetric(float64(len(payload)), "response-B")
}
