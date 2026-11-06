package store

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"
)

// Run explicitly with -run '^$' -bench '^BenchmarkDashboardQueries$' -benchtime=20x
// -count=1 -v. Each size/mode gets a fresh temporary DB, cleaned by testing.
// Fixtures are deterministic and skewed (24h activity on machine 1), not a
// production capacity model. Enrichment progress starts empty. No network or production data.
func BenchmarkDashboardQueries(b *testing.B) {
	b.Logf("runtime=%s GOOS=%s GOARCH=%s GOMAXPROCS=%d", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.GOMAXPROCS(0))
	for _, size := range []int{10000, 100000, 1000000} {
		for _, indexed := range []bool{false, true} {
			b.Run(fmt.Sprintf("rows=%d/ipindex=%t", size, indexed), func(b *testing.B) {
				seedStart := time.Now()
				s, path, ids := queryBenchmarkFixture(b, size, indexed)
				b.Cleanup(func() { s.Close() })
				b.Logf("seed-ms=%.1f", float64(time.Since(seedStart).Microseconds())/1000)
				ctx := context.Background()
				now := queryBenchmarkTime
				var version string
				if err := s.DB().QueryRow("SELECT sqlite_version()").Scan(&version); err != nil {
					b.Fatal(err)
				}
				b.Logf("page-wide-reference=%t", os.Getenv("DASHBOARD_BENCH_WIDE_PAGE") == "1")
				b.Logf("sqlite=%s fixture: 10 machines, half rows on machine 1, 20%% rows share IPs in pairs, 90-day spread, country aliases; first read=SQLite-cold/OS-cache-possible; DB=%d WAL=%d", version, fileBytes(path), fileBytes(path+"-wal"))
				// Explain the actual general-IP write and representative list/count/summary
				// shapes, including the production country expression and enrichment query.
				benchmarkPlan(b, s, "ip-update", `UPDATE attackers SET isp=? WHERE ip_address=?`, "fixture", queryBenchmarkIP(0, size))
				benchmarkPlan(b, s, "page", `SELECT machine_id,ip_address FROM attackers WHERE machine_id IN (1,2,3,4,5,6,7,8,9,10) AND last_measured_activity_at>=? ORDER BY trapped_seconds DESC,ip_address,machine_id LIMIT 50 OFFSET ?`, now.Add(-90*24*time.Hour).Unix(), size*3/4)
				benchmarkPlan(b, s, "page-details", attackerPageQuery(" WHERE attackers.machine_id IN (1,2,3,4,5,6,7,8,9,10) AND last_measured_activity_at>=? AND last_measured_activity_at<?", "trapped_seconds", "DESC"), now.Add(-90*24*time.Hour).Unix(), now.Add(time.Minute).Unix(), 50, size*3/4)
				benchmarkPlan(b, s, "page-wide-reference", benchmarkWidePageQuery(" WHERE attackers.machine_id IN (1,2,3,4,5,6,7,8,9,10) AND last_measured_activity_at>=? AND last_measured_activity_at<?"), now.Add(-90*24*time.Hour).Unix(), now.Add(time.Minute).Unix(), 50, size*3/4)
				benchmarkPlan(b, s, "countries", `SELECT `+countryKeySQL+`,COUNT(DISTINCT ip_address),SUM(connections) FROM attackers WHERE machine_id IN (1,2,3,4,5,6,7,8,9,10) AND last_measured_activity_at>=? GROUP BY `+countryKeySQL, now.Add(-24*time.Hour).Unix())
				benchmarkPlan(b, s, "enrichment", enrichmentDueQuery, "fixture", "fixture", now.Unix(), "fixture", 100)
				filter := AttackerFilter{MachineIDs: ids, Since: now.Add(-90 * 24 * time.Hour), Until: now.Add(time.Minute), SortColumn: "trapped_seconds", SortDescending: true, Page: 1, PerPage: 50, ActiveSince: now.Add(-time.Minute)}
				listPage := func(f AttackerFilter) error {
					if os.Getenv("DASHBOARD_BENCH_WIDE_PAGE") == "1" {
						_, err := benchmarkWidePage(s, f)
						return err
					}
					_, err := s.ListAttackers(ctx, f)
					return err
				}
				cases := []struct {
					name string
					run  func() error
				}{
					{"overview-24h", func() error {
						_, err := s.Overview(ctx, ids, now.Add(-24*time.Hour), now.Add(-time.Minute), now.Add(time.Minute))
						return err
					}},
					{"countries-24h", func() error {
						_, err := s.CountryTotalsInRange(ctx, ids, TimeRange{From: now.Add(-24 * time.Hour), To: now.Add(time.Minute)}, false)
						return err
					}},
					{"page-first-90d", func() error { return listPage(filter) }},
					{"page-deep-90d", func() error { f := filter; f.Page = 1 + size*3/4/50; return listPage(f) }},
					{"enrichment-due", func() error { _, err := s.EnrichmentDue(ctx, "fixture", now, 100); return err }},
					{"enrichment-update", func() error {
						return s.SetAttackerLocation(ctx, queryBenchmarkIP(0, size), AttackerLocation{CountryCode: "DE", ISP: "fixture"})
					}},
				}
				for _, c := range cases {
					b.Run(c.name, func(b *testing.B) {
						// Reopen to discard SQLite connection page caches, not the OS file cache.
						if err := s.Close(); err != nil {
							b.Fatal(err)
						}
						var err error
						s, err = Open(path)
						if err != nil {
							b.Fatal(err)
						}
						start := time.Now()
						if err := c.run(); err != nil {
							b.Fatal(err)
						}
						cold := time.Since(start)
						benchmarkSamples(b, c.run)
						b.ReportMetric(float64(cold.Nanoseconds())/1e6, "first-ms")
					})
				}
				// Keys-only cursor probe excludes COUNT, detail fetching and cursor discovery;
				// it evaluates a future
				// sequential-navigation API, not an interchangeable full endpoint result.
				var trapped float64
				var ip string
				var machine int64
				if err := s.DB().QueryRow(`SELECT trapped_seconds,ip_address,machine_id FROM attackers ORDER BY trapped_seconds DESC,ip_address,machine_id LIMIT 1 OFFSET ?`, size*3/4).Scan(&trapped, &ip, &machine); err != nil {
					b.Fatal(err)
				}
				b.Run("keyset-probe", func(b *testing.B) {
					benchmarkSamples(b, func() error {
						rows, err := s.DB().Query(`SELECT machine_id,ip_address FROM attackers WHERE trapped_seconds<? OR (trapped_seconds=? AND (ip_address>? OR (ip_address=? AND machine_id>?))) ORDER BY trapped_seconds DESC,ip_address,machine_id LIMIT 50`, trapped, trapped, ip, ip, machine)
						if err != nil {
							return err
						}
						defer rows.Close()
						for rows.Next() {
							var m int64
							var ip string
							if err = rows.Scan(&m, &ip); err != nil {
								return err
							}
						}
						return rows.Err()
					})
				})
				// Real ApplyScrape batches, including row merges, counters, totals, rollups
				// and generation fencing; no HTTP/parser time. Read workloads finish first.
				writeSequence := int64(0)
				for _, insert := range []bool{false, true} {
					b.Run(fmt.Sprintf("scrape100/new=%t", insert), func(b *testing.B) {
						delta := queryBenchmarkDelta(size)
						before := fileBytes(path + "-wal")
						benchmarkSamples(b, func() error {
							writeSequence++
							delta.At = now.Add(time.Duration(writeSequence) * time.Millisecond)
							if insert {
								for j := range delta.Attackers {
									delta.Attackers[j].IPAddress = queryBenchmarkAddress(1, int(writeSequence)*100+j)
								}
							}
							return s.ApplyScrape(ctx, delta)
						})
						b.ReportMetric(float64(max(0, fileBytes(path+"-wal")-before)), "wal-file-growth-B")
					})
				}
				// One refresh reader in parallel with a paced 100-row scrape writer.
				b.Run("concurrent-overview-scrape100", func(b *testing.B) {
					stop := make(chan struct{})
					done := make(chan error, 1)
					delta := queryBenchmarkDelta(size)
					writeSamples := []time.Duration{}
					go func() {
						for {
							select {
							case <-stop:
								done <- nil
								return
							default:
							}
							writeSequence++
							delta.At = now.Add(time.Duration(writeSequence) * time.Millisecond)
							start := time.Now()
							if err := s.ApplyScrape(ctx, delta); err != nil {
								done <- err
								return
							}
							if len(writeSamples) < 10000 {
								writeSamples = append(writeSamples, time.Since(start))
							}
							time.Sleep(time.Millisecond)
						}
					}()
					defer func() {
						close(stop)
						if err := <-done; err != nil {
							b.Fatal(err)
						}
						sort.Slice(writeSamples, func(i, j int) bool { return writeSamples[i] < writeSamples[j] })
						if n := len(writeSamples); n > 0 {
							b.ReportMetric(float64(writeSamples[(n-1)/2].Microseconds())/1000, "write-p50-ms")
							b.ReportMetric(float64(writeSamples[(n*95+99)/100-1].Microseconds())/1000, "write-p95-ms")
							b.ReportMetric(float64(n), "writes")
						}
					}()
					benchmarkSamples(b, func() error {
						_, err := s.Overview(ctx, ids, now.Add(-24*time.Hour), now.Add(-time.Minute))
						return err
					})
				})
				if _, err := s.DB().Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
					b.Fatal(err)
				}
				b.Logf("final DB=%d WAL=%d", fileBytes(path), fileBytes(path+"-wal"))
				s.Close()
			})
		}
	}
}

var queryBenchmarkTime = time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)

func fileBytes(path string) int64 {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		panic(err)
	}
	return info.Size()
}
func queryBenchmarkIP(n, size int) string {
	ip := n + size
	if n%5 == 0 {
		ip = n / 10
	}
	return queryBenchmarkAddress(0, ip)
}
func queryBenchmarkAddress(subnet uint16, ip int) string {
	address := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	binary.BigEndian.PutUint16(address[4:6], subnet)
	binary.BigEndian.PutUint32(address[12:], uint32(ip))
	return netip.AddrFrom16(address).String()
}

func queryBenchmarkDelta(size int) ScrapeDelta {
	d := ScrapeDelta{MachineID: 1, TargetGeneration: 0, Opens: 100, TrappedSeconds: 100, CounterStates: map[string]float64{"total:opens": 100}}
	for j := range 100 {
		d.Attackers = append(d.Attackers, AttackerDelta{IPAddress: queryBenchmarkIP(j*2, size), Connections: 1, TrappedSeconds: 1, Country: "Germany", CountryCode: "DE", Active: true})
	}
	return d
}
func queryBenchmarkFixture(b *testing.B, size int, indexed bool) (*Store, string, []int64) {
	b.Helper()
	path := filepath.Join(b.TempDir(), "queries.db")
	s, err := Open(path)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { s.Close() })
	ctx := context.Background()
	if err = s.Migrate(ctx); err != nil {
		b.Fatal(err)
	}
	if !indexed {
		if _, err = s.DB().Exec("DROP INDEX idx_attackers_enrichment_ip"); err != nil {
			b.Fatal(err)
		}
	}
	ids := []int64{}
	for i := range 10 {
		m, err := s.CreateMachine(ctx, Machine{Name: fmt.Sprintf("fixture-%d", i), Host: "192.0.2.1", Port: 2222, MetricsPath: "/metrics", Enabled: true})
		if err != nil {
			b.Fatal(err)
		}
		ids = append(ids, m.ID)
	}
	tx, err := s.DB().Begin()
	if err != nil {
		b.Fatal(err)
	}
	defer tx.Rollback()
	// Bounded recursive chunks avoid Go heap proportional to fixture size.
	for start := 0; start < size; start += 10000 {
		_, err = tx.Exec(`WITH RECURSIVE seq(n) AS (VALUES(?) UNION ALL SELECT n+1 FROM seq WHERE n+1<?), fixture AS (SELECT n,CASE WHEN n%5=0 THEN n/10 ELSE n+? END AS ip FROM seq)
 INSERT INTO attackers(machine_id,ip_address,first_seen,last_seen,last_activity_at,last_observed_at,last_measured_activity_at,connections,trapped_seconds,country,country_code,location,latitude,longitude,has_undated_history,first_observation_known)
 SELECT CASE WHEN n%2=0 THEN 1 ELSE 2+(n%18)/2 END,CASE WHEN ip=0 THEN '2001:db8::' WHEN ip<65536 THEN printf('2001:db8::%x',ip) ELSE printf('2001:db8::%x:%x',ip>>16,ip&65535) END,?-90*86400,?-((n%90)*86400+(n%1440)*60),?-((n%90)*86400+(n%1440)*60),?,?-((n%90)*86400+(n%1440)*60),n%1000,n%1000,
 CASE n%4 WHEN 0 THEN 'Germany' WHEN 1 THEN 'Deutschland' WHEN 2 THEN 'United States' ELSE '' END,CASE n%4 WHEN 0 THEN 'DE' WHEN 1 THEN 'de' WHEN 2 THEN 'US' ELSE '' END,CASE WHEN n%10=0 THEN '' ELSE 'Fixture city' END,CASE WHEN n%4<3 THEN 50.0 END,CASE WHEN n%4<3 THEN 10.0 END,0,1 FROM fixture`, start, min(start+10000, size), size, queryBenchmarkTime.Unix(), queryBenchmarkTime.Unix(), queryBenchmarkTime.Unix(), queryBenchmarkTime.Unix(), queryBenchmarkTime.Unix())
		if err != nil {
			b.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		b.Fatal(err)
	}
	var count int
	if err = s.DB().QueryRow("SELECT COUNT(*) FROM attackers").Scan(&count); err != nil || count != size {
		b.Fatalf("fixture rows=%d want=%d: %v", count, size, err)
	}
	for _, n := range []int{0, size / 2, size - 1} {
		machine := 1
		if n%2 != 0 {
			machine = 2 + (n%18)/2
		}
		var ip string
		if err = s.DB().QueryRow("SELECT ip_address FROM attackers WHERE machine_id=? AND ip_address=?", machine, queryBenchmarkIP(n, size)).Scan(&ip); err != nil {
			b.Fatalf("canonical fixture identity n=%d: %v", n, err)
		}
	}
	if _, err = s.DB().Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		b.Fatal(err)
	}
	return s, path, ids
}
func benchmarkSamples(b *testing.B, run func() error) {
	b.Helper()
	samples := make([]time.Duration, 0, b.N)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		start := time.Now()
		if err := run(); err != nil {
			b.Fatal(err)
		}
		samples = append(samples, time.Since(start))
	}
	b.StopTimer()
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	if len(samples) > 0 {
		b.ReportMetric(float64(samples[(len(samples)-1)/2].Nanoseconds())/1e6, "p50-ms")
		b.ReportMetric(float64(samples[(len(samples)*95+99)/100-1].Nanoseconds())/1e6, "p95-ms")
	}
}
func benchmarkPlan(b *testing.B, s *Store, name, query string, args ...any) {
	b.Helper()
	rows, err := s.DB().Query("EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		b.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err = rows.Scan(&id, &parent, &unused, &detail); err != nil {
			b.Fatal(err)
		}
		b.Logf("plan %s: %s", name, detail)
	}
	if err = rows.Err(); err != nil {
		b.Fatal(err)
	}
}

// Wide-row reference for reproducible comparisons with narrow-key production
// pagination. It includes the same count, detail decoding and complete order.
// Only this benchmark's fixed trapped-seconds sort is supported.
func benchmarkWidePage(s *Store, f AttackerFilter) (AttackerPage, error) {
	where := " WHERE attackers.machine_id IN (" + placeholders(len(f.MachineIDs)) + ") AND last_measured_activity_at>=? AND last_measured_activity_at<?"
	args := append(int64Args(f.MachineIDs), MinuteBoundary(f.Since).Unix(), MinuteBoundary(f.Until).Unix())
	var total, distinct int
	if err := s.DB().QueryRow("SELECT COUNT(*),COUNT(DISTINCT ip_address) FROM attackers"+where, args...).Scan(&total, &distinct); err != nil {
		return AttackerPage{}, err
	}
	rows, err := s.DB().Query(benchmarkWidePageQuery(where), append(args, f.PerPage, (f.Page-1)*f.PerPage)...)

	if err != nil {
		return AttackerPage{}, err
	}
	defer rows.Close()
	page := AttackerPage{Total: total, DistinctIPs: distinct, Page: f.Page, PerPage: f.PerPage}
	for rows.Next() {
		row, lastActivity, err := scanAttackerRow(rows)
		if err != nil {
			return AttackerPage{}, err
		}
		row.Status = StatusGaveUp
		if row.LastMeasuredActivityAt == nil {
			row.Status = "unknown"
		} else if lastActivity >= f.ActiveSince.Unix() {
			row.Status = StatusTrapped
		}
		page.Rows = append(page.Rows, row)
	}
	return page, rows.Err()
}

func benchmarkWidePageQuery(where string) string {
	return "SELECT " + attackerColumns + " FROM attackers JOIN machines ON machines.id=attackers.machine_id" + where + " ORDER BY attackers.trapped_seconds DESC,attackers.ip_address,attackers.machine_id LIMIT ? OFFSET ?"
}
