package scrape

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"endlessh-dashboard/internal/geo"
	"endlessh-dashboard/internal/registry"
	"endlessh-dashboard/internal/store"
)

const (
	modeOK      = "ok"
	modeStatus  = "500"
	modeGarbage = "garbage"
	modeHang    = "hang"

	testScrapeTimeout = 50 * time.Millisecond
	testInterval      = time.Minute
)

func TestCounterDelta(t *testing.T) {
	const series = "total:endlessh_sent_bytes_total|22"

	cases := []struct {
		name     string
		previous map[string]float64
		value    float64
		want     float64
	}{
		{
			name:     "first sighting contributes nothing",
			previous: map[string]float64{},
			value:    91234.5,
			want:     0,
		},
		{
			name:     "growth contributes the difference",
			previous: map[string]float64{series: 100},
			value:    175.25,
			want:     75.25,
		},
		{
			name:     "unchanged counter contributes nothing",
			previous: map[string]float64{series: 100},
			value:    100,
			want:     0,
		},
		{
			name:     "counter that went backwards is a restart, delta is the new value",
			previous: map[string]float64{series: 91234.5},
			value:    812.5,
			want:     812.5,
		},
		{
			name:     "restart back to zero contributes nothing",
			previous: map[string]float64{series: 91234.5},
			value:    0,
			want:     0,
		},
		{
			name:     "a different series does not satisfy the first sighting",
			previous: map[string]float64{"total:endlessh_sent_bytes_total|2222": 100},
			value:    500,
			want:     0,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := counterDelta(testCase.previous, series, testCase.value)
			if got != testCase.want {
				t.Errorf("counterDelta = %v, want %v", got, testCase.want)
			}
			if got < 0 {
				t.Errorf("counterDelta must never be negative, got %v", got)
			}
		})
	}
}

func TestIsTotalSeries(t *testing.T) {
	cases := []struct {
		key    string
		metric string
		want   bool
	}{
		{key: TotalSeriesKey(MetricOpenCountTotal, "22"), metric: MetricOpenCountTotal, want: true},
		{key: TotalSeriesKey(MetricOpenCountTotal, "22"), metric: MetricClosedCountTotal, want: false},
		{key: ClientSeriesKey(MetricClientOpenCount, "1.2.3.4"), metric: MetricOpenCountTotal, want: false},
		// endlessh_client_open_count is a prefix of endlessh_client_open_count_total,
		// so the separator has to be part of the comparison.
		{key: TotalSeriesKey(MetricOpenCountTotal, "22"), metric: MetricClientOpenCount, want: false},
	}

	for _, testCase := range cases {
		if got := isTotalSeries(testCase.key, testCase.metric); got != testCase.want {
			t.Errorf("isTotalSeries(%q, %q) = %v, want %v", testCase.key, testCase.metric, got, testCase.want)
		}
	}
}

// metricsServer is a stand-in endlessh-go endpoint whose body and failure mode
// the test swaps between scrapes.
type metricsServer struct {
	server  *httptest.Server
	body    atomic.Pointer[[]byte]
	mode    atomic.Pointer[string]
	release chan struct{}
}

func newMetricsServer(t *testing.T, fixture string) *metricsServer {
	t.Helper()
	endpoint := &metricsServer{release: make(chan struct{})}
	endpoint.serve(t, fixture)
	endpoint.setMode(modeOK)

	endpoint.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/metrics" {
			http.NotFound(writer, request)
			return
		}
		switch *endpoint.mode.Load() {
		case modeStatus:
			http.Error(writer, "boom", http.StatusInternalServerError)
		case modeGarbage:
			writer.Header().Set("Content-Type", "text/plain")
			io.WriteString(writer, "endlessh_client_open_count_total{local_port=\"22\" 12\nnot a metric at all\n")
		case modeHang:
			select {
			case <-request.Context().Done():
			case <-endpoint.release:
			}
		default:
			writer.Header().Set("Content-Type", "text/plain; version=0.0.4")
			writer.Write(*endpoint.body.Load())
		}
	}))

	// Registered after the server exists so cleanup runs release-then-close:
	// httptest.Server.Close waits for the hanging handler to return.
	t.Cleanup(endpoint.server.Close)
	t.Cleanup(func() { close(endpoint.release) })
	return endpoint
}

func (m *metricsServer) serve(t *testing.T, fixture string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", fixture))
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixture, err)
	}
	m.body.Store(&body)
	m.setMode(modeOK)
}

func (m *metricsServer) setMode(mode string) {
	m.mode.Store(&mode)
}

func (m *metricsServer) hostPort(t *testing.T) (string, int) {
	t.Helper()
	parsed, err := url.Parse(m.server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatalf("split server address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse server port: %v", err)
	}
	return host, port
}

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	dataStore, err := store.Open(filepath.Join(t.TempDir(), "dashboard.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { dataStore.Close() })
	if err := dataStore.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return dataStore
}

func newTestPoller(t *testing.T, dataStore *store.Store) *Poller {
	t.Helper()
	_, loopback, err := net.ParseCIDR("127.0.0.0/8")
	if err != nil {
		t.Fatalf("parse loopback cidr: %v", err)
	}
	geoResolver, err := geo.Open("")
	if err != nil {
		t.Fatalf("open geo resolver: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	return NewPoller(
		dataStore,
		registry.NewValidator([]*net.IPNet{loopback}, false),
		geoResolver,
		logger,
		testInterval,
		testScrapeTimeout,
	)
}

// newScrapeFixture wires a store, a poller and a fake endpoint together and
// returns the machine row the poller will scrape.
func newScrapeFixture(t *testing.T, fixture string) (*store.Store, *Poller, *metricsServer, store.Machine) {
	t.Helper()
	dataStore := newTestStore(t)
	poller := newTestPoller(t, dataStore)
	endpoint := newMetricsServer(t, fixture)

	host, port := endpoint.hostPort(t)
	machine, err := dataStore.CreateMachine(context.Background(), store.Machine{
		Name:        "tarpit",
		Host:        host,
		Port:        port,
		MetricsPath: "/metrics",
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("create machine: %v", err)
	}
	return dataStore, poller, endpoint, machine
}

type totalsRow struct {
	Opens          int64
	Closes         int64
	BytesSent      int64
	TrappedSeconds float64
}

func countAttackers(t *testing.T, dataStore *store.Store, machineID int64) int {
	t.Helper()
	var count int
	if err := dataStore.DB().QueryRow(
		"SELECT COUNT(DISTINCT ip_address) FROM attackers WHERE machine_id = ?",
		machineID).Scan(&count); err != nil {
		t.Fatalf("count attackers: %v", err)
	}
	return count
}

func readTotals(t *testing.T, dataStore *store.Store, machineID int64) totalsRow {
	t.Helper()
	var row totalsRow
	err := dataStore.DB().QueryRow(
		"SELECT opens, closes, bytes_sent, trapped_seconds FROM machine_totals WHERE machine_id = ?",
		machineID).Scan(&row.Opens, &row.Closes, &row.BytesSent, &row.TrappedSeconds)
	if err != nil {
		t.Fatalf("read machine totals: %v", err)
	}
	return row
}

type attackerRow struct {
	Connections    int64
	TrappedSeconds float64
	LastActivityAt int64
	Country        string
	Geohash        string
	Location       string
}

func readAttacker(t *testing.T, dataStore *store.Store, machineID int64, ipAddress string) attackerRow {
	t.Helper()
	var row attackerRow
	err := dataStore.DB().QueryRow(
		`SELECT connections, trapped_seconds, last_activity_at, country, geohash, location
		 FROM attackers WHERE machine_id = ? AND ip_address = ?`,
		machineID, ipAddress).Scan(&row.Connections, &row.TrappedSeconds, &row.LastActivityAt,
		&row.Country, &row.Geohash, &row.Location)
	if err != nil {
		t.Fatalf("read attacker %s: %v", ipAddress, err)
	}
	return row
}

func countRows(t *testing.T, dataStore *store.Store, query string, args ...any) int {
	t.Helper()
	var count int
	if err := dataStore.DB().QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	return count
}

func TestPollerFirstScrapeContributesNoDelta(t *testing.T) {
	dataStore, poller, _, machine := newScrapeFixture(t, "normal.txt")
	ctx := context.Background()

	poller.pollOne(ctx, machine)

	totals := readTotals(t, dataStore, machine.ID)
	if totals.Opens != 0 || totals.Closes != 0 || totals.BytesSent != 0 || totals.TrappedSeconds != 0 {
		t.Errorf("a lifetime counter was imported as traffic: %+v", totals)
	}
	if attackerCount := countAttackers(t, dataStore, machine.ID); attackerCount != 3 {
		t.Errorf("attacker rows = %d, want 3", attackerCount)
	}
	if rollups := countRows(t, dataStore, "SELECT COUNT(*) FROM machine_rollups WHERE machine_id = ?", machine.ID); rollups != 0 {
		t.Errorf("rollup rows = %d, want 0 on a first scrape", rollups)
	}

	// The attacker row adopts that client's own counters, which are its lifetime
	// figures and true regardless of when this dashboard started watching. What
	// it must NOT do is claim the client is trapped right now: nothing has been
	// observed to grow yet, so liveness is still unknown.
	first := readAttacker(t, dataStore, machine.ID, "45.155.205.233")
	if first.Connections != 100 || first.TrappedSeconds != 4000.75 {
		t.Errorf("first sighting did not adopt the client's own counters: %+v", first)
	}
	if first.LastActivityAt != 0 {
		t.Errorf("last_activity_at = %d, want 0: a first sighting proves nothing about liveness", first.LastActivityAt)
	}
	if first.Country != "Germany" || first.Geohash != "u0yjjd6" {
		t.Errorf("geography not stored: %+v", first)
	}

	// The state is recorded, so the next scrape has something to subtract from.
	states, err := dataStore.LoadCounterStates(ctx, machine.ID)
	if err != nil {
		t.Fatalf("load counter states: %v", err)
	}
	if got := states[TotalSeriesKey(MetricSentBytesTotal, "22")]; got != 4823164 {
		t.Errorf("sent bytes state = %v, want 4823164", got)
	}
	if got := states[RawClientSeriesKey(MetricClientTrappedTimeSeconds, "45.155.205.233", "22")]; got != 3600.5 {
		t.Errorf("client trapped state = %v, want 4000.75", got)
	}
	if len(states) != 16 {
		t.Errorf("counter states = %d, want 16 (8 aggregate series + 8 raw client/port series)", len(states))
	}
}

func TestPollerSecondScrapeAppliesTheDifference(t *testing.T) {
	dataStore, poller, endpoint, machine := newScrapeFixture(t, "normal.txt")
	ctx := context.Background()

	poller.pollOne(ctx, machine)
	endpoint.serve(t, "second-scrape.txt")
	poller.pollOne(ctx, machine)

	totals := readTotals(t, dataStore, machine.ID)
	want := totalsRow{Opens: 40, Closes: 25, BytesSent: 28626, TrappedSeconds: 352.5}
	if totals != want {
		t.Errorf("totals = %+v, want %+v", totals, want)
	}

	if rollups := countRows(t, dataStore, "SELECT COUNT(*) FROM machine_rollups WHERE machine_id = ?", machine.ID); rollups == 0 {
		t.Error("a scrape with a delta must write a rollup bucket")
	}

	// An attacker row carries that client's own lifetime figures, so after the
	// first sighting adopts the counter and the second adds its delta, the row
	// equals what the endpoint currently reports (summed across local ports).
	cases := map[string]struct {
		connections int64
		trapped     float64
	}{
		"45.155.205.233": {connections: 113, trapped: 4351},
		"218.92.0.204":   {connections: 512, trapped: 18400},
		"92.63.197.55":   {connections: 46, trapped: 727.75},
	}
	for ipAddress, expected := range cases {
		row := readAttacker(t, dataStore, machine.ID, ipAddress)
		if row.Connections != expected.connections {
			t.Errorf("%s connections = %d, want %d", ipAddress, row.Connections, expected.connections)
		}
		if row.TrappedSeconds != expected.trapped {
			t.Errorf("%s trapped seconds = %v, want %v", ipAddress, row.TrappedSeconds, expected.trapped)
		}
	}
}

func TestPollerMarksOnlyGrowingAttackersActive(t *testing.T) {
	dataStore, poller, endpoint, machine := newScrapeFixture(t, "normal.txt")
	ctx := context.Background()

	poller.pollOne(ctx, machine)
	endpoint.serve(t, "second-scrape.txt")
	poller.pollOne(ctx, machine)

	growing := readAttacker(t, dataStore, machine.ID, "45.155.205.233")
	if growing.LastActivityAt <= 0 {
		t.Errorf("attacker whose trapped time grew must be active, last_activity_at = %d", growing.LastActivityAt)
	}

	stalled := readAttacker(t, dataStore, machine.ID, "218.92.0.204")
	if stalled.LastActivityAt != 0 {
		t.Errorf("attacker with unchanged counters must not be active, last_activity_at = %d", stalled.LastActivityAt)
	}

	// Still listed and still carrying its geography, just no longer trapped.
	if stalled.Country != "China" {
		t.Errorf("inactive attacker lost its country: %+v", stalled)
	}
}

func TestPollerTreatsLowerCountersAsRestart(t *testing.T) {
	dataStore, poller, endpoint, machine := newScrapeFixture(t, "normal.txt")
	ctx := context.Background()

	poller.pollOne(ctx, machine)
	endpoint.serve(t, "after-restart.txt")
	poller.pollOne(ctx, machine)

	totals := readTotals(t, dataStore, machine.ID)
	want := totalsRow{Opens: 21, Closes: 15, BytesSent: 50340, TrappedSeconds: 909.25}
	if totals != want {
		t.Errorf("totals = %+v, want %+v", totals, want)
	}
	if totals.Opens < 0 || totals.Closes < 0 || totals.BytesSent < 0 || totals.TrappedSeconds < 0 {
		t.Errorf("a restart produced negative history: %+v", totals)
	}

	// 100 connections and 4000.75s were adopted at the first sighting; the
	// restart is recognised (3 < 100) so the post-restart values are added
	// rather than subtracted, and nothing goes backwards.
	restarted := readAttacker(t, dataStore, machine.ID, "45.155.205.233")
	if restarted.Connections != 103 {
		t.Errorf("connections after restart = %d, want 103 (adopted 100 + post-restart 3)", restarted.Connections)
	}
	if restarted.TrappedSeconds != 4041.5 {
		t.Errorf("trapped seconds after restart = %v, want 4041.5 (adopted 4000.75 + post-restart 40.75)", restarted.TrappedSeconds)
	}

	// The state now tracks the restarted instance, not the pre-restart peak.
	states, err := dataStore.LoadCounterStates(ctx, machine.ID)
	if err != nil {
		t.Fatalf("load counter states: %v", err)
	}
	if got := states[TotalSeriesKey(MetricSentBytesTotal, "22")]; got != 41230 {
		t.Errorf("sent bytes state = %v, want 41230", got)
	}
}

func TestPollerFailureKeepsHistoryIntact(t *testing.T) {
	cases := []struct {
		name    string
		mode    string
		payload string
	}{
		{name: "http 500", mode: modeStatus},
		{name: "timeout", mode: modeHang},
		{name: "garbage body", mode: modeGarbage},
		{name: "nonfinite counter", mode: modeOK, payload: "endlessh_trapped_time_seconds_total +Inf\n"},
		{name: "NaN counter", mode: modeOK, payload: "endlessh_trapped_time_seconds_total NaN\n"},
		{name: "negative counter", mode: modeOK, payload: "endlessh_sent_bytes_total -1\n"},
		{name: "wrong metric type", mode: modeOK, payload: "# TYPE endlessh_trapped_time_seconds_total gauge\nendlessh_trapped_time_seconds_total 10\n"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			dataStore, poller, endpoint, machine := newScrapeFixture(t, "normal.txt")
			ctx := context.Background()

			poller.pollOne(ctx, machine)
			endpoint.serve(t, "second-scrape.txt")
			poller.pollOne(ctx, machine)

			before := readTotals(t, dataStore, machine.ID)
			beforeAttacker := readAttacker(t, dataStore, machine.ID, "45.155.205.233")
			beforeStates, err := dataStore.LoadCounterStates(ctx, machine.ID)
			if err != nil {
				t.Fatalf("load counter states: %v", err)
			}
			healthy, err := dataStore.GetMachine(ctx, machine.ID)
			if err != nil {
				t.Fatalf("get machine: %v", err)
			}
			if healthy.LastOKAt == nil {
				t.Fatal("a successful scrape must stamp last_ok_at")
			}

			endpoint.setMode(testCase.mode)
			if testCase.payload != "" {
				body := []byte(testCase.payload)
				endpoint.body.Store(&body)
			}
			poller.pollOne(ctx, machine)

			if after := readTotals(t, dataStore, machine.ID); after != before {
				t.Errorf("failed scrape changed totals: %+v, want %+v", after, before)
			}
			if after := readAttacker(t, dataStore, machine.ID, "45.155.205.233"); after != beforeAttacker {
				t.Errorf("failed scrape changed attacker history: %+v, want %+v", after, beforeAttacker)
			}
			afterStates, err := dataStore.LoadCounterStates(ctx, machine.ID)
			if err != nil {
				t.Fatalf("load counter states: %v", err)
			}
			for series, value := range beforeStates {
				if afterStates[series] != value {
					t.Errorf("failed scrape lost counter state %q: %v, want %v", series, afterStates[series], value)
				}
			}

			failed, err := dataStore.GetMachine(ctx, machine.ID)
			if err != nil {
				t.Fatalf("get machine: %v", err)
			}
			if failed.ConsecutiveFailures != 1 {
				t.Errorf("consecutive failures = %d, want 1", failed.ConsecutiveFailures)
			}
			if failed.LastError == "" {
				t.Error("a failed scrape must record a message the UI can show")
			}
			if failed.LastOKAt == nil || !failed.LastOKAt.Equal(*healthy.LastOKAt) {
				t.Errorf("last_ok_at = %v, want it untouched at %v", failed.LastOKAt, healthy.LastOKAt)
			}
			if failed.LastScrapeAt == nil {
				t.Error("a failed scrape must still stamp last_scrape_at")
			}
		})
	}
}

// After a failure the recorded state must still be the last good reading, so the
// next successful scrape produces a real delta instead of re-importing a total.
func TestPollerResumesDeltasAfterFailure(t *testing.T) {
	dataStore, poller, endpoint, machine := newScrapeFixture(t, "normal.txt")
	ctx := context.Background()

	poller.pollOne(ctx, machine)

	endpoint.setMode(modeStatus)
	poller.pollOne(ctx, machine)

	endpoint.serve(t, "second-scrape.txt")
	poller.pollOne(ctx, machine)

	totals := readTotals(t, dataStore, machine.ID)
	want := totalsRow{Opens: 40, Closes: 25, BytesSent: 28626, TrappedSeconds: 352.5}
	if totals != want {
		t.Errorf("totals = %+v, want %+v", totals, want)
	}

	recovered, err := dataStore.GetMachine(ctx, machine.ID)
	if err != nil {
		t.Fatalf("get machine: %v", err)
	}
	if recovered.ConsecutiveFailures != 0 {
		t.Errorf("consecutive failures = %d, want 0 after a success", recovered.ConsecutiveFailures)
	}
	if recovered.LastError != "" {
		t.Errorf("last error = %q, want it cleared after a success", recovered.LastError)
	}
}

func TestPollerBacksOffAfterConsecutiveFailures(t *testing.T) {
	_, poller, endpoint, machine := newScrapeFixture(t, "normal.txt")
	ctx := context.Background()
	endpoint.setMode(modeStatus)

	if !poller.due(machine.ID) {
		t.Fatal("a machine that has never been scraped is due immediately")
	}

	poller.pollOne(ctx, machine)
	if poller.due(machine.ID) {
		t.Error("a machine that just failed must not be retried immediately")
	}

	poller.mutex.Lock()
	firstBackoff := poller.nextAttempt[machine.ID]
	poller.mutex.Unlock()

	poller.pollOne(ctx, machine)
	poller.mutex.Lock()
	secondBackoff := poller.nextAttempt[machine.ID]
	streak := poller.failureStreaks[machine.ID]
	poller.mutex.Unlock()

	if !secondBackoff.After(firstBackoff) {
		t.Errorf("backoff did not grow: %v then %v", firstBackoff, secondBackoff)
	}
	if streak != 2 {
		t.Errorf("failure streak = %d, want 2", streak)
	}

	endpoint.serve(t, "normal.txt")
	poller.pollOne(ctx, machine)
	if !poller.due(machine.ID) {
		t.Error("a machine that recovered must be due again")
	}
}

// A target that resolves to a blocked address is refused before any request is
// made, and the refusal is recorded like any other scrape failure.
func TestPollerRefusesBlockedTarget(t *testing.T) {
	dataStore := newTestStore(t)
	poller := newTestPoller(t, dataStore)
	ctx := context.Background()

	machine, err := dataStore.CreateMachine(ctx, store.Machine{
		Name:        "metadata",
		Host:        "169.254.169.254",
		Port:        80,
		MetricsPath: "/metrics",
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("create machine: %v", err)
	}

	poller.pollOne(ctx, machine)

	refused, err := dataStore.GetMachine(ctx, machine.ID)
	if err != nil {
		t.Fatalf("get machine: %v", err)
	}
	if refused.ConsecutiveFailures != 1 {
		t.Errorf("consecutive failures = %d, want 1", refused.ConsecutiveFailures)
	}
	if refused.LastError == "" {
		t.Error("the refusal must be explained in last_error")
	}
	if attackers := countRows(t, dataStore, "SELECT COUNT(*) FROM attackers WHERE machine_id = ?", machine.ID); attackers != 0 {
		t.Errorf("attackers = %d, want 0", attackers)
	}
}

// hostileStatusLine serves one thing: an HTTP response whose status line carries
// an enormous reason phrase. net/http/httptest cannot do this — a ResponseWriter
// derives the phrase from the code — so the response is written as raw bytes,
// which is also exactly how a hostile endpoint would do it.
func hostileStatusLine(t *testing.T, reasonPhrase string) (string, int) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func(connection net.Conn) {
				defer connection.Close()
				// The request has to be drained before answering, or the client
				// sees the connection go away rather than the response.
				reader := bufio.NewReader(connection)
				for {
					line, err := reader.ReadString('\n')
					if err != nil || line == "\r\n" || line == "\n" {
						break
					}
				}
				fmt.Fprintf(connection, "HTTP/1.1 500 %s\r\nContent-Length: 0\r\n\r\n", reasonPhrase)
			}(connection)
		}
	}()

	address := listener.Addr().(*net.TCPAddr)
	return address.IP.String(), address.Port
}

func TestScrapeFailureFromAHostileEndpointIsBounded(t *testing.T) {
	dataStore := newTestStore(t)
	poller := newTestPoller(t, dataStore)
	ctx := context.Background()

	host, port := hostileStatusLine(t, strings.Repeat("A", 8000))
	machine, err := dataStore.CreateMachine(ctx, store.Machine{
		Name:        "hostile",
		Host:        host,
		Port:        port,
		MetricsPath: "/metrics",
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("create machine: %v", err)
	}

	poller.pollOne(ctx, machine)

	// The whole chain: the endpoint chooses the text, the poller quotes it into
	// the failure message, and the store decides how much of it is kept. Without
	// that last step the machine row, and every /api/machines response, carries
	// as much as the endpoint felt like sending.
	failed, err := dataStore.GetMachine(ctx, machine.ID)
	if err != nil {
		t.Fatalf("GetMachine: %v", err)
	}
	if failed.ConsecutiveFailures != 1 {
		t.Fatalf("consecutive failures = %d, want the scrape to have failed once", failed.ConsecutiveFailures)
	}
	if len(failed.LastError) > 512 {
		t.Errorf("stored error is %d bytes; the endpoint chose the length", len(failed.LastError))
	}
	if !strings.Contains(failed.LastError, "500") {
		t.Errorf("stored error = %q, want it to still say what happened", failed.LastError)
	}
}
