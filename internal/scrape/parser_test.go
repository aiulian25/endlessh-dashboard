package scrape

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func parseFixture(t *testing.T, name string) Snapshot {
	t.Helper()
	file, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("open fixture %s: %v", name, err)
	}
	defer file.Close()

	snapshot, err := Parse(file)
	if err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return snapshot
}

func TestParseNormalTotalsPerLocalPort(t *testing.T) {
	snapshot := parseFixture(t, "normal.txt")

	expected := map[string]float64{
		TotalSeriesKey(MetricOpenCountTotal, "22"):            1204,
		TotalSeriesKey(MetricOpenCountTotal, "2222"):          311,
		TotalSeriesKey(MetricClosedCountTotal, "22"):          1180,
		TotalSeriesKey(MetricClosedCountTotal, "2222"):        300,
		TotalSeriesKey(MetricSentBytesTotal, "22"):            4823164,
		TotalSeriesKey(MetricSentBytesTotal, "2222"):          993210,
		TotalSeriesKey(MetricTrappedTimeSecondsTotal, "22"):   91234.5,
		TotalSeriesKey(MetricTrappedTimeSecondsTotal, "2222"): 20114.25,
	}
	if !reflect.DeepEqual(snapshot.Totals, expected) {
		t.Fatalf("totals mismatch\n got: %v\nwant: %v", snapshot.Totals, expected)
	}
}

func TestParseNormalTotalsSumAcrossLocalPorts(t *testing.T) {
	snapshot := parseFixture(t, "normal.txt")

	sums := map[string]float64{}
	for key, value := range snapshot.Totals {
		metric, _, found := strings.Cut(strings.TrimPrefix(key, "total:"), "|")
		if !found {
			t.Fatalf("series key %q is not metric|local_port shaped", key)
		}
		sums[metric] += value
	}

	expected := map[string]float64{
		MetricOpenCountTotal:          1515,
		MetricClosedCountTotal:        1480,
		MetricSentBytesTotal:          5816374,
		MetricTrappedTimeSecondsTotal: 111348.75,
	}
	if !reflect.DeepEqual(sums, expected) {
		t.Fatalf("summed totals mismatch\n got: %v\nwant: %v", sums, expected)
	}
}

func TestParseNormalClientsSummedAcrossPortsWithGeography(t *testing.T) {
	snapshot := parseFixture(t, "normal.txt")

	expected := map[string]ClientSample{
		"45.155.205.233": {
			IPAddress:      "45.155.205.233",
			Connections:    100,
			TrappedSeconds: 4000.75,
			Country:        "Germany",
			Geohash:        "u0yjjd6",
			Location:       "Germany, Hesse, Frankfurt am Main",
		},
		"218.92.0.204": {
			IPAddress:      "218.92.0.204",
			Connections:    512,
			TrappedSeconds: 18400,
			Country:        "China",
			Geohash:        "wtw3sjq",
			Location:       "China, Jiangsu, Nanjing",
		},
		"92.63.197.55": {
			IPAddress:      "92.63.197.55",
			Connections:    44,
			TrappedSeconds: 725.5,
			Country:        "Russia",
			Geohash:        "ucfv0j4",
			Location:       "Russia, Moscow",
		},
	}
	if !reflect.DeepEqual(snapshot.Clients, expected) {
		t.Fatalf("clients mismatch\n got: %#v\nwant: %#v", snapshot.Clients, expected)
	}
}

// The scraper joins trapped time back onto the client by IP, because
// endlessh_client_trapped_time_seconds carries no geography labels of its own.
func TestParseJoinsTrappedTimeOntoGeographyByIP(t *testing.T) {
	snapshot := parseFixture(t, "normal.txt")

	sample, ok := snapshot.Clients["45.155.205.233"]
	if !ok {
		t.Fatal("client missing from snapshot")
	}
	if sample.TrappedSeconds == 0 {
		t.Fatal("trapped seconds were not joined onto the client")
	}
	if sample.Country == "" || sample.Geohash == "" || sample.Location == "" {
		t.Fatalf("geography lost while joining trapped time: %#v", sample)
	}
}

func TestParseStripsGeoPlaceholders(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		ip      string
	}{
		{name: "geoip disabled", fixture: "geoip-off.txt", ip: "45.155.205.233"},
		{name: "lookup failed", fixture: "geoip-unknown.txt", ip: "10.11.12.13"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			snapshot := parseFixture(t, testCase.fixture)
			sample, ok := snapshot.Clients[testCase.ip]
			if !ok {
				t.Fatalf("client %s missing from snapshot", testCase.ip)
			}
			if sample.Country != "" {
				t.Errorf("country = %q, want empty: placeholders must not reach the UI as data", sample.Country)
			}
			if sample.Location != "" {
				t.Errorf("location = %q, want empty: placeholders must not reach the UI as data", sample.Location)
			}
			if sample.Geohash != "" {
				t.Errorf("geohash = %q, want empty: placeholders must not reach the UI as data", sample.Geohash)
			}
		})
	}
}

// The placeholders replace geography only; the counters in the same sample are
// real data and must survive.
func TestParseGeoIPOffKeepsCounters(t *testing.T) {
	snapshot := parseFixture(t, "geoip-off.txt")

	sample := snapshot.Clients["45.155.205.233"]
	if sample.Connections != 100 {
		t.Errorf("connections = %v, want 100", sample.Connections)
	}
	if sample.TrappedSeconds != 4000.75 {
		t.Errorf("trapped seconds = %v, want 4000.75", sample.TrappedSeconds)
	}
	if got := snapshot.Totals[TotalSeriesKey(MetricSentBytesTotal, "22")]; got != 4823164 {
		t.Errorf("sent bytes on port 22 = %v, want 4823164", got)
	}
}

func TestParseEmptyEndpointYieldsNoClients(t *testing.T) {
	snapshot := parseFixture(t, "empty.txt")

	if len(snapshot.Clients) != 0 {
		t.Errorf("clients = %#v, want none", snapshot.Clients)
	}
	if len(snapshot.Totals) != 0 {
		t.Errorf("totals = %#v, want none", snapshot.Totals)
	}
	if snapshot.Clients == nil || snapshot.Totals == nil {
		t.Error("maps must be initialised so callers can range over them")
	}
}

func TestParseMalformedReturnsError(t *testing.T) {
	file, err := os.Open(filepath.Join("testdata", "malformed.txt"))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer file.Close()

	snapshot, err := Parse(file)
	if err == nil {
		t.Fatalf("expected an error, got snapshot %#v", snapshot)
	}
	if !strings.Contains(err.Error(), "parse metrics") {
		t.Errorf("error %q should be wrapped with context for the failure log", err)
	}
}

func TestParseIgnoresUnrelatedMetricFamilies(t *testing.T) {
	// Every fixture carries go/process/promhttp noise; none of it may leak into
	// the snapshot, and promhttp_metric_handler_requests_total in particular is a
	// labelled counter that a sloppy parser would happily aggregate.
	for _, fixture := range []string{"normal.txt", "geoip-off.txt", "after-restart.txt", "empty.txt"} {
		t.Run(fixture, func(t *testing.T) {
			snapshot := parseFixture(t, fixture)
			for key := range snapshot.Totals {
				if !strings.HasPrefix(key, "total:endlessh_") {
					t.Errorf("unrelated family leaked into totals: %q", key)
				}
			}
			for ipAddress := range snapshot.Clients {
				if strings.Contains(ipAddress, "go1.") || ipAddress == "200" {
					t.Errorf("unrelated label leaked into clients: %q", ipAddress)
				}
			}
		})
	}
}

func TestParseSampleEdgeCases(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		clients map[string]ClientSample
		totals  map[string]float64
	}{
		{
			name: "sample without an ip label is skipped",
			payload: `# TYPE endlessh_client_open_count counter
endlessh_client_open_count{country="Germany",geohash="u0yjjd6",ip="",local_port="22",location="Germany"} 5
`,
			clients: map[string]ClientSample{},
			totals:  map[string]float64{},
		},
		{
			name: "untyped samples still carry their value",
			payload: `# TYPE endlessh_sent_bytes_total untyped
endlessh_sent_bytes_total{local_port="22"} 4096
`,
			clients: map[string]ClientSample{},
			totals:  map[string]float64{TotalSeriesKey(MetricSentBytesTotal, "22"): 4096},
		},
		{
			name: "gauge samples still carry their value",
			payload: `# TYPE endlessh_trapped_time_seconds_total gauge
endlessh_trapped_time_seconds_total{local_port="2222"} 12.5
`,
			clients: map[string]ClientSample{},
			totals:  map[string]float64{TotalSeriesKey(MetricTrappedTimeSecondsTotal, "2222"): 12.5},
		},
		{
			name: "repeated local_port samples are summed into one series",
			payload: `# TYPE endlessh_client_open_count_total counter
endlessh_client_open_count_total{local_port="22"} 7
`,
			clients: map[string]ClientSample{},
			totals:  map[string]float64{TotalSeriesKey(MetricOpenCountTotal, "22"): 7},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			snapshot, err := Parse(strings.NewReader(testCase.payload))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !reflect.DeepEqual(snapshot.Clients, testCase.clients) {
				t.Errorf("clients = %#v, want %#v", snapshot.Clients, testCase.clients)
			}
			if !reflect.DeepEqual(snapshot.Totals, testCase.totals) {
				t.Errorf("totals = %#v, want %#v", snapshot.Totals, testCase.totals)
			}
		})
	}
}

func TestSeriesKeysAreDistinctPerLabelValue(t *testing.T) {
	if TotalSeriesKey(MetricOpenCountTotal, "22") == TotalSeriesKey(MetricOpenCountTotal, "2222") {
		t.Error("total series keys must distinguish local ports")
	}
	if ClientSeriesKey(MetricClientOpenCount, "1.2.3.4") == ClientSeriesKey(MetricClientTrappedTimeSeconds, "1.2.3.4") {
		t.Error("client series keys must distinguish metrics")
	}
	if strings.HasPrefix(ClientSeriesKey(MetricClientOpenCount, "1.2.3.4"), "total:") {
		t.Error("client keys must not collide with the total: namespace")
	}
}
