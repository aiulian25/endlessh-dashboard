// Package scrape turns an endlessh-go /metrics response into deltas this app
// can store. endlessh-go is treated strictly as a black box: nothing here
// depends on its source, only on the six metric names it publishes.
package scrape

import (
	"fmt"
	"io"
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"

	"endlessh-dashboard/internal/geo"
	"endlessh-dashboard/internal/ipidentity"
	"endlessh-dashboard/internal/metricvalue"
	"endlessh-dashboard/internal/store"
)

// The six metrics endlessh-go exposes. The four *_total counters are labelled
// by local_port only. Of the two per-client counters, only open_count carries
// geography — trapped_time_seconds has just ip and local_port, so location has
// to be joined back by IP.
const (
	MetricOpenCountTotal           = "endlessh_client_open_count_total"
	MetricClosedCountTotal         = "endlessh_client_closed_count_total"
	MetricSentBytesTotal           = "endlessh_sent_bytes_total"
	MetricTrappedTimeSecondsTotal  = "endlessh_trapped_time_seconds_total"
	MetricClientOpenCount          = "endlessh_client_open_count"
	MetricClientTrappedTimeSeconds = "endlessh_client_trapped_time_seconds"
)

const (
	LabelIPAddress = "ip"
	LabelLocalPort = "local_port"
	LabelCountry   = "country"
	LabelGeohash   = "geohash"
	LabelLocation  = "location"
)

// Values endlessh-go emits when GeoIP is switched off or a lookup failed. They
// are placeholders, not data, and must never reach the UI. The geohash it emits
// alongside them is geo.PlaceholderGeohash, which the decoder rejects for the
// same reason.
const (
	geoDisabledLabel = "Geohash off"
	geoUnknownLabel  = "Unknown"
)

// ClientSample is one attacker's raw counter values in a single scrape,
// summed across local ports for presentation; deltas use ClientSeries.
type ClientSample struct {
	IPAddress      string
	Connections    float64
	TrappedSeconds float64
	Country        string
	Geohash        string
	Location       string
}

// MetricFamilyEvidence is bounded to the six supported names, without raw labels.
type MetricFamilyEvidence struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Samples int    `json:"samples"`
}

// Snapshot is one scrape: raw counter readings, not deltas.
type Snapshot struct {
	MetricFamilies []MetricFamilyEvidence
	Totals         map[string]float64
	Clients        map[string]ClientSample
	ClientSeries   map[string]RawClientSample
}

// RawClientSample keeps presence and port identity until after differencing.
type RawClientSample struct {
	Metric    string
	IPAddress string
	LocalPort string
	Value     float64
}

// RawClientSeriesKey requires a valid address at the parser/store boundary.
func RawClientSeriesKey(metric, ip, port string) string {
	canonical, err := ipidentity.Canonical(ip)
	if err == nil {
		ip = canonical
	}
	return ipidentity.RawKey(metric, ip, port)
}

// TotalSeriesKey identifies an aggregate counter for one local port.
func TotalSeriesKey(metric, localPort string) string {
	return "total:" + metric + "|" + localPort
}

// ClientSeriesKey identifies the legacy, port-collapsed baseline format.
func ClientSeriesKey(metric, ipAddress string) string {
	return "ip:" + metric + "|" + ipAddress
}

func Parse(reader io.Reader) (Snapshot, error) {
	// The zero-value TextParser has no name-validation scheme and panics on the
	// first metric it reads, so the scheme is always passed explicitly. UTF-8 is
	// the current upstream default and accepts every name endlessh-go emits.
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(reader)
	if err != nil {
		return Snapshot{}, fmt.Errorf("parse metrics: %w", err)
	}

	evidence := make([]MetricFamilyEvidence, 0, 6)

	// Only the selected counter families are constrained; unrelated exporter
	// gauges/summaries remain ignored. Untyped exposition is an existing contract.
	for _, name := range []string{MetricOpenCountTotal, MetricClosedCountTotal, MetricSentBytesTotal, MetricTrappedTimeSecondsTotal, MetricClientOpenCount, MetricClientTrappedTimeSeconds} {
		family, ok := families[name]
		if !ok {
			continue
		}
		if family.GetType() != dto.MetricType_COUNTER && family.GetType() != dto.MetricType_UNTYPED {
			return Snapshot{}, fmt.Errorf("metric %s must be counter or untyped (got %s)", name, strings.ToLower(family.GetType().String()))
		}
		for _, metric := range family.GetMetric() {
			if err := metricvalue.Validate(sampleValue(metric), integerMetric(name)); err != nil {
				return Snapshot{}, fmt.Errorf("metric %s: %w", name, err)
			}
		}
	}
	for _, name := range []string{MetricOpenCountTotal, MetricClosedCountTotal, MetricSentBytesTotal, MetricTrappedTimeSecondsTotal, MetricClientOpenCount, MetricClientTrappedTimeSeconds} {
		if family := families[name]; family != nil && len(family.GetMetric()) > 0 {
			evidence = append(evidence, MetricFamilyEvidence{Name: name, Type: strings.ToLower(family.GetType().String()), Samples: len(family.GetMetric())})
		}
	}
	snapshot := Snapshot{
		MetricFamilies: evidence,
		Totals:         map[string]float64{},
		Clients:        map[string]ClientSample{},
		ClientSeries:   map[string]RawClientSample{},
	}

	ports := map[string]bool{}
	for _, metricName := range []string{
		MetricOpenCountTotal,
		MetricClosedCountTotal,
		MetricSentBytesTotal,
		MetricTrappedTimeSecondsTotal,
	} {
		family, ok := families[metricName]
		if !ok {
			continue
		}
		for _, metric := range family.GetMetric() {
			labels := labelMap(metric)
			port, err := store.PortFromLabel(labels[LabelLocalPort])
			if err != nil {
				return Snapshot{}, fmt.Errorf("metric %s: %w", metricName, err)
			}
			ports[port] = true
			if len(ports) > store.MaxScrapePorts {
				return Snapshot{}, fmt.Errorf("too many local ports (maximum %d)", store.MaxScrapePorts)
			}
			key := TotalSeriesKey(metricName, labels[LabelLocalPort])
			snapshot.Totals[key] += sampleValue(metric)
		}
	}

	if family, ok := families[MetricClientOpenCount]; ok {
		for _, metric := range family.GetMetric() {
			labels := labelMap(metric)
			ipAddress, err := ipidentity.Canonical(labels[LabelIPAddress])
			if err != nil {
				return Snapshot{}, fmt.Errorf("metric %s: %w", MetricClientOpenCount, err)
			}

			key := RawClientSeriesKey(MetricClientOpenCount, ipAddress, labels[LabelLocalPort])
			value := sampleValue(metric)
			if existing, ok := snapshot.ClientSeries[key]; ok {
				if existing.Value != value {
					return Snapshot{}, fmt.Errorf("conflicting duplicate client series")
				}
				continue
			}
			snapshot.ClientSeries[key] = RawClientSample{Metric: MetricClientOpenCount, IPAddress: ipAddress, LocalPort: labels[LabelLocalPort], Value: value}
			sample := snapshot.Clients[ipAddress]
			sample.IPAddress = ipAddress
			sample.Connections += sampleValue(metric)
			applyGeography(&sample, labels)
			snapshot.Clients[ipAddress] = sample
		}
	}

	if family, ok := families[MetricClientTrappedTimeSeconds]; ok {
		for _, metric := range family.GetMetric() {
			labels := labelMap(metric)
			ipAddress, err := ipidentity.Canonical(labels[LabelIPAddress])
			if err != nil {
				return Snapshot{}, fmt.Errorf("metric %s: %w", MetricClientTrappedTimeSeconds, err)
			}

			key := RawClientSeriesKey(MetricClientTrappedTimeSeconds, ipAddress, labels[LabelLocalPort])
			value := sampleValue(metric)
			if existing, ok := snapshot.ClientSeries[key]; ok {
				if existing.Value != value {
					return Snapshot{}, fmt.Errorf("conflicting duplicate client series")
				}
				continue
			}
			snapshot.ClientSeries[key] = RawClientSample{Metric: MetricClientTrappedTimeSeconds, IPAddress: ipAddress, LocalPort: labels[LabelLocalPort], Value: value}
			sample := snapshot.Clients[ipAddress]
			sample.IPAddress = ipAddress
			sample.TrappedSeconds += sampleValue(metric)
			snapshot.Clients[ipAddress] = sample
		}
	}

	if err := validateSnapshot(snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func applyGeography(sample *ClientSample, labels map[string]string) {
	if country := cleanGeoValue(labels[LabelCountry]); country != "" {
		sample.Country = country
	}
	if location := cleanGeoValue(labels[LabelLocation]); location != "" {
		sample.Location = location
	}
	geohash := strings.TrimSpace(labels[LabelGeohash])
	if geohash != "" && geohash != geo.PlaceholderGeohash && geohash != geoDisabledLabel {
		sample.Geohash = geohash
	}
}

func cleanGeoValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == geoDisabledLabel || trimmed == geoUnknownLabel {
		return ""
	}
	return trimmed
}

func labelMap(metric *dto.Metric) map[string]string {
	labels := make(map[string]string, len(metric.GetLabel()))
	for _, pair := range metric.GetLabel() {
		labels[pair.GetName()] = pair.GetValue()
	}
	return labels
}

// sampleValue is used only after checking the selected family type.
func sampleValue(metric *dto.Metric) float64 {
	if counter := metric.GetCounter(); counter != nil {
		return counter.GetValue()
	}
	if untyped := metric.GetUntyped(); untyped != nil {
		return untyped.GetValue()
	}
	return 0
}

func integerMetric(name string) bool {
	return name != MetricTrappedTimeSecondsTotal && name != MetricClientTrappedTimeSeconds
}

// validateSnapshot also protects direct callers that did not use Parse.
func validateSnapshot(snapshot Snapshot) error {
	if len(snapshot.Clients) > 0 && len(snapshot.ClientSeries) == 0 {
		return fmt.Errorf("client snapshot is missing raw series presence")
	}
	for key, series := range snapshot.ClientSeries {
		canonical, err := ipidentity.Canonical(series.IPAddress)
		if err != nil || canonical != series.IPAddress {
			return fmt.Errorf("raw client IP must be canonical and unscoped")
		}
		if series.Metric != MetricClientOpenCount && series.Metric != MetricClientTrappedTimeSeconds {
			return fmt.Errorf("unknown client counter family")
		}
		if key != RawClientSeriesKey(series.Metric, series.IPAddress, series.LocalPort) {
			return fmt.Errorf("invalid raw client series identity")
		}
		if err := metricvalue.Validate(series.Value, integerMetric(series.Metric)); err != nil {
			return err
		}
	}

	for key, value := range snapshot.Totals {
		if err := metricvalue.Validate(value, !isTotalSeries(key, MetricTrappedTimeSecondsTotal)); err != nil {
			return fmt.Errorf("invalid total counter: %w", err)
		}
	}
	for key, client := range snapshot.Clients {
		canonical, err := ipidentity.Canonical(client.IPAddress)
		if err != nil || key != canonical || client.IPAddress != canonical {
			return fmt.Errorf("client IP must be canonical and unscoped")
		}
		if err := metricvalue.Validate(client.Connections, true); err != nil {
			return err
		}
		if err := metricvalue.Validate(client.TrappedSeconds, false); err != nil {
			return err
		}
	}
	return nil
}
