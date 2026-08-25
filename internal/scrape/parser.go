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
// summed across local ports.
type ClientSample struct {
	IPAddress      string
	Connections    float64
	TrappedSeconds float64
	Country        string
	Geohash        string
	Location       string
}

// Snapshot is one scrape: raw counter readings, not deltas.
type Snapshot struct {
	Totals  map[string]float64
	Clients map[string]ClientSample
}

// TotalSeriesKey identifies an aggregate counter for one local port.
func TotalSeriesKey(metric, localPort string) string {
	return "total:" + metric + "|" + localPort
}

// ClientSeriesKey identifies one attacker's counter, ports collapsed.
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

	snapshot := Snapshot{
		Totals:  map[string]float64{},
		Clients: map[string]ClientSample{},
	}

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
			key := TotalSeriesKey(metricName, labels[LabelLocalPort])
			snapshot.Totals[key] += sampleValue(metric)
		}
	}

	if family, ok := families[MetricClientOpenCount]; ok {
		for _, metric := range family.GetMetric() {
			labels := labelMap(metric)
			ipAddress := labels[LabelIPAddress]
			if ipAddress == "" {
				continue
			}
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
			ipAddress := labels[LabelIPAddress]
			if ipAddress == "" {
				continue
			}
			sample := snapshot.Clients[ipAddress]
			sample.IPAddress = ipAddress
			sample.TrappedSeconds += sampleValue(metric)
			snapshot.Clients[ipAddress] = sample
		}
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

// sampleValue reads whichever of the counter/gauge/untyped shapes carries the
// number, so the parser survives a future type change upstream.
func sampleValue(metric *dto.Metric) float64 {
	if counter := metric.GetCounter(); counter != nil {
		return counter.GetValue()
	}
	if gauge := metric.GetGauge(); gauge != nil {
		return gauge.GetValue()
	}
	if untyped := metric.GetUntyped(); untyped != nil {
		return untyped.GetValue()
	}
	return 0
}
