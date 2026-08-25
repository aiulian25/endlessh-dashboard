// Package geo turns an attacker's address into a place. It has three sources,
// in the order they win: the labels the tarpit itself published, a MaxMind
// database mounted on this host, and — only when the operator switches it on —
// an online provider. The first two are free and offline; the third is the one
// deliberate exception to this app's rule that nothing phones home, so it is
// off unless GEOIP_ONLINE says otherwise.
package geo

import (
	"fmt"
	"net"
	"strings"

	"github.com/oschwald/geoip2-golang"
)

const englishLocale = "en"

// SourceDisabled is reported to the settings page when no database is mounted.
const (
	SourceDisabled = "disabled"
	SourceMaxMind  = "maxmind-local"
)

// Location is what any of the three sources can say about one address. The
// coordinate is a pair of pointers rather than two floats because 0,0 is a real
// place: only nil means "this source did not know where the address is".
type Location struct {
	Country     string
	CountryCode string
	Location    string
	ISP         string
	Latitude    *float64
	Longitude   *float64
}

type Resolver struct {
	reader *geoip2.Reader
	path   string
}

// Open returns a disabled resolver when path is empty, so callers never need a
// nil check or a feature flag of their own.
func Open(path string) (*Resolver, error) {
	if strings.TrimSpace(path) == "" {
		return &Resolver{}, nil
	}
	reader, err := geoip2.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open GeoIP database %s: %w", path, err)
	}
	return &Resolver{reader: reader, path: path}, nil
}

func (r *Resolver) Enabled() bool {
	return r != nil && r.reader != nil
}

func (r *Resolver) Source() string {
	if !r.Enabled() {
		return SourceDisabled
	}
	return SourceMaxMind
}

func (r *Resolver) Path() string {
	if !r.Enabled() {
		return ""
	}
	return r.path
}

// Lookup returns the country and a human-readable location, or false when the
// resolver is disabled or the address is unknown to the database.
func (r *Resolver) Lookup(ipAddress string) (Location, bool) {
	if !r.Enabled() {
		return Location{}, false
	}
	parsed := net.ParseIP(ipAddress)
	if parsed == nil {
		return Location{}, false
	}
	record, err := r.reader.City(parsed)
	if err != nil || record == nil {
		return Location{}, false
	}

	country := record.Country.Names[englishLocale]
	if country == "" {
		country = record.Country.IsoCode
	}
	if country == "" {
		return Location{}, false
	}

	parts := []string{country}
	if len(record.Subdivisions) > 0 {
		if region := record.Subdivisions[0].Names[englishLocale]; region != "" {
			parts = append(parts, region)
		}
	}
	if city := record.City.Names[englishLocale]; city != "" {
		parts = append(parts, city)
	}

	location := Location{
		Country:     country,
		CountryCode: record.Country.IsoCode,
		Location:    strings.Join(parts, ", "),
	}
	// A country-only database carries no coordinate, and its zero value is a
	// point in the Gulf of Guinea. AccuracyRadius is set for every record that
	// really has a position, so it is what separates the two.
	if record.Location.AccuracyRadius > 0 {
		location.Latitude = &record.Location.Latitude
		location.Longitude = &record.Location.Longitude
	}
	return location, true
}

func (r *Resolver) Close() error {
	if !r.Enabled() {
		return nil
	}
	return r.reader.Close()
}
