package geo

import "strings"

// geohashAlphabet is the standard base-32 geohash alphabet: the digits and the
// lowercase letters minus a, i, l and o.
const geohashAlphabet = "0123456789bcdefghjkmnpqrstuvwxyz"

// bitsPerCharacter is what one base-32 character contributes to the two
// interleaved binary searches a geohash encodes.
const bitsPerCharacter = 5

// PlaceholderGeohash is what endlessh-go labels every client with when GeoIP is
// switched off. It is a valid geohash — it decodes to a point in the Atlantic
// off the coast of Africa — so it has to be rejected by name, or every attacker
// on a tarpit without GeoIP would be plotted in the same empty patch of ocean.
const PlaceholderGeohash = "s000"

const (
	minimumLatitude  = -90.0
	maximumLatitude  = 90.0
	minimumLongitude = -180.0
	maximumLongitude = 180.0
)

// DecodeGeohash returns the centre of the cell a geohash names. It reports
// false for the empty string, for endlessh-go's placeholder, and for anything
// that is not a geohash.
func DecodeGeohash(hash string) (latitude, longitude float64, ok bool) {
	normalized := strings.ToLower(strings.TrimSpace(hash))
	if normalized == "" || normalized == PlaceholderGeohash {
		return 0, 0, false
	}

	latitudeRange := interval{low: minimumLatitude, high: maximumLatitude}
	longitudeRange := interval{low: minimumLongitude, high: maximumLongitude}
	// A geohash interleaves the two searches, longitude first.
	halvingLongitude := true

	for _, character := range normalized {
		value := strings.IndexRune(geohashAlphabet, character)
		if value < 0 {
			return 0, 0, false
		}
		for bit := bitsPerCharacter - 1; bit >= 0; bit-- {
			upperHalf := value>>bit&1 == 1
			if halvingLongitude {
				longitudeRange.halve(upperHalf)
			} else {
				latitudeRange.halve(upperHalf)
			}
			halvingLongitude = !halvingLongitude
		}
	}
	return latitudeRange.centre(), longitudeRange.centre(), true
}

type interval struct {
	low  float64
	high float64
}

func (i *interval) halve(upperHalf bool) {
	middle := (i.low + i.high) / 2
	if upperHalf {
		i.low = middle
		return
	}
	i.high = middle
}

func (i interval) centre() float64 {
	return (i.low + i.high) / 2
}
