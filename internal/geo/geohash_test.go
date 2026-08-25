package geo

import (
	"math"
	"testing"
)

func TestDecodeGeohashKnownPlaces(t *testing.T) {
	cases := []struct {
		name          string
		hash          string
		wantLatitude  float64
		wantLongitude float64
		tolerance     float64
	}{
		{
			// The canonical worked example: eleven characters is a few metres.
			name:         "Jutland to eleven characters",
			hash:         "u4pruydqqvj",
			wantLatitude: 57.64911, wantLongitude: 10.40744,
			tolerance: 0.0001,
		},
		{
			name:         "San Francisco to five characters",
			hash:         "9q8yy",
			wantLatitude: 37.75, wantLongitude: -122.42,
			// Five characters is a cell of roughly 5 km.
			tolerance: 0.05,
		},
		{
			// The geohash a real endlessh-go instance labelled a Frankfurt client with.
			name:         "Frankfurt to seven characters",
			hash:         "u0yjjd6",
			wantLatitude: 50.11, wantLongitude: 8.68,
			tolerance: 0.01,
		},
		{
			name:         "uppercase decodes like lowercase",
			hash:         "U4PRUYDQQVJ",
			wantLatitude: 57.64911, wantLongitude: 10.40744,
			tolerance: 0.0001,
		},
		{
			name:         "surrounding whitespace is trimmed",
			hash:         "  9q8yy  ",
			wantLatitude: 37.75, wantLongitude: -122.42,
			tolerance: 0.05,
		},
		{
			// One character is a quarter of the planet: still a usable coordinate,
			// and proof the search starts from the full range.
			name:         "single character is the centre of its cell",
			hash:         "0",
			wantLatitude: -67.5, wantLongitude: -157.5,
			tolerance: 0.0001,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			latitude, longitude, ok := DecodeGeohash(testCase.hash)
			if !ok {
				t.Fatalf("DecodeGeohash(%q) reported failure, want a coordinate", testCase.hash)
			}
			if math.Abs(latitude-testCase.wantLatitude) > testCase.tolerance {
				t.Errorf("latitude = %v, want %v ± %v", latitude, testCase.wantLatitude, testCase.tolerance)
			}
			if math.Abs(longitude-testCase.wantLongitude) > testCase.tolerance {
				t.Errorf("longitude = %v, want %v ± %v", longitude, testCase.wantLongitude, testCase.tolerance)
			}
		})
	}
}

func TestDecodeGeohashRejects(t *testing.T) {
	cases := []struct {
		name string
		hash string
	}{
		{name: "empty string", hash: ""},
		{name: "whitespace only", hash: "   "},
		{
			// The whole reason the placeholder is rejected by name: it decodes to
			// a real point in the Atlantic, so letting it through would plot every
			// attacker of a GeoIP-less tarpit off the coast of Africa.
			name: "endlessh-go placeholder",
			hash: PlaceholderGeohash,
		},
		{name: "placeholder in uppercase", hash: "S000"},
		{name: "placeholder with whitespace", hash: " s000 "},
		{name: "letters excluded from the alphabet", hash: "ailoaiil"},
		{name: "one excluded letter in an otherwise valid hash", hash: "u4pruydqqva"},
		{name: "punctuation", hash: "u4pru!"},
		{name: "a country name rather than a geohash", hash: "Geohash off"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			latitude, longitude, ok := DecodeGeohash(testCase.hash)
			if ok {
				t.Errorf("DecodeGeohash(%q) = %v, %v, true; want a rejection", testCase.hash, latitude, longitude)
			}
			if latitude != 0 || longitude != 0 {
				t.Errorf("a rejected hash returned %v, %v; want the zero coordinate", latitude, longitude)
			}
		})
	}
}

// TestDecodeGeohashPrefixesNest checks the property that makes a geohash a
// geohash: dropping characters must widen the cell around the same point.
func TestDecodeGeohashPrefixesNest(t *testing.T) {
	full, fullLongitude, ok := DecodeGeohash("u4pruydqqvj")
	if !ok {
		t.Fatal("DecodeGeohash of the full hash failed")
	}
	for _, prefix := range []string{"u", "u4", "u4p", "u4pr", "u4pru"} {
		latitude, longitude, ok := DecodeGeohash(prefix)
		if !ok {
			t.Fatalf("DecodeGeohash(%q) failed", prefix)
		}
		// Each dropped character at most multiplies the cell by 8 in either
		// direction; five characters back is still well inside a degree of slack
		// scaled by how much precision was thrown away.
		slack := 180.0 / math.Pow(2, float64(len(prefix)*bitsPerCharacter)/2)
		if math.Abs(latitude-full) > slack || math.Abs(longitude-fullLongitude) > slack {
			t.Errorf("prefix %q decoded to %v,%v, which is not within %v of %v,%v",
				prefix, latitude, longitude, slack, full, fullLongitude)
		}
	}
}
