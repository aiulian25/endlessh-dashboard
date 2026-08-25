package config

import (
	"strings"
	"testing"

	"endlessh-dashboard/internal/geo"
)

func TestOnlineGeoIPDefaultsToOff(t *testing.T) {
	t.Setenv(EnvDataDirectory, t.TempDir())

	configuration, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// The one setting that lets this app talk to a third party has to stay off
	// until somebody says otherwise, in as many words.
	if configuration.GeoIPOnline {
		t.Error("GEOIP_ONLINE defaulted to on")
	}
	if configuration.GeoIPOnlineRate != defaultGeoIPOnlineRate {
		t.Errorf("rate = %d, want %d", configuration.GeoIPOnlineRate, defaultGeoIPOnlineRate)
	}
	if configuration.GeoIPOnlineEndpoint != geo.DefaultOnlineEndpoint {
		t.Errorf("endpoint = %q, want the provider default", configuration.GeoIPOnlineEndpoint)
	}
}

func TestOnlineGeoIPValidation(t *testing.T) {
	cases := []struct {
		name        string
		rate        string
		endpoint    string
		wantErrText string
	}{
		{name: "accepts a lower rate", rate: "5"},
		{name: "accepts the provider ceiling", rate: "45"},
		{
			name:        "refuses a rate above the free tier",
			rate:        "46",
			wantErrText: EnvGeoIPOnlineRate,
		},
		{
			name:        "refuses a rate of zero, which would stall every lookup",
			rate:        "0",
			wantErrText: EnvGeoIPOnlineRate,
		},
		{
			name:        "refuses a rate that is not a number",
			rate:        "fast",
			wantErrText: EnvGeoIPOnlineRate,
		},
		{
			name:     "accepts an endpoint with the address placeholder",
			endpoint: "https://example.test/lookup/" + geo.OnlineIPPlaceholder,
		},
		{
			// Without the placeholder every attacker would be "resolved" to
			// whatever one fixed URL answered with.
			name:        "refuses an endpoint with no placeholder",
			endpoint:    "https://example.test/lookup",
			wantErrText: geo.OnlineIPPlaceholder,
		},
		{
			name:        "refuses a scheme that is not http",
			endpoint:    "ftp://example.test/" + geo.OnlineIPPlaceholder,
			wantErrText: "http",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv(EnvDataDirectory, t.TempDir())
			t.Setenv(EnvGeoIPOnline, "true")
			if testCase.rate != "" {
				t.Setenv(EnvGeoIPOnlineRate, testCase.rate)
			}
			if testCase.endpoint != "" {
				t.Setenv(EnvGeoIPOnlineEndpoint, testCase.endpoint)
			}

			configuration, err := Load()
			if testCase.wantErrText == "" {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				if !configuration.GeoIPOnline {
					t.Error("GEOIP_ONLINE=true did not switch online lookups on")
				}
				return
			}
			if err == nil {
				t.Fatalf("Load accepted %+v, want an error mentioning %q", configuration, testCase.wantErrText)
			}
			if !strings.Contains(err.Error(), testCase.wantErrText) {
				t.Errorf("error = %q, want it to mention %q", err, testCase.wantErrText)
			}
		})
	}
}
