package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"

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

func TestSessionLifetimeIsConfigurableAndBounded(t *testing.T) {
	t.Setenv(EnvAdminPassword, "seed-password-1")

	// Unset means the documented default, so an install that never heard of
	// this variable keeps the behaviour it already had.
	unset, err := Load()
	if err != nil {
		t.Fatalf("Load with no %s: %v", EnvSessionLifetime, err)
	}
	if unset.SessionLifetime != 12*time.Hour {
		t.Errorf("default session lifetime = %s, want 12h", unset.SessionLifetime)
	}

	t.Setenv(EnvSessionLifetime, "45m")
	shortened, err := Load()
	if err != nil {
		t.Fatalf("Load with %s=45m: %v", EnvSessionLifetime, err)
	}
	if shortened.SessionLifetime != 45*time.Minute {
		t.Errorf("session lifetime = %s, want 45m", shortened.SessionLifetime)
	}

	// The bounds exist to stop two different footguns: a session so short it
	// logs you out mid-task, and one so long the cookie is a standing
	// credential. Both are refused at startup rather than silently accepted.
	for _, refused := range []string{"30s", "721h", "0s", "-1h"} {
		t.Setenv(EnvSessionLifetime, refused)
		if _, err := Load(); err == nil {
			t.Errorf("%s=%s was accepted, want it refused", EnvSessionLifetime, refused)
		}
	}

	// Go's duration parser has no day unit, so "7d" is not a short week — it is
	// a syntax error. Worth pinning, because it is the spelling people reach for.
	t.Setenv(EnvSessionLifetime, "7d")
	if _, err := Load(); err == nil {
		t.Errorf("%s=7d was accepted; Go durations have no day unit", EnvSessionLifetime)
	}

	t.Setenv(EnvSessionLifetime, "not-a-duration")
	if _, err := Load(); err == nil {
		t.Errorf("%s=not-a-duration was accepted, want a parse error", EnvSessionLifetime)
	}
}

func TestBooleanSettingsRefuseSpellingsGoDoesNotUnderstand(t *testing.T) {
	// Every boolean setting shares one parser, but each has its own call site,
	// and a call site that drops the error is exactly the regression this pins.
	settings := []struct {
		env   string
		value func(*Config) bool
	}{
		{env: EnvBackupDaily, value: func(c *Config) bool { return c.BackupDaily }},
		{env: EnvScrapeBlockPrivate, value: func(c *Config) bool { return c.ScrapeBlockPrivate }},
		{env: EnvGeoIPOnline, value: func(c *Config) bool { return c.GeoIPOnline }},
	}

	cases := []struct {
		raw     string
		want    bool
		refused bool
	}{
		{raw: "true", want: true},
		{raw: "TRUE", want: true},
		{raw: "1", want: true},
		{raw: "false", want: false},
		{raw: "0", want: false},
		// Empty is "not set", which is the documented default, not a mistake.
		{raw: "", want: false},
		// Spellings ParseBool has never accepted. Reading them as "off" is the
		// bug: SCRAPE_BLOCK_PRIVATE=yes would leave the SSRF guard down while
		// the .env file says it is up, and BACKUP_DAILY=yes would take no
		// backups. Both now refuse to start instead.
		{raw: "yes", refused: true},
		{raw: "on", refused: true},
		{raw: "enabled", refused: true},
		{raw: "2", refused: true},
	}

	for _, setting := range settings {
		for _, testCase := range cases {
			t.Run(setting.env+"="+testCase.raw, func(t *testing.T) {
				t.Setenv(EnvDataDirectory, t.TempDir())
				t.Setenv(setting.env, testCase.raw)

				configuration, err := Load()
				if testCase.refused {
					if err == nil {
						t.Fatalf("Load accepted %s=%q, want it refused", setting.env, testCase.raw)
					}
					if !strings.Contains(err.Error(), setting.env) {
						t.Errorf("error = %q, want it to name %s", err, setting.env)
					}
					return
				}
				if err != nil {
					t.Fatalf("Load with %s=%q: %v", setting.env, testCase.raw, err)
				}
				if got := setting.value(configuration); got != testCase.want {
					t.Errorf("%s=%q loaded as %t, want %t", setting.env, testCase.raw, got, testCase.want)
				}
			})
		}
	}
}

func TestTrustedProxyCIDRsAreOffByDefaultAndValidated(t *testing.T) {
	t.Setenv(EnvDataDirectory, t.TempDir())

	// Unset means nobody is trusted to speak for a client, which is the right
	// default for a dashboard reached directly.
	unset, err := Load()
	if err != nil {
		t.Fatalf("Load with no %s: %v", EnvTrustedProxyCIDRs, err)
	}
	if len(unset.TrustedProxyCIDRs) != 0 {
		t.Errorf("%s defaulted to %v, want nothing trusted", EnvTrustedProxyCIDRs, unset.TrustedProxyCIDRs)
	}

	t.Setenv(EnvTrustedProxyCIDRs, "127.0.0.1/32, 172.18.0.0/16")
	configured, err := Load()
	if err != nil {
		t.Fatalf("Load with two proxies: %v", err)
	}
	if len(configured.TrustedProxyCIDRs) != 2 {
		t.Fatalf("parsed %d networks, want 2", len(configured.TrustedProxyCIDRs))
	}

	// A bare address is the likely mistake, and it must not be read as "trust
	// nothing" — that would leave the throttle broken with no sign of why.
	for _, refused := range []string{"127.0.0.1", "not-a-network", "10.0.0.0/33"} {
		t.Setenv(EnvTrustedProxyCIDRs, refused)
		if _, err := Load(); err == nil {
			t.Errorf("%s=%s was accepted, want it refused", EnvTrustedProxyCIDRs, refused)
		}
	}
}

func TestLogLevelIsNamedNotNumbered(t *testing.T) {
	t.Setenv(EnvDataDirectory, t.TempDir())

	// Unset is the level the app has always logged at, so an install that has
	// never heard of this variable sees exactly what it saw before.
	unset, err := Load()
	if err != nil {
		t.Fatalf("Load with no %s: %v", EnvLogLevel, err)
	}
	if unset.LogLevel != slog.LevelInfo {
		t.Errorf("default log level = %v, want info", unset.LogLevel)
	}

	accepted := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
		// Spelled the way somebody actually types it into a .env file.
		"DEBUG": slog.LevelDebug,
		" Warn": slog.LevelWarn,
	}
	for raw, want := range accepted {
		t.Run("accepts "+raw, func(t *testing.T) {
			t.Setenv(EnvDataDirectory, t.TempDir())
			t.Setenv(EnvLogLevel, raw)
			configuration, err := Load()
			if err != nil {
				t.Fatalf("Load with %s=%q: %v", EnvLogLevel, raw, err)
			}
			if configuration.LogLevel != want {
				t.Errorf("%s=%q loaded as %v, want %v", EnvLogLevel, raw, configuration.LogLevel, want)
			}
		})
	}

	// slog's own numbers, and the spellings from other tools, are refused rather
	// than silently logging at a level nobody chose — the same way every other
	// setting in this file refuses what it does not understand.
	for _, refused := range []string{"trace", "verbose", "warning", "0", "-4", "quiet"} {
		t.Run("refuses "+refused, func(t *testing.T) {
			t.Setenv(EnvDataDirectory, t.TempDir())
			t.Setenv(EnvLogLevel, refused)
			if _, err := Load(); err == nil {
				t.Errorf("%s=%s was accepted", EnvLogLevel, refused)
			} else if !strings.Contains(err.Error(), EnvLogLevel) {
				t.Errorf("error = %q, want it to name %s", err, EnvLogLevel)
			}
		})
	}
}
