package api

import (
	"net/http"

	"endlessh-dashboard/internal/geo"
)

type settingsResponse struct {
	ScrapeConcurrency      int    `json:"scrape_concurrency"`
	ScrapeIntervalSeconds  int    `json:"scrape_interval_seconds"`
	ScrapeTimeoutSeconds   int    `json:"scrape_timeout_seconds"`
	RetentionDays          int    `json:"retention_days"`
	SessionLifetimeSeconds int    `json:"session_lifetime_seconds"`
	GeoIPEnabled           bool   `json:"geoip_enabled"`
	GeoIPSource            string `json:"geoip_source"`
	// The online provider is the one thing here that leaves the host, so the UI
	// gets to state plainly whether it is on and how hard it is allowed to poll.
	GeoIPOnlineProviderHost  string `json:"geoip_online_provider_host"`
	GeoIPOnlineScheme        string `json:"geoip_online_scheme"`
	GeoIPOnlineEnabled       bool   `json:"geoip_online_enabled"`
	GeoIPOnlineRatePerMinute int    `json:"geoip_online_rate_per_minute"`
	BackupKeepLast           int    `json:"backup_keep_last"`
	BackupDailyEnabled       bool   `json:"backup_daily_enabled"`
	BlockPrivate             bool   `json:"block_private"`
	Version                  string `json:"version"`
}

// handleSettings exposes the effective configuration read-only, so an operator
// can see what the container is actually running without shell access. Secrets
// are deliberately absent.
func (s *Server) handleSettings(writer http.ResponseWriter, _ *http.Request) {
	provider := geo.OnlineProvider(s.config.GeoIPOnlineEndpoint)
	writeJSON(writer, http.StatusOK, settingsResponse{
		GeoIPOnlineProviderHost:  provider.Host,
		GeoIPOnlineScheme:        provider.Scheme,
		ScrapeIntervalSeconds:    int(s.config.ScrapeInterval.Seconds()),
		ScrapeConcurrency:        s.config.ScrapeConcurrency,
		ScrapeTimeoutSeconds:     int(s.config.ScrapeTimeout.Seconds()),
		RetentionDays:            s.config.RetentionDays,
		SessionLifetimeSeconds:   int(s.config.SessionLifetime.Seconds()),
		GeoIPEnabled:             s.geoResolver.Enabled(),
		GeoIPSource:              s.geoResolver.Source(),
		GeoIPOnlineEnabled:       s.config.GeoIPOnline,
		GeoIPOnlineRatePerMinute: s.config.GeoIPOnlineRate,
		BackupKeepLast:           s.config.BackupKeepLast,
		BackupDailyEnabled:       s.config.BackupDaily,
		BlockPrivate:             s.config.ScrapeBlockPrivate,
		Version:                  s.version,
	})
}
