package api

import "net/http"

type settingsResponse struct {
	ScrapeIntervalSeconds int    `json:"scrape_interval_seconds"`
	ScrapeTimeoutSeconds  int    `json:"scrape_timeout_seconds"`
	RetentionDays         int    `json:"retention_days"`
	GeoIPEnabled          bool   `json:"geoip_enabled"`
	GeoIPSource           string `json:"geoip_source"`
	// The online provider is the one thing here that leaves the host, so the UI
	// gets to state plainly whether it is on and how hard it is allowed to poll.
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
	writeJSON(writer, http.StatusOK, settingsResponse{
		ScrapeIntervalSeconds:    int(s.config.ScrapeInterval.Seconds()),
		ScrapeTimeoutSeconds:     int(s.config.ScrapeTimeout.Seconds()),
		RetentionDays:            s.config.RetentionDays,
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
