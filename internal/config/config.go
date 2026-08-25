package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"endlessh-dashboard/internal/geo"
)

const (
	EnvListenAddress        = "LISTEN_ADDR"
	EnvDataDirectory        = "DATA_DIR"
	EnvScrapeInterval       = "SCRAPE_INTERVAL"
	EnvScrapeTimeout        = "SCRAPE_TIMEOUT"
	EnvRetentionDays        = "RETENTION_DAYS"
	EnvAdminUsername        = "ADMIN_USERNAME"
	EnvAdminPassword        = "ADMIN_PASSWORD"
	EnvSecureCookies        = "SECURE_COOKIES"
	EnvSessionLifetime      = "SESSION_LIFETIME"
	EnvGeoIPDatabasePath    = "GEOIP_MMDB_PATH"
	EnvGeoIPOnline          = "GEOIP_ONLINE"
	EnvGeoIPOnlineRate      = "GEOIP_ONLINE_RATE_PER_MINUTE"
	EnvGeoIPOnlineEndpoint  = "GEOIP_ONLINE_ENDPOINT"
	EnvScrapeAllowlistCIDRs = "SCRAPE_ALLOWLIST_CIDRS"
	EnvScrapeBlockPrivate   = "SCRAPE_BLOCK_PRIVATE"
	EnvBackupDaily          = "BACKUP_DAILY"
	EnvBackupKeepLast       = "BACKUP_KEEP_LAST"
)

const (
	defaultListenAddress  = ":18222"
	defaultDataDirectory  = "/data"
	defaultScrapeInterval = 15 * time.Second
	defaultScrapeTimeout  = 5 * time.Second
	defaultRetentionDays  = 90
	defaultAdminUsername  = "admin"
	defaultBackupKeepLast = 7

	databaseFileName = "endlessh.db"
	backupDirName    = "backups"
	// A session shorter than a minute would log the operator out mid-task, and
	// one longer than a month is a credential in all but name: a stolen cookie
	// stays useful for as long as the session lives.
	defaultSessionLifetime = 12 * time.Hour
	minSessionLifetime     = time.Minute
	maxSessionLifetime     = 30 * 24 * time.Hour

	minScrapeInterval = time.Second
	minScrapeTimeout  = 100 * time.Millisecond
	minRetentionDays  = 1
	minBackupKeepLast = 1
)

const (
	// defaultGeoIPOnlineRate sits under the free tier's 45 requests per minute
	// from one source address, leaving room for the retries and clock drift that
	// would otherwise earn this host a ban.
	defaultGeoIPOnlineRate = 40
	minGeoIPOnlineRate     = 1
	maxGeoIPOnlineRate     = 45

	httpScheme  = "http"
	httpsScheme = "https"
)

// SecureCookieMode decides whether session cookies carry the Secure attribute.
type SecureCookieMode string

const (
	// SecureCookieAuto marks cookies Secure when the request arrived over TLS,
	// directly or through a proxy that set X-Forwarded-Proto.
	SecureCookieAuto SecureCookieMode = "auto"
	SecureCookieOn   SecureCookieMode = "on"
	SecureCookieOff  SecureCookieMode = "off"
)

// Config holds the effective settings for one run. There is deliberately no
// session-signing key: sessions live in the database and are looked up by the
// hash of a random token, so there is no secret to keep in step across restarts.
type Config struct {
	ListenAddress     string
	DataDirectory     string
	ScrapeInterval    time.Duration
	ScrapeTimeout     time.Duration
	RetentionDays     int
	AdminUsername     string
	SessionLifetime   time.Duration
	AdminPassword     string
	SecureCookies     SecureCookieMode
	GeoIPDatabasePath string
	// GeoIPOnline is the one setting that lets this app talk to a third party.
	// It is false unless the operator switched it on in as many words.
	GeoIPOnline          bool
	GeoIPOnlineRate      int
	GeoIPOnlineEndpoint  string
	ScrapeAllowlistCIDRs []*net.IPNet
	ScrapeBlockPrivate   bool
	BackupDaily          bool
	BackupKeepLast       int
}

func (c *Config) DatabasePath() string {
	return filepath.Join(c.DataDirectory, databaseFileName)
}

func (c *Config) BackupDirectory() string {
	return filepath.Join(c.DataDirectory, backupDirName)
}

// StaleClientThreshold is how long an attacker may go without new trapped time
// before the dashboard stops calling it actively trapped. Two scrape intervals
// tolerates one missed scrape without flapping the status display.
func (c *Config) StaleClientThreshold() time.Duration {
	return 2 * c.ScrapeInterval
}

func Load() (*Config, error) {
	config := &Config{
		ListenAddress:     stringValue(EnvListenAddress, defaultListenAddress),
		DataDirectory:     stringValue(EnvDataDirectory, defaultDataDirectory),
		AdminUsername:     stringValue(EnvAdminUsername, defaultAdminUsername),
		AdminPassword:     os.Getenv(EnvAdminPassword),
		GeoIPDatabasePath: os.Getenv(EnvGeoIPDatabasePath),
	}

	// How long a login stays valid. The clock starts at sign-in and does not
	// slide with activity: the session ends at its expiry whatever the operator
	// is doing, which is the point of a bounded session.
	sessionLifetime, err := durationValue(EnvSessionLifetime, defaultSessionLifetime)
	if err != nil {
		return nil, err
	}
	if sessionLifetime < minSessionLifetime || sessionLifetime > maxSessionLifetime {
		return nil, fmt.Errorf("%s must be between %s and %s", EnvSessionLifetime, minSessionLifetime, maxSessionLifetime)
	}
	config.SessionLifetime = sessionLifetime

	scrapeInterval, err := durationValue(EnvScrapeInterval, defaultScrapeInterval)
	if err != nil {
		return nil, err
	}
	if scrapeInterval < minScrapeInterval {
		return nil, fmt.Errorf("%s must be at least %s", EnvScrapeInterval, minScrapeInterval)
	}
	config.ScrapeInterval = scrapeInterval

	scrapeTimeout, err := durationValue(EnvScrapeTimeout, defaultScrapeTimeout)
	if err != nil {
		return nil, err
	}
	// A zero or negative timeout would not mean "no timeout": every request
	// context would already be past its deadline, so every scrape would fail
	// before it dialled.
	if scrapeTimeout < minScrapeTimeout {
		return nil, fmt.Errorf("%s must be at least %s", EnvScrapeTimeout, minScrapeTimeout)
	}
	config.ScrapeTimeout = scrapeTimeout

	retentionDays, err := intValue(EnvRetentionDays, defaultRetentionDays)
	if err != nil {
		return nil, err
	}
	if retentionDays < minRetentionDays {
		return nil, fmt.Errorf("%s must be at least %d", EnvRetentionDays, minRetentionDays)
	}
	config.RetentionDays = retentionDays

	backupKeepLast, err := intValue(EnvBackupKeepLast, defaultBackupKeepLast)
	if err != nil {
		return nil, err
	}
	if backupKeepLast < minBackupKeepLast {
		return nil, fmt.Errorf("%s must be at least %d", EnvBackupKeepLast, minBackupKeepLast)
	}
	config.BackupKeepLast = backupKeepLast

	config.BackupDaily = boolValue(EnvBackupDaily, false)
	config.ScrapeBlockPrivate = boolValue(EnvScrapeBlockPrivate, false)
	config.GeoIPOnline = boolValue(EnvGeoIPOnline, false)

	onlineRate, err := intValue(EnvGeoIPOnlineRate, defaultGeoIPOnlineRate)
	if err != nil {
		return nil, err
	}
	// The ceiling is the provider's, not ours: exceeding it gets this host
	// banned, which is a worse outcome than a slow backfill.
	if onlineRate < minGeoIPOnlineRate || onlineRate > maxGeoIPOnlineRate {
		return nil, fmt.Errorf("%s must be between %d and %d",
			EnvGeoIPOnlineRate, minGeoIPOnlineRate, maxGeoIPOnlineRate)
	}
	config.GeoIPOnlineRate = onlineRate

	onlineEndpoint, err := onlineEndpointValue(EnvGeoIPOnlineEndpoint, geo.DefaultOnlineEndpoint)
	if err != nil {
		return nil, err
	}
	config.GeoIPOnlineEndpoint = onlineEndpoint

	secureCookies, err := secureCookieValue(EnvSecureCookies, SecureCookieAuto)
	if err != nil {
		return nil, err
	}
	config.SecureCookies = secureCookies

	allowlist, err := cidrListValue(EnvScrapeAllowlistCIDRs)
	if err != nil {
		return nil, err
	}
	config.ScrapeAllowlistCIDRs = allowlist

	return config, nil
}

func stringValue(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func durationValue(name string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a duration such as 15s or 2m", name, raw)
	}
	return parsed, nil
}

func intValue(name string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a whole number", name, raw)
	}
	return parsed, nil
}

func boolValue(name string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return parsed
}

func secureCookieValue(name string, fallback SecureCookieMode) (SecureCookieMode, error) {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if raw == "" {
		return fallback, nil
	}
	mode := SecureCookieMode(raw)
	if mode != SecureCookieAuto && mode != SecureCookieOn && mode != SecureCookieOff {
		return "", fmt.Errorf("%s: %q must be auto, on or off", name, raw)
	}
	return mode, nil
}

// onlineEndpointValue checks the template can actually be turned into a
// request. A URL missing the address placeholder would send every lookup to the
// same page and quietly resolve every attacker to whatever it answered with.
func onlineEndpointValue(name, fallback string) (string, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%s: %q is not a URL", name, raw)
	}
	if parsed.Scheme != httpScheme && parsed.Scheme != httpsScheme {
		return "", fmt.Errorf("%s: %q must be an http:// or https:// URL", name, raw)
	}
	if !strings.Contains(raw, geo.OnlineIPPlaceholder) {
		return "", fmt.Errorf("%s: %q must contain %s where the address goes",
			name, raw, geo.OnlineIPPlaceholder)
	}
	return raw, nil
}

func cidrListValue(name string) ([]*net.IPNet, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil, nil
	}
	var networks []*net.IPNet
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a CIDR such as 10.0.0.0/8", name, entry)
		}
		networks = append(networks, network)
	}
	return networks, nil
}
