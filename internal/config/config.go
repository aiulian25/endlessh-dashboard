package config

import (
	"fmt"
	"log/slog"
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
	EnvLogLevel             = "LOG_LEVEL"
	EnvDataDirectory        = "DATA_DIR"
	EnvScrapeInterval       = "SCRAPE_INTERVAL"
	EnvScrapeTimeout        = "SCRAPE_TIMEOUT"
	EnvScrapeConcurrency    = "SCRAPE_CONCURRENCY"
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
	EnvTrustedProxyCIDRs    = "TRUSTED_PROXY_CIDRS"
	EnvScrapeBlockPrivate   = "SCRAPE_BLOCK_PRIVATE"
	EnvBackupDaily          = "BACKUP_DAILY"
	EnvBackupKeepLast       = "BACKUP_KEEP_LAST"
)

const (
	defaultListenAddress     = ":18222"
	defaultDataDirectory     = "/data"
	defaultScrapeInterval    = 15 * time.Second
	defaultScrapeTimeout     = 5 * time.Second
	defaultScrapeConcurrency = 4
	maxScrapeConcurrency     = 32
	defaultRetentionDays     = 90
	defaultAdminUsername     = "admin"
	defaultLogLevel          = slog.LevelInfo
	defaultBackupKeepLast    = 7

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
	// directly or through a configured trusted proxy that set X-Forwarded-Proto.
	SecureCookieAuto SecureCookieMode = "auto"
	SecureCookieOn   SecureCookieMode = "on"
	SecureCookieOff  SecureCookieMode = "off"
)

// Config holds the effective settings for one run. There is deliberately no
// session-signing key: sessions live in the database and are looked up by the
// hash of a random token, so there is no secret to keep in step across restarts.
type Config struct {
	ListenAddress string
	// LogLevel is the floor for what reaches the container log. Debug is where
	// the per-request line lives, which is the one worth reaching for when a
	// proxy or a CSRF header is not behaving.
	LogLevel          slog.Level
	DataDirectory     string
	ScrapeInterval    time.Duration
	ScrapeTimeout     time.Duration
	ScrapeConcurrency int
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
	// TrustedProxyCIDRs lists the addresses allowed to speak for a client other
	// than themselves. Empty — the default — means the socket address is the
	// client, which is the truth for a directly exposed dashboard.
	TrustedProxyCIDRs  []*net.IPNet
	ScrapeBlockPrivate bool
	BackupDaily        bool
	BackupKeepLast     int
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
	concurrency, err := intValue(EnvScrapeConcurrency, defaultScrapeConcurrency)
	if err != nil {
		return nil, err
	}
	if concurrency < 1 || concurrency > maxScrapeConcurrency {
		return nil, fmt.Errorf("%s must be between 1 and %d", EnvScrapeConcurrency, maxScrapeConcurrency)
	}
	config.ScrapeConcurrency = concurrency

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

	backupDaily, err := boolValue(EnvBackupDaily, false)
	if err != nil {
		return nil, err
	}
	config.BackupDaily = backupDaily

	scrapeBlockPrivate, err := boolValue(EnvScrapeBlockPrivate, false)
	if err != nil {
		return nil, err
	}
	config.ScrapeBlockPrivate = scrapeBlockPrivate

	geoIPOnline, err := boolValue(EnvGeoIPOnline, false)
	if err != nil {
		return nil, err
	}
	config.GeoIPOnline = geoIPOnline

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

	logLevel, err := logLevelValue(EnvLogLevel, defaultLogLevel)
	if err != nil {
		return nil, err
	}
	config.LogLevel = logLevel

	allowlist, err := cidrListValue(EnvScrapeAllowlistCIDRs)
	if err != nil {
		return nil, err
	}
	config.ScrapeAllowlistCIDRs = allowlist

	trustedProxies, err := cidrListValue(EnvTrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	config.TrustedProxyCIDRs = trustedProxies

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

// boolValue refuses a spelling ParseBool does not know rather than falling back
// to the default. "yes" and "on" are the spellings people reach for, and two of
// the three callers are safety switches: SCRAPE_BLOCK_PRIVATE read as "off"
// would leave the SSRF guard down while the .env file says it is up.
func boolValue(name string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s: %q must be true or false", name, raw)
	}
	return parsed, nil
}

// logLevelValue reads the log floor by the names people write in a .env file
// rather than slog's own numbers, and refuses anything else at startup instead
// of quietly logging at a level nobody asked for.
func logLevelValue(name string, fallback slog.Level) (slog.Level, error) {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if raw == "" {
		return fallback, nil
	}
	switch raw {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("%s: %q must be debug, info, warn or error", name, raw)
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
		return "", fmt.Errorf("%s: invalid URL", name)
	}
	if parsed.Scheme != httpScheme && parsed.Scheme != httpsScheme {
		return "", fmt.Errorf("%s: must be an http:// or https:// URL", name)
	}
	if parsed.Hostname() == "" {
		return "", fmt.Errorf("%s: URL must have a host", name)
	}
	if !strings.Contains(raw, geo.OnlineIPPlaceholder) {
		return "", fmt.Errorf("%s: must contain %s where the address goes",
			name, geo.OnlineIPPlaceholder)
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
