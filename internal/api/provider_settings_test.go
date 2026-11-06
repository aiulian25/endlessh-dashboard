package api

import (
	"encoding/json"
	"endlessh-dashboard/internal/config"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSettingsSafeOnlineProvider(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		for _, enabled := range []bool{false, true} {
			cfg := &config.Config{GeoIPOnline: enabled, GeoIPOnlineEndpoint: scheme + "://" + url.UserPassword("fictional-user", "fictional-password").String() + "@192.168.1.8:8443/path-secret/{ip}?key=query-secret#fragment-secret"}
			s := &Server{config: cfg}
			w := httptest.NewRecorder()
			s.handleSettings(w, httptest.NewRequest("GET", "/api/settings", nil))
			var body settingsResponse
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.GeoIPOnlineProviderHost != "192.168.1.8:8443" || body.GeoIPOnlineScheme != scheme || body.GeoIPOnlineEnabled != enabled {
				t.Fatalf("inaccurate provider: %+v", body)
			}
			for _, secret := range []string{"fictional-user", "fictional-password", "path-secret", "query-secret", "fragment-secret"} {
				if strings.Contains(w.Body.String(), secret) {
					t.Fatalf("secret exposed in settings: %s", w.Body.String())
				}
			}
		}
	}
}
