package main

import (
	"bytes"
	"endlessh-dashboard/internal/geo"
	"log/slog"
	"net/url"
	"strings"
	"testing"
)

func TestOnlineStartupLogSafeDestination(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		var output bytes.Buffer
		resolver := geo.NewOnlineResolver(enabled, "https://"+url.UserPassword("fictional-user", "fictional-password").String()+"@provider.internal:8443/path-secret/{ip}?key=query-secret#fragment-secret", 40)
		defer resolver.Close()
		logOnlineProvider(slog.New(slog.NewJSONHandler(&output, nil)), resolver, 40)
		if !enabled && output.Len() != 0 {
			t.Fatal("disabled provider logged as enabled")
		}
		if enabled && !strings.Contains(output.String(), "https://provider.internal:8443") {
			t.Fatal("safe destination missing")
		}
		for _, secret := range []string{"fictional-user", "fictional-password", "path-secret", "query-secret", "fragment-secret"} {
			if strings.Contains(output.String(), secret) {
				t.Fatalf("secret exposed: %s", output.String())
			}
		}
	}
}
