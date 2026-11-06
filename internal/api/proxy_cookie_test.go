package api

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"endlessh-dashboard/internal/config"
)

func TestSecureCookieProxyTrust(t *testing.T) {
	_, v4, _ := net.ParseCIDR("192.0.2.0/24")
	_, v6, _ := net.ParseCIDR("2001:db8:1::/48")
	cases := []struct {
		name, peer string
		proto      []string
		tls        bool
		mode       config.SecureCookieMode
		want       bool
	}{
		{name: "forwarded address cannot confer trust", peer: "203.0.113.8:1234", proto: []string{"https"}},
		{name: "trusted IPv4", peer: "192.0.2.8:1234", proto: []string{"https"}, want: true},
		{name: "trusted IPv6", peer: "[2001:db8:1::8]:1234", proto: []string{"https"}, want: true},
		{name: "bare trusted IPv6", peer: "2001:db8:1::8", proto: []string{"https"}, want: true},
		{name: "untrusted IPv6", peer: "[2001:db8:2::8]:1234", proto: []string{"https"}},
		{name: "invalid peer", peer: "not-an-address", proto: []string{"https"}},
		{name: "missing scheme", peer: "192.0.2.8:1234"},
		{name: "HTTP proxy", peer: "192.0.2.8:1234", proto: []string{"http"}},
		{name: "normalized scheme", peer: "192.0.2.8:1234", proto: []string{" HTTPS \t"}, want: true},
		{name: "comma chain", peer: "192.0.2.8:1234", proto: []string{"https,http"}},
		{name: "reversed comma chain", peer: "192.0.2.8:1234", proto: []string{"http, https"}},
		{name: "duplicate HTTPS", peer: "192.0.2.8:1234", proto: []string{"https", "https"}},
		{name: "conflicting headers", peer: "192.0.2.8:1234", proto: []string{"https", "http"}},
		{name: "direct TLS overrides forwarded HTTP", peer: "203.0.113.8:1234", proto: []string{"http"}, tls: true, want: true},
		{name: "direct TLS ignores duplicate scheme", peer: "192.0.2.8:1234", proto: []string{"http", "https"}, tls: true, want: true},
		{name: "explicit on", peer: "203.0.113.8:1234", mode: config.SecureCookieOn, want: true},
		{name: "explicit off proxy", peer: "192.0.2.8:1234", proto: []string{"https"}, mode: config.SecureCookieOff},
		{name: "explicit off TLS", peer: "192.0.2.8:1234", tls: true, mode: config.SecureCookieOff},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mode := c.mode
			if mode == "" {
				mode = config.SecureCookieAuto
			}
			s := &Server{config: &config.Config{SecureCookies: mode, TrustedProxyCIDRs: []*net.IPNet{v4, v6}}}
			req := httptest.NewRequest("GET", "http://dashboard.test/", nil)
			req.RemoteAddr = c.peer
			for _, value := range c.proto {
				req.Header.Add(forwardedProtoHeader, value)
			}
			req.Header.Set(forwardedForHeader, "192.0.2.8")
			req.Header.Set("Forwarded", "for=192.0.2.8;proto=https")
			if c.tls {
				req.TLS = &tls.ConnectionState{}
			}
			w := httptest.NewRecorder()
			s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				s.setSessionCookie(w, r, "fixture", time.Now().Add(time.Hour))
				s.clearSessionCookie(w, r)
			})).ServeHTTP(w, req)
			cookies := w.Result().Cookies()
			if len(cookies) != 2 {
				t.Fatalf("cookies=%d", len(cookies))
			}
			for _, cookie := range cookies {
				if cookie.Secure != c.want {
					t.Fatalf("Secure=%v want %v", cookie.Secure, c.want)
				}
				if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
					t.Fatal("other cookie protection changed")
				}
			}
			if got := w.Header().Get("Strict-Transport-Security") != ""; got != c.want {
				t.Fatalf("HSTS=%v want %v", got, c.want)
			}
		})
	}
}

func TestDirectTLSCookieServer(t *testing.T) {
	s := &Server{config: &config.Config{SecureCookies: config.SecureCookieAuto}}
	server := httptest.NewTLSServer(s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.setSessionCookie(w, r, "fixture", time.Now().Add(time.Hour))
	})))
	defer server.Close()
	req, _ := http.NewRequest("GET", server.URL, nil)
	req.Header.Set(forwardedProtoHeader, "http")
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if cookies := response.Cookies(); len(cookies) != 1 || !cookies[0].Secure {
		t.Fatal("direct TLS did not issue a Secure cookie")
	}
	if response.Header.Get("Strict-Transport-Security") == "" {
		t.Fatal("direct TLS omitted HSTS")
	}
}
