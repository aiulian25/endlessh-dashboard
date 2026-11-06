package geo

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type endpointTransport func(*http.Request) (*http.Response, error)

func (f endpointTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOnlineEndpointSecrets(t *testing.T) {
	endpoint := "https://" + url.UserPassword("fictional-user", "fictional-password").String() + "@provider.internal:8443/path-secret/{ip}?key=query-secret#fragment-secret"
	for _, kind := range []string{"transport", "redirect", "status", "json", "build", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			r := NewOnlineResolver(true, endpoint, 40)
			defer r.Close()
			r.client.Transport = endpointTransport(func(req *http.Request) (*http.Response, error) {
				if !strings.Contains(req.URL.String(), "path-secret/8.8.8.8?key=query-secret") {
					t.Fatal("configured template was not preserved for requests")
				}
				switch kind {
				case "transport":
					return nil, errors.New(endpoint)
				case "cancel":
					return nil, context.Canceled
				case "redirect":
					return nil, errors.New("redirects are not followed")
				case "status":
					return &http.Response{StatusCode: 503, Status: endpoint, Body: io.NopCloser(strings.NewReader(endpoint)), Header: make(http.Header)}, nil
				default:
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(endpoint)), Header: make(http.Header)}, nil
				}
			})
			if kind == "build" {
				r.endpoint = "https://" + url.UserPassword("fictional-user", "fictional-password").String() + "@provider.internal/path-secret/%zz/{ip}?key=query-secret"
			}
			_, err := r.request(context.Background(), "8.8.8.8")
			if err == nil {
				t.Fatal("expected safe error")
			}
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			logger.Warn("configured provider", "endpoint", r.Endpoint())
			logger.Error("lookup failed", "error", err)
			for _, secret := range []string{"fictional-user", "fictional-password", "path-secret", "query-secret", "fragment-secret"} {
				if strings.Contains(logs.String(), secret) {
					t.Fatalf("secret %q exposed: %s", secret, logs.String())
				}
			}
			if kind != "build" && r.Endpoint() != "https://provider.internal:8443" {
				t.Fatalf("unsafe or inaccurate descriptor: %s", r.Endpoint())
			}
			if kind == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation identity lost")
			}
		})
	}
}

func TestOnlineRedirectDoesNotExposeDestination(t *testing.T) {
	r := NewOnlineResolver(true, "https://provider.internal/{ip}", 40)
	defer r.Close()
	var calls int
	r.client.Transport = endpointTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://" + url.UserPassword("user-secret", "password-secret").String() + "@other.internal/path-secret?key=query-secret"}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	})
	_, err := r.request(context.Background(), "8.8.8.8")
	if err == nil || !strings.Contains(err.Error(), "redirects are not followed") || calls != 1 {
		t.Fatalf("redirect policy changed: calls=%d err=%v", calls, err)
	}
	for _, secret := range []string{"user-secret", "password-secret", "other.internal", "path-secret", "query-secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("redirect secret exposed: %v", err)
		}
	}
}

func TestEnrichmentGenerationRetainsPrivateEndpointIdentity(t *testing.T) {
	a := NewOnlineResolver(true, "https://provider.internal/path-a/{ip}?key=one", 40)
	defer a.Close()
	b := NewOnlineResolver(true, "https://provider.internal/path-b/{ip}?key=two", 40)
	defer b.Close()
	local := &changingLocalSource{generation: "same"}
	first := NewEnricher(nil, local, a, nil).sourceGeneration()
	second := NewEnricher(nil, local, b, nil).sourceGeneration()
	if a.Endpoint() != b.Endpoint() || first == second {
		t.Fatal("redaction changed provider generation semantics")
	}
}
