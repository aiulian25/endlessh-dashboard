package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"endlessh-dashboard/internal/config"
	"endlessh-dashboard/internal/store"
)

type contextKey string

const (
	contextKeyUser    contextKey = "user"
	contextKeySession contextKey = "session"

	forwardedProtoHeader = "X-Forwarded-Proto"
	forwardedForHeader   = "X-Forwarded-For"
)

// contentSecurityPolicy allows nothing but this origin, with no inline script
// or style at all. The interface is built to hold to it: chart colours are CSS
// classes rather than style attributes. It doubles as a tripwire — an asset
// that ever starts pointing at a CDN stops loading here first.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"connect-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'none'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		header := writer.Header()
		header.Set("Content-Security-Policy", contentSecurityPolicy)
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Cross-Origin-Opener-Policy", "same-origin")
		header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
		if s.useSecureCookies(request) {
			header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(writer, request)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: writer, status: http.StatusOK}
		next.ServeHTTP(recorder, request)

		// Query strings can carry search terms; only the path is logged.
		s.logger.Debug("request",
			"method", request.Method,
			"path", request.URL.Path,
			"status", recorder.status,
			"duration_ms", time.Since(started).Milliseconds(),
		)
	})
}

func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("panic serving request", "path", request.URL.Path, "panic", recovered)
				writeError(writer, http.StatusInternalServerError, "something went wrong handling that request")
			}
		}()
		next.ServeHTTP(writer, request)
	})
}

func (s *Server) public(handler http.HandlerFunc) http.Handler {
	return handler
}

// protected requires a live session, enforces CSRF on mutating requests, and
// funnels a user who must change their password into doing exactly that.
func (s *Server) protected(handler http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie(SessionCookieName)
		if err != nil {
			writeError(writer, http.StatusUnauthorized, "sign in to continue")
			return
		}

		session, user, err := s.auth.Session(request.Context(), cookie.Value)
		if errors.Is(err, store.ErrSessionNotFound) {
			s.clearSessionCookie(writer, request)
			writeError(writer, http.StatusUnauthorized, "your session has expired, sign in again")
			return
		}
		if err != nil {
			s.logger.Error("look up session", "error", err)
			writeError(writer, http.StatusInternalServerError, "could not verify your session")
			return
		}

		if isMutating(request.Method) {
			presented := request.Header.Get(CSRFHeaderName)
			if subtle.ConstantTimeCompare([]byte(presented), []byte(session.CSRFToken)) != 1 {
				writeError(writer, http.StatusForbidden, "your page is out of date, reload and try again")
				return
			}
		}

		if user.MustChangePassword && !isPasswordChangeExempt(request) {
			writeError(writer, http.StatusForbidden, "choose a new password before continuing")
			return
		}

		ctx := context.WithValue(request.Context(), contextKeyUser, user)
		ctx = context.WithValue(ctx, contextKeySession, session)
		handler(writer, request.WithContext(ctx))
	})
}

func isMutating(method string) bool {
	return method == http.MethodPost || method == http.MethodPut ||
		method == http.MethodPatch || method == http.MethodDelete
}

func isPasswordChangeExempt(request *http.Request) bool {
	switch request.URL.Path {
	case "/api/password", "/api/session", "/api/logout":
		return true
	}
	return false
}

func userFrom(ctx context.Context) (store.User, bool) {
	user, ok := ctx.Value(contextKeyUser).(store.User)
	return user, ok
}

func sessionFrom(ctx context.Context) (store.Session, bool) {
	session, ok := ctx.Value(contextKeySession).(store.Session)
	return session, ok
}

func (s *Server) useSecureCookies(request *http.Request) bool {
	switch s.config.SecureCookies {
	case config.SecureCookieOn:
		return true
	case config.SecureCookieOff:
		return false
	}
	if request.TLS != nil {
		return true
	}
	return strings.EqualFold(request.Header.Get(forwardedProtoHeader), "https")
}

func (s *Server) setSessionCookie(writer http.ResponseWriter, request *http.Request, token string, expires time.Time) {
	http.SetCookie(writer, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.useSecureCookies(request),
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(writer http.ResponseWriter, request *http.Request) {
	http.SetCookie(writer, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.useSecureCookies(request),
		SameSite: http.SameSiteStrictMode,
	})
}

// clientKey identifies a login attempt source for throttling: the account being
// tried, at the address trying it. Both halves matter — the address alone would
// let one noisy client on a shared line lock out everybody behind it, and the
// username alone would let anyone lock out the only account this app has.
func (s *Server) clientKey(request *http.Request, username string) string {
	return strings.ToLower(username) + "@" + s.clientHost(request)
}

// clientHost is the address a login attempt is counted against. The socket
// address is the honest answer and the default one. It stops being the client's
// address only behind a reverse proxy, where every request arrives from the
// proxy and one wrong password from anybody would lock the account for
// everybody — so an operator who has such a proxy names it in
// TRUSTED_PROXY_CIDRS and the address it reports is used instead.
//
// Only the last X-Forwarded-For entry is read. That is the one the trusted
// proxy appended itself, so it is the one a client cannot dictate by sending a
// header of its own; everything to the left of it is caller-supplied text and
// is ignored. The cost of that choice is a chain of two or more proxies, which
// reports the last hop rather than the original client — the safe direction to
// be wrong in, because the alternative is trusting an attacker's header.
func (s *Server) clientHost(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	if !s.isTrustedProxy(host) {
		return host
	}
	forwarded := lastForwardedFor(request)
	if forwarded == "" {
		return host
	}
	return forwarded
}

func (s *Server) isTrustedProxy(host string) bool {
	address := net.ParseIP(host)
	if address == nil {
		return false
	}
	for _, network := range s.config.TrustedProxyCIDRs {
		if network.Contains(address) {
			return true
		}
	}
	return false
}

// lastForwardedFor returns the final address in the header, in its canonical
// form, or an empty string when there is not one. Anything that does not parse
// as an address is discarded rather than passed on: the throttle map is keyed
// on what this returns, and a header full of junk would otherwise fill it with
// junk under a name that no longer means anything.
func lastForwardedFor(request *http.Request) string {
	values := request.Header.Values(forwardedForHeader)
	if len(values) == 0 {
		return ""
	}
	entries := strings.Split(values[len(values)-1], ",")
	address := net.ParseIP(strings.TrimSpace(entries[len(entries)-1]))
	if address == nil {
		return ""
	}
	return address.String()
}
