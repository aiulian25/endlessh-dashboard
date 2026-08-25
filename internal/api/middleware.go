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
	return strings.EqualFold(request.Header.Get("X-Forwarded-Proto"), "https")
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

// clientKey identifies a login attempt source for throttling. Behind a proxy
// the socket address is the proxy's, which is why the throttle also keys on
// the username being tried.
func clientKey(request *http.Request, username string) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	return strings.ToLower(username) + "@" + host
}
