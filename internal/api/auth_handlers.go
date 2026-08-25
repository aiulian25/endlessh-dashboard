package api

import (
	"errors"
	"net/http"

	"endlessh-dashboard/internal/auth"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type sessionResponse struct {
	Username           string `json:"username"`
	MustChangePassword bool   `json:"must_change_password"`
	CSRFToken          string `json:"csrf_token"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) handleLogin(writer http.ResponseWriter, request *http.Request) {
	var payload loginRequest
	if !decodeJSON(writer, request, &payload) {
		return
	}

	token, session, user, err := s.auth.Login(
		request.Context(), payload.Username, payload.Password,
		clientKey(request, payload.Username),
	)
	if errors.Is(err, auth.ErrInvalidCredentials) {
		writeError(writer, http.StatusUnauthorized, "username or password is incorrect")
		return
	}
	if errors.Is(err, auth.ErrTooManyAttempts) {
		writeError(writer, http.StatusTooManyRequests, err.Error())
		return
	}
	if errors.Is(err, auth.ErrBusy) {
		writer.Header().Set("Retry-After", "5")
		writeError(writer, http.StatusServiceUnavailable, err.Error())
		return
	}
	if err != nil {
		s.logger.Error("login", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not sign you in")
		return
	}

	s.setSessionCookie(writer, request, token, session.ExpiresAt)
	writeJSON(writer, http.StatusOK, sessionResponse{
		Username:           user.Username,
		MustChangePassword: user.MustChangePassword,
		CSRFToken:          session.CSRFToken,
	})
}

func (s *Server) handleLogout(writer http.ResponseWriter, request *http.Request) {
	if cookie, err := request.Cookie(SessionCookieName); err == nil {
		if err := s.auth.Logout(request.Context(), cookie.Value); err != nil {
			s.logger.Error("logout", "error", err)
		}
	}
	s.clearSessionCookie(writer, request)
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSession(writer http.ResponseWriter, request *http.Request) {
	user, ok := userFrom(request.Context())
	session, sessionOK := sessionFrom(request.Context())
	if !ok || !sessionOK {
		writeError(writer, http.StatusUnauthorized, "sign in to continue")
		return
	}
	writeJSON(writer, http.StatusOK, sessionResponse{
		Username:           user.Username,
		MustChangePassword: user.MustChangePassword,
		CSRFToken:          session.CSRFToken,
	})
}

func (s *Server) handleChangePassword(writer http.ResponseWriter, request *http.Request) {
	user, ok := userFrom(request.Context())
	if !ok {
		writeError(writer, http.StatusUnauthorized, "sign in to continue")
		return
	}

	var payload changePasswordRequest
	if !decodeJSON(writer, request, &payload) {
		return
	}

	err := s.auth.ChangePassword(request.Context(), user.ID, payload.CurrentPassword, payload.NewPassword)
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeFieldError(writer, http.StatusBadRequest, "current_password", "current password is incorrect")
		return
	case errors.Is(err, auth.ErrWeakPassword), errors.Is(err, auth.ErrPasswordTooLong):
		writeFieldError(writer, http.StatusBadRequest, "new_password", err.Error())
		return
	case errors.Is(err, auth.ErrSamePassword):
		writeFieldError(writer, http.StatusBadRequest, "new_password", err.Error())
		return
	case err != nil:
		s.logger.Error("change password", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not change the password")
		return
	}

	// Every session was just invalidated, including this one.
	s.clearSessionCookie(writer, request)
	writer.WriteHeader(http.StatusNoContent)
}
