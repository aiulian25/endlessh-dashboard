package api

import (
	"net/http"
)

type geoPointResponse struct {
	CountryKey     string  `json:"country_key"`
	Latitude       float64 `json:"lat"`
	Longitude      float64 `json:"lon"`
	Country        string  `json:"country"`
	CountryCode    string  `json:"country_code"`
	Attackers      int     `json:"attackers"`
	Connections    int64   `json:"connections"`
	TrappedSeconds float64 `json:"trapped_seconds"`
}

type geoCountryResponse struct {
	CountryKey  string `json:"country_key"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Attackers   int    `json:"attackers"`
	Connections int64  `json:"connections"`
}

func (s *Server) handleGeoPoints(writer http.ResponseWriter, request *http.Request) {
	machines, err := s.resolveMachines(request)
	if err != nil {
		s.logger.Error("resolve machines", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load the machine list")
		return
	}

	span, _, ok := readTimeRange(writer, request)
	if !ok {
		return
	}
	points, err := s.store.GeoPoints(
		request.Context(), machineIDs(machines), span.From, span.To)
	if err != nil {
		s.logger.Error("geo points", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load the map data")
		return
	}

	payload := make([]geoPointResponse, 0, len(points))
	for _, point := range points {
		payload = append(payload, geoPointResponse{
			Latitude:       point.Latitude,
			Longitude:      point.Longitude,
			Country:        point.Country,
			CountryKey:     point.CountryKey,
			CountryCode:    point.CountryCode,
			Attackers:      point.Attackers,
			Connections:    point.Connections,
			TrappedSeconds: point.TrappedSeconds,
		})
	}
	writeJSON(writer, http.StatusOK, payload)
}

func (s *Server) handleGeoCountries(writer http.ResponseWriter, request *http.Request) {
	machines, err := s.resolveMachines(request)
	if err != nil {
		s.logger.Error("resolve machines", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load the machine list")
		return
	}

	span, _, ok := readTimeRange(writer, request)
	if !ok {
		return
	}
	totals, err := s.store.CountryTotalsInRange(
		request.Context(), machineIDs(machines), span, false)
	if err != nil {
		s.logger.Error("country totals", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load the country breakdown")
		return
	}

	payload := make([]geoCountryResponse, 0, len(totals))
	for _, total := range totals {
		payload = append(payload, geoCountryResponse{
			Country:     total.Country,
			CountryKey:  total.CountryKey,
			CountryCode: total.CountryCode,
			Attackers:   total.Attackers,
			Connections: total.Connections,
		})
	}
	writeJSON(writer, http.StatusOK, payload)
}
