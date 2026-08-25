package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"endlessh-dashboard/internal/store"
)

const (
	defaultPageSize = 50
	maxPageSize     = 200
)

type overviewResponse struct {
	TimeWastedSeconds      float64                 `json:"time_wasted_seconds"`
	TimeWastedDeltaSeconds float64                 `json:"time_wasted_delta_seconds"`
	AttackersTrapped       int64                   `json:"attackers_trapped"`
	AttackersTrappedDelta  int64                   `json:"attackers_trapped_delta"`
	BytesSent              int64                   `json:"bytes_sent"`
	BytesSentDelta         int64                   `json:"bytes_sent_delta"`
	TrappedNow             int64                   `json:"trapped_now"`
	MachineCount           int                     `json:"machine_count"`
	UniqueAttackers        int64                   `json:"unique_attackers"`
	Countries              int                     `json:"countries"`
	LatestAttacker         *latestAttackerResponse `json:"latest_attacker"`
}

// latestAttackerResponse is the newest catch. It is a pointer on the overview so
// an install that has never seen anybody sends null rather than a row of zeroes.
type latestAttackerResponse struct {
	IPAddress   string    `json:"ip"`
	Country     string    `json:"country"`
	CountryCode string    `json:"country_code"`
	Location    string    `json:"location"`
	At          time.Time `json:"at"`
}

type seriesPointResponse struct {
	At             time.Time `json:"t"`
	TrappedSeconds float64   `json:"trapped_seconds"`
	Opens          int64     `json:"opens"`
	BytesSent      int64     `json:"bytes_sent"`
}

type seriesResponse struct {
	MachineID   int64                 `json:"machine_id"`
	MachineName string                `json:"machine_name"`
	Points      []seriesPointResponse `json:"points"`
}

type timeSeriesResponse struct {
	BucketSeconds int              `json:"bucket_seconds"`
	From          time.Time        `json:"from"`
	To            time.Time        `json:"to"`
	Series        []seriesResponse `json:"series"`
}

type attackerResponse struct {
	IPAddress      string    `json:"ip"`
	MachineID      int64     `json:"machine_id"`
	MachineName    string    `json:"machine_name"`
	Country        string    `json:"country"`
	CountryCode    string    `json:"country_code"`
	Geohash        string    `json:"geohash"`
	Location       string    `json:"location"`
	ISP            string    `json:"isp"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	Connections    int64     `json:"connections"`
	TrappedSeconds float64   `json:"trapped_seconds"`
	Status         string    `json:"status"`
}

type attackerPageResponse struct {
	Total   int                `json:"total"`
	Page    int                `json:"page"`
	PerPage int                `json:"per_page"`
	Rows    []attackerResponse `json:"rows"`
}

type countryCountResponse struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
}

func (s *Server) handleOverview(writer http.ResponseWriter, request *http.Request) {
	machines, err := s.resolveMachines(request)
	if err != nil {
		s.logger.Error("resolve machines", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load the machine list")
		return
	}

	windowDuration, _ := resolveWindow(request)
	now := time.Now().UTC()
	selected := machineIDs(machines)
	overview, err := s.store.Overview(
		request.Context(), selected,
		now.Add(-windowDuration), now.Add(-s.config.StaleClientThreshold()),
	)
	if err != nil {
		s.logger.Error("overview", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load the summary")
		return
	}

	// The newest catch is deliberately not windowed: a quiet week should still
	// show who came last, not an empty strip.
	latest, found, err := s.store.LatestAttacker(request.Context(), selected)
	if err != nil {
		s.logger.Error("latest attacker", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load the summary")
		return
	}

	payload := overviewResponse{
		TimeWastedSeconds:      overview.TimeWastedSeconds,
		TimeWastedDeltaSeconds: overview.TimeWastedDeltaSeconds,
		AttackersTrapped:       overview.AttackersTrapped,
		AttackersTrappedDelta:  overview.AttackersTrappedDelta,
		BytesSent:              overview.BytesSent,
		BytesSentDelta:         overview.BytesSentDelta,
		TrappedNow:             overview.TrappedNow,
		MachineCount:           overview.MachineCount,
		UniqueAttackers:        overview.UniqueAttackers,
		Countries:              overview.Countries,
	}
	if found {
		payload.LatestAttacker = &latestAttackerResponse{
			IPAddress:   latest.IPAddress,
			Country:     latest.Country,
			CountryCode: latest.CountryCode,
			Location:    latest.Location,
			At:          latest.LastSeen,
		}
	}
	writeJSON(writer, http.StatusOK, payload)
}

func (s *Server) handleTimeSeries(writer http.ResponseWriter, request *http.Request) {
	machines, err := s.resolveMachines(request)
	if err != nil {
		s.logger.Error("resolve machines", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load the machine list")
		return
	}

	windowDuration, bucketSeconds := resolveWindow(request)
	to := time.Now().UTC()
	from := to.Add(-windowDuration)

	series, err := s.store.TimeSeries(request.Context(), machines, from, to, bucketSeconds)
	if err != nil {
		s.logger.Error("time series", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load the chart data")
		return
	}

	payload := timeSeriesResponse{
		BucketSeconds: bucketSeconds,
		From:          from,
		To:            to,
		Series:        make([]seriesResponse, 0, len(series)),
	}
	for _, machineSeries := range series {
		points := make([]seriesPointResponse, 0, len(machineSeries.Points))
		for _, point := range machineSeries.Points {
			points = append(points, seriesPointResponse{
				At:             point.At,
				TrappedSeconds: point.TrappedSeconds,
				Opens:          point.Opens,
				BytesSent:      point.BytesSent,
			})
		}
		payload.Series = append(payload.Series, seriesResponse{
			MachineID:   machineSeries.MachineID,
			MachineName: machineSeries.MachineName,
			Points:      points,
		})
	}
	writeJSON(writer, http.StatusOK, payload)
}

func (s *Server) handleAttackers(writer http.ResponseWriter, request *http.Request) {
	machines, err := s.resolveMachines(request)
	if err != nil {
		s.logger.Error("resolve machines", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load the machine list")
		return
	}

	query := request.URL.Query()
	windowDuration, _ := resolveWindow(request)
	now := time.Now().UTC()

	page, perPage := paginationFrom(query)
	sortColumn, descending := sortFrom(query)

	filter := store.AttackerFilter{
		MachineIDs:     machineIDs(machines),
		Since:          now.Add(-windowDuration),
		Country:        strings.TrimSpace(query.Get("country")),
		Status:         strings.TrimSpace(query.Get("status")),
		Search:         strings.TrimSpace(query.Get("q")),
		SortColumn:     sortColumn,
		SortDescending: descending,
		Page:           page,
		PerPage:        perPage,
		ActiveSince:    now.Add(-s.config.StaleClientThreshold()),
	}

	result, err := s.store.ListAttackers(request.Context(), filter)
	if err != nil {
		s.logger.Error("list attackers", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load the attacker list")
		return
	}

	payload := attackerPageResponse{
		Total:   result.Total,
		Page:    page,
		PerPage: perPage,
		Rows:    make([]attackerResponse, 0, len(result.Rows)),
	}
	for _, row := range result.Rows {
		payload.Rows = append(payload.Rows, attackerResponse{
			IPAddress:      row.IPAddress,
			MachineID:      row.MachineID,
			MachineName:    row.MachineName,
			Country:        row.Country,
			CountryCode:    row.CountryCode,
			Geohash:        row.Geohash,
			Location:       row.Location,
			ISP:            row.ISP,
			FirstSeen:      row.FirstSeen,
			LastSeen:       row.LastSeen,
			Connections:    row.Connections,
			TrappedSeconds: row.TrappedSeconds,
			Status:         row.Status,
		})
	}
	writeJSON(writer, http.StatusOK, payload)
}

func (s *Server) handleAttackerCountries(writer http.ResponseWriter, request *http.Request) {
	machines, err := s.resolveMachines(request)
	if err != nil {
		s.logger.Error("resolve machines", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load the machine list")
		return
	}

	// The same aggregation the map's breakdown is built from, so a country's
	// chip on this page and its slice in the donut can never report different
	// numbers for the same window. The chips need only the count; the rest of
	// the row is what the donut draws with.
	windowDuration, _ := resolveWindow(request)
	totals, err := s.store.CountryTotals(
		request.Context(), machineIDs(machines), time.Now().UTC().Add(-windowDuration))
	if err != nil {
		s.logger.Error("country counts", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load the country summary")
		return
	}

	payload := make([]countryCountResponse, 0, len(totals))
	for _, total := range totals {
		payload = append(payload, countryCountResponse{Country: total.Country, Count: total.Attackers})
	}
	writeJSON(writer, http.StatusOK, payload)
}

func paginationFrom(query map[string][]string) (int, int) {
	page := 1
	perPage := defaultPageSize

	if values, ok := query["page"]; ok && len(values) > 0 {
		if parsed, err := strconv.Atoi(values[0]); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if values, ok := query["per_page"]; ok && len(values) > 0 {
		if parsed, err := strconv.Atoi(values[0]); err == nil && parsed > 0 {
			perPage = min(parsed, maxPageSize)
		}
	}
	return page, perPage
}

func sortFrom(query map[string][]string) (string, bool) {
	column := "trapped_seconds"
	if values, ok := query["sort"]; ok && len(values) > 0 && values[0] != "" {
		column = values[0]
	}
	descending := true
	if values, ok := query["order"]; ok && len(values) > 0 {
		descending = !strings.EqualFold(values[0], "asc")
	}
	return column, descending
}
