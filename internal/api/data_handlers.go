package api

import (
	"encoding/json"
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
	Activity               activityMetadata        `json:"activity"`
	From                   time.Time               `json:"from"`
	To                     time.Time               `json:"to"`
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
	PortScoped      bool       `json:"-"`
	Coverage        string     `json:"coverage"`
	ObservedSeconds float64    `json:"observed_seconds"`
	Attempts        int64      `json:"attempts"`
	Successes       int64      `json:"successes"`
	UncertainFrom   *time.Time `json:"uncertain_from"`
	UncertainTo     *time.Time `json:"uncertain_to"`
	At              time.Time  `json:"t"`
	To              time.Time  `json:"to"`
	Partial         bool       `json:"partial"`
	TrappedSeconds  float64    `json:"trapped_seconds"`
	Opens           int64      `json:"opens"`
	BytesSent       int64      `json:"bytes_sent"`
}

// Port history has no synthetic zero before collection or during absent samples.
// Legacy unfiltered response fields and types are unchanged.
func (p seriesPointResponse) MarshalJSON() ([]byte, error) {
	type plain seriesPointResponse
	if !p.PortScoped {
		return json.Marshal(plain(p))
	}
	var opens *int64
	var bytes *int64
	var seconds *float64
	available := p.Attempts > 0 || p.ObservedSeconds > 0
	if available {
		opens = &p.Opens
		bytes = &p.BytesSent
		seconds = &p.TrappedSeconds
	}
	return json.Marshal(struct {
		plain
		Available bool     `json:"available"`
		Opens     *int64   `json:"opens"`
		Bytes     *int64   `json:"bytes_sent"`
		Seconds   *float64 `json:"trapped_seconds"`
	}{plain(p), available, opens, bytes, seconds})
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
	IPAddress              string     `json:"ip"`
	MachineID              int64      `json:"machine_id"`
	MachineName            string     `json:"machine_name"`
	Country                string     `json:"country"`
	CountryCode            string     `json:"country_code"`
	Geohash                string     `json:"geohash"`
	Location               string     `json:"location"`
	ISP                    string     `json:"isp"`
	FirstSeen              time.Time  `json:"first_seen"`
	LastSeen               time.Time  `json:"last_seen"`
	Connections            int64      `json:"connections"`
	TrappedSeconds         float64    `json:"trapped_seconds"`
	Status                 string     `json:"status"`
	LastObservedAt         time.Time  `json:"last_observed_at"`
	LastMeasuredActivityAt *time.Time `json:"last_measured_activity_at"`
	HasUndatedHistory      bool       `json:"has_undated_history"`
	FirstObservationKnown  bool       `json:"first_observation_known"`
}

type attackerPageResponse struct {
	DistinctIPs int                `json:"distinct_ips"`
	Activity    activityMetadata   `json:"activity"`
	From        time.Time          `json:"from"`
	To          time.Time          `json:"to"`
	Total       int                `json:"total"`
	Page        int                `json:"page"`
	PerPage     int                `json:"per_page"`
	Rows        []attackerResponse `json:"rows"`
}

type countryCountResponse struct {
	CountryKey  string `json:"country_key"`
	CountryCode string `json:"country_code"`
	Country     string `json:"country"`
	Count       int    `json:"count"`
}

func (s *Server) handleOverview(writer http.ResponseWriter, request *http.Request) {
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
	now := time.Now().UTC()
	selected := machineIDs(machines)
	overview, err := s.store.Overview(
		request.Context(), selected,
		span.From, now.Add(-s.config.StaleClientThreshold()), span.To,
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

	payload := overviewResponse{Activity: s.activityMetadata(machines, now), From: span.From, To: span.To,
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
	if found && latest.LastMeasuredActivityAt != nil {
		payload.LatestAttacker = &latestAttackerResponse{
			IPAddress:   latest.IPAddress,
			Country:     latest.Country,
			CountryCode: latest.CountryCode,
			Location:    latest.Location,
			At:          *latest.LastMeasuredActivityAt,
		}
	}
	writeJSON(writer, http.StatusOK, payload)
}

func (s *Server) handleTimeSeries(writer http.ResponseWriter, request *http.Request) {
	port, ok := readPort(writer, request)
	if !ok {
		return
	}
	machines, err := s.resolveMachines(request)
	if err != nil {
		s.logger.Error("resolve machines", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load the machine list")
		return
	}

	span, bucketSeconds, ok := readTimeRange(writer, request)
	if !ok {
		return
	}
	from, to := span.From, span.To

	var series []store.MachineSeries
	if port != "" {
		series, err = s.store.TimeSeriesForPort(request.Context(), machines, from, to, bucketSeconds, port)
	} else {
		series, err = s.store.TimeSeries(request.Context(), machines, from, to, bucketSeconds)
	}
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
				PortScoped: port != "",
				At:         point.At, To: point.To, Partial: point.Partial,
				Coverage: point.Coverage, ObservedSeconds: point.ObservedSeconds, Attempts: point.Attempts, Successes: point.Successes, UncertainFrom: point.UncertainFrom, UncertainTo: point.UncertainTo,
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
	span, _, ok := readTimeRange(writer, request)
	if !ok {
		return
	}
	now := time.Now().UTC()

	page, perPage := paginationFrom(query)
	sortColumn, descending := sortFrom(query)

	filter := store.AttackerFilter{
		MachineIDs: machineIDs(machines),
		Since:      span.From, Until: span.To,
		Country:         strings.TrimSpace(query.Get("country")),
		CountryKey:      query.Get("country_key"),
		Status:          strings.TrimSpace(query.Get("status")),
		Search:          strings.TrimSpace(query.Get("q")),
		SortColumn:      sortColumn,
		SortDescending:  descending,
		Page:            page,
		PerPage:         perPage,
		ActiveSince:     now.Add(-s.config.StaleClientThreshold()),
		ObservationOnly: query.Get("basis") == "observed",
	}

	result, err := s.store.ListAttackers(request.Context(), filter)
	if err != nil {
		s.logger.Error("list attackers", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load the attacker list")
		return
	}

	payload := attackerPageResponse{DistinctIPs: result.DistinctIPs, Activity: s.activityMetadata(machines, now), From: span.From, To: span.To,
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
			LastObservedAt: row.LastObservedAt, LastMeasuredActivityAt: row.LastMeasuredActivityAt, HasUndatedHistory: row.HasUndatedHistory, FirstObservationKnown: row.FirstObservationKnown,
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
	span, _, ok := readTimeRange(writer, request)
	if !ok {
		return
	}
	totals, err := s.store.CountryTotalsInRange(request.Context(), machineIDs(machines), span, request.URL.Query().Get("basis") == "observed")
	if err != nil {
		s.logger.Error("country counts", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not load the country summary")
		return
	}

	payload := make([]countryCountResponse, 0, len(totals))
	for _, total := range totals {
		payload = append(payload, countryCountResponse{Country: total.Country, CountryKey: total.CountryKey, CountryCode: total.CountryCode, Count: total.Attackers})
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
