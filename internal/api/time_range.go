package api

import (
	"endlessh-dashboard/internal/store"
	"fmt"
	"net/http"
	"time"
)

// All windowed endpoints accept either an explicit pair or a shared as_of.
// Range values are minute-start selections, not a database snapshot token.
func readTimeRange(w http.ResponseWriter, r *http.Request) (store.TimeRange, int, bool) {
	duration, bucket := resolveWindow(r)
	q := r.URL.Query()
	now := time.Now().UTC()
	from, to := now.Add(-duration), now
	parse := func(value string) (time.Time, error) {
		v, e := time.Parse(time.RFC3339Nano, value)
		if e != nil || v.Before(time.Unix(0, 0)) {
			return time.Time{}, fmt.Errorf("range timestamps must be RFC3339 dates on or after 1970")
		}
		return v.UTC(), nil
	}
	var err error
	_, hasFrom := q["from"]
	_, hasTo := q["to"]
	_, hasAsOf := q["as_of"]
	if hasFrom || hasTo {
		if !hasFrom || !hasTo || hasAsOf {
			err = fmt.Errorf("use both from and to, or as_of with window")
		} else {
			from, err = parse(q.Get("from"))
			if err == nil {
				to, err = parse(q.Get("to"))
			}
		}
	} else if hasAsOf {
		to, err = parse(q.Get("as_of"))
		from = to.Add(-duration)
	}
	if err == nil && (from.After(to) || to.Sub(from) > 90*24*time.Hour || from.Before(time.Unix(0, 0))) {
		err = fmt.Errorf("range must be ordered and at most 90 days")
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return store.TimeRange{}, 0, false
	}
	span := store.NewTimeRange(from, to)
	if span.From.Year() > 9999 || span.To.Year() > 9999 {
		writeError(w, http.StatusBadRequest, "rounded range exceeds supported dates")
		return store.TimeRange{}, 0, false
	}
	w.Header().Set("X-Range-From", span.From.Format(time.RFC3339))
	w.Header().Set("X-Range-To", span.To.Format(time.RFC3339))
	w.Header().Set("X-Range-Resolution-Seconds", "60")
	return span, bucket, true
}
