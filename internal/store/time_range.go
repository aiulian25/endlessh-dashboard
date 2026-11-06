package store

import "time"

// MinuteBoundary rounds up: stored minute-start keys selected by an exact
// timestamp predicate are precisely those in [ceil(from), ceil(to)).
func MinuteBoundary(at time.Time) time.Time {
	if at.IsZero() {
		return at
	}
	at = at.UTC()
	minute := at.Truncate(time.Minute)
	if !at.Equal(minute) {
		minute = minute.Add(time.Minute)
	}
	return minute
}

type TimeRange struct{ From, To time.Time }

func NewTimeRange(from, to time.Time) TimeRange {
	return TimeRange{MinuteBoundary(from), MinuteBoundary(to)}
}
func optionalUntil(until []time.Time) time.Time {
	if len(until) == 0 {
		return time.Time{}
	}
	return MinuteBoundary(until[0])
}
