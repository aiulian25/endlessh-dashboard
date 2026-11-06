// Package metricvalue defines numeric limits shared by collection and storage.
package metricvalue

import (
	"fmt"
	"math"
)

// MaxExactInteger is the supported safe-integer ceiling for float64 counts.
const MaxExactInteger = float64(1<<53 - 1)

func Validate(value float64, integer bool) error {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return fmt.Errorf("counter must be finite and nonnegative")
	}
	if integer && (value > MaxExactInteger || math.Trunc(value) != value) {
		return fmt.Errorf("count/byte counter must be an integer at most 2^53-1")
	}
	return nil
}

func AddInt(a, b int64) (int64, error) {
	if a < 0 || b < 0 || b > math.MaxInt64-a {
		return 0, fmt.Errorf("integer counter accumulation exceeds int64 or contains negative history")
	}
	return a + b, nil
}

func AddFloat(a, b float64) (float64, error) {
	if err := Validate(a, false); err != nil {
		return 0, err
	}
	if err := Validate(b, false); err != nil {
		return 0, err
	}
	result := a + b
	if err := Validate(result, false); err != nil {
		return 0, fmt.Errorf("time counter accumulation overflow: %w", err)
	}
	return result, nil
}
