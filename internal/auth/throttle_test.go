package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestThrottleFailureStateNeverExceedsCap(t *testing.T) {
	service := NewService(nil, time.Hour)
	now := time.Now()
	for i := 0; i < maxTrackedClients; i++ {
		service.attempts[fmt.Sprintf("locked-%d", i)] = &attemptRecord{firstFailed: now, lockedUntil: now.Add(lockoutDuration)}
	}
	service.recordFailure("overflow")
	if len(service.attempts) > maxTrackedClients {
		t.Fatalf("throttle state grew to %d entries; limit is %d", len(service.attempts), maxTrackedClients)
	}
	for i := 0; i < maxTrackedClients; i++ {
		if service.attempts[fmt.Sprintf("locked-%d", i)] == nil {
			t.Fatal("key churn removed an active lockout")
		}
	}
}

func TestThrottleCapacityRejectsChurnWithoutEvictingLiveHistory(t *testing.T) {
	for _, locked := range []bool{false, true} {
		t.Run(fmt.Sprintf("locked=%v", locked), func(t *testing.T) {
			service := NewService(nil, time.Hour)
			now := time.Now()
			for i := 0; i < maxTrackedClients; i++ {
				record := &attemptRecord{firstFailed: now, count: 1}
				if locked {
					record.lockedUntil = now.Add(lockoutDuration)
				}
				service.attempts[fmt.Sprintf("existing-%d", i)] = record
			}
			target := service.attempts["existing-0"]
			for i := 0; i < 1024; i++ {
				if err := service.admitAttempt(fmt.Sprintf("churn-%d", i)); !errors.Is(err, ErrTooManyAttempts) {
					t.Fatal("capacity admitted a new key")
				}
				if len(service.attempts) != maxTrackedClients {
					t.Fatal("capacity changed during churn")
				}
			}
			if service.attempts["existing-0"] != target || target.count != 1 {
				t.Fatal("churn erased live throttle history")
			}
			// A full-map Login must reject before touching a database or doing Argon2.
			if _, _, _, err := service.Login(context.Background(), "unknown", "bad", "another-key"); !errors.Is(err, ErrTooManyAttempts) {
				t.Fatal("full login was not cheaply rejected")
			}
		})
	}
}

func TestThrottleReclaimsExpiredButNeverReservedRecords(t *testing.T) {
	service := NewService(nil, time.Hour)
	now := time.Now()
	for i := 0; i < maxTrackedClients; i++ {
		service.attempts[fmt.Sprint(i)] = &attemptRecord{firstFailed: now, lockedUntil: now.Add(lockoutDuration)}
	}
	service.attempts["0"] = &attemptRecord{firstFailed: now.Add(-2 * loginWindow), lockedUntil: now.Add(-time.Second)}
	service.attempts["1"] = &attemptRecord{firstFailed: now.Add(-2 * loginWindow), inFlight: true}
	if err := service.admitAttempt("new"); err != nil {
		t.Fatal(err)
	}
	if len(service.attempts) != maxTrackedClients || service.attempts["0"] != nil || service.attempts["1"] == nil {
		t.Fatal("expiry reclaimed wrong records")
	}
	service.finishAttempt("new", false)
	if len(service.attempts) != maxTrackedClients-1 {
		t.Fatal("unused reservation was retained")
	}
}

func TestThrottleConcurrentAdmissionRespectsFailureThreshold(t *testing.T) {
	service, _ := newSeededService(t, time.Hour)
	service.attempts[testClientKey] = &attemptRecord{count: maxLoginAttempts - 1, firstFailed: time.Now()}
	ready, release := pauseVerification(service)
	defer release()
	var verifications atomic.Int32
	paused := service.verifyPassword
	service.verifyPassword = func(hash, password string) (bool, error) { verifications.Add(1); return paused(hash, password) }
	first := make(chan error, 1)
	go func() {
		_, _, _, err := service.Login(context.Background(), testUsername, wrongPassword, testClientKey)
		first <- err
	}()
	waitForVerification(t, ready)
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			_, _, _, err := service.Login(context.Background(), testUsername, testPassword, testClientKey)
			results <- err
		}()
	}
	for i := 0; i < 8; i++ {
		if err := waitForRotation(t, results); !errors.Is(err, ErrTooManyAttempts) {
			t.Fatal("overlapping key bypassed admission")
		}
	}
	if verifications.Load() != 1 {
		t.Fatal("overlapping requests performed extra hashes")
	}
	if _, _, _, err := service.Login(context.Background(), testUsername, testPassword, otherClientKey); err != nil {
		t.Fatal("reserved key blocked a different client")
	}
	release()
	if err := waitForRotation(t, first); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal(err)
	}
	if _, _, _, err := service.Login(context.Background(), testUsername, testPassword, testClientKey); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatal("final failure did not enforce lockout")
	}
}

func TestThrottleLegitimateLoginRecoversAfterExpiry(t *testing.T) {
	service, _ := newSeededService(t, time.Hour)
	now := time.Now()
	service.attempts[testClientKey] = &attemptRecord{firstFailed: now.Add(-2 * loginWindow), lockedUntil: now.Add(-time.Second)}
	if _, _, _, err := service.Login(context.Background(), testUsername, testPassword, testClientKey); err != nil {
		t.Fatal("expired client did not recover")
	}
	if len(service.attempts) != 0 {
		t.Fatal("successful login retained throttle history")
	}
	record := attemptRecord{firstFailed: now.Add(-loginWindow), lockedUntil: now}
	if !record.staleAt(now) {
		t.Fatal("record did not expire at exact boundary")
	}
	record.inFlight = true
	if record.staleAt(now) {
		t.Fatal("active reservation expired")
	}
}

func TestThrottleReleasesAdmissionOnHashQueueAndServiceErrors(t *testing.T) {
	t.Run("hash-queue", func(t *testing.T) {
		service, _ := newSeededService(t, time.Hour)
		for i := 0; i < maxConcurrentHashes; i++ {
			service.hashingSlots <- struct{}{}
		}
		for _, known := range []bool{false, true} {
			if known {
				service.attempts[testClientKey] = &attemptRecord{count: 1, firstFailed: time.Now()}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_, _, _, err := service.Login(ctx, testUsername, testPassword, testClientKey)
			cancel()
			if !errors.Is(err, ErrBusy) {
				t.Fatal("saturated hashing queue was not busy")
			}
			record := service.attempts[testClientKey]
			if !known && record != nil {
				t.Fatal("busy queue leaked new reservation")
			}
			if known && (record == nil || record.inFlight || record.count != 1) {
				t.Fatal("busy queue changed failure history")
			}
		}
		for i := 0; i < maxConcurrentHashes; i++ {
			<-service.hashingSlots
		}
		if _, _, _, err := service.Login(context.Background(), testUsername, testPassword, testClientKey); err != nil {
			t.Fatal("busy queue did not release admission")
		}
	})
	t.Run("verifier", func(t *testing.T) {
		service, _ := newSeededService(t, time.Hour)
		service.verifyPassword = func(string, string) (bool, error) { return false, ErrInvalidHash }
		if _, _, _, err := service.Login(context.Background(), testUsername, testPassword, testClientKey); !errors.Is(err, ErrInvalidHash) {
			t.Fatal("verifier error lost")
		}
		if len(service.attempts) != 0 {
			t.Fatal("verifier error leaked admission")
		}
	})
	t.Run("database", func(t *testing.T) {
		service, db := newSeededService(t, time.Hour)
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := service.Login(context.Background(), testUsername, testPassword, testClientKey); err == nil {
			t.Fatal("closed database login succeeded")
		}
		if len(service.attempts) != 0 {
			t.Fatal("database failure leaked admission")
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		service, _ := newSeededService(t, time.Hour)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, _, _, err := service.Login(ctx, testUsername, testPassword, testClientKey); err == nil {
			t.Fatal("cancelled login succeeded")
		}
		if len(service.attempts) != 0 {
			t.Fatal("cancelled login leaked admission")
		}
	})
}

func BenchmarkThrottleFullLockedCapacity(b *testing.B) {
	service := NewService(nil, time.Hour)
	now := time.Now()
	for i := 0; i < maxTrackedClients; i++ {
		service.attempts[fmt.Sprint(i)] = &attemptRecord{firstFailed: now, lockedUntil: now.Add(lockoutDuration)}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := service.admitAttempt("overflow"); err != ErrTooManyAttempts {
			b.Fatal(err)
		}
	}
}

func TestThrottleConcurrentDistinctKeysCannotOverbookCapacity(t *testing.T) {
	service := NewService(nil, time.Hour)
	now := time.Now()
	const free = 8
	for i := 0; i < maxTrackedClients-free; i++ {
		service.attempts[fmt.Sprint(i)] = &attemptRecord{firstFailed: now, lockedUntil: now.Add(lockoutDuration)}
	}
	admitted := make(chan string, 64)
	errs := make(chan error, 64)
	var workers sync.WaitGroup
	for i := 0; i < 64; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			key := fmt.Sprintf("parallel-%d", i)
			err := service.admitAttempt(key)
			if err == nil {
				admitted <- key
			} else {
				errs <- err
			}
		}(i)
	}
	workers.Wait()
	close(admitted)
	close(errs)
	if len(service.attempts) != maxTrackedClients || len(admitted) != free {
		t.Fatalf("capacity overbooked or underused: state=%d admissions=%d", len(service.attempts), len(admitted))
	}
	for err := range errs {
		if !errors.Is(err, ErrTooManyAttempts) {
			t.Fatal(err)
		}
	}
	for key := range admitted {
		service.finishAttempt(key, false)
	}
	if len(service.attempts) != maxTrackedClients-free {
		t.Fatal("concurrent reservations leaked")
	}
}
