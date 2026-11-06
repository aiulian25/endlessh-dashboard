package scrape

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"endlessh-dashboard/internal/store"
)

func generationMetrics(value string) string {
	return "endlessh_sent_bytes_total{local_port=\"22\"} " + value + "\nendlessh_client_open_count{ip=\"192.0.2.1\",local_port=\"22\"} " + value + "\n"
}

func TestDelayedScrapesCannotCrossMachineChanges(t *testing.T) {
	for _, action := range []string{"endpoint", "disable", "reenable", "delete"} {
		for _, status := range []int{200, 500} {
			t.Run(action+http.StatusText(status), func(t *testing.T) {
				db := newTestStore(t)
				p := newTestPoller(t, db)
				ctx := context.Background()
				p.timeout = 5 * time.Second
				p.httpClient.Timeout = 5 * time.Second
				m, err := db.CreateMachine(ctx, store.Machine{Name: "fenced", Host: "127.0.0.1", Port: 2112, MetricsPath: "/metrics", Enabled: true})
				if err != nil {
					t.Fatal(err)
				}
				seed, err := Parse(strings.NewReader(generationMetrics("10")))
				if err != nil {
					t.Fatal(err)
				}
				at := time.Now().Add(-time.Minute)
				if err = p.applySnapshot(ctx, m, at, seed); err != nil {
					t.Fatal(err)
				}
				if err = db.RecordScrapeSuccess(ctx, m.ID, at, m.TargetGeneration); err != nil {
					t.Fatal(err)
				}
				before := readTotals(t, db, m.ID)
				attack := readAttacker(t, db, m.ID, "192.0.2.1")
				entered := make(chan struct{})
				release := make(chan struct{})
				done := make(chan struct{})
				p.httpClient.Transport = limitTransport(func(r *http.Request) (*http.Response, error) {
					close(entered)
					select {
					case <-release:
					case <-r.Context().Done():
						return nil, r.Context().Err()
					}
					return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(strings.NewReader(generationMetrics("999"))), Header: http.Header{}}, nil
				})
				go func() { defer close(done); p.pollOne(ctx, m) }()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("request never started")
				}
				updated := m
				switch action {
				case "endpoint":
					updated.MetricsPath = "/replacement"
					err = db.UpdateMachine(ctx, updated)
				case "disable", "reenable":
					updated.Enabled = false
					err = db.UpdateMachine(ctx, updated)
					if err == nil && action == "reenable" {
						updated.Enabled = true
						err = db.UpdateMachine(ctx, updated)
					}
				case "delete":
					err = db.DeleteMachine(ctx, m.ID)
				}
				close(release)
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("scrape did not stop")
				}
				if err != nil {
					t.Fatal(err)
				}
				if action == "delete" {
					states, e := db.LoadCounterStates(ctx, m.ID)
					if e != nil || len(states) != 0 {
						t.Fatal("deleted target received orphan baselines")
					}
					return
				}
				current, e := db.GetMachine(ctx, m.ID)
				if e != nil {
					t.Fatal(e)
				}
				if current.TargetGeneration <= m.TargetGeneration {
					t.Fatal("generation did not change")
				}
				badSuccess := current.LastOKAt != nil
				if action != "endpoint" {
					badSuccess = current.LastOKAt == nil || !current.LastOKAt.Equal(time.Unix(at.Unix(), 0))
				}
				if badSuccess || current.ConsecutiveFailures != 0 || current.LastError != "" {
					t.Fatalf("old response changed health: %+v", current)
				}
				if readTotals(t, db, m.ID) != before || readAttacker(t, db, m.ID, "192.0.2.1") != attack {
					t.Fatal("old response changed history")
				}
				if action != "endpoint" {
					return
				}
				if current.TargetChangedAt == nil {
					t.Fatal("endpoint boundary not recorded")
				}
				if !p.due(current.ID, current.TargetGeneration) {
					t.Fatal("old result delayed new target")
				}
				value := "1000"
				p.httpClient.Transport = limitTransport(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(generationMetrics(value))), Header: http.Header{}}, nil
				})
				p.pollOne(ctx, current)
				if readTotals(t, db, m.ID) != before || readAttacker(t, db, m.ID, "192.0.2.1").Connections != attack.Connections {
					t.Fatal("replacement imported lifetime counters")
				}
				value = "1010"
				p.pollOne(ctx, current)
				if got := readTotals(t, db, m.ID).BytesSent; got != before.BytesSent+10 {
					t.Fatalf("new growth = %d", got)
				}
				// A fresh poller still rejects an old generation using the durable fence.
				restarted := newTestPoller(t, db)
				if err := restarted.applySnapshot(ctx, m, time.Now(), seed); !errors.Is(err, store.ErrObsoleteScrape) {
					t.Fatalf("old generation after restart = %v", err)
				}
			})
		}
	}
}

func TestDisplayEditsAndOutOfOrderSamples(t *testing.T) {
	db := newTestStore(t)
	p := newTestPoller(t, db)
	ctx := context.Background()
	m, err := db.CreateMachine(ctx, store.Machine{Name: "ordered", Host: "127.0.0.1", Port: 2112, MetricsPath: "/metrics", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-time.Minute)
	apply := func(at time.Time, value string) error {
		s, e := Parse(strings.NewReader(generationMetrics(value)))
		if e != nil {
			t.Fatal(e)
		}
		return p.applySnapshot(ctx, m, at, s)
	}
	if err = apply(at, "10"); err != nil {
		t.Fatal(err)
	}
	states, err := db.LoadCounterStates(ctx, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	m.Name = "renamed"
	m.GroupLabel = "site"
	m.Colour = "s-2"
	if err = db.UpdateMachine(ctx, m); err != nil {
		t.Fatal(err)
	}
	current, err := db.GetMachine(ctx, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	after, err := db.LoadCounterStates(ctx, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.TargetGeneration != m.TargetGeneration || current.TargetChangedAt != nil || !reflect.DeepEqual(states, after) {
		t.Fatal("display edit reset identity")
	}
	if err = apply(at.Add(2*time.Second), "20"); err != nil {
		t.Fatal(err)
	}
	before := readTotals(t, db, m.ID)
	if err = apply(at.Add(2*time.Second), "999"); !errors.Is(err, store.ErrObsoleteScrape) {
		t.Fatalf("duplicate sample timestamp = %v", err)
	}
	if err = apply(at.Add(time.Second), "999"); !errors.Is(err, store.ErrObsoleteScrape) {
		t.Fatalf("older result = %v", err)
	}
	if !errors.Is(db.RecordScrapeFailure(ctx, m.ID, at, "late failure", m.TargetGeneration), store.ErrObsoleteScrape) {
		t.Fatal("old failure changed health")
	}
	if !errors.Is(db.RecordScrapeSuccess(ctx, m.ID, at, m.TargetGeneration), store.ErrObsoleteScrape) {
		t.Fatal("old success changed health")
	}
	if readTotals(t, db, m.ID) != before {
		t.Fatal("out-of-order result changed totals")
	}
	state, err := db.LoadScrapeState(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	delta := store.ScrapeDelta{MachineID: m.ID, TargetGeneration: m.TargetGeneration, Revision: &state.Revision, At: at.Add(3 * time.Second), Opens: 1}
	if err = db.ApplyScrape(ctx, delta); err != nil {
		t.Fatal(err)
	}
	if err = db.ApplyScrape(ctx, delta); !errors.Is(err, store.ErrObsoleteScrape) {
		t.Fatalf("stale baseline revision = %v", err)
	}
}

func TestOldResponseCannotOverwriteReplacementSuccess(t *testing.T) {
	for _, status := range []int{200, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			db := newTestStore(t)
			p := newTestPoller(t, db)
			ctx := context.Background()
			p.timeout = 5 * time.Second
			p.httpClient.Timeout = 5 * time.Second
			m, err := db.CreateMachine(ctx, store.Machine{Name: "late", Host: "127.0.0.1", Port: 2112, MetricsPath: "/metrics", Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			entered := make(chan struct{})
			release := make(chan struct{})
			done := make(chan struct{})
			p.httpClient.Transport = limitTransport(func(r *http.Request) (*http.Response, error) {
				code := 200
				if r.URL.Path == "/metrics" {
					close(entered)
					select {
					case <-release:
					case <-r.Context().Done():
						return nil, r.Context().Err()
					}
					code = status
				}
				return &http.Response{StatusCode: code, Status: http.StatusText(code), Body: io.NopCloser(strings.NewReader(generationMetrics("1000"))), Header: http.Header{}}, nil
			})
			go func() { defer close(done); p.pollOne(ctx, m) }()
			<-entered
			updated := m
			updated.MetricsPath = "/replacement"
			if err = db.UpdateMachine(ctx, updated); err != nil {
				close(release)
				<-done
				t.Fatal(err)
			}
			current, err := db.GetMachine(ctx, m.ID)
			if err != nil {
				close(release)
				<-done
				t.Fatal(err)
			}
			p.pollOne(ctx, current)
			healthy, err := db.GetMachine(ctx, m.ID)
			if err != nil {
				close(release)
				<-done
				t.Fatal(err)
			}
			states, err := db.LoadCounterStates(ctx, m.ID)
			if err != nil {
				close(release)
				<-done
				t.Fatal(err)
			}
			close(release)
			<-done
			after, err := db.GetMachine(ctx, m.ID)
			if err != nil {
				t.Fatal(err)
			}
			afterStates, err := db.LoadCounterStates(ctx, m.ID)
			if err != nil {
				t.Fatal(err)
			}
			if healthy.LastOKAt == nil || !reflect.DeepEqual(after, healthy) || !reflect.DeepEqual(states, afterStates) {
				t.Fatal("late old response changed replacement state")
			}
			if !p.due(current.ID, current.TargetGeneration) {
				t.Fatal("late old failure added retry delay")
			}
		})
	}
}
