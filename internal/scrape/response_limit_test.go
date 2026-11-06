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

type limitTransport func(*http.Request) (*http.Response, error)

func (f limitTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type trackedMetricsBody struct {
	io.Reader
	bytes  int
	closed bool
}

func (b *trackedMetricsBody) Read(p []byte) (int, error) {
	n, e := b.Reader.Read(p)
	b.bytes += n
	return n, e
}
func (b *trackedMetricsBody) Close() error { b.closed = true; return nil }

func limitSizedMetrics(size int) string {
	prefix := "endlessh_sent_bytes_total 1\n"
	return prefix + "#" + strings.Repeat("x", size-len(prefix)-2) + "\n"
}

func TestResponseLimitBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		size      int
		length    int64
		malformed bool
	}{
		{"below", maxResponseBytes - 1, -1, false},
		{"exact", maxResponseBytes, maxResponseBytes, false},
		{"one over unknown length", maxResponseBytes + 1, -1, false},
		{"one over false low length", maxResponseBytes + 1, 10, false},
		{"exact false high length", maxResponseBytes, maxResponseBytes + 100, false},
		{"malformed over limit", maxResponseBytes + 50, -1, true},
		{"malformed below limit", 100, -1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestPoller(t, newTestStore(t))
			payload := limitSizedMetrics(tc.size)
			if tc.malformed {
				payload = "bad{\n" + payload[5:]
			}
			body := &trackedMetricsBody{Reader: strings.NewReader(payload)}
			p.httpClient.Transport = limitTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: body, ContentLength: tc.length, Header: http.Header{}}, nil
			})
			snapshot, err := p.fetch(context.Background(), store.Machine{Host: "127.0.0.1", Port: 2112, MetricsPath: "/metrics"})
			if tc.size > maxResponseBytes {
				if err == nil || !strings.Contains(err.Error(), "8388608-byte limit") {
					t.Fatalf("overflow error = %v", err)
				}
				if len(snapshot.Totals) != 0 {
					t.Fatal("partial snapshot returned")
				}
			} else if tc.malformed {
				if err == nil || !strings.Contains(err.Error(), "parse metrics") {
					t.Fatalf("parse error = %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if body.bytes > maxResponseBytes+1 {
				t.Fatalf("read beyond bounded limit: %d", body.bytes)
			}
			if !body.closed {
				t.Fatal("response body not closed")
			}
		})
	}
}

func TestOversizedScrapePreservesHistoryAndProbeFails(t *testing.T) {
	db, p, endpoint, machine := newScrapeFixture(t, "normal.txt")
	ctx := context.Background()
	p.timeout = 5 * time.Second
	p.httpClient.Timeout = 5 * time.Second
	p.pollOne(ctx, machine)
	endpoint.serve(t, "second-scrape.txt")
	p.pollOne(ctx, machine)
	beforeTotals := readTotals(t, db, machine.ID)
	beforeAttacker := readAttacker(t, db, machine.ID, "45.155.205.233")
	before, err := db.LoadCounterStates(ctx, machine.ID)
	if err != nil {
		t.Fatal(err)
	}
	healthy, err := db.GetMachine(ctx, machine.ID)
	if err != nil {
		t.Fatal(err)
	}
	// This prefix is complete Prometheus text exactly at the old cut-off. The
	// following valid metric used to be silently discarded as a successful scrape.
	payload := limitSizedMetrics(maxResponseBytes) + "endlessh_client_open_count_total 999\n"
	body := []byte(payload)
	endpoint.body.Store(&body)
	// Large writes from the mock server use chunked HTTP framing.
	chunked := false
	p.httpClient.Transport = limitTransport(func(r *http.Request) (*http.Response, error) {
		response, err := http.DefaultTransport.RoundTrip(r)
		if err == nil {
			chunked = len(response.TransferEncoding) > 0 && response.TransferEncoding[0] == "chunked"
		}
		return response, err
	})
	p.pollOne(ctx, machine)
	if !chunked {
		t.Fatal("mock did not exercise chunked framing")
	}
	after, err := db.LoadCounterStates(ctx, machine.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) || readTotals(t, db, machine.ID) != beforeTotals || readAttacker(t, db, machine.ID, "45.155.205.233") != beforeAttacker {
		t.Fatal("oversized response changed history")
	}
	failed, err := db.GetMachine(ctx, machine.ID)
	if err != nil {
		t.Fatal(err)
	}
	if failed.ConsecutiveFailures != 1 || failed.LastOKAt == nil || !failed.LastOKAt.Equal(*healthy.LastOKAt) || !strings.Contains(failed.LastError, "8 MiB") {
		t.Fatalf("incorrect failure state: %+v", failed)
	}
	if _, err := p.Probe(ctx, machine.Host, machine.Port, machine.MetricsPath); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("probe error = %v", err)
	}
}

type cancelledMetricsReader struct{ ctx context.Context }

func (r cancelledMetricsReader) Read([]byte) (int, error) { <-r.ctx.Done(); return 0, r.ctx.Err() }

func TestResponseLimitCancellationClosesBody(t *testing.T) {
	for _, parentCancel := range []bool{false, true} {
		name := "deadline"
		if parentCancel {
			name = "parent cancellation"
		}
		t.Run(name, func(t *testing.T) {
			p := newTestPoller(t, newTestStore(t))
			var body *trackedMetricsBody
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p.httpClient.Transport = limitTransport(func(r *http.Request) (*http.Response, error) {
				body = &trackedMetricsBody{Reader: cancelledMetricsReader{r.Context()}}
				if parentCancel {
					cancel()
				}
				return &http.Response{StatusCode: 200, Body: body, Header: http.Header{}}, nil
			})
			_, err := p.fetch(ctx, store.Machine{Host: "127.0.0.1", Port: 2112, MetricsPath: "/metrics"})
			want := context.DeadlineExceeded
			if parentCancel {
				want = context.Canceled
			}
			if !errors.Is(err, want) {
				t.Fatalf("cancellation error = %v, want %v", err, want)
			}
			if body == nil || !body.closed {
				t.Fatal("cancelled response body not closed")
			}
		})
	}
}
