package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type lifecycleResult struct {
	safe bool
	err  error
}

func testListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}
func awaitLifecycle(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("lifecycle fixture did not progress")
	}
}

func TestShutdownJoinsWorkersAndRequestsOnEveryExitPath(t *testing.T) {
	for _, trigger := range []string{"signal", "restore", "listener failure"} {
		t.Run(trigger, func(t *testing.T) {
			listener := testListener(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			restart := make(chan struct{}, 1)
			var mutex sync.Mutex
			events := []string{}
			record := func(s string) { mutex.Lock(); defer mutex.Unlock(); events = append(events, s) }
			workers := []backgroundWorker{}
			cancelled := make([]chan struct{}, 3)
			started := make([]chan struct{}, 3)
			release := make(chan struct{})
			var releaseWorkers sync.Once
			defer releaseWorkers.Do(func() { close(release) })
			// Each deliberately blocked tail still uses shared state after cancellation.
			for i, name := range []string{"scraper", "maintenance", "geography"} {
				started[i] = make(chan struct{})
				cancelled[i] = make(chan struct{})
				workers = append(workers, backgroundWorker{name: name, run: func(ctx context.Context) {
					close(started[i])
					<-ctx.Done()
					close(cancelled[i])
					<-release
					record(name + " exited")
				}})
			}
			requestStarted := make(chan struct{})
			releaseRequest := make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(releaseRequest) })
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(requestStarted)
				<-releaseRequest
				record("handler exited")
				w.Write([]byte("done"))
			})}
			result := make(chan lifecycleResult, 1)
			returned := make(chan struct{})
			go func() {
				safe, err := serveWithWorkers(ctx, restart, server, listener, workers, slog.New(slog.NewTextHandler(io.Discard, nil)), 2*time.Second)
				if safe {
					record("resources closed")
				}
				result <- lifecycleResult{safe, err}
				close(returned)
			}()
			for _, ch := range started {
				awaitLifecycle(t, ch)
			}
			requestDone := make(chan struct{})
			client := &http.Client{Timeout: 3 * time.Second}
			defer client.CloseIdleConnections()
			go func() {
				defer close(requestDone)
				response, err := client.Get("http://" + listener.Addr().String())
				if err == nil {
					io.Copy(io.Discard, response.Body)
					response.Body.Close()
				}
			}()
			awaitLifecycle(t, requestStarted)
			switch trigger {
			case "signal":
				cancel()
			case "restore":
				restart <- struct{}{}
			case "listener failure":
				listener.Close()
			}
			for _, ch := range cancelled {
				awaitLifecycle(t, ch)
			}
			// Closing the admission gate is part of the transition, not just cancellation.
			response, err := client.Get("http://" + listener.Addr().String())
			if err == nil {
				response.Body.Close()
				if response.StatusCode != 503 {
					t.Errorf("new request accepted while draining: %d", response.StatusCode)
				}
			}
			select {
			case <-returned:
				t.Fatal("shutdown returned before workers finished")
			default:
			}
			releaseOnce.Do(func() { close(releaseRequest) })
			awaitLifecycle(t, requestDone)
			select {
			case <-returned:
				t.Fatal("resources closed while worker tails were blocked")
			default:
			}
			// Release without double-closing the deferred cleanup channel.
			releaseWorkers.Do(func() { close(release) })
			awaitLifecycle(t, returned)
			answer := <-result
			if !answer.safe {
				t.Fatal("graceful join not safe", answer.err)
			}
			if (trigger == "listener failure") != (answer.err != nil) {
				t.Fatalf("exit cause lost: %v", answer.err)
			}
			mutex.Lock()
			defer mutex.Unlock()
			if len(events) != 5 || events[len(events)-1] != "resources closed" {
				t.Fatalf("resource order: %v", events)
			}
		})
	}
}

func TestShutdownTimeoutDoesNotAuthorizeResourceClosure(t *testing.T) {
	listener := testListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	release := make(chan struct{})
	exited := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var logs bytes.Buffer
	result := make(chan lifecycleResult, 1)
	go func() {
		safe, err := serveWithWorkers(ctx, nil, &http.Server{Handler: http.NotFoundHandler()}, listener, []backgroundWorker{{name: "blocked filesystem", run: func(ctx context.Context) { close(entered); <-ctx.Done(); <-release; close(exited) }}}, slog.New(slog.NewTextHandler(&logs, nil)), 40*time.Millisecond)
		result <- lifecycleResult{safe, err}
	}()
	awaitLifecycle(t, entered)
	start := time.Now()
	cancel()
	var answer lifecycleResult
	select {
	case answer = <-result:
	case <-time.After(time.Second):
		t.Fatal("shutdown ignored its deadline")
	}
	if answer.safe || !errors.Is(answer.err, context.DeadlineExceeded) {
		t.Fatalf("forced exit reported graceful: %+v", answer)
	}
	if time.Since(start) > time.Second || !strings.Contains(logs.String(), "blocked filesystem") || !strings.Contains(logs.String(), "without closing shared resources") {
		t.Fatalf("timeout not explicit: %s", logs.String())
	}
	once.Do(func() { close(release) })
	awaitLifecycle(t, exited)
}

func TestAlreadyCancelledStartupStartsNoWorkers(t *testing.T) {
	listener := testListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	safe, err := serveWithWorkers(ctx, nil, &http.Server{}, listener, []backgroundWorker{{name: "must not run", run: func(context.Context) { t.Error("started after cancellation") }}}, slog.Default(), time.Second)
	if !safe || err != nil {
		t.Fatal(safe, err)
	}
}

func TestDrainingRejectsRequestsOnExistingConnections(t *testing.T) {
	calls := 0
	drain := &requestDrain{handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ })}
	drain.stop()
	r := httptest.NewRecorder()
	drain.ServeHTTP(r, httptest.NewRequest(http.MethodPost, "/api/machines", strings.NewReader(`{}`)))
	if r.Code != 503 || r.Header().Get("Connection") != "close" || calls != 0 {
		t.Fatalf("new mutation admitted during drain: %d %d", r.Code, calls)
	}
}

func TestShutdownTimeoutIncludesUnfinishedHandlers(t *testing.T) {
	listener := testListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	server := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(entered); <-release })}
	var logs bytes.Buffer
	result := make(chan lifecycleResult, 1)
	go func() {
		safe, err := serveWithWorkers(ctx, nil, server, listener, nil, slog.New(slog.NewTextHandler(&logs, nil)), 40*time.Millisecond)
		result <- lifecycleResult{safe, err}
	}()
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		client := &http.Client{Timeout: time.Second}
		response, err := client.Get("http://" + listener.Addr().String())
		if err == nil {
			response.Body.Close()
		}
		client.CloseIdleConnections()
	}()
	awaitLifecycle(t, entered)
	cancel()
	select {
	case answer := <-result:
		if answer.safe || !errors.Is(answer.err, context.DeadlineExceeded) || !strings.Contains(logs.String(), "HTTP handlers pending: true") {
			t.Fatalf("unsafe timeout: %+v %s", answer, logs.String())
		}
	case <-time.After(time.Second):
		t.Fatal("handler blocked the shutdown deadline")
	}
	once.Do(func() { close(release) })
	awaitLifecycle(t, requestDone)
}
