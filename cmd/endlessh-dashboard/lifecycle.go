package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type backgroundWorker struct {
	name string
	run  func(context.Context)
}

// requestDrain rejects new requests, including requests on existing keep-alive
// connections, before workers are cancelled. Admitted handlers must also finish
// before it is safe to close their shared database and resolvers.
type requestDrain struct {
	handler  http.Handler
	mutex    sync.Mutex
	draining bool
	requests sync.WaitGroup
}

func (d *requestDrain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mutex.Lock()
	if d.draining {
		d.mutex.Unlock()
		w.Header().Set("Connection", "close")
		http.Error(w, "dashboard shutting down", http.StatusServiceUnavailable)
		return
	}
	d.requests.Add(1)
	d.mutex.Unlock()
	defer d.requests.Done()
	d.handler.ServeHTTP(w, r)
}
func (d *requestDrain) stop() { d.mutex.Lock(); d.draining = true; d.mutex.Unlock() }

// serveWithWorkers owns every goroutine that can use shared resources. The
// returned bool authorizes resource closure only after handlers and workers exit.
// A timeout is fatal: main exits without closing resources under unfinished work.
func serveWithWorkers(ctx context.Context, restart <-chan struct{}, server *http.Server, listener net.Listener, workers []backgroundWorker, logger *slog.Logger, grace time.Duration) (bool, error) {
	if ctx.Err() != nil {
		listener.Close()
		return true, nil
	}
	drain := &requestDrain{handler: server.Handler}
	server.Handler = drain
	workerCtx, cancelWorkers := context.WithCancel(context.Background())
	defer cancelWorkers()
	var group sync.WaitGroup
	exits := make([]chan struct{}, len(workers))
	for i, worker := range workers {
		exits[i] = make(chan struct{})
		group.Add(1)
		go func(worker backgroundWorker, done chan struct{}) {
			defer group.Done()
			defer close(done)
			if workerCtx.Err() == nil {
				worker.run(workerCtx)
			}
		}(worker, exits[i])
	}
	workersDone := make(chan struct{})
	go func() { group.Wait(); close(workersDone) }()
	serveResult := make(chan error, 1)
	serveDone := make(chan struct{})
	go func() { defer close(serveDone); serveResult <- server.Serve(listener) }()
	var cause error
	select {
	case err := <-serveResult:
		cause = fmt.Errorf("HTTP listener stopped: %w", err)
	case <-restart:
		logger.Info("restarting to apply a restore")
	case <-ctx.Done():
		logger.Info("shutting down")
	}
	// One shared deadline covers HTTP draining and worker completion, concurrently.
	shutdownCtx, cancelDeadline := context.WithTimeout(context.Background(), grace)
	defer cancelDeadline()
	drain.stop()
	server.SetKeepAlivesEnabled(false)
	listener.Close()
	cancelWorkers()
	shutdownDone := make(chan struct{})
	var shutdownErr error
	go func() { defer close(shutdownDone); shutdownErr = server.Shutdown(shutdownCtx) }()
	requestsDone := make(chan struct{})
	go func() { drain.requests.Wait(); close(requestsDone) }()
	allDone := make(chan struct{})
	go func() { <-workersDone; <-requestsDone; <-serveDone; <-shutdownDone; close(allDone) }()
	select {
	case <-allDone:
		if shutdownErr != nil {
			logger.Error("HTTP shutdown failed", "error", shutdownErr)
		}
		logger.Info("background workers and HTTP handlers stopped")
		return true, errors.Join(cause, shutdownErr)
	case <-shutdownCtx.Done():
		// Prefer a completed join when the deadline and completion race.
		select {
		case <-allDone:
			return true, errors.Join(cause, shutdownErr)
		default:
		}
		pending := []string{}
		for i, done := range exits {
			select {
			case <-done:
			default:
				pending = append(pending, workers[i].name)
			}
		}
		requestsPending := true
		select {
		case <-requestsDone:
			requestsPending = false
		default:
		}
		names := strings.Join(pending, ", ")
		if names == "" {
			names = "none"
		}
		err := fmt.Errorf("shutdown timed out after %s (workers pending: %s; HTTP handlers pending: %t); shared resources left open for process exit: %w", grace, names, requestsPending, shutdownCtx.Err())
		logger.Error("shutdown timed out; forcing process exit without closing shared resources", "error", err)
		return false, errors.Join(cause, err)
	}
}
