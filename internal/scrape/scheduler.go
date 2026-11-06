package scrape

import (
	"context"
	"sync"
	"time"

	"endlessh-dashboard/internal/store"
)

func (p *Poller) acquireWork(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	select {
	case p.workSlots <- struct{}{}:
		if ctx.Err() != nil {
			p.releaseWork()
			return false
		}
		return true
	case <-ctx.Done():
		return false
	}
}
func (p *Poller) releaseWork() { <-p.workSlots }

// Run has one scheduler owner and a fixed worker pool. Unbuffered dispatch means
// queued targets retain registry metadata only, never response bodies/parsers.
func (p *Poller) Run(ctx context.Context) {
	if ctx.Err() != nil || !p.runMutex.TryLock() {
		return
	}
	defer p.runMutex.Unlock()
	p.workerBeat(true)
	defer p.workerBeat(false)
	p.pollAll(ctx)
}

type scheduledTarget struct {
	machine store.Machine
	next    time.Time
}

func (p *Poller) pollAll(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	jobs := make(chan store.Machine)
	finished := make(chan int64, p.concurrency)
	var group sync.WaitGroup
	p.mutex.Lock()
	p.scheduling = true
	p.scheduledGenerations = map[int64]int64{}
	p.mutex.Unlock()
	for i := 0; i < p.concurrency; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case target, ok := <-jobs:
					if !ok {
						return
					}
					p.pollOne(ctx, target)
					select {
					case finished <- target.ID:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	defer func() {
		cancel()
		close(jobs)
		group.Wait()
		p.mutex.Lock()
		p.scheduling = false
		p.scheduledGenerations = nil
		p.mutex.Unlock()
	}()
	targets := map[int64]scheduledTarget{}
	busy := map[int64]bool{}
	nextRefresh := time.Time{}
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		now := time.Now()
		p.workerBeat(true)
		if !now.Before(nextRefresh) {
			machines, err := p.store.ListEnabledMachines(ctx)
			nextRefresh = now.Add(p.interval)
			if err != nil {
				if ctx.Err() == nil {
					p.logger.Error("list machines for scraping", "error", err)
				}
			} else {
				targets = p.refreshTargets(targets, machines, now)
			}
		}
		// Earliest due target first; stable IDs break ties. Dispatch advances its
		// deadline, so a fast target cannot repeatedly jump ahead of waiting peers.
		for len(busy) < p.concurrency {
			id, ready, _ := p.nextTarget(targets, busy, time.Now())
			if !ready {
				break
			}
			target := targets[id]
			select {
			case jobs <- target.machine:
				busy[id] = true
				target.next = time.Now().Add(p.interval)
				targets[id] = target
			case <-ctx.Done():
				return
			}
		}
		wake := nextRefresh
		if len(busy) < p.concurrency {
			_, _, wake = p.nextTarget(targets, busy, time.Now())
		}
		if wake.IsZero() || nextRefresh.Before(wake) {
			wake = nextRefresh
		}
		wait := time.Until(wake)
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		timer.Reset(wait)
		select {
		case <-ctx.Done():
			return
		case id := <-finished:
			delete(busy, id)
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		}
	}
}

func (p *Poller) refreshTargets(old map[int64]scheduledTarget, machines []store.Machine, now time.Time) map[int64]scheduledTarget {
	result := make(map[int64]scheduledTarget, len(machines))
	allowed := make(map[int64]int64, len(machines))
	for _, m := range machines {
		target, ok := old[m.ID]
		if !ok || target.machine.TargetGeneration != m.TargetGeneration {
			target.next = now
		}
		target.machine = m
		result[m.ID] = target
		allowed[m.ID] = m.TargetGeneration
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.scheduledGenerations = allowed
	// A late completion cannot resurrect removed state: acceptGeneration checks
	// membership and generation while this scheduler owns the poller.
	for id := range p.attemptGenerations {
		if _, ok := allowed[id]; !ok {
			delete(p.attemptGenerations, id)
			delete(p.failureStreaks, id)
			delete(p.nextAttempt, id)
		}
	}
	for _, m := range machines {
		p.acceptGeneration(m.ID, m.TargetGeneration)
	}
	return result
}

func (p *Poller) nextTarget(targets map[int64]scheduledTarget, busy map[int64]bool, now time.Time) (int64, bool, time.Time) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	var chosen int64
	var earliest time.Time
	for id, target := range targets {
		if busy[id] {
			continue
		}
		due := target.next
		if retry := p.nextAttempt[id]; retry.After(due) {
			due = retry
		}
		if earliest.IsZero() || due.Before(earliest) || (due.Equal(earliest) && id < chosen) {
			chosen = id
			earliest = due
		}
	}
	return chosen, !earliest.IsZero() && !earliest.After(now), earliest
}
