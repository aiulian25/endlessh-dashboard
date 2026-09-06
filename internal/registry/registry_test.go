package registry

import (
	"context"
	"path/filepath"
	"testing"

	"endlessh-dashboard/internal/store"
)

// blockedHost is a loopback literal, which the default validator refuses. It
// stands in for a target that has stopped being reachable or allowed since it
// was registered — the DNS record retired, or the address policy tightened —
// without any of these tests touching the network: ResolveTarget answers a
// literal from the address rules alone and never asks a resolver.
const blockedHost = "127.0.0.1"

const (
	testPort        = 2112
	testMetricsPath = "/metrics"
)

func newRegistryFixture(t *testing.T) (*Service, *store.Store) {
	t.Helper()

	dataStore, err := store.Open(filepath.Join(t.TempDir(), "endlessh.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { dataStore.Close() })
	if err := dataStore.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate store: %v", err)
	}
	return NewService(dataStore, NewValidator(nil, false)), dataStore
}

// seedUnreachableMachine writes a machine straight to the store, the way one
// registered while its target was still allowed would look after the policy
// around it changed. The registry would refuse to create this now, which is the
// whole point: it exists, and the operator has to be able to manage it.
func seedUnreachableMachine(t *testing.T, dataStore *store.Store, enabled bool) store.Machine {
	t.Helper()

	machine, err := dataStore.CreateMachine(context.Background(), store.Machine{
		Name:        "retired",
		Host:        blockedHost,
		Port:        testPort,
		MetricsPath: testMetricsPath,
		Enabled:     enabled,
		Colour:      "s-1",
	})
	if err != nil {
		t.Fatalf("seed the machine: %v", err)
	}
	return machine
}

func inputFor(machine store.Machine) MachineInput {
	return MachineInput{
		Name:        machine.Name,
		Host:        machine.Host,
		Port:        machine.Port,
		MetricsPath: machine.MetricsPath,
		GroupLabel:  machine.GroupLabel,
		Enabled:     machine.Enabled,
		Colour:      machine.Colour,
	}
}

func TestUpdateCanRecolourAndPauseAMachineWhoseTargetIsGone(t *testing.T) {
	service, dataStore := newRegistryFixture(t)
	machine := seedUnreachableMachine(t, dataStore, true)

	// Neither of these asks the scraper to go anywhere. Before, both failed on
	// the target, leaving the operator with a machine they could only delete —
	// losing every attacker and every figure recorded against it.
	input := inputFor(machine)
	input.Colour = "s-7"
	input.Enabled = false

	updated, err := service.Update(context.Background(), machine.ID, input)
	if err != nil {
		t.Fatalf("recolouring and pausing a machine whose target is gone: %v", err)
	}
	if updated.Colour != "s-7" {
		t.Errorf("colour = %q, want s-7", updated.Colour)
	}
	if updated.Enabled {
		t.Error("the machine is still enabled after being paused")
	}

	stored, err := dataStore.GetMachine(context.Background(), machine.ID)
	if err != nil {
		t.Fatalf("read the machine back: %v", err)
	}
	if stored.Colour != "s-7" || stored.Enabled {
		t.Errorf("stored machine = %+v, want the new colour and paused", stored)
	}
}

func TestUpdateStillRefusesAMoveToABlockedTarget(t *testing.T) {
	service, dataStore := newRegistryFixture(t)
	machine := seedUnreachableMachine(t, dataStore, false)

	// The security half. Changing where the scraper would connect is exactly
	// the case the address rules exist for, and skipping the check here would
	// let anyone point a machine anywhere by editing rather than creating.
	cases := []struct {
		name   string
		adjust func(*MachineInput)
	}{
		{name: "a different host", adjust: func(input *MachineInput) { input.Host = "169.254.169.254" }},
		{name: "a different port", adjust: func(input *MachineInput) { input.Port = 9999 }},
		{name: "a different metrics path", adjust: func(input *MachineInput) { input.MetricsPath = "/other" }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			input := inputFor(machine)
			testCase.adjust(&input)
			if _, err := service.Update(context.Background(), machine.ID, input); err == nil {
				t.Fatalf("changing %s was accepted without re-checking the target", testCase.name)
			}
		})
	}
}

func TestUpdateRechecksTheTargetWhenAPausedMachineIsResumed(t *testing.T) {
	service, dataStore := newRegistryFixture(t)
	machine := seedUnreachableMachine(t, dataStore, false)

	// Putting a machine back into the rotation is asking the scraper to start
	// reaching for it again, so this is the one edit that does not move the
	// target and still has to prove it.
	input := inputFor(machine)
	input.Enabled = true

	if _, err := service.Update(context.Background(), machine.ID, input); err == nil {
		t.Fatal("a paused machine was resumed onto a target that is not allowed")
	}

	stored, err := dataStore.GetMachine(context.Background(), machine.ID)
	if err != nil {
		t.Fatalf("read the machine back: %v", err)
	}
	if stored.Enabled {
		t.Error("the machine was enabled despite the update being refused")
	}
}

func TestUpdateStillValidatesShapeWhateverTheTarget(t *testing.T) {
	service, dataStore := newRegistryFixture(t)
	machine := seedUnreachableMachine(t, dataStore, false)

	// Skipping the lookup must not mean skipping validation. These never touched
	// the network to begin with and are refused as they always were.
	cases := []struct {
		name   string
		adjust func(*MachineInput)
	}{
		{name: "an empty name", adjust: func(input *MachineInput) { input.Name = "" }},
		{name: "a colour outside the palette", adjust: func(input *MachineInput) { input.Colour = "s-99" }},
		{name: "a traversing metrics path", adjust: func(input *MachineInput) { input.MetricsPath = "/../etc" }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			input := inputFor(machine)
			testCase.adjust(&input)
			if _, err := service.Update(context.Background(), machine.ID, input); err == nil {
				t.Fatalf("%s was accepted", testCase.name)
			}
		})
	}
}

func TestCreateStillResolvesTheTarget(t *testing.T) {
	service, _ := newRegistryFixture(t)

	// Creating is unchanged: there is no existing target to compare against, so
	// the address is always checked before a machine is registered at all.
	_, err := service.Create(context.Background(), MachineInput{
		Name:        "new",
		Host:        blockedHost,
		Port:        testPort,
		MetricsPath: testMetricsPath,
		Enabled:     true,
	})
	if err == nil {
		t.Fatal("a machine on a blocked target was registered")
	}
}
