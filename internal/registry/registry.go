package registry

import (
	"context"
	"errors"
	"fmt"

	"endlessh-dashboard/internal/store"
)

// Service is the only path through which machines are created or changed, so
// validation cannot be bypassed by a second code path.
type Service struct {
	store     *store.Store
	validator *Validator
}

func NewService(dataStore *store.Store, validator *Validator) *Service {
	return &Service{store: dataStore, validator: validator}
}

func (s *Service) Validator() *Validator {
	return s.validator
}

func (s *Service) List(ctx context.Context) ([]store.Machine, error) {
	return s.store.ListMachines(ctx)
}

func (s *Service) ListEnabled(ctx context.Context) ([]store.Machine, error) {
	return s.store.ListEnabledMachines(ctx)
}

func (s *Service) Get(ctx context.Context, id int64) (store.Machine, error) {
	return s.store.GetMachine(ctx, id)
}

func (s *Service) Create(ctx context.Context, input MachineInput) (store.Machine, error) {
	if err := s.checkShape(&input); err != nil {
		return store.Machine{}, err
	}
	if _, err := s.validator.ResolveTarget(ctx, input.Host); err != nil {
		return store.Machine{}, err
	}
	colour := input.Colour
	if colour == "" {
		chosen, err := s.freeColour(ctx)
		if err != nil {
			return store.Machine{}, err
		}
		colour = chosen
	}
	machine, err := s.store.CreateMachine(ctx, store.Machine{
		Name:        input.Name,
		Host:        input.Host,
		Port:        input.Port,
		MetricsPath: input.MetricsPath,
		GroupLabel:  input.GroupLabel,
		Enabled:     input.Enabled,
		Colour:      colour,
	})
	if errors.Is(err, store.ErrDuplicateMachineName) {
		return store.Machine{}, invalid("name", "a machine named %q already exists", input.Name)
	}
	return machine, err
}

// freeColour picks a colour for a machine registered without one: the lowest
// slot nobody is using, or — once every slot is taken — the least used, so the
// sixteenth machine repeats a colour instead of being given none.
func (s *Service) freeColour(ctx context.Context) (string, error) {
	used, err := s.store.UsedColours(ctx)
	if err != nil {
		return "", err
	}
	best, fewest := "", -1
	for slot := 1; slot <= PaletteSize; slot++ {
		colour := fmt.Sprintf("s-%d", slot)
		count := used[colour]
		if count == 0 {
			return colour, nil
		}
		if fewest < 0 || count < fewest {
			best, fewest = colour, count
		}
	}
	return best, nil
}

func (s *Service) Update(ctx context.Context, id int64, input MachineInput) (store.Machine, error) {
	existing, err := s.store.GetMachine(ctx, id)
	if err != nil {
		return store.Machine{}, err
	}
	if err := s.checkShape(&input); err != nil {
		return store.Machine{}, err
	}

	// Resolving the host reaches the network and applies the address policy. It
	// is worth doing when the edit changes where the scraper would connect, or
	// brings a paused machine back into the rotation. It is not worth doing for
	// a rename or a colour: the poller resolves the host again before every
	// single scrape and dials the address it got, so nothing here is the thing
	// keeping a blocked target from being reached — while running it on every
	// edit meant a machine whose host had gone away could not even be turned
	// off, only deleted, taking its history with it.
	targetChanged := input.Host != existing.Host ||
		input.Port != existing.Port ||
		input.MetricsPath != existing.MetricsPath
	returningToService := input.Enabled && !existing.Enabled
	if targetChanged || returningToService {
		if _, err := s.validator.ResolveTarget(ctx, input.Host); err != nil {
			return store.Machine{}, err
		}
	}

	existing.Name = input.Name
	existing.Host = input.Host
	existing.Port = input.Port
	existing.MetricsPath = input.MetricsPath
	existing.GroupLabel = input.GroupLabel
	existing.Enabled = input.Enabled
	// Only when one was sent. An empty colour means "not specified", so a
	// caller editing the host or the port does not silently wipe the machine's
	// colour by leaving the field out.
	if input.Colour != "" {
		existing.Colour = input.Colour
	}

	if err := s.store.UpdateMachine(ctx, existing); err != nil {
		if errors.Is(err, store.ErrDuplicateMachineName) {
			return store.Machine{}, invalid("name", "a machine named %q already exists", input.Name)
		}
		return store.Machine{}, err
	}
	return s.store.GetMachine(ctx, id)
}

// Reorder records the sidebar order. It is deliberately thin — there is nothing
// to validate that the store does not already handle, and no scrape target is
// being changed — but it keeps the handler talking to one service rather than
// reaching past it into the store for this one call.
func (s *Service) Reorder(ctx context.Context, machineIDs []int64) error {
	return s.store.SetMachineOrder(ctx, machineIDs)
}

func (s *Service) Delete(ctx context.Context, id int64) error {
	return s.store.DeleteMachine(ctx, id)
}

// checkShape normalises the input and validates everything that can be decided
// without touching the network. Resolving the target is deliberately not part of
// it: the two are needed at different moments, and keeping them apart is what
// lets an edit that does not move the target skip a lookup it does not need.
func (s *Service) checkShape(input *MachineInput) error {
	input.Normalize()
	return s.validator.ValidateSyntax(*input)
}
