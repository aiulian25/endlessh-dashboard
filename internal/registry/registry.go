package registry

import (
	"context"
	"errors"

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
	if err := s.check(ctx, &input); err != nil {
		return store.Machine{}, err
	}
	machine, err := s.store.CreateMachine(ctx, store.Machine{
		Name:        input.Name,
		Host:        input.Host,
		Port:        input.Port,
		MetricsPath: input.MetricsPath,
		GroupLabel:  input.GroupLabel,
		Enabled:     input.Enabled,
	})
	if errors.Is(err, store.ErrDuplicateMachineName) {
		return store.Machine{}, invalid("name", "a machine named %q already exists", input.Name)
	}
	return machine, err
}

func (s *Service) Update(ctx context.Context, id int64, input MachineInput) (store.Machine, error) {
	existing, err := s.store.GetMachine(ctx, id)
	if err != nil {
		return store.Machine{}, err
	}
	if err := s.check(ctx, &input); err != nil {
		return store.Machine{}, err
	}

	existing.Name = input.Name
	existing.Host = input.Host
	existing.Port = input.Port
	existing.MetricsPath = input.MetricsPath
	existing.GroupLabel = input.GroupLabel
	existing.Enabled = input.Enabled

	if err := s.store.UpdateMachine(ctx, existing); err != nil {
		if errors.Is(err, store.ErrDuplicateMachineName) {
			return store.Machine{}, invalid("name", "a machine named %q already exists", input.Name)
		}
		return store.Machine{}, err
	}
	return existing, nil
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

// check runs both halves of validation: shape first, then the network-level
// address rules. Re-running this on every edit is the point — a machine that
// was fine yesterday may point somewhere blocked today.
func (s *Service) check(ctx context.Context, input *MachineInput) error {
	input.Normalize()
	if err := s.validator.ValidateSyntax(*input); err != nil {
		return err
	}
	if _, err := s.validator.ResolveTarget(ctx, input.Host); err != nil {
		return err
	}
	return nil
}
