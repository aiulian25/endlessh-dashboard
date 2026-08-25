// Package registry owns the user-editable list of scrape targets. Because that
// list is edited at runtime rather than fixed at deploy time, every target is
// treated as untrusted input and re-validated on every add, edit and scrape.
package registry

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

const (
	MinPort           = 1
	MaxPort           = 65535
	MaxNameLength     = 64
	MaxHostLength     = 253
	MaxPathLength     = 256
	MaxGroupLength    = 64
	DefaultMetricsPat = "/metrics"
)

var (
	hostnamePattern    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$`)
	metricsPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
	namePattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]*$`)
)

// ValidationError carries a message written for the person typing into the form.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

func invalid(field, format string, args ...any) *ValidationError {
	return &ValidationError{Field: field, Message: fmt.Sprintf(format, args...)}
}

type Validator struct {
	allowlist    []*net.IPNet
	blockPrivate bool
	resolver     *net.Resolver
}

func NewValidator(allowlist []*net.IPNet, blockPrivate bool) *Validator {
	return &Validator{
		allowlist:    allowlist,
		blockPrivate: blockPrivate,
		resolver:     net.DefaultResolver,
	}
}

// MachineInput is what the API accepts for a scrape target.
type MachineInput struct {
	Name        string
	Host        string
	Port        int
	MetricsPath string
	GroupLabel  string
	Enabled     bool
}

// Normalize trims the input and fills defaults before validation.
func (input *MachineInput) Normalize() {
	input.Name = strings.TrimSpace(input.Name)
	input.Host = strings.TrimSpace(strings.Trim(strings.TrimSpace(input.Host), "[]"))
	input.GroupLabel = strings.TrimSpace(input.GroupLabel)
	input.MetricsPath = strings.TrimSpace(input.MetricsPath)
	if input.MetricsPath == "" {
		input.MetricsPath = DefaultMetricsPat
	}
	if !strings.HasPrefix(input.MetricsPath, "/") {
		input.MetricsPath = "/" + input.MetricsPath
	}
}

// ValidateSyntax checks the shape of the input without touching the network.
// ValidateSyntax checks the whole record: its label fields and its target.
func (v *Validator) ValidateSyntax(input MachineInput) error {
	if input.Name == "" {
		return invalid("name", "give the machine a name")
	}
	if len(input.Name) > MaxNameLength {
		return invalid("name", "name must be %d characters or fewer", MaxNameLength)
	}
	if !namePattern.MatchString(input.Name) {
		return invalid("name", "name may use letters, numbers, spaces, dots, dashes and underscores")
	}
	if len(input.GroupLabel) > MaxGroupLength {
		return invalid("group_label", "group must be %d characters or fewer", MaxGroupLength)
	}
	return v.ValidateTarget(input)
}

// ValidateTarget checks only where the scraper would connect. The connection
// test uses this on its own, because a target is worth testing before the
// record around it has been named.
func (v *Validator) ValidateTarget(input MachineInput) error {
	if input.Host == "" {
		return invalid("host", "give the host or IP address of the endlessh-go instance")
	}
	if len(input.Host) > MaxHostLength {
		return invalid("host", "host must be %d characters or fewer", MaxHostLength)
	}
	if _, err := netip.ParseAddr(input.Host); err != nil && !hostnamePattern.MatchString(input.Host) {
		return invalid("host", "%q is not a valid hostname or IP address", input.Host)
	}
	if input.Port < MinPort || input.Port > MaxPort {
		return invalid("port", "port must be between %d and %d", MinPort, MaxPort)
	}
	if len(input.MetricsPath) > MaxPathLength {
		return invalid("metrics_path", "metrics path must be %d characters or fewer", MaxPathLength)
	}
	if !metricsPathPattern.MatchString(input.MetricsPath) {
		return invalid("metrics_path", "metrics path may only contain letters, numbers and ._~-/ characters")
	}
	if strings.Contains(input.MetricsPath, "..") {
		return invalid("metrics_path", "metrics path may not contain ..")
	}
	return nil
}

// ResolveTarget resolves the host and returns the first address the scraper is
// allowed to dial. The scraper then dials that exact address, so a DNS answer
// that changes after validation cannot redirect the request somewhere else.
func (v *Validator) ResolveTarget(ctx context.Context, host string) (netip.Addr, error) {
	if literal, err := netip.ParseAddr(host); err == nil {
		if blockErr := v.CheckAddress(literal); blockErr != nil {
			return netip.Addr{}, blockErr
		}
		return literal.Unmap(), nil
	}

	addresses, err := v.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, invalid("host", "could not resolve %q: %v", host, err)
	}
	if len(addresses) == 0 {
		return netip.Addr{}, invalid("host", "%q did not resolve to any address", host)
	}

	var firstBlocked error
	for _, address := range addresses {
		unmapped := address.Unmap()
		if blockErr := v.CheckAddress(unmapped); blockErr != nil {
			if firstBlocked == nil {
				firstBlocked = blockErr
			}
			continue
		}
		return unmapped, nil
	}
	return netip.Addr{}, firstBlocked
}

// CheckAddress applies the block list. The allowlist wins, so an operator can
// deliberately monitor a tarpit on localhost or a metadata-adjacent range.
func (v *Validator) CheckAddress(address netip.Addr) error {
	unmapped := address.Unmap()
	if v.isAllowlisted(unmapped) {
		return nil
	}
	if !unmapped.IsValid() || unmapped.IsUnspecified() {
		return invalid("host", "%s is not a routable address", address)
	}
	if unmapped.IsLoopback() {
		return invalid("host", "%s is a loopback address, which is blocked; add it to SCRAPE_ALLOWLIST_CIDRS to monitor a tarpit on this host", address)
	}
	if unmapped.IsLinkLocalUnicast() || unmapped.IsLinkLocalMulticast() {
		return invalid("host", "%s is a link-local address, which is blocked because it covers the cloud metadata service", address)
	}
	if unmapped.IsInterfaceLocalMulticast() || unmapped.IsMulticast() {
		return invalid("host", "%s is a multicast address, which cannot serve metrics", address)
	}
	if v.blockPrivate && unmapped.IsPrivate() {
		return invalid("host", "%s is a private address and SCRAPE_BLOCK_PRIVATE is on", address)
	}
	return nil
}

func (v *Validator) isAllowlisted(address netip.Addr) bool {
	if len(v.allowlist) == 0 {
		return false
	}
	candidate := net.IP(address.AsSlice())
	for _, network := range v.allowlist {
		if network.Contains(candidate) {
			return true
		}
	}
	return false
}
