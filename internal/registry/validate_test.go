package registry

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse cidr %s: %v", cidr, err)
	}
	return network
}

func mustAddr(t *testing.T, address string) netip.Addr {
	t.Helper()
	parsed, err := netip.ParseAddr(address)
	if err != nil {
		t.Fatalf("parse address %s: %v", address, err)
	}
	return parsed
}

// validationField pulls the form field out of an error so the assertions can
// prove the UI has something to highlight.
func validationField(t *testing.T, err error) string {
	t.Helper()
	var validationError *ValidationError
	if !errors.As(err, &validationError) {
		t.Fatalf("error %v is not a *ValidationError", err)
	}
	if validationError.Message == "" {
		t.Error("a validation error must carry a message for the operator")
	}
	return validationError.Field
}

func TestCheckAddressBlocksUnroutableAndInternalTargets(t *testing.T) {
	validator := NewValidator(nil, false)

	blocked := []struct {
		name    string
		address string
	}{
		{name: "IPv4 loopback", address: "127.0.0.1"},
		{name: "IPv4 loopback outside .0.1", address: "127.99.12.7"},
		{name: "IPv6 loopback", address: "::1"},
		{name: "cloud metadata service", address: "169.254.169.254"},
		{name: "IPv4 link-local", address: "169.254.10.20"},
		{name: "IPv6 link-local", address: "fe80::1"},
		{name: "IPv4 unspecified", address: "0.0.0.0"},
		{name: "IPv6 unspecified", address: "::"},
		{name: "IPv4 link-local multicast", address: "224.0.0.1"},
		{name: "IPv4 global multicast", address: "239.255.255.250"},
		{name: "IPv6 multicast", address: "ff02::1"},
		{name: "IPv4-mapped loopback", address: "::ffff:127.0.0.1"},
		{name: "IPv4-mapped metadata service", address: "::ffff:169.254.169.254"},
		{name: "IPv4-mapped unspecified", address: "::ffff:0.0.0.0"},
	}

	for _, testCase := range blocked {
		t.Run(testCase.name, func(t *testing.T) {
			err := validator.CheckAddress(mustAddr(t, testCase.address))
			if err == nil {
				t.Fatalf("CheckAddress(%s) = nil, want the address blocked", testCase.address)
			}
			if field := validationField(t, err); field != "host" {
				t.Errorf("field = %q, want %q", field, "host")
			}
		})
	}
}

// RFC1918 is deliberately allowed by default: the common deployment is a home
// lab scraping a tarpit on the LAN.
func TestCheckAddressAllowsPublicAndPrivateByDefault(t *testing.T) {
	validator := NewValidator(nil, false)

	allowed := []string{
		"93.184.216.34",
		"192.168.1.10",
		"10.0.0.5",
		"172.16.4.9",
		"2606:2800:220:1:248:1893:25c8:1946",
		"::ffff:93.184.216.34",
	}

	for _, address := range allowed {
		t.Run(address, func(t *testing.T) {
			if err := validator.CheckAddress(mustAddr(t, address)); err != nil {
				t.Errorf("CheckAddress(%s) = %v, want nil", address, err)
			}
		})
	}
}

func TestCheckAddressBlockPrivate(t *testing.T) {
	validator := NewValidator(nil, true)

	cases := []struct {
		address string
		blocked bool
	}{
		{address: "192.168.1.10", blocked: true},
		{address: "10.0.0.5", blocked: true},
		{address: "172.16.4.9", blocked: true},
		{address: "fd00::1", blocked: true},
		{address: "::ffff:192.168.1.10", blocked: true},
		{address: "93.184.216.34", blocked: false},
		{address: "2606:2800:220:1:248:1893:25c8:1946", blocked: false},
	}

	for _, testCase := range cases {
		t.Run(testCase.address, func(t *testing.T) {
			err := validator.CheckAddress(mustAddr(t, testCase.address))
			if testCase.blocked && err == nil {
				t.Fatalf("CheckAddress(%s) = nil, want blocked with SCRAPE_BLOCK_PRIVATE on", testCase.address)
			}
			if !testCase.blocked && err != nil {
				t.Fatalf("CheckAddress(%s) = %v, want nil", testCase.address, err)
			}
			if err != nil {
				if field := validationField(t, err); field != "host" {
					t.Errorf("field = %q, want %q", field, "host")
				}
			}
		})
	}
}

func TestAllowlistOverridesBlockRules(t *testing.T) {
	validator := NewValidator([]*net.IPNet{mustCIDR(t, "127.0.0.0/8")}, true)

	for _, address := range []string{"127.0.0.1", "127.4.5.6", "::ffff:127.0.0.1"} {
		t.Run("allowed/"+address, func(t *testing.T) {
			if err := validator.CheckAddress(mustAddr(t, address)); err != nil {
				t.Errorf("CheckAddress(%s) = %v, want nil: the allowlist wins", address, err)
			}
		})
	}

	// Only what the allowlist covers is unblocked.
	for _, address := range []string{"::1", "169.254.169.254", "192.168.1.10"} {
		t.Run("still blocked/"+address, func(t *testing.T) {
			if err := validator.CheckAddress(mustAddr(t, address)); err == nil {
				t.Errorf("CheckAddress(%s) = nil, want blocked: it is not in the allowlist", address)
			}
		})
	}
}

// The loopback refusal has to tell the operator how to allow it on purpose.
func TestLoopbackErrorNamesTheAllowlistSetting(t *testing.T) {
	err := NewValidator(nil, false).CheckAddress(mustAddr(t, "127.0.0.1"))
	if err == nil {
		t.Fatal("expected loopback to be blocked")
	}
	if !strings.Contains(err.Error(), "SCRAPE_ALLOWLIST_CIDRS") {
		t.Errorf("message %q should name the setting that unblocks it", err)
	}
}

func TestResolveTargetLiterals(t *testing.T) {
	validator := NewValidator(nil, false)
	ctx := context.Background()

	blocked := []string{"127.0.0.1", "::1", "169.254.169.254", "fe80::1", "0.0.0.0", "224.0.0.1", "::ffff:127.0.0.1"}
	for _, host := range blocked {
		t.Run("blocked/"+host, func(t *testing.T) {
			address, err := validator.ResolveTarget(ctx, host)
			if err == nil {
				t.Fatalf("ResolveTarget(%s) = %v, want an error", host, address)
			}
			if field := validationField(t, err); field != "host" {
				t.Errorf("field = %q, want %q", field, "host")
			}
		})
	}

	accepted := map[string]string{
		"93.184.216.34":                      "93.184.216.34",
		"192.168.1.10":                       "192.168.1.10",
		"::ffff:93.184.216.34":               "93.184.216.34",
		"2606:2800:220:1:248:1893:25c8:1946": "2606:2800:220:1:248:1893:25c8:1946",
	}
	for host, want := range accepted {
		t.Run("accepted/"+host, func(t *testing.T) {
			address, err := validator.ResolveTarget(ctx, host)
			if err != nil {
				t.Fatalf("ResolveTarget(%s) = %v, want nil", host, err)
			}
			if address.String() != want {
				t.Errorf("address = %s, want %s", address, want)
			}
			// An IPv4-mapped form must be unmapped before it is handed to the
			// dialler, so the address that was checked is the address dialled.
			if address.Is4In6() {
				t.Errorf("address %s is still IPv4-mapped", address)
			}
		})
	}
}

func TestResolveTargetWithBlockPrivate(t *testing.T) {
	validator := NewValidator(nil, true)
	if _, err := validator.ResolveTarget(context.Background(), "192.168.1.10"); err == nil {
		t.Error("ResolveTarget(192.168.1.10) = nil, want blocked with SCRAPE_BLOCK_PRIVATE on")
	}
	if _, err := validator.ResolveTarget(context.Background(), "93.184.216.34"); err != nil {
		t.Errorf("ResolveTarget(93.184.216.34) = %v, want nil", err)
	}
}

func TestValidateSyntax(t *testing.T) {
	validator := NewValidator(nil, false)

	valid := MachineInput{
		Name:        "Edge tarpit 01",
		Host:        "tarpit.example.com",
		Port:        2112,
		MetricsPath: "/metrics",
		GroupLabel:  "edge",
	}

	withName := func(name string) MachineInput {
		input := valid
		input.Name = name
		return input
	}
	withHost := func(host string) MachineInput {
		input := valid
		input.Host = host
		return input
	}
	withPort := func(port int) MachineInput {
		input := valid
		input.Port = port
		return input
	}
	withPath := func(path string) MachineInput {
		input := valid
		input.MetricsPath = path
		return input
	}

	cases := []struct {
		name  string
		input MachineInput
		field string
	}{
		{name: "happy path", input: valid},
		{name: "happy path with an IPv4 literal host", input: withHost("192.168.1.10")},
		{name: "happy path with an IPv6 literal host", input: withHost("2001:db8::1")},
		{name: "happy path with a nested metrics path", input: withPath("/inner/metrics-v2")},
		{name: "happy path at the port boundaries", input: withPort(MaxPort)},

		{name: "empty name", input: withName(""), field: "name"},
		{name: "whitespace-only name", input: withName("   "), field: "name"},
		{name: "overlong name", input: withName(strings.Repeat("a", MaxNameLength+1)), field: "name"},
		{name: "name with a control character", input: withName("edge\ntarpit"), field: "name"},
		{name: "name starting with punctuation", input: withName("-edge"), field: "name"},

		{name: "empty host", input: withHost(""), field: "host"},
		{name: "overlong host", input: withHost(strings.Repeat("a", MaxHostLength+1)), field: "host"},
		{name: "host with a space", input: withHost("not a host"), field: "host"},
		{name: "host with a scheme", input: withHost("http://tarpit.example.com"), field: "host"},
		{name: "host with a port", input: withHost("tarpit.example.com:2112"), field: "host"},
		{name: "host with an underscore", input: withHost("tar_pit.example.com"), field: "host"},

		{name: "port zero", input: withPort(0), field: "port"},
		{name: "negative port", input: withPort(-1), field: "port"},
		{name: "port above the 16-bit range", input: withPort(70000), field: "port"},

		{name: "metrics path traversal", input: withPath("/../../etc/passwd"), field: "metrics_path"},
		{name: "metrics path with a bare ..", input: withPath("/metrics/.."), field: "metrics_path"},
		{name: "metrics path with a scheme", input: withPath("http://evil.example/metrics"), field: "metrics_path"},
		{name: "metrics path with a query string", input: withPath("/metrics?target=x"), field: "metrics_path"},
		{name: "overlong metrics path", input: withPath("/" + strings.Repeat("m", MaxPathLength)), field: "metrics_path"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := validator.ValidateSyntax(testCase.input)
			if testCase.field == "" {
				if err != nil {
					t.Fatalf("ValidateSyntax(%+v) = %v, want nil", testCase.input, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateSyntax(%+v) = nil, want a %s error", testCase.input, testCase.field)
			}
			if field := validationField(t, err); field != testCase.field {
				t.Errorf("field = %q, want %q", field, testCase.field)
			}
		})
	}
}

func TestValidateSyntaxOverlongGroupLabel(t *testing.T) {
	input := MachineInput{
		Name:        "edge",
		Host:        "tarpit.example.com",
		Port:        2112,
		MetricsPath: "/metrics",
		GroupLabel:  strings.Repeat("g", MaxGroupLength+1),
	}
	err := NewValidator(nil, false).ValidateSyntax(input)
	if err == nil {
		t.Fatal("ValidateSyntax = nil, want a group_label error")
	}
	if field := validationField(t, err); field != "group_label" {
		t.Errorf("field = %q, want %q", field, "group_label")
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		name  string
		input MachineInput
		want  MachineInput
	}{
		{
			name:  "empty metrics path gets the default",
			input: MachineInput{Name: "edge", Host: "tarpit.example.com", Port: 2112},
			want:  MachineInput{Name: "edge", Host: "tarpit.example.com", Port: 2112, MetricsPath: DefaultMetricsPat},
		},
		{
			name:  "whitespace-only metrics path gets the default",
			input: MachineInput{Name: "edge", Host: "tarpit.example.com", MetricsPath: "   "},
			want:  MachineInput{Name: "edge", Host: "tarpit.example.com", MetricsPath: DefaultMetricsPat},
		},
		{
			name:  "missing leading slash is added",
			input: MachineInput{Name: "edge", Host: "tarpit.example.com", MetricsPath: "custom-metrics"},
			want:  MachineInput{Name: "edge", Host: "tarpit.example.com", MetricsPath: "/custom-metrics"},
		},
		{
			name:  "surrounding whitespace is trimmed everywhere",
			input: MachineInput{Name: "  edge  ", Host: "  tarpit.example.com  ", MetricsPath: "  metrics  ", GroupLabel: "  eu  "},
			want:  MachineInput{Name: "edge", Host: "tarpit.example.com", MetricsPath: "/metrics", GroupLabel: "eu"},
		},
		{
			name:  "IPv6 brackets are stripped",
			input: MachineInput{Name: "edge", Host: "[2001:db8::1]", MetricsPath: "/metrics"},
			want:  MachineInput{Name: "edge", Host: "2001:db8::1", MetricsPath: "/metrics"},
		},
		{
			name:  "padded and bracketed IPv6 is stripped",
			input: MachineInput{Name: "edge", Host: "  [::1]  ", MetricsPath: "/metrics"},
			want:  MachineInput{Name: "edge", Host: "::1", MetricsPath: "/metrics"},
		},
		{
			name:  "an already normalized input is left alone",
			input: MachineInput{Name: "edge", Host: "tarpit.example.com", Port: 2112, MetricsPath: "/metrics", GroupLabel: "eu", Enabled: true},
			want:  MachineInput{Name: "edge", Host: "tarpit.example.com", Port: 2112, MetricsPath: "/metrics", GroupLabel: "eu", Enabled: true},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			input := testCase.input
			input.Normalize()
			if input != testCase.want {
				t.Errorf("Normalize() = %+v, want %+v", input, testCase.want)
			}
		})
	}
}

// A bracketed IPv6 literal has to survive normalization all the way into the
// address check, otherwise the form rejects a legitimate host.
func TestNormalizeThenValidateAcceptsBracketedIPv6(t *testing.T) {
	input := MachineInput{Name: "edge", Host: "[2606:2800:220:1:248:1893:25c8:1946]", Port: 2112}
	input.Normalize()

	validator := NewValidator(nil, false)
	if err := validator.ValidateSyntax(input); err != nil {
		t.Fatalf("ValidateSyntax = %v, want nil", err)
	}
	address, err := validator.ResolveTarget(context.Background(), input.Host)
	if err != nil {
		t.Fatalf("ResolveTarget = %v, want nil", err)
	}
	if address.String() != "2606:2800:220:1:248:1893:25c8:1946" {
		t.Errorf("address = %s, want the bracket-free literal", address)
	}
}
