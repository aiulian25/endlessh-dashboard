// Package ipidentity defines the shared exporter and stored attacker identity.
package ipidentity

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
)

// Canonical rejects whitespace, missing/invalid addresses and scoped addresses.
// IPv4-mapped IPv6 is the same identity as IPv4; ordinary IPv6 is compressed.
func Canonical(value string) (string, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" {
		return "", errors.New("invalid or scoped attacker IP label")
	}
	return address.Unmap().String(), nil
}
func RawKey(metric, ip, port string) string {
	tuple, _ := json.Marshal([]string{ip, port})
	return "ip:v2:" + metric + "|" + string(tuple)
}

// NormalizeRawKey accepts the versioned per-port families used by the collector.
// Legacy collapsed keys cannot be reconstructed and are handled by migration.
func NormalizeRawKey(key string) (normalized, ip string, err error) {
	prefix, tuple, ok := strings.Cut(key, "|")
	if !ok || (prefix != "ip:v2:endlessh_client_open_count" && prefix != "ip:v2:endlessh_client_trapped_time_seconds") {
		return "", "", errors.New("unsupported raw client series")
	}
	var parts []string
	if json.Unmarshal([]byte(tuple), &parts) != nil || len(parts) != 2 {
		return "", "", errors.New("invalid raw client series tuple")
	}
	ip, err = Canonical(parts[0])
	if err != nil {
		return "", "", err
	}
	return RawKey(strings.TrimPrefix(prefix, "ip:v2:"), ip, parts[1]), ip, nil
}
