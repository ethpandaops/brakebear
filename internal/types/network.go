package types

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// ExcludeNetwork represents a network exclusion configuration
type ExcludeNetwork struct {
	Type       string
	CIDRConfig *CIDRConfig
	DNSConfig  *DNSConfig
}

// CIDRConfig contains CIDR range configurations
type CIDRConfig struct {
	Ranges []string
}

// DNSConfig contains DNS resolution configuration
type DNSConfig struct {
	Names         []string      // List of hostnames to resolve
	CheckInterval time.Duration // How often to check DNS for changes
}

// DNSResolver interface for DNS resolution operations
type DNSResolver interface {
	Start(ctx context.Context) error
	Stop() error
	ResolveHostnames(hostnames []string) ([]string, error)
	GetCachedIPs(hostname string) ([]string, bool)
}

// ParseCIDR parses and validates a CIDR string
func ParseCIDR(cidr string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR format '%s': %w", cidr, err)
	}
	return ipNet, nil
}

// ValidateCIDRRange validates a CIDR range string
func ValidateCIDRRange(cidr string) error {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return errors.New("CIDR range cannot be empty")
	}

	_, err := ParseCIDR(cidr)
	return err
}

// GetDefaultPrivateRanges returns RFC1918 private network ranges
func GetDefaultPrivateRanges() []string {
	return []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
}

// ParseExcludeNetworks processes exclusion config and applies defaults
func ParseExcludeNetworks(excludes []ExcludeNetwork, resolver DNSResolver) ([]string, error) {
	var ranges []string

	for _, exclude := range excludes {
		excludeRanges, err := processExclude(exclude, resolver)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, excludeRanges...)
	}

	return ranges, nil
}

// processExclude handles a single exclude configuration
func processExclude(exclude ExcludeNetwork, resolver DNSResolver) ([]string, error) {
	switch exclude.Type {
	case "cidr":
		return processCIDRExclude(exclude.CIDRConfig)
	case "private-ranges":
		return GetDefaultPrivateRanges(), nil
	case "dns":
		return processDNSExclude(exclude.DNSConfig, resolver)
	default:
		if exclude.Type != "" {
			return nil, fmt.Errorf("unsupported exclude network type '%s', supported types: 'cidr', 'private-ranges', 'dns'", exclude.Type)
		}
		return nil, nil
	}
}

// processCIDRExclude handles CIDR-based exclusions
func processCIDRExclude(config *CIDRConfig) ([]string, error) {
	if config == nil {
		return nil, nil
	}

	ranges := make([]string, 0, len(config.Ranges))
	for _, cidr := range config.Ranges {
		if err := ValidateCIDRRange(cidr); err != nil {
			return nil, fmt.Errorf("invalid CIDR range '%s': %w", cidr, err)
		}
		ranges = append(ranges, strings.TrimSpace(cidr))
	}
	return ranges, nil
}

// processDNSExclude handles DNS-based exclusions
func processDNSExclude(config *DNSConfig, resolver DNSResolver) ([]string, error) {
	if config == nil || resolver == nil {
		return nil, nil
	}

	ips, err := resolver.ResolveHostnames(config.Names)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve DNS hostnames: %w", err)
	}

	ranges := make([]string, 0, len(ips))
	for _, ip := range ips {
		cidr := convertIPToCIDR(ip)
		if cidr != "" {
			ranges = append(ranges, cidr)
		}
	}
	return ranges, nil
}

// convertIPToCIDR converts an IP address to a CIDR range (IPv4 only for now)
func convertIPToCIDR(ip string) string {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "" // Skip invalid IPs
	}

	// Only process IPv4 addresses for now (tc u32 doesn't support IPv6 easily)
	if parsedIP.To4() != nil {
		return ip + "/32" // IPv4 address
	}
	return "" // Skip IPv6 addresses for now
}
