package types

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ExcludeNetwork represents a network exclusion configuration
type ExcludeNetwork struct {
	Type                string
	CIDRConfig          *CIDRConfig
	DNSConfig           *DNSConfig
	PortConfig          *PortConfig
	DockerNetworkConfig *DockerNetworkConfig
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

// PortConfig contains port exclusion configuration
type PortConfig struct {
	TCP []string `json:"tcp,omitempty"`
	UDP []string `json:"udp,omitempty"`
}

// DockerNetworkConfig contains Docker network exclusion configuration
type DockerNetworkConfig struct {
	Names []string // Network names to exclude, ["*"] for all bridge networks
}

// PortRange represents a range of ports
type PortRange struct {
	Start int
	End   int
}

// PortSpec represents a single port specification
type PortSpec struct {
	Port     int
	Protocol string // "tcp", "udp"
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
	case "private-networks":
		return GetDefaultPrivateRanges(), nil
	case "dns":
		return processDNSExclude(exclude.DNSConfig, resolver)
	case "ports":
		// Port exclusions don't return CIDR ranges - they're handled separately in TC layer
		return nil, nil
	case "docker-networks":
		// Docker network exclusions return empty - handled dynamically at service layer
		return nil, nil
	default:
		if exclude.Type != "" {
			return nil, fmt.Errorf("unsupported exclude network type '%s', supported types: 'cidr', 'private-networks', 'dns', 'ports', 'docker-networks'",
				exclude.Type)
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

// ParsePortConfig parses a PortConfig into a list of PortSpec entries
func ParsePortConfig(config *PortConfig) ([]PortSpec, error) {
	if config == nil {
		return nil, nil
	}

	var specs []PortSpec

	// Parse TCP ports
	for _, portStr := range config.TCP {
		portRanges, err := ParsePortString(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid TCP port specification '%s': %w", portStr, err)
		}
		for _, portRange := range portRanges {
			for port := portRange.Start; port <= portRange.End; port++ {
				specs = append(specs, PortSpec{Port: port, Protocol: "tcp"})
			}
		}
	}

	// Parse UDP ports
	for _, portStr := range config.UDP {
		portRanges, err := ParsePortString(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid UDP port specification '%s': %w", portStr, err)
		}
		for _, portRange := range portRanges {
			for port := portRange.Start; port <= portRange.End; port++ {
				specs = append(specs, PortSpec{Port: port, Protocol: "udp"})
			}
		}
	}

	return specs, nil
}

// ParsePortString parses a port string into PortRange entries
// Supports formats: "80", "80-90", "80,443,8080", "8000-9000,3000,4000-4010"
func ParsePortString(portStr string) ([]PortRange, error) {
	portStr = strings.TrimSpace(portStr)
	if portStr == "" {
		return nil, errors.New("port string cannot be empty")
	}

	var ranges []PortRange

	// Split by commas to handle multiple ports/ranges
	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check if it's a range (contains dash)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range format '%s', expected 'start-end'", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port '%s': %w", rangeParts[0], err)
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port '%s': %w", rangeParts[1], err)
			}

			if err := ValidatePortRange(start); err != nil {
				return nil, fmt.Errorf("invalid start port %d: %w", start, err)
			}
			if err := ValidatePortRange(end); err != nil {
				return nil, fmt.Errorf("invalid end port %d: %w", end, err)
			}

			if start > end {
				return nil, fmt.Errorf("start port %d cannot be greater than end port %d", start, end)
			}

			ranges = append(ranges, PortRange{Start: start, End: end})
		} else {
			// Single port
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port '%s': %w", part, err)
			}

			if err := ValidatePortRange(port); err != nil {
				return nil, fmt.Errorf("invalid port %d: %w", port, err)
			}

			ranges = append(ranges, PortRange{Start: port, End: port})
		}
	}

	return ranges, nil
}

// ValidatePortRange validates that a port number is in valid range (1-65535)
func ValidatePortRange(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d is out of valid range (1-65535)", port)
	}
	return nil
}
