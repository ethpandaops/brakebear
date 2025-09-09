package types

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ExcludeNetwork represents a network exclusion configuration
type ExcludeNetwork struct {
	Type       string
	CIDRConfig *CIDRConfig
}

// CIDRConfig contains CIDR range configurations
type CIDRConfig struct {
	Ranges []string
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
func ParseExcludeNetworks(excludes []ExcludeNetwork) ([]string, error) {
	var ranges []string

	for _, exclude := range excludes {
		switch exclude.Type {
		case "cidr":
			if exclude.CIDRConfig != nil {
				// Validate each CIDR range before adding
				for _, cidr := range exclude.CIDRConfig.Ranges {
					if err := ValidateCIDRRange(cidr); err != nil {
						return nil, fmt.Errorf("invalid CIDR range '%s': %w", cidr, err)
					}
					ranges = append(ranges, strings.TrimSpace(cidr))
				}
			}
		case "private-ranges":
			// Add RFC1918 private network ranges
			ranges = append(ranges, GetDefaultPrivateRanges()...)
		default:
			if exclude.Type != "" {
				return nil, fmt.Errorf("unsupported exclude network type '%s', supported types: 'cidr', 'private-ranges'", exclude.Type)
			}
		}
	}

	return ranges, nil
}
