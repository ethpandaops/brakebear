package docker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/docker/docker/api/types/network"
	brakebeartypes "github.com/ethpandaops/brakebear/internal/types"
	"github.com/sirupsen/logrus"
)

// NetworkInspector provides Docker network inspection and discovery functionality
type NetworkInspector struct {
	client *Client
	log    logrus.FieldLogger
}

// NewNetworkInspector creates a new Docker network inspector
func NewNetworkInspector(client *Client, log logrus.FieldLogger) *NetworkInspector {
	if log == nil {
		log = logrus.New()
	}

	return &NetworkInspector{
		client: client,
		log:    log.WithField("package", "docker-network-inspector"),
	}
}

// DiscoverNetworks discovers Docker networks and extracts CIDR ranges for exclusion
func (ni *NetworkInspector) DiscoverNetworks(ctx context.Context, config *brakebeartypes.DockerNetworkConfig) ([]string, error) {
	if config == nil {
		return nil, errors.New("docker network config cannot be nil")
	}

	ni.log.WithField("config", config).Debug("Discovering Docker networks")

	networks, err := ni.client.ListNetworks(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	var cidrs []string

	// Check for wildcard configuration
	if ni.hasWildcard(config.Names) {
		ni.log.Debug("Wildcard configuration detected, including all bridge networks")
		cidrs = ni.extractCIDRsFromAllBridgeNetworks(ctx, networks)
	} else {
		// Process specific network names
		cidrs, err = ni.extractCIDRsFromNamedNetworks(ctx, networks, config.Names)
		if err != nil {
			return nil, fmt.Errorf("failed to extract CIDRs from named networks: %w", err)
		}
	}

	ni.log.WithFields(logrus.Fields{
		"network_count": len(networks),
		"cidrs_found":   len(cidrs),
		"cidrs":         cidrs,
	}).Debug("Network discovery completed")

	return cidrs, nil
}

// GetNetworkByName retrieves network information by name
func (ni *NetworkInspector) GetNetworkByName(ctx context.Context, name string) (*network.Inspect, error) {
	if name == "" {
		return nil, errors.New("network name cannot be empty")
	}

	ni.log.WithField("network_name", name).Debug("Getting network by name")

	networks, err := ni.client.ListNetworks(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	for _, net := range networks {
		if net.Name == name {
			networkInfo, err := ni.client.InspectNetwork(ctx, net.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to inspect network %s: %w", name, err)
			}
			return &networkInfo, nil
		}
	}

	return nil, fmt.Errorf("network not found: %s", name)
}

// GetBridgeNetworks returns all bridge networks
func (ni *NetworkInspector) GetBridgeNetworks(ctx context.Context) ([]network.Summary, error) {
	ni.log.Debug("Getting all bridge networks")

	networks, err := ni.client.ListNetworks(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	var bridgeNetworks []network.Summary
	for _, net := range networks {
		if net.Driver == "bridge" {
			bridgeNetworks = append(bridgeNetworks, net)
		}
	}

	ni.log.WithField("bridge_count", len(bridgeNetworks)).Debug("Found bridge networks")
	return bridgeNetworks, nil
}

// hasWildcard checks if the configuration contains a wildcard ("*")
func (ni *NetworkInspector) hasWildcard(names []string) bool {
	for _, name := range names {
		if name == "*" {
			return true
		}
	}
	return false
}

// extractCIDRsFromAllBridgeNetworks extracts CIDR ranges from all bridge networks
func (ni *NetworkInspector) extractCIDRsFromAllBridgeNetworks(ctx context.Context, networks []network.Summary) []string {
	var cidrs []string

	for _, net := range networks {
		if net.Driver != "bridge" {
			continue
		}

		networkCIDRs, err := ni.extractCIDRsFromNetwork(ctx, net.ID, net.Name)
		if err != nil {
			ni.log.WithFields(logrus.Fields{
				"network_id":   net.ID,
				"network_name": net.Name,
				"error":        err.Error(),
			}).Warn("Failed to extract CIDR from bridge network, skipping")
			continue
		}

		cidrs = append(cidrs, networkCIDRs...)
	}

	return cidrs
}

// extractCIDRsFromNamedNetworks extracts CIDR ranges from specific named networks
func (ni *NetworkInspector) extractCIDRsFromNamedNetworks(ctx context.Context, networks []network.Summary, names []string) ([]string, error) {
	var cidrs []string
	foundNetworks := make(map[string]bool)

	for _, net := range networks {
		for _, targetName := range names {
			if net.Name == targetName {
				foundNetworks[targetName] = true

				networkCIDRs, err := ni.extractCIDRsFromNetwork(ctx, net.ID, net.Name)
				if err != nil {
					return nil, fmt.Errorf("failed to extract CIDR from network %s: %w", targetName, err)
				}

				cidrs = append(cidrs, networkCIDRs...)
			}
		}
	}

	// Check for networks that weren't found
	var missingNetworks []string
	for _, name := range names {
		if !foundNetworks[name] {
			missingNetworks = append(missingNetworks, name)
		}
	}

	if len(missingNetworks) > 0 {
		ni.log.WithField("missing_networks", missingNetworks).Warn("Some configured networks were not found")
	}

	return cidrs, nil
}

// extractCIDRsFromNetwork extracts CIDR ranges from a specific network
func (ni *NetworkInspector) extractCIDRsFromNetwork(ctx context.Context, networkID, networkName string) ([]string, error) {
	ni.log.WithFields(logrus.Fields{
		"network_id":   networkID,
		"network_name": networkName,
	}).Debug("Extracting CIDR from network")

	networkInfo, err := ni.client.InspectNetwork(ctx, networkID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect network %s: %w", networkID, err)
	}

	var cidrs []string

	// Extract CIDR ranges from IPAM configuration
	if len(networkInfo.IPAM.Config) > 0 {
		for _, config := range networkInfo.IPAM.Config {
			if config.Subnet != "" {
				// Validate the subnet is a valid CIDR
				if err := ni.validateCIDR(config.Subnet); err != nil {
					ni.log.WithFields(logrus.Fields{
						"network_name": networkName,
						"subnet":       config.Subnet,
						"error":        err.Error(),
					}).Warn("Invalid CIDR in network configuration, skipping")
					continue
				}

				cidrs = append(cidrs, config.Subnet)
				ni.log.WithFields(logrus.Fields{
					"network_name": networkName,
					"cidr":         config.Subnet,
				}).Debug("Extracted CIDR from network")
			}
		}
	}

	if len(cidrs) == 0 {
		ni.log.WithField("network_name", networkName).Debug("No CIDR ranges found in network")
	}

	return cidrs, nil
}

// validateCIDR validates that a string is a valid CIDR range
func (ni *NetworkInspector) validateCIDR(cidr string) error {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return errors.New("CIDR cannot be empty")
	}

	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR format: %w", err)
	}

	return nil
}
