package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/ethpandaops/brakebear/internal/types"
	"github.com/sirupsen/logrus"
)

// Controller orchestrates network namespace and traffic control operations
type Controller struct {
	netnsManager *NetnsManager
	tcManager    *TCManager
	log          logrus.FieldLogger
	mu           sync.RWMutex
	// Track container network state for dynamic updates
	containerState map[string]*ContainerNetworkState
}

// ContainerNetworkState tracks network configuration for a container
type ContainerNetworkState struct {
	ContainerID string
	Namespace   string
	Limits      *types.NetworkLimits
	Interfaces  []string
}

// NewController creates a new network controller
func NewController(log logrus.FieldLogger) *Controller {
	if log == nil {
		log = logrus.New()
	}

	logger := log.WithField("package", "network-controller")

	return &Controller{
		netnsManager:   NewNetnsManager(logger),
		tcManager:      NewTCManager(logger),
		log:            logger,
		containerState: make(map[string]*ContainerNetworkState),
	}
}

// ApplyContainerLimits applies network limits to a container's network namespace
func (c *Controller) ApplyContainerLimits(ctx context.Context, containerID string, nsPath string, limits *types.NetworkLimits) error {
	if containerID == "" {
		return errors.New("container ID cannot be empty")
	}
	if nsPath == "" {
		return errors.New("namespace path cannot be empty")
	}
	if limits == nil {
		return errors.New("network limits cannot be nil")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"namespace":    nsPath,
		"limits":       fmt.Sprintf("%+v", limits),
	}).Info("Applying container network limits")

	// Execute the traffic control operations within the container's network namespace
	interfaces, err := c.applyLimitsInNamespaceWithInterfaces(ctx, nsPath, limits)
	if err != nil {
		return fmt.Errorf("failed to apply limits in namespace %s for container %s: %w", nsPath, containerID, err)
	}

	// Store container state for dynamic updates
	c.containerState[containerID] = &ContainerNetworkState{
		ContainerID: containerID,
		Namespace:   nsPath,
		Limits:      limits,
		Interfaces:  interfaces,
	}

	c.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"namespace":    nsPath,
	}).Info("Successfully applied container network limits")

	return nil
}

// RemoveContainerLimits removes network limits from a container's network namespace
func (c *Controller) RemoveContainerLimits(ctx context.Context, containerID string, nsPath string) error {
	if containerID == "" {
		return errors.New("container ID cannot be empty")
	}
	if nsPath == "" {
		return errors.New("namespace path cannot be empty")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"namespace":    nsPath,
	}).Info("Removing container network limits")

	// Execute the traffic control removal within the container's network namespace
	if err := c.removeLimitsInNamespace(ctx, nsPath); err != nil {
		return fmt.Errorf("failed to remove limits in namespace %s for container %s: %w", nsPath, containerID, err)
	}

	// Remove container state
	delete(c.containerState, containerID)

	c.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"namespace":    nsPath,
	}).Info("Successfully removed container network limits")

	return nil
}

// UpdateContainerLimits updates network limits for a container's network namespace
func (c *Controller) UpdateContainerLimits(ctx context.Context, containerID string, nsPath string, limits *types.NetworkLimits) error {
	if containerID == "" {
		return errors.New("container ID cannot be empty")
	}
	if nsPath == "" {
		return errors.New("namespace path cannot be empty")
	}
	if limits == nil {
		return errors.New("network limits cannot be nil")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"namespace":    nsPath,
		"limits":       fmt.Sprintf("%+v", limits),
	}).Info("Updating container network limits")

	// Remove existing limits first, then apply new ones
	if err := c.removeLimitsInNamespace(ctx, nsPath); err != nil {
		c.log.WithFields(logrus.Fields{
			"container_id": containerID,
			"namespace":    nsPath,
			"error":        err,
		}).Warn("Failed to remove existing limits before update, continuing with apply")
	}

	// Apply new limits
	interfaces, err := c.applyLimitsInNamespaceWithInterfaces(ctx, nsPath, limits)
	if err != nil {
		return fmt.Errorf("failed to apply updated limits in namespace %s for container %s: %w", nsPath, containerID, err)
	}

	// Update container state
	c.containerState[containerID] = &ContainerNetworkState{
		ContainerID: containerID,
		Namespace:   nsPath,
		Limits:      limits,
		Interfaces:  interfaces,
	}

	c.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"namespace":    nsPath,
	}).Info("Successfully updated container network limits")

	return nil
}

// applyLimitsInNamespace applies traffic control limits within a network namespace
func (c *Controller) applyLimitsInNamespace(ctx context.Context, nsPath string, limits *types.NetworkLimits) error {
	c.log.WithFields(logrus.Fields{
		"namespace": nsPath,
		"limits":    fmt.Sprintf("%+v", limits),
	}).Debug("Applying limits in network namespace")

	// Execute within the network namespace
	return c.netnsManager.ExecuteInNamespace(nsPath, func() error {
		// Get all network interfaces in the namespace
		interfaces, err := c.tcManager.GetInterfaces()
		if err != nil {
			return fmt.Errorf("failed to get network interfaces: %w", err)
		}

		if len(interfaces) == 0 {
			c.log.WithField("namespace", nsPath).Warn("No network interfaces found in namespace")
			return nil
		}

		c.log.WithFields(logrus.Fields{
			"namespace":  nsPath,
			"interfaces": interfaces,
		}).Debug("Found network interfaces in namespace")

		// Apply limits to all relevant interfaces
		var lastErr error
		successCount := 0

		for _, iface := range interfaces {
			c.log.WithFields(logrus.Fields{
				"namespace": nsPath,
				"interface": iface,
			}).Debug("Applying limits to interface")

			if err := c.tcManager.ApplyLimits(ctx, iface, limits); err != nil {
				c.log.WithFields(logrus.Fields{
					"namespace": nsPath,
					"interface": iface,
					"error":     err,
				}).Warn("Failed to apply limits to interface")
				lastErr = err
				continue
			}

			successCount++
			c.log.WithFields(logrus.Fields{
				"namespace": nsPath,
				"interface": iface,
			}).Debug("Successfully applied limits to interface")
		}

		if successCount == 0 && lastErr != nil {
			return fmt.Errorf("failed to apply limits to any interface: %w", lastErr)
		}

		if successCount < len(interfaces) {
			c.log.WithFields(logrus.Fields{
				"namespace":  nsPath,
				"total":      len(interfaces),
				"successful": successCount,
				"failed":     len(interfaces) - successCount,
			}).Warn("Applied limits to some interfaces only")
		}

		return nil
	})
}

// removeLimitsInNamespace removes traffic control limits within a network namespace
func (c *Controller) removeLimitsInNamespace(ctx context.Context, nsPath string) error {
	c.log.WithField("namespace", nsPath).Debug("Removing limits in network namespace")

	// Execute within the network namespace
	return c.netnsManager.ExecuteInNamespace(nsPath, func() error {
		// Get all network interfaces in the namespace
		interfaces, err := c.tcManager.GetInterfaces()
		if err != nil {
			return fmt.Errorf("failed to get network interfaces: %w", err)
		}

		if len(interfaces) == 0 {
			c.log.WithField("namespace", nsPath).Debug("No network interfaces found in namespace")
			return nil
		}

		c.log.WithFields(logrus.Fields{
			"namespace":  nsPath,
			"interfaces": interfaces,
		}).Debug("Found network interfaces for limit removal")

		// Remove limits from all interfaces
		for _, iface := range interfaces {
			c.log.WithFields(logrus.Fields{
				"namespace": nsPath,
				"interface": iface,
			}).Debug("Removing limits from interface")

			if err := c.tcManager.RemoveLimits(ctx, iface); err != nil {
				// Log but don't fail - limits might not exist
				c.log.WithFields(logrus.Fields{
					"namespace": nsPath,
					"interface": iface,
					"error":     err,
				}).Debug("Failed to remove limits from interface (may not exist)")
			} else {
				c.log.WithFields(logrus.Fields{
					"namespace": nsPath,
					"interface": iface,
				}).Debug("Successfully removed limits from interface")
			}
		}

		return nil
	})
}

// UpdateDNSExclusions updates DNS exclusions for a specific container
func (c *Controller) UpdateDNSExclusions(ctx context.Context, containerID string, hostname string, oldIPs, newIPs []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get container state
	state, exists := c.containerState[containerID]
	if !exists {
		return fmt.Errorf("container %s not found in state", containerID)
	}

	c.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"hostname":     hostname,
		"old_ips":      oldIPs,
		"new_ips":      newIPs,
	}).Info("Updating DNS exclusions for container")

	// Create updated limits with new IP exclusions
	updatedLimits := c.updateLimitsWithNewIPs(state.Limits, oldIPs, newIPs)

	// Apply updated limits
	interfaces, err := c.applyLimitsInNamespaceWithInterfaces(ctx, state.Namespace, updatedLimits)
	if err != nil {
		return fmt.Errorf("failed to update DNS exclusions for container %s: %w", containerID, err)
	}

	// Update container state
	state.Limits = updatedLimits
	state.Interfaces = interfaces

	c.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"hostname":     hostname,
	}).Info("Successfully updated DNS exclusions for container")

	return nil
}

// GetContainersWithDNSHostname returns container IDs that use a specific DNS hostname
func (c *Controller) GetContainersWithDNSHostname(hostname string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var containerIDs []string

	for containerID, state := range c.containerState {
		if c.containerUsesDNSHostname(state.Limits, hostname) {
			containerIDs = append(containerIDs, containerID)
		}
	}

	return containerIDs
}

// UpdateDockerNetworkExclusions updates Docker network exclusions for a specific container
func (c *Controller) UpdateDockerNetworkExclusions(ctx context.Context, containerID string, newCIDRs []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get container state
	state, exists := c.containerState[containerID]
	if !exists {
		return fmt.Errorf("container %s not found in state", containerID)
	}

	c.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"new_cidrs":    newCIDRs,
	}).Info("Updating Docker network exclusions for container")

	// Create updated limits with new Docker network exclusions
	updatedLimits := c.updateLimitsWithDockerNetworks(state.Limits, newCIDRs)

	// Apply updated limits
	interfaces, err := c.applyLimitsInNamespaceWithInterfaces(ctx, state.Namespace, updatedLimits)
	if err != nil {
		return fmt.Errorf("failed to apply updated Docker network exclusions: %w", err)
	}

	// Update stored state
	state.Limits = updatedLimits
	state.Interfaces = interfaces

	c.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"new_cidrs":    newCIDRs,
	}).Info("Successfully updated Docker network exclusions")

	return nil
}

// GetContainersWithDockerNetworkExclusions returns containers that use Docker network exclusions
func (c *Controller) GetContainersWithDockerNetworkExclusions() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var containers []string
	for containerID, state := range c.containerState {
		if c.containerUsesDockerNetworks(state.Limits) {
			containers = append(containers, containerID)
		}
	}

	c.log.WithField("container_count", len(containers)).Debug("Found containers using Docker network exclusions")
	return containers
}

// applyLimitsInNamespaceWithInterfaces applies traffic control limits and returns interfaces used
func (c *Controller) applyLimitsInNamespaceWithInterfaces(ctx context.Context, nsPath string, limits *types.NetworkLimits) ([]string, error) {
	c.log.WithFields(logrus.Fields{
		"namespace": nsPath,
		"limits":    fmt.Sprintf("%+v", limits),
	}).Debug("Applying limits in network namespace with interface tracking")

	var appliedInterfaces []string

	// Execute within the network namespace
	err := c.netnsManager.ExecuteInNamespace(nsPath, func() error {
		// Get all network interfaces in the namespace
		interfaces, err := c.tcManager.GetInterfaces()
		if err != nil {
			return fmt.Errorf("failed to get network interfaces: %w", err)
		}

		if len(interfaces) == 0 {
			c.log.WithField("namespace", nsPath).Warn("No network interfaces found in namespace")
			return nil
		}

		c.log.WithFields(logrus.Fields{
			"namespace":  nsPath,
			"interfaces": interfaces,
		}).Debug("Found network interfaces in namespace")

		// Apply limits to all relevant interfaces
		var lastErr error
		successCount := 0

		for _, iface := range interfaces {
			c.log.WithFields(logrus.Fields{
				"namespace": nsPath,
				"interface": iface,
			}).Debug("Applying limits to interface")

			if err := c.tcManager.ApplyLimits(ctx, iface, limits); err != nil {
				c.log.WithFields(logrus.Fields{
					"namespace": nsPath,
					"interface": iface,
					"error":     err,
				}).Warn("Failed to apply limits to interface")
				lastErr = err
				continue
			}

			successCount++
			appliedInterfaces = append(appliedInterfaces, iface)
			c.log.WithFields(logrus.Fields{
				"namespace": nsPath,
				"interface": iface,
			}).Debug("Successfully applied limits to interface")
		}

		if successCount == 0 && lastErr != nil {
			return fmt.Errorf("failed to apply limits to any interface: %w", lastErr)
		}

		if successCount < len(interfaces) {
			c.log.WithFields(logrus.Fields{
				"namespace":  nsPath,
				"total":      len(interfaces),
				"successful": successCount,
				"failed":     len(interfaces) - successCount,
			}).Warn("Applied limits to some interfaces only")
		}

		return nil
	})

	return appliedInterfaces, err
}

// containerUsesDNSHostname checks if container limits include a specific DNS hostname
func (c *Controller) containerUsesDNSHostname(limits *types.NetworkLimits, hostname string) bool {
	if limits == nil || len(limits.ExcludeNetworks) == 0 {
		return false
	}

	for _, exclude := range limits.ExcludeNetworks {
		if exclude.Type == "dns" && exclude.DNSConfig != nil {
			for _, name := range exclude.DNSConfig.Names {
				if name == hostname {
					return true
				}
			}
		}
	}

	return false
}

// updateLimitsWithNewIPs updates network limits by replacing old IPs with new ones
func (c *Controller) updateLimitsWithNewIPs(limits *types.NetworkLimits, oldIPs, newIPs []string) *types.NetworkLimits {
	if limits == nil {
		return limits
	}

	// Create a copy of the limits
	updatedLimits := c.copyNetworkLimits(limits)

	// Update each exclude network
	for i, exclude := range limits.ExcludeNetworks {
		if exclude.Type == "cidr" && exclude.CIDRConfig != nil {
			updatedRanges := c.updateCIDRRanges(exclude.CIDRConfig.Ranges, oldIPs, newIPs)
			updatedLimits.ExcludeNetworks[i].CIDRConfig = &types.CIDRConfig{
				Ranges: updatedRanges,
			}
		}
	}

	return updatedLimits
}

// copyNetworkLimits creates a deep copy of network limits
func (c *Controller) copyNetworkLimits(limits *types.NetworkLimits) *types.NetworkLimits {
	excludeNetworks := make([]types.ExcludeNetwork, len(limits.ExcludeNetworks))
	copy(excludeNetworks, limits.ExcludeNetworks)

	return &types.NetworkLimits{
		DownloadRate:    limits.DownloadRate,
		UploadRate:      limits.UploadRate,
		Latency:         limits.Latency,
		Jitter:          limits.Jitter,
		Loss:            limits.Loss,
		ExcludeNetworks: excludeNetworks,
	}
}

// updateCIDRRanges filters out old IPs and adds new IPs to CIDR ranges
func (c *Controller) updateCIDRRanges(ranges []string, oldIPs, newIPs []string) []string {
	updatedRanges := make([]string, 0)

	// Filter out old IPs
	for _, cidr := range ranges {
		ip := c.extractIPFromCIDR(cidr)
		if !c.contains(oldIPs, ip) {
			updatedRanges = append(updatedRanges, cidr)
		}
	}

	// Add new IPs (IPv4 only)
	for _, newIP := range newIPs {
		if c.isValidIPv4(newIP) {
			updatedRanges = append(updatedRanges, newIP+"/32")
		}
	}

	return updatedRanges
}

// extractIPFromCIDR removes the /32 or /128 suffix from CIDR
func (c *Controller) extractIPFromCIDR(cidr string) string {
	if len(cidr) > 3 && cidr[len(cidr)-3:] == "/32" {
		return cidr[:len(cidr)-3]
	}
	if len(cidr) > 4 && cidr[len(cidr)-4:] == "/128" {
		return cidr[:len(cidr)-4]
	}
	return cidr
}

// contains checks if a slice contains a specific string
func (c *Controller) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// isValidIPv4 checks if an IP is a valid IPv4 address
func (c *Controller) isValidIPv4(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() != nil
}

// updateLimitsWithDockerNetworks creates updated limits with new Docker network CIDRs
func (c *Controller) updateLimitsWithDockerNetworks(limits *types.NetworkLimits, newCIDRs []string) *types.NetworkLimits {
	// Create a copy of the limits
	updatedLimits := c.copyNetworkLimits(limits)

	// Find and update Docker network exclusions
	for i, exclude := range limits.ExcludeNetworks {
		if exclude.Type == "docker-networks" {
			// Replace Docker network exclusion with CIDR exclusion containing the new CIDRs
			updatedLimits.ExcludeNetworks[i] = types.ExcludeNetwork{
				Type: "cidr",
				CIDRConfig: &types.CIDRConfig{
					Ranges: newCIDRs,
				},
			}
		} else if exclude.Type == "cidr" && exclude.CIDRConfig != nil {
			// Check if this CIDR exclusion was originally from Docker networks
			// If it contains Docker-discovered CIDRs, replace them with the new ones
			// For simplicity, we'll just append new CIDRs to existing CIDR exclusions
			updatedRanges := make([]string, 0, len(exclude.CIDRConfig.Ranges)+len(newCIDRs))
			updatedRanges = append(updatedRanges, exclude.CIDRConfig.Ranges...)

			// Add new Docker network CIDRs if not already present
			for _, newCIDR := range newCIDRs {
				if !c.contains(updatedRanges, newCIDR) {
					updatedRanges = append(updatedRanges, newCIDR)
				}
			}

			updatedLimits.ExcludeNetworks[i].CIDRConfig = &types.CIDRConfig{
				Ranges: updatedRanges,
			}
		}
	}

	return updatedLimits
}

// containerUsesDockerNetworks checks if a container uses Docker network exclusions
func (c *Controller) containerUsesDockerNetworks(limits *types.NetworkLimits) bool {
	if limits == nil || len(limits.ExcludeNetworks) == 0 {
		return false
	}

	for _, exclude := range limits.ExcludeNetworks {
		if exclude.Type == "docker-networks" {
			return true
		}
	}

	return false
}
