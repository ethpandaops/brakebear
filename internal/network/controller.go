package network

import (
	"fmt"
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
}

// NewController creates a new network controller
func NewController(log logrus.FieldLogger) *Controller {
	if log == nil {
		log = logrus.New()
	}

	logger := log.WithField("package", "network-controller")

	return &Controller{
		netnsManager: NewNetnsManager(logger),
		tcManager:    NewTCManager(logger),
		log:          logger,
	}
}

// ApplyContainerLimits applies network limits to a container's network namespace
func (c *Controller) ApplyContainerLimits(containerID string, nsPath string, limits *types.NetworkLimits) error {
	if containerID == "" {
		return fmt.Errorf("container ID cannot be empty")
	}
	if nsPath == "" {
		return fmt.Errorf("namespace path cannot be empty")
	}
	if limits == nil {
		return fmt.Errorf("network limits cannot be nil")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"namespace":    nsPath,
		"limits":       fmt.Sprintf("%+v", limits),
	}).Info("Applying container network limits")

	// Execute the traffic control operations within the container's network namespace
	if err := c.applyLimitsInNamespace(nsPath, limits); err != nil {
		return fmt.Errorf("failed to apply limits in namespace %s for container %s: %w", nsPath, containerID, err)
	}

	c.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"namespace":    nsPath,
	}).Info("Successfully applied container network limits")

	return nil
}

// RemoveContainerLimits removes network limits from a container's network namespace
func (c *Controller) RemoveContainerLimits(containerID string, nsPath string) error {
	if containerID == "" {
		return fmt.Errorf("container ID cannot be empty")
	}
	if nsPath == "" {
		return fmt.Errorf("namespace path cannot be empty")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"namespace":    nsPath,
	}).Info("Removing container network limits")

	// Execute the traffic control removal within the container's network namespace
	if err := c.removeLimitsInNamespace(nsPath); err != nil {
		return fmt.Errorf("failed to remove limits in namespace %s for container %s: %w", nsPath, containerID, err)
	}

	c.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"namespace":    nsPath,
	}).Info("Successfully removed container network limits")

	return nil
}

// UpdateContainerLimits updates network limits for a container's network namespace
func (c *Controller) UpdateContainerLimits(containerID string, nsPath string, limits *types.NetworkLimits) error {
	if containerID == "" {
		return fmt.Errorf("container ID cannot be empty")
	}
	if nsPath == "" {
		return fmt.Errorf("namespace path cannot be empty")
	}
	if limits == nil {
		return fmt.Errorf("network limits cannot be nil")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"namespace":    nsPath,
		"limits":       fmt.Sprintf("%+v", limits),
	}).Info("Updating container network limits")

	// Remove existing limits first, then apply new ones
	if err := c.removeLimitsInNamespace(nsPath); err != nil {
		c.log.WithFields(logrus.Fields{
			"container_id": containerID,
			"namespace":    nsPath,
			"error":        err,
		}).Warn("Failed to remove existing limits before update, continuing with apply")
	}

	// Apply new limits
	if err := c.applyLimitsInNamespace(nsPath, limits); err != nil {
		return fmt.Errorf("failed to apply updated limits in namespace %s for container %s: %w", nsPath, containerID, err)
	}

	c.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"namespace":    nsPath,
	}).Info("Successfully updated container network limits")

	return nil
}

// applyLimitsInNamespace applies traffic control limits within a network namespace
func (c *Controller) applyLimitsInNamespace(nsPath string, limits *types.NetworkLimits) error {
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

			if err := c.tcManager.ApplyLimits(iface, limits); err != nil {
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
func (c *Controller) removeLimitsInNamespace(nsPath string) error {
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

			if err := c.tcManager.RemoveLimits(iface); err != nil {
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
