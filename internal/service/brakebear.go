package service

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ethpandaops/brakebear/internal/config"
	"github.com/ethpandaops/brakebear/internal/docker"
	"github.com/ethpandaops/brakebear/internal/network"
	"github.com/ethpandaops/brakebear/internal/state"
	"github.com/ethpandaops/brakebear/internal/types"
	"github.com/sirupsen/logrus"
)

// Service defines the interface for the main BrakeBear service
type Service interface {
	// Start initializes and starts all components and event processing
	Start(ctx context.Context) error
	// Stop gracefully shuts down all components
	Stop() error
}

// service implements the Service interface and orchestrates all BrakeBear components
type service struct {
	config     *config.Config
	docker     *docker.Client
	inspector  *docker.Inspector
	monitor    *docker.Monitor
	controller *network.Controller
	state      state.Manager
	log        logrus.FieldLogger
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// NewService creates a new BrakeBear service with all required components
func NewService(cfg *config.Config, log logrus.FieldLogger) Service {
	if log == nil {
		log = logrus.New()
	}
	if cfg == nil {
		log.Fatal("Configuration cannot be nil")
	}

	logger := log.WithField("package", "service")

	return &service{
		config:     cfg,
		docker:     nil, // Will be initialized in Start()
		inspector:  nil, // Will be initialized in Start()
		monitor:    nil, // Will be initialized in Start()
		controller: network.NewController(logger),
		state:      state.NewManager(logger),
		log:        logger,
	}
}

// Start initializes and starts all components and event processing
func (s *service) Start(ctx context.Context) error {
	s.log.Info("Starting BrakeBear service")

	// Create cancellable context for service lifecycle
	s.ctx, s.cancel = context.WithCancel(ctx)

	// Initialize Docker client
	var err error
	s.docker, err = docker.NewClient(s.log)
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}

	// Start Docker client
	if err := s.docker.Start(s.ctx); err != nil {
		return fmt.Errorf("failed to start Docker client: %w", err)
	}
	s.log.Info("Docker client started successfully")

	// Initialize Docker inspector
	s.inspector = docker.NewInspector(s.docker, s.log)
	s.log.Info("Docker inspector initialized successfully")

	// Initialize Docker monitor
	s.monitor = docker.NewMonitor(s.docker, s.inspector, s.log)

	// Start state manager
	if err := s.state.Start(s.ctx); err != nil {
		return fmt.Errorf("failed to start state manager: %w", err)
	}
	s.log.Info("State manager started successfully")

	// Start Docker monitor
	if err := s.monitor.Start(s.ctx); err != nil {
		return fmt.Errorf("failed to start Docker monitor: %w", err)
	}
	s.log.Info("Docker monitor started successfully")

	// Apply initial configuration to existing containers
	if err := s.applyConfiguration(); err != nil {
		s.log.WithError(err).Warn("Failed to apply initial configuration, continuing...")
	}

	// Start event processing goroutine
	s.wg.Add(1)
	go s.watchEvents(s.ctx)

	s.log.Info("BrakeBear service started successfully")
	return nil
}

// Stop gracefully shuts down all components
func (s *service) Stop() error {
	s.log.Info("Stopping BrakeBear service")

	// Cancel context to signal all goroutines to stop
	if s.cancel != nil {
		s.cancel()
	}

	// Wait for all goroutines to finish
	s.log.Debug("Waiting for goroutines to finish")
	s.wg.Wait()

	// Stop components in reverse order of startup
	var stopErrors []error

	// Stop Docker monitor
	if s.monitor != nil {
		if err := s.monitor.Stop(); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("failed to stop Docker monitor: %w", err))
		} else {
			s.log.Info("Docker monitor stopped successfully")
		}
	}

	// Clean up all network limits before shutting down
	if err := s.cleanup(); err != nil {
		s.log.WithError(err).Warn("Failed to clean up network limits during shutdown")
	}

	// Stop state manager
	if s.state != nil {
		if err := s.state.Stop(); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("failed to stop state manager: %w", err))
		} else {
			s.log.Info("State manager stopped successfully")
		}
	}

	// Stop Docker client
	if s.docker != nil {
		if err := s.docker.Stop(); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("failed to stop Docker client: %w", err))
		} else {
			s.log.Info("Docker client stopped successfully")
		}
	}

	if len(stopErrors) > 0 {
		s.log.WithField("error_count", len(stopErrors)).Error("Some components failed to stop cleanly")
		return stopErrors[0] // Return first error
	}

	s.log.Info("BrakeBear service stopped successfully")
	return nil
}

// handleContainerEvent processes container lifecycle events
func (s *service) handleContainerEvent(event docker.ContainerEvent) {
	s.log.WithFields(logrus.Fields{
		"event_type":   event.Type,
		"container_id": event.ContainerID,
		"timestamp":    event.Timestamp,
	}).Debug("Processing container event")

	switch event.Type {
	case "start":
		if err := s.handleContainerStart(event.ContainerID); err != nil {
			s.log.WithFields(logrus.Fields{
				"container_id": event.ContainerID,
				"error":        err,
			}).Error("Failed to handle container start event")
		}
	case "stop", "die":
		if err := s.handleContainerStop(event.ContainerID); err != nil {
			s.log.WithFields(logrus.Fields{
				"container_id": event.ContainerID,
				"error":        err,
			}).Error("Failed to handle container stop event")
		}
	case "update":
		// Container updated - reapply configuration if managed
		if s.state.HasContainer(event.ContainerID) {
			if err := s.handleContainerStart(event.ContainerID); err != nil {
				s.log.WithFields(logrus.Fields{
					"container_id": event.ContainerID,
					"error":        err,
				}).Warn("Failed to handle container update event")
			}
		}
	default:
		s.log.WithFields(logrus.Fields{
			"event_type":   event.Type,
			"container_id": event.ContainerID,
		}).Debug("Ignoring unhandled container event type")
	}
}

// handleContainerStart processes container start events
func (s *service) handleContainerStart(containerID string) error {
	s.log.WithField("container_id", containerID).Debug("Handling container start")

	// Check if we have configuration for this container
	containerConfig, exists := s.findContainerConfig(containerID)
	if !exists {
		s.log.WithField("container_id", containerID).Debug("No configuration found for container")
		return nil
	}

	// Process the container with its configuration
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	return s.processContainer(ctx, containerConfig)
}

// handleContainerStop processes container stop events
func (s *service) handleContainerStop(containerID string) error {
	s.log.WithField("container_id", containerID).Debug("Handling container stop")

	// Get container state
	containerState, exists := s.state.GetContainerState(containerID)
	if !exists {
		s.log.WithField("container_id", containerID).Debug("No state found for stopped container")
		return nil
	}

	// Remove network limits if they exist
	if containerState.NetworkNS != "" {
		if err := s.controller.RemoveContainerLimits(containerID, containerState.NetworkNS); err != nil {
			// Check if it's a "namespace does not exist" error - this is expected when containers are removed
			if strings.Contains(err.Error(), "does not exist") || strings.Contains(err.Error(), "no such file or directory") {
				s.log.WithFields(logrus.Fields{
					"container_id": containerID,
					"network_ns":   containerState.NetworkNS,
				}).Debug("Container namespace no longer exists, limits already removed")
			} else {
				s.log.WithFields(logrus.Fields{
					"container_id": containerID,
					"network_ns":   containerState.NetworkNS,
					"error":        err,
				}).Warn("Failed to remove network limits for stopped container")
			}
		}
	}

	// Remove container from state
	if err := s.state.RemoveContainerState(containerID); err != nil {
		return fmt.Errorf("failed to remove container state: %w", err)
	}

	s.log.WithField("container_id", containerID).Info("Container cleanup completed")
	return nil
}

// applyConfiguration applies initial configuration to existing containers
func (s *service) applyConfiguration() error {
	s.log.Info("Applying initial configuration to existing containers")

	ctx, cancel := context.WithTimeout(s.ctx, 60*time.Second)
	defer cancel()

	// Reconcile configuration with running containers
	if err := s.reconcileContainers(ctx); err != nil {
		return fmt.Errorf("failed to reconcile containers: %w", err)
	}

	s.log.Info("Initial configuration applied successfully")
	return nil
}

// reconcileContainers syncs state with running containers
func (s *service) reconcileContainers(ctx context.Context) error {
	s.log.Debug("Reconciling container configuration with running containers")

	// Track active container IDs to identify stale entries
	activeIDs := make(map[string]bool)

	// Process each configured container
	for _, containerConfig := range s.config.DockerContainers {
		if err := s.processContainer(ctx, containerConfig); err != nil {
			s.log.WithError(err).Warn("Failed to process container during reconciliation")
			continue
		}

		// Find the container to get its ID
		identifier := containerConfig.GetIdentifier()
		container, err := s.inspector.GetContainerByIdentifier(ctx, identifier)
		if err != nil {
			s.log.WithFields(logrus.Fields{
				"identifier_type":  identifier.Type,
				"identifier_value": identifier.Value,
				"error":            err,
			}).Debug("Container not found during reconciliation")
			continue
		}

		activeIDs[container.ID] = true
	}

	// Remove stale containers from state
	if err := s.removeStaleContainers(activeIDs); err != nil {
		return fmt.Errorf("failed to remove stale containers: %w", err)
	}

	s.log.WithField("active_containers", len(activeIDs)).Debug("Container reconciliation completed")
	return nil
}

// processContainer processes individual container configuration
func (s *service) processContainer(ctx context.Context, cfg config.ContainerConfig) error {
	identifier := cfg.GetIdentifier()

	s.log.WithFields(logrus.Fields{
		"identifier_type":  identifier.Type,
		"identifier_value": identifier.Value,
	}).Debug("Processing container configuration")

	// Find the container
	container, err := s.inspector.GetContainerByIdentifier(ctx, identifier)
	if err != nil {
		if err == types.ErrContainerNotFound {
			s.log.WithFields(logrus.Fields{
				"identifier_type":  identifier.Type,
				"identifier_value": identifier.Value,
			}).Debug("Container not found, skipping")
			return nil
		}
		return fmt.Errorf("failed to find container: %w", err)
	}

	// Get network namespace
	nsPath, err := s.inspector.GetContainerNetworkNamespace(ctx, container.ID)
	if err != nil {
		return fmt.Errorf("failed to get network namespace for container %s: %w", container.ID, err)
	}

	// Convert configuration to network limits
	limits, err := cfg.ToNetworkLimits()
	if err != nil {
		return fmt.Errorf("failed to parse network limits: %w", err)
	}

	// Check if we already have this container in state
	_, exists := s.state.GetContainerState(container.ID)
	if exists {
		// Update existing limits if different
		if err := s.controller.UpdateContainerLimits(container.ID, nsPath, limits); err != nil {
			return fmt.Errorf("failed to update container limits: %w", err)
		}
		s.log.WithField("container_id", container.ID).Info("Container limits updated")
	} else {
		// Apply new limits
		if err := s.controller.ApplyContainerLimits(container.ID, nsPath, limits); err != nil {
			return fmt.Errorf("failed to apply container limits: %w", err)
		}
		s.log.WithField("container_id", container.ID).Info("Container limits applied")
	}

	// Update state
	containerState := &types.ContainerState{
		ContainerID: container.ID,
		NetworkNS:   nsPath,
		Limits:      limits,
		LastUpdated: time.Now(),
	}

	if err := s.state.SetContainerState(container.ID, containerState); err != nil {
		return fmt.Errorf("failed to update container state: %w", err)
	}

	return nil
}

// removeStaleContainers cleans up containers not in current configuration
func (s *service) removeStaleContainers(activeIDs map[string]bool) error {
	allStates := s.state.GetAllStates()

	for containerID, containerState := range allStates {
		if !activeIDs[containerID] {
			s.log.WithField("container_id", containerID).Debug("Removing stale container from state")

			// Remove network limits
			if containerState.NetworkNS != "" {
				if err := s.controller.RemoveContainerLimits(containerID, containerState.NetworkNS); err != nil {
					s.log.WithFields(logrus.Fields{
						"container_id": containerID,
						"error":        err,
					}).Warn("Failed to remove limits for stale container")
				}
			}

			// Remove from state
			if err := s.state.RemoveContainerState(containerID); err != nil {
				s.log.WithFields(logrus.Fields{
					"container_id": containerID,
					"error":        err,
				}).Warn("Failed to remove stale container from state")
			}
		}
	}

	return nil
}

// watchEvents is the main event processing loop
func (s *service) watchEvents(ctx context.Context) {
	defer s.wg.Done()

	s.log.Debug("Starting event processing loop")

	events := s.monitor.Events()

	for {
		select {
		case <-ctx.Done():
			s.log.Debug("Event processing loop stopping due to context cancellation")
			return
		case event, ok := <-events:
			if !ok {
				s.log.Debug("Event channel closed, stopping event processing loop")
				return
			}
			s.handleContainerEvent(event)
		}
	}
}

// findContainerConfig finds configuration for a container by ID
func (s *service) findContainerConfig(containerID string) (config.ContainerConfig, bool) {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()

	// Get container details
	containers, err := s.inspector.ListContainers(ctx)
	if err != nil {
		s.log.WithError(err).Warn("Failed to list containers while finding config")
		return config.ContainerConfig{}, false
	}

	var targetContainer *types.Container
	for _, container := range containers {
		if container.ID == containerID {
			targetContainer = &container
			break
		}
	}

	if targetContainer == nil {
		return config.ContainerConfig{}, false
	}

	// Check each configured container to see if it matches
	for _, containerConfig := range s.config.DockerContainers {
		identifier := containerConfig.GetIdentifier()

		switch identifier.Type {
		case types.IdentifierTypeName:
			if name, ok := identifier.Value.(string); ok && targetContainer.Name == name {
				return containerConfig, true
			}
		case types.IdentifierTypeID:
			if id, ok := identifier.Value.(string); ok && targetContainer.ID == id {
				return containerConfig, true
			}
		case types.IdentifierTypeLabels:
			if targetLabels, ok := identifier.Value.(map[string]string); ok {
				if s.matchesLabels(targetContainer.Labels, targetLabels) {
					return containerConfig, true
				}
			}
		}
	}

	return config.ContainerConfig{}, false
}

// matchesLabels checks if container labels match all target labels
func (s *service) matchesLabels(containerLabels map[string]string, targetLabels map[string]string) bool {
	if containerLabels == nil && len(targetLabels) > 0 {
		return false
	}

	// All target labels must be present and match in the container labels
	for key, value := range targetLabels {
		containerValue, exists := containerLabels[key]
		if !exists || containerValue != value {
			return false
		}
	}

	return true
}

// cleanup removes all network limits and clears state during shutdown
func (s *service) cleanup() error {
	s.log.Info("Cleaning up network limits during shutdown")

	allStates := s.state.GetAllStates()

	for containerID, containerState := range allStates {
		if containerState.NetworkNS != "" {
			if err := s.controller.RemoveContainerLimits(containerID, containerState.NetworkNS); err != nil {
				s.log.WithFields(logrus.Fields{
					"container_id": containerID,
					"network_ns":   containerState.NetworkNS,
					"error":        err,
				}).Warn("Failed to remove network limits during cleanup")
			} else {
				s.log.WithField("container_id", containerID).Debug("Network limits removed during cleanup")
			}
		}
	}

	if err := s.state.Cleanup(); err != nil {
		return fmt.Errorf("failed to cleanup state: %w", err)
	}

	s.log.Info("Network limits cleanup completed")
	return nil
}
