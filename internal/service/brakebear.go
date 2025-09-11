package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ethpandaops/brakebear/internal/config"
	"github.com/ethpandaops/brakebear/internal/dns"
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
	config           *config.Config
	docker           *docker.Client
	inspector        *docker.Inspector
	networkInspector *docker.NetworkInspector
	monitor          *docker.Monitor
	networkMonitor   *docker.NetworkMonitor
	controller       *network.Controller
	state            state.Manager
	dnsResolver      *dns.Resolver
	log              logrus.FieldLogger
	cancel           context.CancelFunc
	wg               sync.WaitGroup
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
		config:           cfg,
		docker:           nil, // Will be initialized in Start()
		inspector:        nil, // Will be initialized in Start()
		networkInspector: nil, // Will be initialized in Start()
		monitor:          nil, // Will be initialized in Start()
		networkMonitor:   nil, // Will be initialized in Start()
		controller:       network.NewController(logger),
		state:            state.NewManager(logger),
		dnsResolver:      dns.NewResolver(logger),
		log:              logger,
	}
}

// Start initializes and starts all components and event processing
func (s *service) Start(ctx context.Context) error {
	s.log.Info("Starting BrakeBear service")

	// Create cancellable context for service lifecycle
	serviceCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	// Initialize Docker client
	var err error
	s.docker, err = docker.NewClient(s.log)
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}

	// Start Docker client
	if err := s.docker.Start(ctx); err != nil {
		return fmt.Errorf("failed to start Docker client: %w", err)
	}
	s.log.Info("Docker client started successfully")

	// Initialize Docker inspector
	s.inspector = docker.NewInspector(s.docker, s.log)
	s.log.Info("Docker inspector initialized successfully")

	// Initialize Docker network inspector
	s.networkInspector = docker.NewNetworkInspector(s.docker, s.log)
	s.log.Info("Docker network inspector initialized successfully")

	// Initialize Docker monitor
	s.monitor = docker.NewMonitor(s.docker, s.inspector, s.log)

	// Initialize Docker network monitor
	s.networkMonitor = docker.NewNetworkMonitor(s.docker, s.log)
	s.networkMonitor.AddHandler(s)
	s.log.Info("Docker network monitor initialized successfully")

	// Start state manager
	if err := s.state.Start(ctx); err != nil {
		return fmt.Errorf("failed to start state manager: %w", err)
	}
	s.log.Info("State manager started successfully")

	// Start DNS resolver
	if err := s.dnsResolver.Start(serviceCtx); err != nil {
		return fmt.Errorf("failed to start DNS resolver: %w", err)
	}
	s.log.Info("DNS resolver started successfully")

	// Start Docker monitor
	if err := s.monitor.Start(ctx); err != nil {
		return fmt.Errorf("failed to start Docker monitor: %w", err)
	}
	s.log.Info("Docker monitor started successfully")

	// Start Docker network monitor
	if err := s.networkMonitor.Start(ctx); err != nil {
		return fmt.Errorf("failed to start Docker network monitor: %w", err)
	}
	s.log.Info("Docker network monitor started successfully")

	// Apply initial configuration to existing containers
	if err := s.applyConfiguration(ctx); err != nil {
		s.log.WithError(err).Warn("Failed to apply initial configuration, continuing...")
	}

	// Start event processing goroutine
	s.wg.Add(1)
	go s.watchEvents(serviceCtx)

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

	// Stop Docker network monitor
	if s.networkMonitor != nil {
		if err := s.networkMonitor.Stop(); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("failed to stop Docker network monitor: %w", err))
		} else {
			s.log.Info("Docker network monitor stopped successfully")
		}
	}

	// Stop Docker monitor
	if s.monitor != nil {
		if err := s.monitor.Stop(); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("failed to stop Docker monitor: %w", err))
		} else {
			s.log.Info("Docker monitor stopped successfully")
		}
	}

	// Stop DNS resolver
	if s.dnsResolver != nil {
		if err := s.dnsResolver.Stop(); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("failed to stop DNS resolver: %w", err))
		} else {
			s.log.Info("DNS resolver stopped successfully")
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

// OnNetworkEvent implements docker.NetworkEventHandler interface
func (s *service) OnNetworkEvent(ctx context.Context, event docker.NetworkEvent) error {
	s.log.WithFields(logrus.Fields{
		"event_type":   event.Type,
		"network_id":   event.NetworkID,
		"network_name": event.Name,
		"driver":       event.Driver,
		"timestamp":    event.Timestamp,
	}).Debug("Processing network event")

	switch event.Type {
	case "create":
		s.handleNetworkCreate(ctx, event)
	case "destroy":
		s.handleNetworkDestroy(ctx, event)
	case "connect", "disconnect":
		s.handleNetworkChange(ctx, event)
	default:
		s.log.WithFields(logrus.Fields{
			"event_type": event.Type,
			"network_id": event.NetworkID,
		}).Debug("Ignoring unhandled network event type")
	}

	return nil
}

// handleNetworkCreate processes network creation events
func (s *service) handleNetworkCreate(ctx context.Context, event docker.NetworkEvent) {
	s.log.WithFields(logrus.Fields{
		"network_id":   event.NetworkID,
		"network_name": event.Name,
	}).Debug("Handling network create event")

	// Refresh Docker network exclusions for all containers that use wildcard
	s.refreshDockerNetworkExclusions(ctx)
}

// handleNetworkDestroy processes network destruction events
func (s *service) handleNetworkDestroy(ctx context.Context, event docker.NetworkEvent) {
	s.log.WithFields(logrus.Fields{
		"network_id":   event.NetworkID,
		"network_name": event.Name,
	}).Debug("Handling network destroy event")

	// Refresh Docker network exclusions for all containers
	s.refreshDockerNetworkExclusions(ctx)
}

// handleNetworkChange processes network connection/disconnection events
func (s *service) handleNetworkChange(ctx context.Context, event docker.NetworkEvent) {
	s.log.WithFields(logrus.Fields{
		"event_type":   event.Type,
		"network_id":   event.NetworkID,
		"network_name": event.Name,
	}).Debug("Handling network change event")

	// Network topology changed, refresh exclusions
	s.refreshDockerNetworkExclusions(ctx)
}

// refreshDockerNetworkExclusions updates Docker network exclusions for all managed containers
func (s *service) refreshDockerNetworkExclusions(ctx context.Context) {
	s.log.Debug("Refreshing Docker network exclusions for all containers")

	// Get all container states
	allStates := s.state.GetAllStates()

	for containerID, containerState := range allStates {
		// Check if this container has Docker network exclusions
		if s.containerHasDockerNetworkExclusions(containerState.Limits) {
			s.log.WithField("container_id", containerID).Debug("Updating Docker network exclusions")

			// Find the container configuration
			containerConfig, exists := s.findContainerConfig(ctx, containerID)
			if !exists {
				s.log.WithField("container_id", containerID).Debug("No configuration found for container during network refresh")
				continue
			}

			// Process the container to update exclusions
			ctxWithTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
			if err := s.processContainer(ctxWithTimeout, containerConfig); err != nil {
				s.log.WithError(err).WithField("container_id", containerID).Error("Failed to refresh Docker network exclusions for container")
			}
			cancel()
		}
	}
}

// containerHasDockerNetworkExclusions checks if a container has Docker network exclusions
func (s *service) containerHasDockerNetworkExclusions(limits *types.NetworkLimits) bool {
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

// handleContainerEvent processes container lifecycle events
func (s *service) handleContainerEvent(ctx context.Context, event docker.ContainerEvent) {
	s.log.WithFields(logrus.Fields{
		"event_type":   event.Type,
		"container_id": event.ContainerID,
		"timestamp":    event.Timestamp,
	}).Debug("Processing container event")

	switch event.Type {
	case "start":
		if err := s.handleContainerStart(ctx, event.ContainerID); err != nil {
			s.log.WithFields(logrus.Fields{
				"container_id": event.ContainerID,
				"error":        err,
			}).Error("Failed to handle container start event")
		}
	case "stop", "die":
		if err := s.handleContainerStop(ctx, event.ContainerID); err != nil {
			s.log.WithFields(logrus.Fields{
				"container_id": event.ContainerID,
				"error":        err,
			}).Error("Failed to handle container stop event")
		}
	case "update":
		// Container updated - reapply configuration if managed
		if s.state.HasContainer(event.ContainerID) {
			if err := s.handleContainerStart(ctx, event.ContainerID); err != nil {
				s.log.WithFields(logrus.Fields{
					"container_id": event.ContainerID,
					"error":        err,
				}).Warn("Failed to handle container update event")
			}
		}
	case "reconnected":
		s.log.Info("Docker daemon reconnected, re-applying configuration to existing containers")
		// Re-run container reconciliation to reapply limits to existing containers
		ctxWithTimeout, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		s.reconcileContainers(ctxWithTimeout)
	default:
		s.log.WithFields(logrus.Fields{
			"event_type":   event.Type,
			"container_id": event.ContainerID,
		}).Debug("Ignoring unhandled container event type")
	}
}

// handleContainerStart processes container start events
func (s *service) handleContainerStart(ctx context.Context, containerID string) error {
	s.log.WithField("container_id", containerID).Debug("Handling container start")

	// Check if we have configuration for this container
	containerConfig, exists := s.findContainerConfig(ctx, containerID)
	if !exists {
		s.log.WithField("container_id", containerID).Debug("No configuration found for container")
		return nil
	}

	// Process the container with its configuration
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	return s.processContainer(ctxWithTimeout, containerConfig)
}

// handleContainerStop processes container stop events
func (s *service) handleContainerStop(ctx context.Context, containerID string) error {
	s.log.WithField("container_id", containerID).Debug("Handling container stop")

	// Get container state
	containerState, exists := s.state.GetContainerState(containerID)
	if !exists {
		s.log.WithField("container_id", containerID).Debug("No state found for stopped container")
		return nil
	}

	// Remove network limits if they exist
	if containerState.NetworkNS != "" {
		if err := s.controller.RemoveContainerLimits(ctx, containerID, containerState.NetworkNS); err != nil {
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
func (s *service) applyConfiguration(ctx context.Context) error {
	s.log.Info("Applying initial configuration to existing containers")

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Reconcile configuration with running containers
	s.reconcileContainers(ctxWithTimeout)

	s.log.Info("Initial configuration applied successfully")
	return nil
}

// reconcileContainers syncs state with running containers
func (s *service) reconcileContainers(ctx context.Context) {
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
	s.removeStaleContainers(ctx, activeIDs)

	s.log.WithField("active_containers", len(activeIDs)).Debug("Container reconciliation completed")
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
		if errors.Is(err, types.ErrContainerNotFound) {
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

	// Resolve DNS exclusions before applying limits
	if err := s.resolveDNSExclusions(ctx, limits); err != nil {
		s.log.WithError(err).Warn("Failed to resolve DNS exclusions, proceeding with existing exclusions")
	}

	// Resolve Docker network exclusions before applying limits
	if err := s.resolveDockerNetworkExclusions(ctx, limits); err != nil {
		s.log.WithError(err).Warn("Failed to resolve Docker network exclusions, proceeding with existing exclusions")
	}

	// Start periodic DNS resolution for any DNS-based exclusions
	s.startDNSResolutionForContainer(ctx, limits)

	// Check if we already have this container in state
	_, exists := s.state.GetContainerState(container.ID)
	if exists {
		// Update existing limits if different
		if err := s.controller.UpdateContainerLimits(ctx, container.ID, nsPath, limits); err != nil {
			return fmt.Errorf("failed to update container limits: %w", err)
		}
		s.log.WithField("container_id", container.ID).Info("Container limits updated")
	} else {
		// Apply new limits
		if err := s.controller.ApplyContainerLimits(ctx, container.ID, nsPath, limits); err != nil {
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

// resolveDNSExclusions resolves DNS hostnames and updates exclusion networks with resolved IPs
func (s *service) resolveDNSExclusions(ctx context.Context, limits *types.NetworkLimits) error {
	if limits == nil || len(limits.ExcludeNetworks) == 0 {
		return nil
	}

	for i, exclude := range limits.ExcludeNetworks {
		if exclude.Type == "dns" && exclude.DNSConfig != nil {
			s.log.WithFields(logrus.Fields{
				"hostnames": exclude.DNSConfig.Names,
			}).Info("Resolving DNS hostnames for exclusion")

			ips, err := s.dnsResolver.ResolveHostnames(ctx, exclude.DNSConfig.Names)
			if err != nil {
				return fmt.Errorf("failed to resolve DNS hostnames: %w", err)
			}

			if len(ips) > 0 {
				// Convert all resolved IPs to CIDR ranges (both IPv4 and IPv6)
				var cidrs []string
				for _, ip := range ips {
					parsedIP := net.ParseIP(ip)
					if parsedIP == nil {
						continue
					}
					// Process both IPv4 and IPv6 addresses
					var cidr string
					if parsedIP.To4() != nil {
						cidr = ip + "/32" // IPv4 host
					} else {
						cidr = ip + "/128" // IPv6 host
					}
					if cidr != "" {
						cidrs = append(cidrs, cidr)
					}
				}

				// Convert DNS exclusion to CIDR exclusion with resolved IPs
				limits.ExcludeNetworks[i] = types.ExcludeNetwork{
					Type: "cidr",
					CIDRConfig: &types.CIDRConfig{
						Ranges: cidrs,
					},
				}

				s.log.WithFields(logrus.Fields{
					"hostnames":    exclude.DNSConfig.Names,
					"resolved_ips": ips,
					"cidrs":        cidrs,
				}).Info("DNS hostnames resolved and converted to CIDR exclusions")
			}
		}
	}

	return nil
}

// resolveDockerNetworkExclusions resolves Docker network exclusions and updates exclusion networks with discovered CIDRs
func (s *service) resolveDockerNetworkExclusions(ctx context.Context, limits *types.NetworkLimits) error {
	if limits == nil || len(limits.ExcludeNetworks) == 0 {
		return nil
	}

	for i, exclude := range limits.ExcludeNetworks {
		if exclude.Type == "docker-networks" && exclude.DockerNetworkConfig != nil {
			s.log.WithFields(logrus.Fields{
				"network_names": exclude.DockerNetworkConfig.Names,
			}).Info("Discovering Docker networks for exclusion")

			cidrs, err := s.networkInspector.DiscoverNetworks(ctx, exclude.DockerNetworkConfig)
			if err != nil {
				return fmt.Errorf("failed to discover Docker networks: %w", err)
			}

			if len(cidrs) > 0 {
				// Convert Docker network exclusion to CIDR exclusion with discovered CIDRs
				limits.ExcludeNetworks[i] = types.ExcludeNetwork{
					Type: "cidr",
					CIDRConfig: &types.CIDRConfig{
						Ranges: cidrs,
					},
				}

				s.log.WithFields(logrus.Fields{
					"network_names":    exclude.DockerNetworkConfig.Names,
					"discovered_cidrs": cidrs,
				}).Info("Docker networks discovered and converted to CIDR exclusions")
			} else {
				s.log.WithFields(logrus.Fields{
					"network_names": exclude.DockerNetworkConfig.Names,
				}).Warn("No Docker networks found for exclusion")
			}
		}
	}

	return nil
}

// startDNSResolutionForContainer starts periodic DNS resolution with change detection
func (s *service) startDNSResolutionForContainer(ctx context.Context, limits *types.NetworkLimits) {
	if limits == nil || len(limits.ExcludeNetworks) == 0 {
		return
	}

	for _, exclude := range limits.ExcludeNetworks {
		if exclude.Type == "dns" && exclude.DNSConfig != nil {
			s.log.WithFields(logrus.Fields{
				"hostnames": exclude.DNSConfig.Names,
				"interval":  exclude.DNSConfig.CheckInterval,
			}).Info("Starting DNS resolution with change detection")

			// Create DNS change callback
			callback := s.createDNSChangeCallback()

			// Start periodic resolution with callback
			s.dnsResolver.StartPeriodicResolutionWithCallback(
				ctx,
				exclude.DNSConfig.Names,
				exclude.DNSConfig.CheckInterval,
				callback,
			)
		}
	}
}

// createDNSChangeCallback creates a callback function for DNS change notifications
func (s *service) createDNSChangeCallback() func(ctx context.Context, hostname string, oldIPs, newIPs []string) {
	return func(ctx context.Context, hostname string, oldIPs, newIPs []string) {
		s.log.WithFields(logrus.Fields{
			"hostname": hostname,
			"old_ips":  oldIPs,
			"new_ips":  newIPs,
		}).Info("DNS IP change detected, updating container exclusions")

		// Find all containers that use this hostname
		containerIDs := s.controller.GetContainersWithDNSHostname(hostname)
		if len(containerIDs) == 0 {
			s.log.WithField("hostname", hostname).Debug("No containers found using this DNS hostname")
			return
		}

		s.log.WithFields(logrus.Fields{
			"hostname":      hostname,
			"container_ids": containerIDs,
		}).Info("Updating DNS exclusions for containers")

		// Update each container
		for _, containerID := range containerIDs {
			updateCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			if err := s.controller.UpdateDNSExclusions(updateCtx, containerID, hostname, oldIPs, newIPs); err != nil {
				s.log.WithError(err).WithFields(logrus.Fields{
					"container_id": containerID,
					"hostname":     hostname,
				}).Error("Failed to update DNS exclusions for container")
			} else {
				s.log.WithFields(logrus.Fields{
					"container_id": containerID,
					"hostname":     hostname,
				}).Info("Successfully updated DNS exclusions for container")
			}
			cancel()
		}
	}
}

// removeStaleContainers cleans up containers not in current configuration
func (s *service) removeStaleContainers(ctx context.Context, activeIDs map[string]bool) {
	allStates := s.state.GetAllStates()

	for containerID, containerState := range allStates {
		if !activeIDs[containerID] {
			s.log.WithField("container_id", containerID).Debug("Removing stale container from state")

			// Remove network limits
			if containerState.NetworkNS != "" {
				if err := s.controller.RemoveContainerLimits(ctx, containerID, containerState.NetworkNS); err != nil {
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
			s.handleContainerEvent(ctx, event)
		}
	}
}

// findContainerConfig finds configuration for a container by ID
func (s *service) findContainerConfig(ctx context.Context, containerID string) (config.ContainerConfig, bool) {
	targetContainer := s.getContainerByID(ctx, containerID)
	if targetContainer == nil {
		return config.ContainerConfig{}, false
	}

	return s.findMatchingConfig(*targetContainer)
}

func (s *service) getContainerByID(ctx context.Context, containerID string) *types.Container {
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	containers, err := s.inspector.ListContainers(ctxWithTimeout)
	if err != nil {
		s.log.WithError(err).Warn("Failed to list containers while finding config")
		return nil
	}

	for _, container := range containers {
		if container.ID == containerID {
			return &container
		}
	}

	return nil
}

func (s *service) findMatchingConfig(targetContainer types.Container) (config.ContainerConfig, bool) {
	for _, containerConfig := range s.config.DockerContainers {
		if s.configMatchesContainer(containerConfig, targetContainer) {
			return containerConfig, true
		}
	}

	return config.ContainerConfig{}, false
}

func (s *service) configMatchesContainer(containerConfig config.ContainerConfig, targetContainer types.Container) bool {
	identifier := containerConfig.GetIdentifier()

	switch identifier.Type {
	case types.IdentifierTypeName:
		if name, ok := identifier.Value.(string); ok {
			return targetContainer.Name == name
		}
	case types.IdentifierTypeID:
		if id, ok := identifier.Value.(string); ok {
			return targetContainer.ID == id
		}
	case types.IdentifierTypeLabels:
		if targetLabels, ok := identifier.Value.(map[string]string); ok {
			return s.matchesLabels(targetContainer.Labels, targetLabels)
		}
	}

	return false
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
			if err := s.controller.RemoveContainerLimits(context.Background(), containerID, containerState.NetworkNS); err != nil {
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
