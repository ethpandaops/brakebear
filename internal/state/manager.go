package state

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ethpandaops/brakebear/internal/types"
	"github.com/sirupsen/logrus"
)

// Manager defines the interface for container state management
type Manager interface {
	// Start initializes the state manager (minimal setup only)
	Start(ctx context.Context) error
	// Stop gracefully shuts down the state manager
	Stop() error
	// SetContainerState stores or updates the state for a container
	SetContainerState(containerID string, state *types.ContainerState) error
	// GetContainerState retrieves the state for a container
	GetContainerState(containerID string) (*types.ContainerState, bool)
	// RemoveContainerState removes the state for a container
	RemoveContainerState(containerID string) error
	// GetAllStates returns a copy of all container states
	GetAllStates() map[string]*types.ContainerState
	// HasContainer checks if a container is being managed
	HasContainer(containerID string) bool
	// UpdateNetworkNamespace updates the network namespace path for a container
	UpdateNetworkNamespace(containerID string, nsPath string) error
	// Cleanup removes all states and performs cleanup
	Cleanup() error
}

// manager implements the Manager interface with thread-safe operations
type manager struct {
	states map[string]*types.ContainerState
	mu     sync.RWMutex
	log    logrus.FieldLogger
}

// NewManager creates a new thread-safe state manager
func NewManager(log logrus.FieldLogger) Manager {
	if log == nil {
		log = logrus.New()
	}

	return &manager{
		states: make(map[string]*types.ContainerState),
		log:    log.WithField("package", "state"),
	}
}

// Start initializes the state manager with minimal setup
func (m *manager) Start(ctx context.Context) error {
	m.log.Info("State manager starting")
	m.log.Info("State manager started successfully")
	return nil
}

// Stop gracefully shuts down the state manager
func (m *manager) Stop() error {
	m.log.Info("State manager stopping")

	m.mu.Lock()
	defer m.mu.Unlock()

	// Log current state count before cleanup
	stateCount := len(m.states)
	m.log.WithField("state_count", stateCount).Info("Cleaning up container states")

	// Clear all states
	m.states = make(map[string]*types.ContainerState)

	m.log.Info("State manager stopped successfully")
	return nil
}

// SetContainerState stores or updates the state for a container
func (m *manager) SetContainerState(containerID string, state *types.ContainerState) error {
	if containerID == "" {
		return fmt.Errorf("container ID cannot be empty")
	}
	if state == nil {
		return fmt.Errorf("container state cannot be nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Update timestamp
	state.LastUpdated = time.Now()

	// Ensure container ID matches
	state.ContainerID = containerID

	// Store the state
	m.states[containerID] = state

	m.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"network_ns":   state.NetworkNS,
		"has_limits":   state.Limits != nil,
	}).Debug("Container state updated")

	return nil
}

// GetContainerState retrieves the state for a container
func (m *manager) GetContainerState(containerID string) (*types.ContainerState, bool) {
	if containerID == "" {
		return nil, false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	state, exists := m.states[containerID]
	if !exists {
		return nil, false
	}

	// Return a copy to prevent external modifications
	stateCopy := &types.ContainerState{
		ContainerID: state.ContainerID,
		NetworkNS:   state.NetworkNS,
		Limits:      state.Limits, // NetworkLimits is safe to share as it's immutable
		LastUpdated: state.LastUpdated,
	}

	return stateCopy, true
}

// RemoveContainerState removes the state for a container
func (m *manager) RemoveContainerState(containerID string) error {
	if containerID == "" {
		return fmt.Errorf("container ID cannot be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.states[containerID]; !exists {
		m.log.WithField("container_id", containerID).Debug("Attempted to remove non-existent container state")
		return nil // Not an error - idempotent operation
	}

	delete(m.states, containerID)

	m.log.WithField("container_id", containerID).Debug("Container state removed")
	return nil
}

// GetAllStates returns a copy of all container states
func (m *manager) GetAllStates() map[string]*types.ContainerState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Create a copy of the map to prevent external modifications
	states := make(map[string]*types.ContainerState, len(m.states))
	for id, state := range m.states {
		states[id] = &types.ContainerState{
			ContainerID: state.ContainerID,
			NetworkNS:   state.NetworkNS,
			Limits:      state.Limits,
			LastUpdated: state.LastUpdated,
		}
	}

	return states
}

// HasContainer checks if a container is being managed
func (m *manager) HasContainer(containerID string) bool {
	if containerID == "" {
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	_, exists := m.states[containerID]
	return exists
}

// UpdateNetworkNamespace updates the network namespace path for a container
func (m *manager) UpdateNetworkNamespace(containerID string, nsPath string) error {
	if containerID == "" {
		return fmt.Errorf("container ID cannot be empty")
	}
	if nsPath == "" {
		return fmt.Errorf("network namespace path cannot be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	state, exists := m.states[containerID]
	if !exists {
		return fmt.Errorf("%w: container %s", types.ErrContainerNotFound, containerID)
	}

	oldNsPath := state.NetworkNS
	state.NetworkNS = nsPath
	state.LastUpdated = time.Now()

	m.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"old_ns_path":  oldNsPath,
		"new_ns_path":  nsPath,
	}).Debug("Container network namespace updated")

	return nil
}

// Cleanup removes all states and performs cleanup
func (m *manager) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	stateCount := len(m.states)
	m.states = make(map[string]*types.ContainerState)

	m.log.WithField("cleaned_states", stateCount).Info("State manager cleanup completed")
	return nil
}
