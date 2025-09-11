package docker

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/sirupsen/logrus"
)

// NetworkEvent represents a Docker network event
type NetworkEvent struct {
	Type      string    // "create", "destroy", "connect", "disconnect"
	NetworkID string    // Network ID
	Name      string    // Network name
	Driver    string    // Network driver
	Timestamp time.Time // Event timestamp
}

// NetworkEventHandler handles Docker network events
type NetworkEventHandler interface {
	OnNetworkEvent(ctx context.Context, event NetworkEvent) error
}

// NetworkMonitor monitors Docker network events
type NetworkMonitor struct {
	client   *Client
	log      logrus.FieldLogger
	handlers []NetworkEventHandler
	mu       sync.RWMutex
	stopCh   chan struct{}
	doneCh   chan struct{}
	started  bool
}

// NewNetworkMonitor creates a new Docker network event monitor
func NewNetworkMonitor(client *Client, log logrus.FieldLogger) *NetworkMonitor {
	if log == nil {
		log = logrus.New()
	}

	return &NetworkMonitor{
		client:   client,
		log:      log.WithField("package", "docker-network-monitor"),
		handlers: make([]NetworkEventHandler, 0),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

// Start begins monitoring Docker network events
func (nm *NetworkMonitor) Start(ctx context.Context) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if nm.started {
		return errors.New("network monitor already started")
	}

	if nm.client.GetClient() == nil {
		return errors.New("docker client not initialized")
	}

	nm.log.Info("Starting Docker network event monitor")

	// Start the event monitoring goroutine
	go nm.monitorEvents(ctx)

	nm.started = true
	nm.log.Info("Docker network event monitor started")
	return nil
}

// Stop stops the network event monitor
func (nm *NetworkMonitor) Stop() error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if !nm.started {
		return nil
	}

	nm.log.Info("Stopping Docker network event monitor")

	// Signal stop and wait for completion
	close(nm.stopCh)

	// Wait for monitoring goroutine to finish with timeout
	select {
	case <-nm.doneCh:
		nm.log.Info("Docker network event monitor stopped")
	case <-time.After(5 * time.Second):
		nm.log.Warn("Docker network event monitor stop timeout")
	}

	nm.started = false
	return nil
}

// AddHandler adds a network event handler
func (nm *NetworkMonitor) AddHandler(handler NetworkEventHandler) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	nm.handlers = append(nm.handlers, handler)
	nm.log.WithField("handler_count", len(nm.handlers)).Debug("Added network event handler")
}

// RemoveHandler removes a network event handler
func (nm *NetworkMonitor) RemoveHandler(handler NetworkEventHandler) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	for i, h := range nm.handlers {
		if h == handler {
			nm.handlers = append(nm.handlers[:i], nm.handlers[i+1:]...)
			nm.log.WithField("handler_count", len(nm.handlers)).Debug("Removed network event handler")
			break
		}
	}
}

// monitorEvents runs the event monitoring loop
func (nm *NetworkMonitor) monitorEvents(ctx context.Context) {
	defer close(nm.doneCh)

	nm.log.Debug("Starting Docker network event monitoring loop")

	// Set up event filters for network events only
	eventFilters := filters.NewArgs()
	eventFilters.Add("type", "network")

	for {
		select {
		case <-nm.stopCh:
			nm.log.Debug("Network event monitor received stop signal")
			return
		case <-ctx.Done():
			nm.log.Debug("Network event monitor context cancelled")
			return
		default:
			// Continue with event monitoring
		}

		// Get event stream
		eventCh, errCh := nm.client.GetClient().Events(ctx, events.ListOptions{
			Filters: eventFilters,
		})

		// Apply filters manually since Docker's event filtering might be limited
		nm.processEventStream(ctx, eventCh, errCh)

		// If we reach here, the event stream was interrupted
		// Wait a bit before reconnecting
		select {
		case <-time.After(time.Second):
			nm.log.Debug("Reconnecting to Docker event stream")
		case <-nm.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// processEventStream processes events from the Docker event stream
func (nm *NetworkMonitor) processEventStream(ctx context.Context, eventCh <-chan events.Message, errCh <-chan error) {
	for {
		select {
		case <-nm.stopCh:
			return
		case <-ctx.Done():
			return
		case err := <-errCh:
			if err != nil && !errors.Is(err, io.EOF) {
				nm.log.WithError(err).Error("Docker event stream error")
			}
			return
		case msg, ok := <-eventCh:
			if !ok {
				nm.log.Debug("Docker event stream closed")
				return
			}

			// Process network events only
			if msg.Type == events.NetworkEventType {
				nm.handleNetworkEvent(ctx, msg)
			}
		}
	}
}

// handleNetworkEvent processes a single network event
func (nm *NetworkMonitor) handleNetworkEvent(ctx context.Context, msg events.Message) {
	networkEvent := NetworkEvent{
		Type:      string(msg.Action),
		NetworkID: msg.Actor.ID,
		Timestamp: time.Unix(msg.Time, msg.TimeNano),
	}

	// Extract network name from attributes
	if name, ok := msg.Actor.Attributes["name"]; ok {
		networkEvent.Name = name
	}

	// Extract network driver from attributes
	if driver, ok := msg.Actor.Attributes["type"]; ok {
		networkEvent.Driver = driver
	}

	nm.log.WithFields(logrus.Fields{
		"event_type":   networkEvent.Type,
		"network_id":   networkEvent.NetworkID,
		"network_name": networkEvent.Name,
		"driver":       networkEvent.Driver,
		"timestamp":    networkEvent.Timestamp,
	}).Debug("Received network event")

	// Notify all handlers
	nm.mu.RLock()
	handlers := make([]NetworkEventHandler, len(nm.handlers))
	copy(handlers, nm.handlers)
	nm.mu.RUnlock()

	for _, handler := range handlers {
		if err := handler.OnNetworkEvent(ctx, networkEvent); err != nil {
			nm.log.WithFields(logrus.Fields{
				"event_type":   networkEvent.Type,
				"network_id":   networkEvent.NetworkID,
				"network_name": networkEvent.Name,
				"error":        err.Error(),
			}).Error("Network event handler failed")
		}
	}
}
