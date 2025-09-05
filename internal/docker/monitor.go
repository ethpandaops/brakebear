package docker

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/ethpandaops/brakebear/internal/types"
	"github.com/sirupsen/logrus"
)

// Monitor provides Docker container event monitoring capabilities
type Monitor struct {
	client    *Client
	inspector *Inspector
	log       logrus.FieldLogger
	eventCh   chan ContainerEvent
	done      chan struct{}
	wg        sync.WaitGroup
}

// ContainerEvent represents a Docker container lifecycle event
type ContainerEvent struct {
	Type        string // "start", "stop", "die", "update"
	ContainerID string
	Timestamp   time.Time
}

// NewMonitor creates a new Docker container event monitor
func NewMonitor(client *Client, inspector *Inspector, log logrus.FieldLogger) *Monitor {
	if log == nil {
		log = logrus.New()
	}

	return &Monitor{
		client:    client,
		inspector: inspector,
		log:       log.WithField("package", "docker-monitor"),
		eventCh:   make(chan ContainerEvent, 100), // Buffered channel for better performance
		done:      make(chan struct{}),
	}
}

// Start begins monitoring Docker container events
func (m *Monitor) Start(ctx context.Context) error {
	if m.client == nil {
		return types.ErrInvalidConfiguration
	}

	m.log.Info("Starting Docker event monitoring")

	m.wg.Add(1)
	go m.watchEvents(ctx)

	m.log.Info("Docker event monitoring started successfully")
	return nil
}

// Stop gracefully stops the Docker event monitor
func (m *Monitor) Stop() error {
	m.log.Info("Stopping Docker event monitoring")

	// Signal all goroutines to stop
	close(m.done)

	// Wait for all goroutines to finish
	m.wg.Wait()

	// Close event channel
	close(m.eventCh)

	m.log.Info("Docker event monitoring stopped successfully")
	return nil
}

// Events returns the read-only channel of container events
func (m *Monitor) Events() <-chan ContainerEvent {
	return m.eventCh
}

// watchEvents is the main event watching goroutine
func (m *Monitor) watchEvents(ctx context.Context) {
	defer m.wg.Done()

	m.log.Debug("Starting Docker event watcher goroutine")

	for {
		select {
		case <-ctx.Done():
			m.log.Debug("Context cancelled, stopping event watcher")
			return
		case <-m.done:
			m.log.Debug("Stop signal received, stopping event watcher")
			return
		default:
			if err := m.startEventStream(ctx); err != nil {
				m.log.WithError(err).Warn("Event stream failed, retrying in 5 seconds")

				// Wait before retrying, but still respect cancellation
				select {
				case <-ctx.Done():
					return
				case <-m.done:
					return
				case <-time.After(5 * time.Second):
					continue
				}
			}
		}
	}
}

// startEventStream establishes a new event stream and processes events
func (m *Monitor) startEventStream(ctx context.Context) error {
	cli := m.client.GetClient()
	if cli == nil {
		return types.ErrInvalidConfiguration
	}

	// Create event filters for container events we care about
	eventFilters := filters.NewArgs()
	eventFilters.Add("type", "container")
	eventFilters.Add("event", "start")
	eventFilters.Add("event", "stop")
	eventFilters.Add("event", "die")
	eventFilters.Add("event", "update")

	m.log.Debug("Establishing Docker event stream")

	// Start event stream
	eventsCh, errsCh := cli.Events(ctx, events.ListOptions{
		Filters: eventFilters,
	})

	for {
		select {
		case <-ctx.Done():
			m.log.Debug("Context cancelled during event stream")
			return ctx.Err()
		case <-m.done:
			m.log.Debug("Stop signal received during event stream")
			return nil
		case err := <-errsCh:
			if err != nil && err != io.EOF {
				return err
			}
			m.log.Debug("Event stream ended")
			return nil
		case event := <-eventsCh:
			if err := m.processEvent(event); err != nil {
				m.log.WithError(err).Warn("Failed to process Docker event")
			}
		}
	}
}

// processEvent processes a single Docker event and sends it to the event channel
func (m *Monitor) processEvent(event events.Message) error {
	if event.Type != events.ContainerEventType {
		return nil // Ignore non-container events
	}

	m.log.WithFields(logrus.Fields{
		"event_action":   event.Action,
		"container_id":   event.Actor.ID,
		"container_name": event.Actor.Attributes["name"],
		"timestamp":      event.Time,
	}).Debug("Processing Docker event")

	containerEvent := ContainerEvent{
		Type:        string(event.Action),
		ContainerID: event.Actor.ID,
		Timestamp:   time.Unix(event.Time, 0),
	}

	// Send event to channel with timeout to prevent blocking
	select {
	case m.eventCh <- containerEvent:
		m.log.WithFields(logrus.Fields{
			"event_type":   containerEvent.Type,
			"container_id": containerEvent.ContainerID,
		}).Debug("Container event sent successfully")
	case <-time.After(1 * time.Second):
		m.log.WithFields(logrus.Fields{
			"event_type":   containerEvent.Type,
			"container_id": containerEvent.ContainerID,
		}).Warn("Failed to send container event: channel blocked")
	case <-m.done:
		m.log.Debug("Monitor stopping, discarding event")
	}

	return nil
}
