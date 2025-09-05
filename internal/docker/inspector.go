package docker

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	brakebeartypes "github.com/ethpandaops/brakebear/internal/types"
	"github.com/sirupsen/logrus"
)

// Inspector provides container inspection and discovery functionality
type Inspector struct {
	client *Client
	log    logrus.FieldLogger
}

// NewInspector creates a new container inspector
func NewInspector(client *Client, log logrus.FieldLogger) *Inspector {
	if log == nil {
		log = logrus.New()
	}

	return &Inspector{
		client: client,
		log:    log.WithField("package", "docker-inspector"),
	}
}

// GetContainerByIdentifier finds a container by name, ID, or labels
func (i *Inspector) GetContainerByIdentifier(ctx context.Context, id brakebeartypes.ContainerIdentifier) (*brakebeartypes.Container, error) {
	i.log.WithFields(logrus.Fields{
		"identifier_type":  id.Type,
		"identifier_value": id.Value,
	}).Debug("Looking for container by identifier")

	containers, err := i.ListContainers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	switch id.Type {
	case brakebeartypes.IdentifierTypeName:
		name, ok := id.Value.(string)
		if !ok {
			return nil, fmt.Errorf("invalid name identifier: expected string, got %T", id.Value)
		}
		return i.findByName(containers, name)

	case brakebeartypes.IdentifierTypeID:
		containerID, ok := id.Value.(string)
		if !ok {
			return nil, fmt.Errorf("invalid ID identifier: expected string, got %T", id.Value)
		}
		return i.findByID(containers, containerID)

	case brakebeartypes.IdentifierTypeLabels:
		labels, ok := id.Value.(map[string]string)
		if !ok {
			return nil, fmt.Errorf("invalid labels identifier: expected map[string]string, got %T", id.Value)
		}
		return i.findByLabels(containers, labels)

	default:
		return nil, fmt.Errorf("unsupported identifier type: %s", id.Type)
	}
}

// GetContainerNetworkNamespace extracts the network namespace path from a container
func (i *Inspector) GetContainerNetworkNamespace(ctx context.Context, containerID string) (string, error) {
	i.log.WithField("container_id", containerID).Debug("Getting container network namespace")

	cli := i.client.GetClient()
	if cli == nil {
		return "", fmt.Errorf("Docker client not initialized")
	}

	// Inspect the container to get detailed information
	inspect, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return "", fmt.Errorf("failed to inspect container %s: %w", containerID, err)
	}

	netnsPath, err := i.extractNetnsPath(inspect)
	if err != nil {
		return "", fmt.Errorf("failed to extract netns path for container %s: %w", containerID, err)
	}

	i.log.WithFields(logrus.Fields{
		"container_id": containerID,
		"netns_path":   netnsPath,
	}).Debug("Extracted network namespace path")

	return netnsPath, nil
}

// ListContainers returns a list of all running containers
func (i *Inspector) ListContainers(ctx context.Context) ([]brakebeartypes.Container, error) {
	i.log.Debug("Listing all running containers")

	cli := i.client.GetClient()
	if cli == nil {
		return nil, fmt.Errorf("Docker client not initialized")
	}

	// List only running containers
	dockerContainers, err := cli.ContainerList(ctx, container.ListOptions{
		All: false, // Only running containers
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list Docker containers: %w", err)
	}

	containers := make([]brakebeartypes.Container, 0, len(dockerContainers))
	for _, dockerContainer := range dockerContainers {
		// Convert Docker container to our internal type
		bbContainer := brakebeartypes.Container{
			ID:     dockerContainer.ID,
			Name:   strings.TrimPrefix(dockerContainer.Names[0], "/"), // Remove leading slash
			Labels: dockerContainer.Labels,
			State:  dockerContainer.State,
			Status: dockerContainer.Status,
		}

		containers = append(containers, bbContainer)
	}

	i.log.WithField("container_count", len(containers)).Debug("Listed containers successfully")
	return containers, nil
}

// findByName finds a container by name (supports prefix matching)
func (i *Inspector) findByName(containers []brakebeartypes.Container, name string) (*brakebeartypes.Container, error) {
	i.log.WithField("name", name).Debug("Searching for container by name")

	for _, container := range containers {
		// Check for exact match first
		if container.Name == name {
			i.log.WithFields(logrus.Fields{
				"container_id":   container.ID,
				"container_name": container.Name,
			}).Debug("Found container by exact name match")
			return &container, nil
		}

		// Check for prefix match
		if strings.HasPrefix(container.Name, name) {
			i.log.WithFields(logrus.Fields{
				"container_id":   container.ID,
				"container_name": container.Name,
			}).Debug("Found container by name prefix match")
			return &container, nil
		}
	}

	return nil, fmt.Errorf("%w: no container found with name %s", brakebeartypes.ErrContainerNotFound, name)
}

// findByID finds a container by ID (supports prefix matching)
func (i *Inspector) findByID(containers []brakebeartypes.Container, id string) (*brakebeartypes.Container, error) {
	i.log.WithField("id", id).Debug("Searching for container by ID")

	for _, container := range containers {
		// Check for exact match first
		if container.ID == id {
			i.log.WithFields(logrus.Fields{
				"container_id":   container.ID,
				"container_name": container.Name,
			}).Debug("Found container by exact ID match")
			return &container, nil
		}

		// Check for prefix match (Docker allows short IDs)
		if strings.HasPrefix(container.ID, id) {
			i.log.WithFields(logrus.Fields{
				"container_id":   container.ID,
				"container_name": container.Name,
			}).Debug("Found container by ID prefix match")
			return &container, nil
		}
	}

	return nil, fmt.Errorf("%w: no container found with ID %s", brakebeartypes.ErrContainerNotFound, id)
}

// findByLabels finds a container by matching labels
func (i *Inspector) findByLabels(containers []brakebeartypes.Container, targetLabels map[string]string) (*brakebeartypes.Container, error) {
	i.log.WithField("labels", targetLabels).Debug("Searching for container by labels")

	for _, container := range containers {
		if i.matchesLabels(container.Labels, targetLabels) {
			i.log.WithFields(logrus.Fields{
				"container_id":   container.ID,
				"container_name": container.Name,
				"labels":         container.Labels,
			}).Debug("Found container by label match")
			return &container, nil
		}
	}

	return nil, fmt.Errorf("%w: no container found with labels %v", brakebeartypes.ErrContainerNotFound, targetLabels)
}

// matchesLabels checks if container labels match all target labels
func (i *Inspector) matchesLabels(containerLabels map[string]string, targetLabels map[string]string) bool {
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

// extractNetnsPath extracts the network namespace path from container inspection data
func (i *Inspector) extractNetnsPath(inspect types.ContainerJSON) (string, error) {
	if inspect.State == nil {
		return "", fmt.Errorf("container state information not available")
	}

	pid := inspect.State.Pid
	if pid == 0 {
		return "", fmt.Errorf("container PID not available or container not running")
	}

	// Construct the network namespace path
	netnsPath := filepath.Join("/proc", fmt.Sprintf("%d", pid), "ns", "net")

	i.log.WithFields(logrus.Fields{
		"container_id": inspect.ID,
		"pid":          pid,
		"netns_path":   netnsPath,
	}).Debug("Extracted network namespace path from container")

	return netnsPath, nil
}
