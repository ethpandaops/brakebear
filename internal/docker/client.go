package docker

import (
	"context"
	"errors"
	"fmt"

	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
)

// Client wraps the Docker client with logging and lifecycle management
type Client struct {
	client *client.Client
	log    logrus.FieldLogger
}

// NewClient creates a new Docker client with API version negotiation
func NewClient(log logrus.FieldLogger) (*Client, error) {
	if log == nil {
		return nil, errors.New("logger cannot be nil")
	}

	// Add package-specific fields to logger
	logger := log.WithField("package", "docker")

	return &Client{
		log: logger,
	}, nil
}

// Start initializes the Docker client and verifies connectivity
func (c *Client) Start(ctx context.Context) error {
	c.log.Debug("Initializing Docker client")

	// Create Docker client with API version negotiation
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}

	c.client = cli

	// Verify connectivity to Docker daemon
	if err := c.Ping(ctx); err != nil {
		return fmt.Errorf("failed to connect to Docker daemon: %w", err)
	}

	c.log.Info("Docker client initialized successfully")
	return nil
}

// Stop closes the Docker client connection
func (c *Client) Stop() error {
	if c.client == nil {
		return nil
	}

	c.log.Debug("Closing Docker client connection")

	if err := c.client.Close(); err != nil {
		return fmt.Errorf("failed to close Docker client: %w", err)
	}

	c.client = nil
	c.log.Info("Docker client connection closed")
	return nil
}

// GetClient returns the underlying Docker client
func (c *Client) GetClient() *client.Client {
	return c.client
}

// Ping verifies connectivity to the Docker daemon
func (c *Client) Ping(ctx context.Context) error {
	if c.client == nil {
		return errors.New("docker client not initialized")
	}

	c.log.Debug("Pinging Docker daemon")

	pong, err := c.client.Ping(ctx)
	if err != nil {
		return fmt.Errorf("docker daemon ping failed: %w", err)
	}

	c.log.WithFields(logrus.Fields{
		"api_version": pong.APIVersion,
		"version":     pong.Experimental,
	}).Debug("Docker daemon ping successful")

	return nil
}
