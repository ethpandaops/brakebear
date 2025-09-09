package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ethpandaops/brakebear/internal/types"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Config represents the main configuration structure for BrakeBear
type Config struct {
	// LogLevel specifies the logging level (debug, info, warn, error)
	LogLevel string `mapstructure:"log_level"`
	// DockerContainers contains the list of container configurations
	DockerContainers []ContainerConfig `mapstructure:"docker_containers"`
}

// ContainerConfig represents the configuration for a single Docker container
type ContainerConfig struct {
	// Name identifies the container by its name (mutually exclusive with ID and Labels)
	Name string `mapstructure:"name"`
	// ID identifies the container by its ID (mutually exclusive with Name and Labels)
	ID string `mapstructure:"id"`
	// Labels identifies the container by its labels (mutually exclusive with Name and ID)
	Labels map[string]string `mapstructure:"labels"`
	// DownloadRate specifies the download bandwidth limit (e.g., "100Mbps", "1Gbps")
	DownloadRate string `mapstructure:"download_rate"`
	// UploadRate specifies the upload bandwidth limit (e.g., "100Mbps", "1Gbps")
	UploadRate string `mapstructure:"upload_rate"`
	// Latency specifies the network latency to add (e.g., "20ms", "100ms")
	Latency string `mapstructure:"latency"`
	// Jitter specifies the network jitter to add (e.g., "5ms", "10ms")
	Jitter string `mapstructure:"jitter"`
	// Loss specifies the packet loss percentage (e.g., "0.1%", "1%")
	Loss string `mapstructure:"loss"`
	// ExcludeNetworks specifies networks to exclude from traffic limiting
	ExcludeNetworks []ExcludeNetwork `mapstructure:"exclude_networks"`
}

// ExcludeNetwork represents a network exclusion configuration
type ExcludeNetwork struct {
	// Type specifies the exclusion type (cidr, private-ranges, dns)
	Type string `mapstructure:"type"`
	// CIDRConfig contains CIDR-specific configuration
	CIDRConfig *CIDRConfig `mapstructure:"cidr_config"`
	// DNSConfig contains DNS-specific configuration
	DNSConfig *DNSConfig `mapstructure:"dns_config"`
}

// CIDRConfig contains CIDR range configurations
type CIDRConfig struct {
	// Ranges specifies the CIDR ranges to exclude
	Ranges []string `mapstructure:"ranges"`
}

// DNSConfig contains DNS resolution configuration
type DNSConfig struct {
	// Names specifies the hostnames to resolve
	Names []string `mapstructure:"names"`
	// CheckInterval specifies how often to check DNS for changes
	CheckInterval string `mapstructure:"check_interval"`
}

// LoadConfig loads configuration from a YAML file using viper
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return nil, errors.New("configuration file path cannot be empty")
	}

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file not found: %s", path)
	}

	viper.SetConfigFile(path)
	viper.SetConfigType("yaml")

	// Set defaults
	viper.SetDefault("log_level", "info")

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	// Validate the configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &config, nil
}

// Validate validates the entire configuration including all containers
func (c *Config) Validate() error {
	// Validate log level
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}

	if !validLogLevels[c.LogLevel] {
		return fmt.Errorf("invalid log level: %s (must be one of: debug, info, warn, error)", c.LogLevel)
	}

	// Validate that we have at least one container
	if len(c.DockerContainers) == 0 {
		return errors.New("at least one docker container must be configured")
	}

	// Track container identifiers to check for duplicates
	identifiers := make(map[string]bool)

	// Validate each container configuration
	for i, container := range c.DockerContainers {
		if err := container.validate(); err != nil {
			return fmt.Errorf("container configuration %d validation failed: %w", i, err)
		}

		// Check for duplicate container identifiers
		identifier := container.getUniqueIdentifier()
		if identifiers[identifier] {
			return fmt.Errorf("duplicate container configuration found: %s", identifier)
		}
		identifiers[identifier] = true
	}

	return nil
}

// ToNetworkLimits converts the container configuration to NetworkLimits using types.Parse* functions
func (c *ContainerConfig) ToNetworkLimits() (*types.NetworkLimits, error) {
	limits := &types.NetworkLimits{}

	if err := c.parseRates(limits); err != nil {
		return nil, err
	}

	if err := c.parseDurations(limits); err != nil {
		return nil, err
	}

	if err := c.parseLoss(limits); err != nil {
		return nil, err
	}

	if err := c.parseExcludeNetworks(limits); err != nil {
		return nil, err
	}

	return limits, nil
}

// GetIdentifier extracts the container identifier (name, id, or labels)
func (c *ContainerConfig) GetIdentifier() types.ContainerIdentifier {
	if c.Name != "" {
		return types.ContainerIdentifier{
			Type:  types.IdentifierTypeName,
			Value: c.Name,
		}
	}
	if c.ID != "" {
		return types.ContainerIdentifier{
			Type:  types.IdentifierTypeID,
			Value: c.ID,
		}
	}
	if len(c.Labels) > 0 {
		return types.ContainerIdentifier{
			Type:  types.IdentifierTypeLabels,
			Value: c.Labels,
		}
	}

	// This should never happen if validation is done properly
	logrus.Warn("Container configuration has no valid identifier")
	return types.ContainerIdentifier{}
}

// GetExcludeNetworkRanges returns the list of CIDR ranges to exclude from traffic limiting
func (c *ContainerConfig) GetExcludeNetworkRanges() ([]string, error) {
	// Convert config.ExcludeNetwork to types.ExcludeNetwork
	typesExcludes := make([]types.ExcludeNetwork, 0, len(c.ExcludeNetworks))
	for _, exclude := range c.ExcludeNetworks {
		typesExclude := types.ExcludeNetwork{
			Type: exclude.Type,
		}
		if exclude.CIDRConfig != nil {
			typesExclude.CIDRConfig = &types.CIDRConfig{
				Ranges: exclude.CIDRConfig.Ranges,
			}
		}
		if exclude.DNSConfig != nil {
			interval, err := time.ParseDuration(exclude.DNSConfig.CheckInterval)
			if err != nil {
				// Default to 5 minutes if parsing fails
				interval = 5 * time.Minute
			}
			typesExclude.DNSConfig = &types.DNSConfig{
				Names:         exclude.DNSConfig.Names,
				CheckInterval: interval,
			}
		}
		typesExcludes = append(typesExcludes, typesExclude)
	}

	// Note: DNS resolver not available at config parsing time, pass nil for now
	// DNS exclusions will be resolved at runtime when the resolver is available
	ranges, err := types.ParseExcludeNetworks(typesExcludes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse exclude networks: %w", err)
	}
	return ranges, nil
}

// validate validates a single container configuration
func (c *ContainerConfig) validate() error {
	if err := c.validateIdentifiers(); err != nil {
		return err
	}

	if err := c.validateNetworkParams(); err != nil {
		return err
	}

	return nil
}

// getUniqueIdentifier returns a unique string identifier for this container configuration
func (c *ContainerConfig) getUniqueIdentifier() string {
	if c.Name != "" {
		return "name:" + c.Name
	}
	if c.ID != "" {
		return "id:" + c.ID
	}
	if len(c.Labels) > 0 {
		// Create a consistent string representation of labels
		return fmt.Sprintf("labels:%v", c.Labels)
	}
	return "unknown"
}

func (c *ContainerConfig) parseRates(limits *types.NetworkLimits) error {
	if c.DownloadRate != "" {
		rate, err := types.ParseRate(c.DownloadRate)
		if err != nil {
			return fmt.Errorf("failed to parse download rate: %w", err)
		}
		limits.DownloadRate = rate
	}

	if c.UploadRate != "" {
		rate, err := types.ParseRate(c.UploadRate)
		if err != nil {
			return fmt.Errorf("failed to parse upload rate: %w", err)
		}
		limits.UploadRate = rate
	}

	return nil
}

func (c *ContainerConfig) parseDurations(limits *types.NetworkLimits) error {
	if c.Latency != "" {
		latency, err := types.ParseDuration(c.Latency)
		if err != nil {
			return fmt.Errorf("failed to parse latency: %w", err)
		}
		limits.Latency = latency
	}

	if c.Jitter != "" {
		jitter, err := types.ParseDuration(c.Jitter)
		if err != nil {
			return fmt.Errorf("failed to parse jitter: %w", err)
		}
		limits.Jitter = jitter
	}

	return nil
}

func (c *ContainerConfig) parseLoss(limits *types.NetworkLimits) error {
	if c.Loss != "" {
		loss, err := types.ParseLoss(c.Loss)
		if err != nil {
			return fmt.Errorf("failed to parse loss: %w", err)
		}
		limits.Loss = loss
	}

	return nil
}

func (c *ContainerConfig) parseExcludeNetworks(limits *types.NetworkLimits) error {
	if len(c.ExcludeNetworks) == 0 {
		return nil
	}

	// Convert config.ExcludeNetwork to types.ExcludeNetwork
	excludeNetworks := make([]types.ExcludeNetwork, 0, len(c.ExcludeNetworks))
	for i, exclude := range c.ExcludeNetworks {
		// Validate before converting
		if err := validateExcludeNetwork(exclude, i); err != nil {
			return fmt.Errorf("failed to parse exclude networks: %w", err)
		}

		// Convert to types.ExcludeNetwork
		typesExclude := types.ExcludeNetwork{
			Type: exclude.Type,
		}

		// Convert CIDRConfig if present
		if exclude.CIDRConfig != nil {
			typesExclude.CIDRConfig = &types.CIDRConfig{
				Ranges: exclude.CIDRConfig.Ranges,
			}
		}

		// Convert DNSConfig if present
		if exclude.DNSConfig != nil {
			interval, err := time.ParseDuration(exclude.DNSConfig.CheckInterval)
			if err != nil {
				// Default to 5 minutes if parsing fails
				interval = 5 * time.Minute
			}
			typesExclude.DNSConfig = &types.DNSConfig{
				Names:         exclude.DNSConfig.Names,
				CheckInterval: interval,
			}
		}

		excludeNetworks = append(excludeNetworks, typesExclude)
	}

	limits.ExcludeNetworks = excludeNetworks
	return nil
}

func (c *ContainerConfig) validateIdentifiers() error {
	identifierCount := 0
	if c.Name != "" {
		identifierCount++
	}
	if c.ID != "" {
		identifierCount++
	}
	if len(c.Labels) > 0 {
		identifierCount++
	}

	if identifierCount == 0 {
		return errors.New("container must be identified by name, id, or labels")
	}
	if identifierCount > 1 {
		return errors.New("container identifiers (name, id, labels) are mutually exclusive - only one can be set")
	}

	return nil
}

func (c *ContainerConfig) validateNetworkParams() error {
	if err := c.validateRateParams(); err != nil {
		return err
	}

	if err := c.validateDurationParams(); err != nil {
		return err
	}

	if err := c.validateLossParam(); err != nil {
		return err
	}

	if err := c.validateExcludeNetworks(); err != nil {
		return err
	}

	return nil
}

func (c *ContainerConfig) validateRateParams() error {
	if c.DownloadRate != "" {
		if _, err := types.ParseRate(c.DownloadRate); err != nil {
			return fmt.Errorf("invalid download_rate: %w", err)
		}
	}

	if c.UploadRate != "" {
		if _, err := types.ParseRate(c.UploadRate); err != nil {
			return fmt.Errorf("invalid upload_rate: %w", err)
		}
	}

	return nil
}

func (c *ContainerConfig) validateDurationParams() error {
	if c.Latency != "" {
		if _, err := types.ParseDuration(c.Latency); err != nil {
			return fmt.Errorf("invalid latency: %w", err)
		}
	}

	if c.Jitter != "" {
		if _, err := types.ParseDuration(c.Jitter); err != nil {
			return fmt.Errorf("invalid jitter: %w", err)
		}
	}

	return nil
}

func (c *ContainerConfig) validateLossParam() error {
	if c.Loss != "" {
		if _, err := types.ParseLoss(c.Loss); err != nil {
			return fmt.Errorf("invalid loss: %w", err)
		}
	}

	return nil
}

// validateExcludeNetworks validates the exclude networks configuration
func (c *ContainerConfig) validateExcludeNetworks() error {
	for i, exclude := range c.ExcludeNetworks {
		if err := validateExcludeNetwork(exclude, i); err != nil {
			return err
		}
	}
	return nil
}

// validateExcludeNetwork validates a single exclude network configuration
func validateExcludeNetwork(exclude ExcludeNetwork, index int) error {
	if exclude.Type == "" {
		return fmt.Errorf("exclude network %d: type cannot be empty", index)
	}

	if err := validateExcludeNetworkType(exclude.Type, index); err != nil {
		return err
	}

	return validateExcludeNetworkConfig(exclude, index)
}

// validateExcludeNetworkType validates the exclude network type
func validateExcludeNetworkType(excludeType string, index int) error {
	validTypes := []string{"cidr", "private-ranges", "dns"}
	for _, validType := range validTypes {
		if excludeType == validType {
			return nil
		}
	}
	return fmt.Errorf("exclude network %d: unsupported type '%s', supported types: %v", index, excludeType, validTypes)
}

// validateExcludeNetworkConfig validates type-specific configuration
func validateExcludeNetworkConfig(exclude ExcludeNetwork, index int) error {
	switch exclude.Type {
	case "cidr":
		return validateCIDRExcludeConfig(exclude.CIDRConfig, index)
	case "private-ranges":
		return validatePrivateRangesConfig(exclude.CIDRConfig, index)
	case "dns":
		return validateDNSExcludeConfig(exclude.DNSConfig, index)
	default:
		return nil
	}
}

// validateCIDRExcludeConfig validates CIDR exclusion configuration
func validateCIDRExcludeConfig(config *CIDRConfig, index int) error {
	if config == nil {
		return fmt.Errorf("exclude network %d: cidr_config is required for type 'cidr'", index)
	}
	if len(config.Ranges) == 0 {
		return fmt.Errorf("exclude network %d: cidr_config.ranges cannot be empty for type 'cidr'", index)
	}

	for j, cidr := range config.Ranges {
		if err := types.ValidateCIDRRange(cidr); err != nil {
			return fmt.Errorf("exclude network %d, CIDR range %d: %w", index, j, err)
		}
	}
	return nil
}

// validatePrivateRangesConfig validates private ranges configuration
func validatePrivateRangesConfig(config *CIDRConfig, index int) error {
	if config != nil {
		return fmt.Errorf("exclude network %d: cidr_config should not be specified for type 'private-ranges'", index)
	}
	return nil
}

// validateDNSExcludeConfig validates DNS exclusion configuration
func validateDNSExcludeConfig(config *DNSConfig, index int) error {
	if config == nil {
		return fmt.Errorf("exclude network %d: dns_config is required for type 'dns'", index)
	}
	if len(config.Names) == 0 {
		return fmt.Errorf("exclude network %d: dns_config.names cannot be empty for type 'dns'", index)
	}

	if err := validateDNSCheckInterval(config, index); err != nil {
		return err
	}

	return validateDNSHostnames(config.Names, index)
}

// validateDNSCheckInterval validates the DNS check interval
func validateDNSCheckInterval(config *DNSConfig, index int) error {
	if config.CheckInterval == "" {
		config.CheckInterval = "5m" // Default to 5 minutes
		return nil
	}

	if _, err := time.ParseDuration(config.CheckInterval); err != nil {
		return fmt.Errorf("exclude network %d: invalid dns_config.check_interval '%s': %w", index, config.CheckInterval, err)
	}
	return nil
}

// validateDNSHostnames validates the DNS hostnames
func validateDNSHostnames(hostnames []string, index int) error {
	for j, hostname := range hostnames {
		if hostname == "" {
			return fmt.Errorf("exclude network %d, hostname %d: hostname cannot be empty", index, j)
		}
	}
	return nil
}
