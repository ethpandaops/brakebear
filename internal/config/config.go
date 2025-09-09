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
	// Exclusions specifies networks to exclude from traffic limiting
	Exclusions *ExclusionsConfig `mapstructure:"exclusions"`
}

// ExclusionsConfig represents the new object-based exclusion configuration
type ExclusionsConfig struct {
	// CIDR contains CIDR-specific configuration
	CIDR *CIDRConfig `mapstructure:"cidr"`
	// DNS contains DNS-specific configuration
	DNS *DNSConfig `mapstructure:"dns"`
	// Ports contains port-specific configuration
	Ports *PortConfig `mapstructure:"ports"`
	// PrivateNetworks enables RFC1918 private network exclusions
	PrivateNetworks *bool `mapstructure:"private-networks"`
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

// PortConfig contains port exclusion configuration
type PortConfig struct {
	// TCP specifies TCP ports to exclude (e.g., ["80", "443", "8000-9000"])
	TCP []string `mapstructure:"tcp"`
	// UDP specifies UDP ports to exclude (e.g., ["53", "5353"])
	UDP []string `mapstructure:"udp"`
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

	if err := c.parseExclusionsConfig(limits); err != nil {
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
	if c.Exclusions == nil {
		return nil, nil
	}

	// Convert ExclusionsConfig to types.ExcludeNetwork for processing
	var typesExcludes []types.ExcludeNetwork

	// Add private networks if enabled
	if c.Exclusions.PrivateNetworks != nil && *c.Exclusions.PrivateNetworks {
		typesExcludes = append(typesExcludes, types.ExcludeNetwork{Type: "private-networks"})
	}

	// Add CIDR exclusions
	if c.Exclusions.CIDR != nil {
		typesExcludes = append(typesExcludes, types.ExcludeNetwork{
			Type:       "cidr",
			CIDRConfig: &types.CIDRConfig{Ranges: c.Exclusions.CIDR.Ranges},
		})
	}

	// Add DNS exclusions
	if c.Exclusions.DNS != nil {
		interval, err := time.ParseDuration(c.Exclusions.DNS.CheckInterval)
		if err != nil {
			// Default to 5 minutes if parsing fails
			interval = 5 * time.Minute
		}
		typesExcludes = append(typesExcludes, types.ExcludeNetwork{
			Type: "dns",
			DNSConfig: &types.DNSConfig{
				Names:         c.Exclusions.DNS.Names,
				CheckInterval: interval,
			},
		})
	}

	// Add port exclusions
	if c.Exclusions.Ports != nil {
		typesExcludes = append(typesExcludes, types.ExcludeNetwork{
			Type: "ports",
			PortConfig: &types.PortConfig{
				TCP: c.Exclusions.Ports.TCP,
				UDP: c.Exclusions.Ports.UDP,
			},
		})
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

func (c *ContainerConfig) parseExclusionsConfig(limits *types.NetworkLimits) error {
	if c.Exclusions == nil {
		return nil
	}

	// Validate exclusions config first
	if err := validateExclusionsConfig(c.Exclusions); err != nil {
		return fmt.Errorf("failed to validate exclusions config: %w", err)
	}

	// Convert ExclusionsConfig to []types.ExcludeNetwork for backward compatibility
	var excludeNetworks []types.ExcludeNetwork

	// Add private networks if enabled
	if c.Exclusions.PrivateNetworks != nil && *c.Exclusions.PrivateNetworks {
		excludeNetworks = append(excludeNetworks, types.ExcludeNetwork{Type: "private-networks"})
	}

	// Add CIDR exclusions
	if c.Exclusions.CIDR != nil {
		excludeNetworks = append(excludeNetworks, types.ExcludeNetwork{
			Type:       "cidr",
			CIDRConfig: &types.CIDRConfig{Ranges: c.Exclusions.CIDR.Ranges},
		})
	}

	// Add DNS exclusions
	if c.Exclusions.DNS != nil {
		interval, err := time.ParseDuration(c.Exclusions.DNS.CheckInterval)
		if err != nil {
			// Default to 5 minutes if parsing fails
			interval = 5 * time.Minute
		}
		excludeNetworks = append(excludeNetworks, types.ExcludeNetwork{
			Type: "dns",
			DNSConfig: &types.DNSConfig{
				Names:         c.Exclusions.DNS.Names,
				CheckInterval: interval,
			},
		})
	}

	// Add port exclusions
	if c.Exclusions.Ports != nil {
		excludeNetworks = append(excludeNetworks, types.ExcludeNetwork{
			Type: "ports",
			PortConfig: &types.PortConfig{
				TCP: c.Exclusions.Ports.TCP,
				UDP: c.Exclusions.Ports.UDP,
			},
		})
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

	if err := c.validateExclusionsConfig(); err != nil {
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

// validateExclusionsConfig validates the exclusions configuration
func (c *ContainerConfig) validateExclusionsConfig() error {
	if c.Exclusions == nil {
		return nil
	}

	return validateExclusionsConfig(c.Exclusions)
}

// validateExclusionsConfig validates a single exclusions configuration
func validateExclusionsConfig(exclusions *ExclusionsConfig) error {
	if exclusions == nil {
		return nil
	}

	// Validate CIDR configuration
	if exclusions.CIDR != nil {
		if err := validateCIDRConfig(exclusions.CIDR, "cidr"); err != nil {
			return err
		}
	}

	// Validate DNS configuration
	if exclusions.DNS != nil {
		if err := validateDNSConfig(exclusions.DNS, "dns"); err != nil {
			return err
		}
	}

	// Validate port configuration
	if exclusions.Ports != nil {
		if err := validatePortConfig(exclusions.Ports, "ports"); err != nil {
			return err
		}
	}

	// Private networks is just a boolean, no validation needed beyond type checking

	return nil
}

// validateCIDRConfig validates CIDR exclusion configuration
func validateCIDRConfig(config *CIDRConfig, context string) error {
	if config == nil {
		return fmt.Errorf("%s: configuration is required", context)
	}
	if len(config.Ranges) == 0 {
		return fmt.Errorf("%s: ranges cannot be empty", context)
	}

	for j, cidr := range config.Ranges {
		if err := types.ValidateCIDRRange(cidr); err != nil {
			return fmt.Errorf("%s, CIDR range %d: %w", context, j, err)
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

// validateDNSConfig validates DNS exclusion configuration
func validateDNSConfig(config *DNSConfig, context string) error {
	if config == nil {
		return fmt.Errorf("%s: configuration is required", context)
	}
	if len(config.Names) == 0 {
		return fmt.Errorf("%s: names cannot be empty", context)
	}

	if err := validateDNSCheckIntervalForConfig(config, context); err != nil {
		return err
	}

	return validateDNSHostnamesForConfig(config.Names, context)
}

// validateDNSExcludeConfig validates DNS exclusion configuration (legacy)
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

// validateDNSCheckIntervalForConfig validates the DNS check interval for new config structure
func validateDNSCheckIntervalForConfig(config *DNSConfig, context string) error {
	if config.CheckInterval == "" {
		config.CheckInterval = "5m" // Default to 5 minutes
		return nil
	}

	if _, err := time.ParseDuration(config.CheckInterval); err != nil {
		return fmt.Errorf("%s: invalid check_interval '%s': %w", context, config.CheckInterval, err)
	}
	return nil
}

// validateDNSCheckInterval validates the DNS check interval (legacy)
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

// validateDNSHostnamesForConfig validates the DNS hostnames for new config structure
func validateDNSHostnamesForConfig(hostnames []string, context string) error {
	for j, hostname := range hostnames {
		if hostname == "" {
			return fmt.Errorf("%s, hostname %d: hostname cannot be empty", context, j)
		}
	}
	return nil
}

// validateDNSHostnames validates the DNS hostnames (legacy)
func validateDNSHostnames(hostnames []string, index int) error {
	for j, hostname := range hostnames {
		if hostname == "" {
			return fmt.Errorf("exclude network %d, hostname %d: hostname cannot be empty", index, j)
		}
	}
	return nil
}

// validatePortConfig validates port exclusion configuration
func validatePortConfig(config *PortConfig, context string) error {
	if config == nil {
		return fmt.Errorf("%s: configuration is required", context)
	}

	// Ensure at least one port specification is provided
	if len(config.TCP) == 0 && len(config.UDP) == 0 {
		return fmt.Errorf("%s: must specify at least one of tcp or udp", context)
	}

	// Validate TCP ports
	for j, portStr := range config.TCP {
		if err := validatePortStringForConfig(portStr, "tcp", context, j); err != nil {
			return err
		}
	}

	// Validate UDP ports
	for j, portStr := range config.UDP {
		if err := validatePortStringForConfig(portStr, "udp", context, j); err != nil {
			return err
		}
	}

	return nil
}

// validatePortStringForConfig validates a single port string specification for new config structure
func validatePortStringForConfig(portStr, protocol, context string, portIndex int) error {
	if portStr == "" {
		return fmt.Errorf("%s, %s port %d: port string cannot be empty", context, protocol, portIndex)
	}

	// Use the types package to validate the port string
	_, err := types.ParsePortString(portStr)
	if err != nil {
		return fmt.Errorf("%s, %s port %d: %w", context, protocol, portIndex, err)
	}

	return nil
}
