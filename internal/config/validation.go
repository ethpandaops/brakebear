package config

import (
	"errors"
	"fmt"

	"github.com/ethpandaops/breakbear/internal/types"
)

// ValidateContainerConfig validates a single container configuration
func ValidateContainerConfig(c ContainerConfig) error {
	if err := validateIdentifierMutualExclusion(c); err != nil {
		return fmt.Errorf("container identifier validation failed: %w", err)
	}

	if c.DownloadRate != "" {
		if err := validateRateString(c.DownloadRate); err != nil {
			return fmt.Errorf("invalid download_rate: %w", err)
		}
	}

	if c.UploadRate != "" {
		if err := validateRateString(c.UploadRate); err != nil {
			return fmt.Errorf("invalid upload_rate: %w", err)
		}
	}

	if c.Latency != "" {
		if err := validateDurationString(c.Latency); err != nil {
			return fmt.Errorf("invalid latency: %w", err)
		}
	}

	if c.Jitter != "" {
		if err := validateDurationString(c.Jitter); err != nil {
			return fmt.Errorf("invalid jitter: %w", err)
		}
	}

	if c.Loss != "" {
		if err := validateLossString(c.Loss); err != nil {
			return fmt.Errorf("invalid loss: %w", err)
		}
	}

	return nil
}

// validateIdentifierMutualExclusion ensures only one identifier type is set
func validateIdentifierMutualExclusion(c ContainerConfig) error {
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
		return errors.New("container must have exactly one identifier: name, id, or labels")
	}
	if identifierCount > 1 {
		return errors.New("container must have exactly one identifier: name, id, or labels are mutually exclusive")
	}

	return nil
}

// validateRateString validates a rate string using the types package
func validateRateString(rate string) error {
	if rate == "" || rate == "unlimited" {
		return nil
	}

	_, err := types.ParseRate(rate)
	if err != nil {
		return fmt.Errorf("invalid rate format '%s': %w", rate, err)
	}

	return nil
}

// validateDurationString validates a duration string using the types package
func validateDurationString(duration string) error {
	if duration == "" {
		return nil
	}

	_, err := types.ParseDuration(duration)
	if err != nil {
		return fmt.Errorf("invalid duration format '%s': %w", duration, err)
	}

	return nil
}

// validateLossString validates a loss percentage string using the types package
func validateLossString(loss string) error {
	if loss == "" {
		return nil
	}

	_, err := types.ParseLoss(loss)
	if err != nil {
		return fmt.Errorf("invalid loss format '%s': %w", loss, err)
	}

	return nil
}
