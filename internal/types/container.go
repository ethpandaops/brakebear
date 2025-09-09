package types

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// IdentifierType represents the type of container identifier
type IdentifierType string

const (
	// IdentifierTypeName represents identification by container name
	IdentifierTypeName IdentifierType = "name"
	// IdentifierTypeID represents identification by container ID
	IdentifierTypeID IdentifierType = "id"
	// IdentifierTypeLabels represents identification by container labels
	IdentifierTypeLabels IdentifierType = "labels"
)

// ContainerIdentifier represents a way to identify a container
type ContainerIdentifier struct {
	Type  IdentifierType
	Value any // string for name/id, map[string]string for labels
}

// NetworkLimits represents network traffic control limits
type NetworkLimits struct {
	DownloadRate    *Rate
	UploadRate      *Rate
	Latency         *Duration
	Jitter          *Duration
	Loss            *float64
	ExcludeNetworks []ExcludeNetwork
}

// Rate represents a network rate with value and unit
type Rate struct {
	Value uint64
	Unit  string // "bps", "kbps", "mbps", "gbps"
}

// Duration represents a time duration with value and unit
type Duration struct {
	Value uint64
	Unit  string // "us", "ms", "s"
}

// Container represents essential information about a Docker container
type Container struct {
	ID     string
	Name   string
	Labels map[string]string
	State  string
	Status string
}

// ContainerState represents the current state of a container's network limitations
type ContainerState struct {
	ContainerID string
	NetworkNS   string
	Limits      *NetworkLimits
	LastUpdated time.Time
}

var (
	// Regular expressions for parsing rates, durations, and loss percentages
	rateRegex     = regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*(bps|kbps|mbps|gbps)$`)
	durationRegex = regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*(us|ms|s)$`)
	lossRegex     = regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*%?$`)
)

// ParseRate parses a rate string like "100Mbps" into a Rate struct
func ParseRate(s string) (*Rate, error) {
	if s == "" {
		return nil, ErrInvalidRate
	}

	// Normalize string by removing spaces and converting to lowercase
	normalized := strings.ToLower(strings.ReplaceAll(s, " ", ""))

	matches := rateRegex.FindStringSubmatch(normalized)
	if len(matches) != 3 {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRate, s)
	}

	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid number %s", ErrInvalidRate, matches[1])
	}

	if value < 0 {
		return nil, fmt.Errorf("%w: negative rate not allowed", ErrInvalidRate)
	}

	return &Rate{
		Value: uint64(value),
		Unit:  matches[2],
	}, nil
}

// ParseDuration parses a duration string like "20ms" into a Duration struct
func ParseDuration(s string) (*Duration, error) {
	if s == "" {
		return nil, ErrInvalidDuration
	}

	// Normalize string by removing spaces and converting to lowercase
	normalized := strings.ToLower(strings.ReplaceAll(s, " ", ""))

	matches := durationRegex.FindStringSubmatch(normalized)
	if len(matches) != 3 {
		return nil, fmt.Errorf("%w: %s", ErrInvalidDuration, s)
	}

	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid number %s", ErrInvalidDuration, matches[1])
	}

	if value < 0 {
		return nil, fmt.Errorf("%w: negative duration not allowed", ErrInvalidDuration)
	}

	return &Duration{
		Value: uint64(value),
		Unit:  matches[2],
	}, nil
}

// ParseLoss parses a loss string like "0.1%" into a float64 percentage
func ParseLoss(s string) (*float64, error) {
	if s == "" {
		return nil, ErrInvalidLoss
	}

	// Normalize string by removing spaces and converting to lowercase
	normalized := strings.ToLower(strings.ReplaceAll(s, " ", ""))

	matches := lossRegex.FindStringSubmatch(normalized)
	if len(matches) != 2 {
		return nil, fmt.Errorf("%w: %s", ErrInvalidLoss, s)
	}

	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid number %s", ErrInvalidLoss, matches[1])
	}

	if value < 0 || value > 100 {
		return nil, fmt.Errorf("%w: loss percentage must be between 0 and 100", ErrInvalidLoss)
	}

	return &value, nil
}

// ToBytes converts the rate to bytes per second
func (r *Rate) ToBytes() uint64 {
	if r == nil {
		return 0
	}

	switch r.Unit {
	case "bps":
		return r.Value / 8 // bits to bytes
	case "kbps":
		return r.Value * 1000 / 8 // kilobits to bytes
	case "mbps":
		return r.Value * 1000000 / 8 // megabits to bytes
	case "gbps":
		return r.Value * 1000000000 / 8 // gigabits to bytes
	default:
		return 0
	}
}

// ToNanoseconds converts the duration to nanoseconds
func (d *Duration) ToNanoseconds() uint64 {
	if d == nil {
		return 0
	}

	switch d.Unit {
	case "us":
		return d.Value * 1000 // microseconds to nanoseconds
	case "ms":
		return d.Value * 1000000 // milliseconds to nanoseconds
	case "s":
		return d.Value * 1000000000 // seconds to nanoseconds
	default:
		return 0
	}
}

// String returns a string representation of the rate
func (r *Rate) String() string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%d%s", r.Value, r.Unit)
}

// String returns a string representation of the duration
func (d *Duration) String() string {
	if d == nil {
		return ""
	}
	return fmt.Sprintf("%d%s", d.Value, d.Unit)
}
