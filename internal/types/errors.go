package types

import "errors"

// Core BrakeBear errors for common failure scenarios
var (
	// ErrContainerNotFound is returned when a specified container cannot be found
	ErrContainerNotFound = errors.New("container not found")

	// ErrNetnsNotFound is returned when a network namespace cannot be found
	ErrNetnsNotFound = errors.New("network namespace not found")

	// ErrInvalidConfiguration is returned when configuration parameters are invalid
	ErrInvalidConfiguration = errors.New("invalid configuration")

	// ErrTCOperationFailed is returned when traffic control operations fail
	ErrTCOperationFailed = errors.New("traffic control operation failed")

	// ErrInvalidRate is returned when a rate string cannot be parsed
	ErrInvalidRate = errors.New("invalid rate format")

	// ErrInvalidDuration is returned when a duration string cannot be parsed
	ErrInvalidDuration = errors.New("invalid duration format")

	// ErrInvalidLoss is returned when a loss percentage string cannot be parsed
	ErrInvalidLoss = errors.New("invalid loss percentage format")
)
