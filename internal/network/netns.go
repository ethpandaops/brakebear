package network

import (
	"fmt"
	"os"
	"runtime"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"
)

// NetnsManager manages network namespace operations safely
type NetnsManager struct {
	log logrus.FieldLogger
}

// NewNetnsManager creates a new network namespace manager
func NewNetnsManager(log logrus.FieldLogger) *NetnsManager {
	return &NetnsManager{
		log: log.WithField("package", "network.netns"),
	}
}

// EnterNamespace safely enters a network namespace and returns the handle
// The caller must ensure to call ExitNamespace with the returned handle
func (n *NetnsManager) EnterNamespace(nsPath string) (netns.NsHandle, error) {
	n.log.WithField("namespace", nsPath).Debug("Entering network namespace")

	// Lock OS thread to ensure we don't accidentally switch goroutines
	runtime.LockOSThread()

	// Get current namespace handle for restoration
	currentNs, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		return netns.None(), fmt.Errorf("failed to get current namespace: %w", err)
	}

	// Open the target namespace
	targetNs, err := netns.GetFromPath(nsPath)
	if err != nil {
		if closeErr := currentNs.Close(); closeErr != nil {
			n.log.WithError(closeErr).Debug("Failed to close current namespace handle")
		}
		runtime.UnlockOSThread()
		return netns.None(), fmt.Errorf("failed to open namespace %s: %w", nsPath, err)
	}

	// Set the namespace
	if err := netns.Set(targetNs); err != nil {
		if closeErr := targetNs.Close(); closeErr != nil {
			n.log.WithError(closeErr).Debug("Failed to close target namespace handle")
		}
		if closeErr := currentNs.Close(); closeErr != nil {
			n.log.WithError(closeErr).Debug("Failed to close current namespace handle")
		}
		runtime.UnlockOSThread()
		return netns.None(), fmt.Errorf("failed to set namespace %s: %w", nsPath, err)
	}

	// Close the target handle as we don't need it anymore
	if closeErr := targetNs.Close(); closeErr != nil {
		n.log.WithError(closeErr).Debug("Failed to close target namespace handle")
	}

	n.log.WithField("namespace", nsPath).Debug("Successfully entered network namespace")

	// Return the original namespace handle for restoration
	return currentNs, nil
}

// ExitNamespace safely exits the current network namespace and restores the previous one
func (n *NetnsManager) ExitNamespace(originalNs netns.NsHandle) error {
	defer runtime.UnlockOSThread()
	defer func() {
		if closeErr := originalNs.Close(); closeErr != nil {
			n.log.WithError(closeErr).Debug("Failed to close original namespace handle")
		}
	}()

	n.log.Debug("Exiting network namespace")

	// Restore original namespace
	if err := netns.Set(originalNs); err != nil {
		return fmt.Errorf("failed to restore original namespace: %w", err)
	}

	n.log.Debug("Successfully exited network namespace")
	return nil
}

// ExecuteInNamespace executes a function within a network namespace with proper lock/unlock
// This is a convenience method that handles enter/exit automatically
func (n *NetnsManager) ExecuteInNamespace(nsPath string, fn func() error) error {
	n.log.WithField("namespace", nsPath).Debug("Executing function in network namespace")

	// Check if namespace path exists
	if _, err := os.Stat(nsPath); os.IsNotExist(err) {
		return fmt.Errorf("namespace path %s does not exist: %w", nsPath, err)
	}

	// Enter namespace
	originalNs, err := n.EnterNamespace(nsPath)
	if err != nil {
		return fmt.Errorf("failed to enter namespace %s: %w", nsPath, err)
	}

	// Execute function with proper error handling
	var fnErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				fnErr = fmt.Errorf("panic in namespace function: %v", r)
			}
		}()
		fnErr = fn()
	}()

	// Always exit namespace, even if function failed
	exitErr := n.ExitNamespace(originalNs)
	if exitErr != nil {
		if fnErr != nil {
			return fmt.Errorf("function error: %w, exit error: %w", fnErr, exitErr)
		}
		return fmt.Errorf("failed to exit namespace: %w", exitErr)
	}

	if fnErr != nil {
		return fmt.Errorf("function execution failed: %w", fnErr)
	}

	n.log.WithField("namespace", nsPath).Debug("Successfully executed function in network namespace")
	return nil
}
