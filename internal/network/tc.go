package network

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/ethpandaops/brakebear/internal/types"
)

// TCManager manages traffic control operations using tc commands
type TCManager struct {
	log logrus.FieldLogger
}

// NewTCManager creates a new traffic control manager
func NewTCManager(log logrus.FieldLogger) *TCManager {
	return &TCManager{
		log: log.WithField("package", "network.tc"),
	}
}

// ApplyLimits applies network traffic control rules to the specified interface
func (t *TCManager) ApplyLimits(ctx context.Context, ifaceName string, limits *types.NetworkLimits) error {
	if limits == nil {
		return errors.New("network limits cannot be nil")
	}

	t.log.WithFields(logrus.Fields{
		"interface": ifaceName,
		"limits":    fmt.Sprintf("%+v", limits),
	}).Info("Applying network limits")

	// Remove existing rules first
	if err := t.RemoveLimits(ctx, ifaceName); err != nil {
		t.log.WithField("interface", ifaceName).Debug("Failed to remove existing limits (may not exist)")
	}

	var commands [][]string

	// Apply different types of limits
	if err := t.applyUploadLimits(ifaceName, limits, &commands); err != nil {
		return err
	}

	if err := t.applyDownloadLimits(ifaceName, limits, &commands); err != nil {
		return err
	}

	if err := t.applyNetemLimits(ifaceName, limits, &commands); err != nil {
		return err
	}

	// Execute all commands
	if err := t.executeCommands(ctx, commands); err != nil {
		return err
	}

	// Add diagnostic commands to verify traffic control status
	t.addDiagnostics(ctx, ifaceName, limits)

	t.log.WithField("interface", ifaceName).Info("Successfully applied network limits")
	return nil
}

// RemoveLimits removes all traffic control rules from the specified interface
func (t *TCManager) RemoveLimits(ctx context.Context, ifaceName string) error {
	t.log.WithField("interface", ifaceName).Debug("Removing network limits")

	// Remove root qdisc - this removes all associated qdiscs, classes, and filters
	cmd := []string{"tc", "qdisc", "del", "dev", ifaceName, "root"}
	if err := t.execCommand(ctx, cmd); err != nil {
		// Log but don't fail - qdisc might not exist
		t.log.WithFields(logrus.Fields{
			"interface": ifaceName,
			"error":     err,
		}).Debug("Failed to delete root qdisc (may not exist)")
	}

	// Remove ingress qdisc if it exists
	cmd = []string{"tc", "qdisc", "del", "dev", ifaceName, "ingress"}
	if err := t.execCommand(ctx, cmd); err != nil {
		t.log.WithFields(logrus.Fields{
			"interface": ifaceName,
			"error":     err,
		}).Debug("Failed to delete ingress qdisc (may not exist)")
	}

	// Remove IFB interface if it exists
	ifbInterface := "ifb-" + ifaceName
	cmd = []string{"ip", "link", "del", ifbInterface}
	if err := t.execCommand(ctx, cmd); err != nil {
		t.log.WithFields(logrus.Fields{
			"interface":     ifaceName,
			"ifb_interface": ifbInterface,
			"error":         err,
		}).Debug("Failed to delete IFB interface (may not exist)")
	}

	t.log.WithField("interface", ifaceName).Debug("Removed network limits")
	return nil
}

// GetInterfaces returns a list of network interfaces in the current namespace
func (t *TCManager) GetInterfaces() ([]string, error) {
	return t.getInterfaces()
}

// getInterfaces returns a list of network interfaces in the current namespace
func (t *TCManager) getInterfaces() ([]string, error) {
	t.log.Debug("Getting network interfaces")

	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	ethInterfaces, vethInterfaces := t.filterAndCategorizeInterfaces(links)
	interfaces := append([]string{}, ethInterfaces...)
	interfaces = append(interfaces, vethInterfaces...)

	t.log.WithFields(logrus.Fields{
		"total_interfaces": len(interfaces),
		"eth_interfaces":   len(ethInterfaces),
		"veth_interfaces":  len(vethInterfaces),
		"interfaces":       interfaces,
	}).Debug("Found relevant network interfaces")

	return interfaces, nil
}

func (t *TCManager) filterAndCategorizeInterfaces(links []netlink.Link) ([]string, []string) {
	var ethInterfaces, vethInterfaces []string
	skipPrefixes := []string{
		"tunl", "sit", "ip6tnl", "gre", "ipip", "ip6gre", "docker", "br-", "virbr",
	}

	for _, link := range links {
		name := link.Attrs().Name
		attrs := link.Attrs()

		if t.shouldSkipInterface(name, attrs, skipPrefixes) {
			continue
		}

		t.categorizeInterface(name, &ethInterfaces, &vethInterfaces)
	}

	return ethInterfaces, vethInterfaces
}

func (t *TCManager) shouldSkipInterface(name string, attrs *netlink.LinkAttrs, skipPrefixes []string) bool {
	// Skip loopback
	if name == "lo" {
		return true
	}

	// Skip interfaces that don't carry actual traffic
	for _, prefix := range skipPrefixes {
		if strings.HasPrefix(name, prefix) {
			t.log.WithField("interface", name).Debug("Skipping tunnel/virtual interface")
			return true
		}
	}

	// Only include interfaces that are UP or could be brought UP
	if attrs.OperState != netlink.OperUp && attrs.OperState != netlink.OperDown && attrs.OperState != netlink.OperUnknown {
		t.log.WithFields(logrus.Fields{
			"interface": name,
			"state":     attrs.OperState,
		}).Debug("Skipping interface due to operational state")
		return true
	}

	return false
}

func (t *TCManager) categorizeInterface(name string, ethInterfaces, vethInterfaces *[]string) {
	switch {
	case strings.HasPrefix(name, "eth"):
		*ethInterfaces = append(*ethInterfaces, name)
	case strings.HasPrefix(name, "veth"):
		*vethInterfaces = append(*vethInterfaces, name)
	default:
		// For containers, we mainly care about eth and veth interfaces
		t.log.WithField("interface", name).Debug("Skipping non-eth/veth interface")
	}
}

// addDiagnostics runs diagnostic commands to verify traffic control status
func (t *TCManager) addDiagnostics(ctx context.Context, ifaceName string, limits *types.NetworkLimits) {
	t.log.WithField("interface", ifaceName).Info("Running traffic control diagnostics")

	// Check qdisc status
	diagCmd := []string{"tc", "qdisc", "show", "dev", ifaceName}
	if err := t.execCommand(ctx, diagCmd); err != nil {
		t.log.WithError(err).Warn("Failed to show qdisc status")
	}

	// Check class status if HTB is used
	if limits.UploadRate != nil {
		diagCmd = []string{"tc", "class", "show", "dev", ifaceName}
		if err := t.execCommand(ctx, diagCmd); err != nil {
			t.log.WithError(err).Warn("Failed to show class status")
		}
	}

	// Check IFB interface if download limits exist
	if limits.DownloadRate != nil {
		ifbInterface := "ifb-" + ifaceName
		diagCmd = []string{"tc", "qdisc", "show", "dev", ifbInterface}
		if err := t.execCommand(ctx, diagCmd); err != nil {
			t.log.WithError(err).Warn("Failed to show IFB qdisc status")
		}

		diagCmd = []string{"tc", "class", "show", "dev", ifbInterface}
		if err := t.execCommand(ctx, diagCmd); err != nil {
			t.log.WithError(err).Warn("Failed to show IFB class status")
		}
	}
}

// rateToTcString converts a Rate to tc-compatible rate string
func (t *TCManager) rateToTcString(rate *types.Rate) string {
	if rate == nil {
		return "0"
	}

	switch rate.Unit {
	case "bps":
		return fmt.Sprintf("%dbit", rate.Value)
	case "kbps":
		return fmt.Sprintf("%dkbit", rate.Value) // Let tc handle kbit conversion
	case "mbps":
		return fmt.Sprintf("%dmbit", rate.Value) // Let tc handle mbit conversion
	case "gbps":
		return fmt.Sprintf("%dgbit", rate.Value) // Let tc handle gbit conversion
	default:
		return "0"
	}
}

// execCommand executes a shell command and returns any error
func (t *TCManager) execCommand(ctx context.Context, cmd []string) error {
	if len(cmd) == 0 {
		return errors.New("command cannot be empty")
	}

	// Validate that we're only executing allowed commands for security
	allowedCommands := map[string]bool{
		"tc": true,
		"ip": true,
	}

	if !allowedCommands[cmd[0]] {
		return fmt.Errorf("command not allowed: %s", cmd[0])
	}

	t.log.WithField("command", strings.Join(cmd, " ")).Info("Executing traffic control command")

	// Use context with timeout for command execution
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// #nosec G204 - Command arguments are constructed internally and validated above
	execCmd := exec.CommandContext(ctxWithTimeout, cmd[0], cmd[1:]...)
	output, err := execCmd.CombinedOutput()
	if err != nil {
		t.log.WithFields(logrus.Fields{
			"command": strings.Join(cmd, " "),
			"output":  string(output),
			"error":   err,
		}).Debug("Traffic control command failed")
		return fmt.Errorf("command failed: %w, output: %s", err, string(output))
	}

	t.log.WithFields(logrus.Fields{
		"command": strings.Join(cmd, " "),
		"output":  string(output),
	}).Info("Traffic control command executed successfully")

	return nil
}

func (t *TCManager) applyUploadLimits(ifaceName string, limits *types.NetworkLimits, commands *[][]string) error {
	if limits.UploadRate == nil {
		return nil
	}

	rateStr := t.rateToTcString(limits.UploadRate)
	if rateStr == "0" {
		return nil
	}

	t.log.WithFields(logrus.Fields{
		"interface":   ifaceName,
		"upload_rate": rateStr,
	}).Info("Setting up egress (upload) HTB limits")

	// Create HTB root qdisc for egress
	*commands = append(*commands, []string{
		"tc", "qdisc", "add", "dev", ifaceName, "root", "handle", "1:", "htb", "default", "30",
	})

	// Create parent class
	*commands = append(*commands, []string{
		"tc", "class", "add", "dev", ifaceName, "parent", "1:", "classid", "1:2", "htb",
		"rate", rateStr, "ceil", rateStr, "burst", "1b", "cburst", "1b",
	})

	// Check if we need to add netem for latency/jitter/loss
	if limits.Latency != nil || limits.Jitter != nil || limits.Loss != nil {
		// Add netem as leaf qdisc under HTB class
		netemCmd := []string{"tc", "qdisc", "add", "dev", ifaceName, "parent", "1:2", "handle", "20:", "netem"}

		if limits.Latency != nil {
			latencyMs := limits.Latency.ToNanoseconds() / 1000000
			netemCmd = append(netemCmd, "delay", fmt.Sprintf("%dms", latencyMs))

			if limits.Jitter != nil {
				jitterMs := limits.Jitter.ToNanoseconds() / 1000000
				netemCmd = append(netemCmd, fmt.Sprintf("%dms", jitterMs))
			}
		}

		if limits.Loss != nil {
			netemCmd = append(netemCmd, "loss", fmt.Sprintf("%.2f%%", *limits.Loss))
		}

		*commands = append(*commands, netemCmd)
		t.log.WithField("interface", ifaceName).Debug("Added netem under HTB for latency/jitter/loss")
	}

	// Add filter to classify all traffic to the limited class
	*commands = append(*commands, []string{
		"tc", "filter", "add", "dev", ifaceName, "parent", "1:", "protocol", "all", "prio", "1", "u32",
		"match", "u32", "0", "0", "flowid", "1:2",
	})

	t.log.WithField("interface", ifaceName).Debug("Added HTB egress (upload) limits")
	return nil
}

func (t *TCManager) applyDownloadLimits(ifaceName string, limits *types.NetworkLimits, commands *[][]string) error {
	if limits.DownloadRate == nil {
		return nil
	}

	rateStr := t.rateToTcString(limits.DownloadRate)
	if rateStr == "0" {
		return nil
	}

	ifbInterface := "ifb-" + ifaceName

	t.log.WithFields(logrus.Fields{
		"interface":     ifaceName,
		"ifb_interface": ifbInterface,
		"download_rate": rateStr,
	}).Info("Setting up download limits using IFB redirection")

	// Step 1: Create and configure IFB interface
	*commands = append(*commands, []string{"ip", "link", "add", ifbInterface, "type", "ifb"})
	*commands = append(*commands, []string{"ip", "link", "set", ifbInterface, "up"})

	// Step 2: Add HTB qdisc to IFB interface
	*commands = append(*commands, []string{
		"tc", "qdisc", "add", "dev", ifbInterface, "root", "handle", "1:", "htb", "default", "30",
	})
	*commands = append(*commands, []string{
		"tc", "class", "add", "dev", ifbInterface, "parent", "1:", "classid", "1:2", "htb",
		"rate", rateStr, "ceil", rateStr, "burst", "1b", "cburst", "1b",
	})

	// Check if we need to add netem for latency/jitter/loss on the IFB interface
	if limits.Latency != nil || limits.Jitter != nil || limits.Loss != nil {
		// Add netem as leaf qdisc under HTB class on IFB interface
		netemCmd := []string{"tc", "qdisc", "add", "dev", ifbInterface, "parent", "1:2", "handle", "20:", "netem"}

		if limits.Latency != nil {
			latencyMs := limits.Latency.ToNanoseconds() / 1000000
			netemCmd = append(netemCmd, "delay", fmt.Sprintf("%dms", latencyMs))

			if limits.Jitter != nil {
				jitterMs := limits.Jitter.ToNanoseconds() / 1000000
				netemCmd = append(netemCmd, fmt.Sprintf("%dms", jitterMs))
			}
		}

		if limits.Loss != nil {
			netemCmd = append(netemCmd, "loss", fmt.Sprintf("%.2f%%", *limits.Loss))
		}

		*commands = append(*commands, netemCmd)
		t.log.WithField("ifb_interface", ifbInterface).Debug("Added netem under HTB for latency/jitter/loss on IFB")
	}

	// Add filter to classify all traffic to the limited class on IFB interface
	*commands = append(*commands, []string{
		"tc", "filter", "add", "dev", ifbInterface, "parent", "1:", "protocol", "all", "prio", "1", "u32",
		"match", "u32", "0", "0", "flowid", "1:2",
	})

	// Step 3: Add ingress qdisc to main interface
	*commands = append(*commands, []string{
		"tc", "qdisc", "add", "dev", ifaceName, "handle", "ffff:", "ingress",
	})

	// Step 4: Redirect ingress traffic to IFB interface
	*commands = append(*commands, []string{
		"tc", "filter", "add", "dev", ifaceName, "parent", "ffff:", "protocol", "ip", "u32",
		"match", "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", ifbInterface,
	})

	t.log.WithFields(logrus.Fields{
		"interface":     ifaceName,
		"ifb_interface": ifbInterface,
	}).Debug("Added IFB-based download limits")

	return nil
}

func (t *TCManager) applyNetemLimits(ifaceName string, limits *types.NetworkLimits, commands *[][]string) error {
	if limits.Latency == nil && limits.Jitter == nil && limits.Loss == nil {
		return nil
	}

	// If we have upload or download limits, netem is already added as a child of HTB
	// in applyUploadLimits or applyDownloadLimits functions
	if (limits.UploadRate != nil && limits.UploadRate.ToBytes() > 0) ||
		(limits.DownloadRate != nil && limits.DownloadRate.ToBytes() > 0) {
		t.log.WithField("interface", ifaceName).Debug("Netem already handled with HTB for combined bandwidth and latency limits")
		return nil
	}

	// No bandwidth limits, so we can add netem as root qdisc
	netemCmd := []string{"tc", "qdisc", "add", "dev", ifaceName, "root", "handle", "1:", "netem"}

	if limits.Latency != nil {
		latencyMs := limits.Latency.ToNanoseconds() / 1000000
		netemCmd = append(netemCmd, "delay", fmt.Sprintf("%dms", latencyMs))

		if limits.Jitter != nil {
			jitterMs := limits.Jitter.ToNanoseconds() / 1000000
			netemCmd = append(netemCmd, fmt.Sprintf("%dms", jitterMs))
		}
	}

	if limits.Loss != nil {
		netemCmd = append(netemCmd, "loss", fmt.Sprintf("%.2f%%", *limits.Loss))
	}

	*commands = append(*commands, netemCmd)
	t.log.WithField("interface", ifaceName).Debug("Added netem as root qdisc for network emulation")

	return nil
}

func (t *TCManager) executeCommands(ctx context.Context, commands [][]string) error {
	for _, cmd := range commands {
		if err := t.execCommand(ctx, cmd); err != nil {
			return fmt.Errorf("failed to execute tc command %v: %w", cmd, err)
		}
	}
	return nil
}
