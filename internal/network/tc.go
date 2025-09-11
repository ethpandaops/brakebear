package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/ethpandaops/brakebear/internal/types"
)

// ProtocolConfig defines the dual-stack protocol configuration for traffic control
type ProtocolConfig struct {
	IPv4Enabled  bool
	IPv6Enabled  bool
	IPv4Priority int
	IPv6Priority int
}

// TCManager manages traffic control operations using tc commands
type TCManager struct {
	log      logrus.FieldLogger
	protocol *ProtocolConfig
}

// NewTCManager creates a new traffic control manager
func NewTCManager(log logrus.FieldLogger) *TCManager {
	return &TCManager{
		log: log.WithField("package", "network.tc"),
		protocol: &ProtocolConfig{
			IPv4Enabled:  true,
			IPv6Enabled:  true,
			IPv4Priority: 1,   // IPv4 filters start at priority 1
			IPv6Priority: 100, // IPv6 filters start at priority 100 (separate range)
		},
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

	// Apply egress (upload) limits
	if err := t.applyEgressLimits(ifaceName, limits, &commands); err != nil {
		return err
	}

	// Apply ingress (download) limits using IFB
	if err := t.applyIngressLimits(ifaceName, limits, &commands); err != nil {
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

// generateExclusionFilters creates tc filter commands for excluded CIDR ranges with dual-stack support
// Uses smart filtering to avoid excluding the container's own traffic
func (t *TCManager) generateExclusionFilters(ifaceName string, parent string, excludeRanges []string, isIngress bool) [][]string {
	var filters [][]string
	ipv4Priority := t.protocol.IPv4Priority
	ipv6Priority := t.protocol.IPv6Priority

	for _, cidr := range excludeRanges {
		var protocol, matchPrefix string
		var priority int

		switch {
		case isIPv4CIDR(cidr):
			if !t.protocol.IPv4Enabled {
				continue // Skip IPv4 if disabled
			}
			protocol = "ip"
			matchPrefix = "ip"
			priority = ipv4Priority
			ipv4Priority++
		case isIPv6CIDR(cidr):
			if !t.protocol.IPv6Enabled {
				continue // Skip IPv6 if disabled
			}
			protocol = "ipv6"
			matchPrefix = "ip6"
			priority = ipv6Priority
			ipv6Priority++
		default:
			t.log.WithFields(logrus.Fields{
				"interface": ifaceName,
				"cidr":      cidr,
			}).Warn("Invalid CIDR range, skipping")
			continue
		}

		if isIngress {
			// INGRESS (Download): Only exclude traffic FROM external sources in the CIDR range
			// This allows responses from excluded networks to flow normally while
			// preventing the container from being limited when talking to those networks
			filters = append(filters, []string{
				"tc", "filter", "add", "dev", ifaceName, "parent", parent,
				"protocol", protocol, "prio", strconv.Itoa(priority), "u32",
				"match", matchPrefix, "src", cidr, "flowid", "1:2",
			})
			t.log.WithFields(logrus.Fields{
				"interface": ifaceName,
				"cidr":      cidr,
				"protocol":  protocol,
				"priority":  priority,
				"direction": "ingress",
			}).Debug("Created ingress exclusion filter for external sources")
		} else {
			// EGRESS (Upload): Only exclude traffic TO destinations in the CIDR range
			// This prevents applying latency to local network traffic while
			// still applying limits to external traffic
			filters = append(filters, []string{
				"tc", "filter", "add", "dev", ifaceName, "parent", parent,
				"protocol", protocol, "prio", strconv.Itoa(priority), "u32",
				"match", matchPrefix, "dst", cidr, "flowid", "1:2",
			})
			t.log.WithFields(logrus.Fields{
				"interface": ifaceName,
				"cidr":      cidr,
				"protocol":  protocol,
				"priority":  priority,
				"direction": "egress",
			}).Debug("Created egress exclusion filter for local destinations")
		}
	}

	return filters
}

// generatePortExclusionFilters creates tc filter commands for excluded ports with dual-stack support
func (t *TCManager) generatePortExclusionFilters(ifaceName string, parent string, portConfig *types.PortConfig, isIngress bool) [][]string {
	if portConfig == nil {
		return nil
	}

	// Parse port configuration
	portSpecs, err := types.ParsePortConfig(portConfig)
	if err != nil {
		t.log.WithFields(logrus.Fields{
			"interface": ifaceName,
			"error":     err,
		}).Error("Failed to parse port configuration")
		return nil
	}

	var filters [][]string
	ipv4Priority := t.protocol.IPv4Priority
	ipv6Priority := t.protocol.IPv6Priority

	// Generate filters for each port specification
	for _, spec := range portSpecs {
		var protocolNum string
		var portField string

		// Set protocol number and port field based on protocol
		switch spec.Protocol {
		case "tcp":
			protocolNum = "6"
		case "udp":
			protocolNum = "17"
		default:
			continue // Skip invalid protocols
		}

		if isIngress {
			// INGRESS (Download): Match source ports for incoming traffic
			portField = "sport"
		} else {
			// EGRESS (Upload): Match destination ports for outgoing traffic
			portField = "dport"
		}

		// Create IPv4 filter if enabled
		if t.protocol.IPv4Enabled {
			filters = append(filters, []string{
				"tc", "filter", "add", "dev", ifaceName, "parent", parent,
				"protocol", "ip", "prio", strconv.Itoa(ipv4Priority), "u32",
				"match", "ip", "protocol", protocolNum, "0xff",
				"match", "ip", portField, strconv.Itoa(spec.Port), "0xffff",
				"flowid", "1:2", // unrestricted class
			})
			t.log.WithFields(logrus.Fields{
				"interface":  ifaceName,
				"protocol":   spec.Protocol,
				"port":       spec.Port,
				"ip_version": "IPv4",
				"priority":   ipv4Priority,
				"direction":  map[bool]string{true: "ingress", false: "egress"}[isIngress],
			}).Debug("Created IPv4 port exclusion filter")
			ipv4Priority++
		}

		// Create IPv6 filter if enabled
		if t.protocol.IPv6Enabled {
			filters = append(filters, []string{
				"tc", "filter", "add", "dev", ifaceName, "parent", parent,
				"protocol", "ipv6", "prio", strconv.Itoa(ipv6Priority), "u32",
				"match", "ip6", "protocol", protocolNum, "0xff",
				"match", "ip6", portField, strconv.Itoa(spec.Port), "0xffff",
				"flowid", "1:2", // unrestricted class
			})
			t.log.WithFields(logrus.Fields{
				"interface":  ifaceName,
				"protocol":   spec.Protocol,
				"port":       spec.Port,
				"ip_version": "IPv6",
				"priority":   ipv6Priority,
				"direction":  map[bool]string{true: "ingress", false: "egress"}[isIngress],
			}).Debug("Created IPv6 port exclusion filter")
			ipv6Priority++
		}
	}

	return filters
}

// applyEgressLimits applies upload limits and latency/jitter/loss to egress traffic
func (t *TCManager) applyEgressLimits(ifaceName string, limits *types.NetworkLimits, commands *[][]string) error {
	// Determine the rate to use - if no upload limit, use a high default (10Gbps)
	var rateStr string
	hasUploadLimit := limits.UploadRate != nil && limits.UploadRate.ToBytes() > 0
	hasNetemLimits := t.hasNetemLimits(limits)

	switch {
	case hasUploadLimit:
		rateStr = t.rateToTcString(limits.UploadRate)
		t.log.WithFields(logrus.Fields{
			"interface":   ifaceName,
			"upload_rate": rateStr,
		}).Info("Setting up egress HTB with upload limit")
	case hasNetemLimits:
		// Use a high rate if we only have netem limits (10Gbps default)
		rateStr = "10gbit"
		t.log.WithField("interface", ifaceName).Debug("Setting up egress HTB with default high rate for netem")
	default:
		// No egress limits needed
		return nil
	}

	// Create HTB root qdisc
	*commands = append(*commands, []string{
		"tc", "qdisc", "add", "dev", ifaceName, "root", "handle", "1:", "htb", "default", "1",
	})

	// Create restricted HTB class 1:1 with the rate
	*commands = append(*commands, []string{
		"tc", "class", "add", "dev", ifaceName, "parent", "1:", "classid", "1:1", "htb",
		"rate", rateStr, "ceil", rateStr,
	})

	// Create unrestricted class 1:2 for excluded networks
	*commands = append(*commands, []string{
		"tc", "class", "add", "dev", ifaceName, "parent", "1:", "classid", "1:2",
		"htb", "rate", "10gbit", "ceil", "10gbit",
	})

	// Add netem as leaf qdisc if needed
	if hasNetemLimits {
		netemCmd := []string{"tc", "qdisc", "add", "dev", ifaceName, "parent", "1:1", "handle", "10:", "netem"}

		if limits.Latency != nil {
			// Halve the latency since it applies to both egress and ingress (total RTT = 2x one-way)
			latencyMs := (limits.Latency.ToNanoseconds() / 1000000) / 2
			netemCmd = append(netemCmd, "delay", fmt.Sprintf("%dms", latencyMs))

			if limits.Jitter != nil {
				// Halve jitter as well to maintain proportion with latency
				jitterMs := (limits.Jitter.ToNanoseconds() / 1000000) / 2
				netemCmd = append(netemCmd, fmt.Sprintf("%dms", jitterMs))
			}
		}

		if limits.Loss != nil {
			netemCmd = append(netemCmd, "loss", fmt.Sprintf("%.2f%%", *limits.Loss))
		}

		*commands = append(*commands, netemCmd)
		t.log.WithField("interface", ifaceName).Debug("Added netem for egress latency/jitter/loss")
	}

	// Process excluded networks
	// Note: DNS resolver not available at TC level, so DNS exclusions won't be resolved here
	// This is handled at a higher level in the service
	excludeRanges, err := types.ParseExcludeNetworks(limits.ExcludeNetworks, nil)
	if err != nil {
		return fmt.Errorf("failed to parse exclude networks: %w", err)
	}

	// Add CIDR exclusion filters with priority 1
	exclusionFilters := t.generateExclusionFilters(ifaceName, "1:", excludeRanges, false)
	*commands = append(*commands, exclusionFilters...)

	// Add port exclusion filters with priority 1
	for _, exclude := range limits.ExcludeNetworks {
		if exclude.Type == "ports" && exclude.PortConfig != nil {
			portFilters := t.generatePortExclusionFilters(ifaceName, "1:", exclude.PortConfig, false)
			*commands = append(*commands, portFilters...)
		}
	}

	// Add catch-all filters for restricted traffic (dual-stack support)
	if t.protocol.IPv4Enabled {
		*commands = append(*commands, []string{
			"tc", "filter", "add", "dev", ifaceName, "parent", "1:", "protocol", "ip", "prio", "99", "u32",
			"match", "u32", "0", "0", "flowid", "1:1",
		})
	}
	if t.protocol.IPv6Enabled {
		*commands = append(*commands, []string{
			"tc", "filter", "add", "dev", ifaceName, "parent", "1:", "protocol", "ipv6", "prio", "999", "u32",
			"match", "u32", "0", "0", "flowid", "1:1",
		})
	}

	return nil
}

// applyIngressLimits applies download limits and latency/jitter/loss to ingress traffic
func (t *TCManager) applyIngressLimits(ifaceName string, limits *types.NetworkLimits, commands *[][]string) error {
	// Check if we need ingress limits
	if limits.DownloadRate == nil && !t.hasNetemLimits(limits) {
		return nil
	}

	// Determine the rate to use
	var rateStr string
	if limits.DownloadRate != nil && limits.DownloadRate.ToBytes() > 0 {
		rateStr = t.rateToTcString(limits.DownloadRate)
		t.log.WithFields(logrus.Fields{
			"interface":     ifaceName,
			"download_rate": rateStr,
		}).Info("Setting up ingress HTB with download limit")
	} else {
		// Use a high rate if we only have netem limits
		rateStr = "10gbit"
		t.log.WithField("interface", ifaceName).Debug("Setting up ingress HTB with default high rate for netem")
	}

	ifbInterface := "ifb-" + ifaceName

	// Create and configure IFB interface
	*commands = append(*commands, []string{"ip", "link", "add", ifbInterface, "type", "ifb"})
	*commands = append(*commands, []string{"ip", "link", "set", ifbInterface, "up"})

	// Add HTB qdisc to IFB interface
	*commands = append(*commands, []string{
		"tc", "qdisc", "add", "dev", ifbInterface, "root", "handle", "1:", "htb", "default", "1",
	})

	// Create restricted HTB class 1:1 with the rate
	*commands = append(*commands, []string{
		"tc", "class", "add", "dev", ifbInterface, "parent", "1:", "classid", "1:1", "htb",
		"rate", rateStr, "ceil", rateStr,
	})

	// Create unrestricted class 1:2 for excluded networks
	*commands = append(*commands, []string{
		"tc", "class", "add", "dev", ifbInterface, "parent", "1:", "classid", "1:2",
		"htb", "rate", "10gbit", "ceil", "10gbit",
	})

	// Add netem as leaf qdisc if needed
	if t.hasNetemLimits(limits) {
		netemCmd := []string{"tc", "qdisc", "add", "dev", ifbInterface, "parent", "1:1", "handle", "10:", "netem"}

		if limits.Latency != nil {
			// Halve the latency since it applies to both egress and ingress (total RTT = 2x one-way)
			latencyMs := (limits.Latency.ToNanoseconds() / 1000000) / 2
			netemCmd = append(netemCmd, "delay", fmt.Sprintf("%dms", latencyMs))

			if limits.Jitter != nil {
				// Halve jitter as well to maintain proportion with latency
				jitterMs := (limits.Jitter.ToNanoseconds() / 1000000) / 2
				netemCmd = append(netemCmd, fmt.Sprintf("%dms", jitterMs))
			}
		}

		if limits.Loss != nil {
			netemCmd = append(netemCmd, "loss", fmt.Sprintf("%.2f%%", *limits.Loss))
		}

		*commands = append(*commands, netemCmd)
		t.log.WithField("ifb_interface", ifbInterface).Debug("Added netem for ingress latency/jitter/loss")
	}

	// Process excluded networks
	// Note: DNS resolver not available at TC level, so DNS exclusions won't be resolved here
	// This is handled at a higher level in the service
	excludeRanges, err := types.ParseExcludeNetworks(limits.ExcludeNetworks, nil)
	if err != nil {
		return fmt.Errorf("failed to parse exclude networks: %w", err)
	}

	// Add CIDR exclusion filters for IFB with priority 1
	exclusionFilters := t.generateExclusionFilters(ifbInterface, "1:", excludeRanges, true)
	*commands = append(*commands, exclusionFilters...)

	// Add port exclusion filters for IFB with priority 1
	for _, exclude := range limits.ExcludeNetworks {
		if exclude.Type == "ports" && exclude.PortConfig != nil {
			portFilters := t.generatePortExclusionFilters(ifbInterface, "1:", exclude.PortConfig, true)
			*commands = append(*commands, portFilters...)
		}
	}

	// Add catch-all filters for restricted traffic (dual-stack support)
	if t.protocol.IPv4Enabled {
		*commands = append(*commands, []string{
			"tc", "filter", "add", "dev", ifbInterface, "parent", "1:", "protocol", "ip", "prio", "99", "u32",
			"match", "u32", "0", "0", "flowid", "1:1",
		})
	}
	if t.protocol.IPv6Enabled {
		*commands = append(*commands, []string{
			"tc", "filter", "add", "dev", ifbInterface, "parent", "1:", "protocol", "ipv6", "prio", "999", "u32",
			"match", "u32", "0", "0", "flowid", "1:1",
		})
	}

	// Add ingress qdisc to main interface
	*commands = append(*commands, []string{
		"tc", "qdisc", "add", "dev", ifaceName, "handle", "ffff:", "ingress",
	})

	// Redirect ingress traffic to IFB interface
	*commands = append(*commands, []string{
		"tc", "filter", "add", "dev", ifaceName, "parent", "ffff:", "protocol", "all", "u32",
		"match", "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", ifbInterface,
	})

	t.log.WithFields(logrus.Fields{
		"interface":     ifaceName,
		"ifb_interface": ifbInterface,
	}).Debug("Set up IFB-based ingress limits")

	return nil
}

// hasNetemLimits checks if any netem limits (latency, jitter, loss) are configured
func (t *TCManager) hasNetemLimits(limits *types.NetworkLimits) bool {
	return limits.Latency != nil || limits.Jitter != nil || limits.Loss != nil
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

	// Check class status
	diagCmd = []string{"tc", "class", "show", "dev", ifaceName}
	if err := t.execCommand(ctx, diagCmd); err != nil {
		t.log.WithError(err).Warn("Failed to show class status")
	}

	// Check IFB interface if download limits exist
	if limits.DownloadRate != nil || t.hasNetemLimits(limits) {
		ifbInterface := "ifb-" + ifaceName
		diagCmd = []string{"tc", "qdisc", "show", "dev", ifbInterface}
		if err := t.execCommand(ctx, diagCmd); err != nil {
			t.log.WithError(err).Warn("Failed to show IFB qdisc status")
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
		return fmt.Sprintf("%dkbit", rate.Value)
	case "mbps":
		return fmt.Sprintf("%dmbit", rate.Value)
	case "gbps":
		return fmt.Sprintf("%dgbit", rate.Value)
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

func (t *TCManager) executeCommands(ctx context.Context, commands [][]string) error {
	for _, cmd := range commands {
		if err := t.execCommand(ctx, cmd); err != nil {
			return fmt.Errorf("failed to execute tc command %v: %w", cmd, err)
		}
	}
	return nil
}

// isIPv4CIDR checks if the given CIDR string represents an IPv4 network
func isIPv4CIDR(cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.IP.To4() != nil
}

// isIPv6CIDR checks if the given CIDR string represents an IPv6 network
func isIPv6CIDR(cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.IP.To4() == nil
}
