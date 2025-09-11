package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// CacheEntry represents cached DNS resolution results with IPv4/IPv6 separation
type CacheEntry struct {
	IPv4IPs     []string
	IPv6IPs     []string
	AllIPs      []string // Combined for backward compatibility
	LastUpdated time.Time
	ExpiresAt   time.Time
}

// DNSChangeCallback is called when DNS resolution results change
type DNSChangeCallback func(ctx context.Context, hostname string, oldIPs, newIPs []string)

// DNSMetrics tracks resolution statistics for IPv4 and IPv6
type DNSMetrics struct {
	IPv4Lookups    atomic.Uint64
	IPv6Lookups    atomic.Uint64
	IPv4Successes  atomic.Uint64
	IPv6Successes  atomic.Uint64
	IPv4CacheHits  atomic.Uint64
	IPv6CacheHits  atomic.Uint64
	DualStackHosts atomic.Uint64 // Hosts with both IPv4 and IPv6
	IPv6OnlyHosts  atomic.Uint64 // Hosts with only IPv6
}

// PeriodicResolution tracks a periodic DNS resolution job
type PeriodicResolution struct {
	hostnames []string
	interval  time.Duration
	callback  DNSChangeCallback
	cancel    context.CancelFunc
}

// Resolver implements DNS resolution with caching and IPv6 optimization
type Resolver struct {
	cache         map[string]*CacheEntry
	cacheMu       sync.RWMutex
	log           logrus.FieldLogger
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	resolver      *net.Resolver
	resolutions   map[string]*PeriodicResolution
	resolutionsMu sync.RWMutex
	metrics       *DNSMetrics
}

// NewResolver creates a new DNS resolver with IPv6 optimization
func NewResolver(log logrus.FieldLogger) *Resolver {
	return &Resolver{
		cache:       make(map[string]*CacheEntry),
		log:         log.WithField("package", "dns.resolver"),
		resolver:    &net.Resolver{},
		resolutions: make(map[string]*PeriodicResolution),
		metrics:     &DNSMetrics{},
	}
}

// Start begins DNS resolution goroutines
func (r *Resolver) Start(ctx context.Context) error {
	ctx, r.cancel = context.WithCancel(ctx)

	r.log.Info("Starting DNS resolver service")

	// Start background cleanup goroutine
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.cleanupLoop(ctx)
	}()

	return nil
}

// Stop gracefully shuts down DNS resolution
func (r *Resolver) Stop() error {
	r.log.Info("Stopping DNS resolver service")

	if r.cancel != nil {
		r.cancel()
	}

	r.wg.Wait()

	r.log.Info("DNS resolver service stopped")
	return nil
}

// ResolveHostnames resolves list of hostnames to IP addresses
func (r *Resolver) ResolveHostnames(ctx context.Context, hostnames []string) ([]string, error) {
	allIPs := make([]string, 0)

	for _, hostname := range hostnames {
		ips, err := r.resolveHost(ctx, hostname)
		if err != nil {
			r.log.WithError(err).WithField("hostname", hostname).Warn("Failed to resolve hostname")
			continue
		}
		allIPs = append(allIPs, ips...)
	}

	return allIPs, nil
}

// GetCachedIPs returns cached IPs for hostname if available
func (r *Resolver) GetCachedIPs(hostname string) ([]string, bool) {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()

	entry, exists := r.cache[hostname]
	if !exists {
		return nil, false
	}

	// Check if entry is expired
	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	// Update cache hit metrics
	r.updateCacheHitMetrics(entry)
	return entry.AllIPs, true
}

// StartPeriodicResolution starts periodic resolution for given hostnames
func (r *Resolver) StartPeriodicResolution(ctx context.Context, hostnames []string, interval time.Duration) {
	r.StartPeriodicResolutionWithCallback(ctx, hostnames, interval, nil)
}

// StartPeriodicResolutionWithCallback starts periodic resolution with change detection
func (r *Resolver) StartPeriodicResolutionWithCallback(ctx context.Context, hostnames []string, interval time.Duration, callback DNSChangeCallback) {
	if len(hostnames) == 0 {
		return
	}

	// Create unique key for this resolution job
	jobKey := r.createJobKey(hostnames, interval)

	r.log.WithFields(map[string]interface{}{
		"hostnames": hostnames,
		"interval":  interval,
		"job_key":   jobKey,
	}).Info("Starting periodic DNS resolution with change detection")

	// Stop existing resolution if any
	r.StopPeriodicResolution(jobKey)

	// Create new resolution context
	resCtx, resCancel := context.WithCancel(ctx)

	// Store resolution job
	r.resolutionsMu.Lock()
	r.resolutions[jobKey] = &PeriodicResolution{
		hostnames: hostnames,
		interval:  interval,
		callback:  callback,
		cancel:    resCancel,
	}
	r.resolutionsMu.Unlock()

	// Start the resolution goroutine
	r.startPeriodicResolutionWithCallback(resCtx, hostnames, interval, callback)
}

// StopPeriodicResolution stops a specific periodic resolution job
func (r *Resolver) StopPeriodicResolution(jobKey string) {
	r.resolutionsMu.Lock()
	defer r.resolutionsMu.Unlock()

	if resolution, exists := r.resolutions[jobKey]; exists {
		resolution.cancel()
		delete(r.resolutions, jobKey)
		r.log.WithField("job_key", jobKey).Debug("Stopped periodic DNS resolution")
	}
}

// resolveHost resolves single hostname to IP addresses
func (r *Resolver) resolveHost(ctx context.Context, hostname string) ([]string, error) {
	// Check cache first
	if ips, found := r.GetCachedIPs(hostname); found {
		return ips, nil
	}

	r.log.WithField("hostname", hostname).Debug("Resolving hostname")

	// Resolve both IPv4 and IPv6 addresses using context-aware resolver
	addrs, err := r.resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup IPs for hostname %s: %w", hostname, err)
	}

	// Separate IPv4 and IPv6 addresses
	var ipv4IPs, ipv6IPs []string
	for _, addr := range addrs {
		ipStr := addr.IP.String()
		if addr.IP.To4() != nil {
			ipv4IPs = append(ipv4IPs, ipStr)
		} else {
			ipv6IPs = append(ipv6IPs, ipStr)
		}
	}

	// Update metrics based on what was found
	r.updateResolutionMetrics(hostname, ipv4IPs, ipv6IPs)

	// Combine all IPs for backward compatibility
	allIPs := make([]string, 0, len(ipv4IPs)+len(ipv6IPs))
	allIPs = append(allIPs, ipv4IPs...)
	allIPs = append(allIPs, ipv6IPs...)

	// Update cache with separated IPs
	r.updateCacheWithSeparatedIPs(hostname, ipv4IPs, ipv6IPs, allIPs)

	// Enhanced logging with IPv6 information
	r.log.WithFields(logrus.Fields{
		"hostname":   hostname,
		"total_ips":  len(allIPs),
		"ipv4_ips":   ipv4IPs,
		"ipv6_ips":   ipv6IPs,
		"ipv4_count": len(ipv4IPs),
		"ipv6_count": len(ipv6IPs),
		"dual_stack": len(ipv4IPs) > 0 && len(ipv6IPs) > 0,
		"ipv6_only":  len(ipv4IPs) == 0 && len(ipv6IPs) > 0,
	}).Debug("Resolved hostname with IPv4/IPv6 breakdown")

	return allIPs, nil
}

// startPeriodicResolutionWithCallback starts background DNS resolution with change detection
func (r *Resolver) startPeriodicResolutionWithCallback(ctx context.Context, hostnames []string, interval time.Duration, callback DNSChangeCallback) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, hostname := range hostnames {
					// Get old IPs from cache
					oldIPs, _ := r.GetCachedIPs(hostname)

					// Resolve new IPs
					newIPs, err := r.resolveHost(ctx, hostname)
					if err != nil {
						r.log.WithError(err).WithField("hostname", hostname).Warn("Periodic DNS resolution failed")
						continue
					}

					// Check if IPs changed and notify callback
					if callback != nil && r.ipsChanged(oldIPs, newIPs) {
						r.log.WithFields(map[string]interface{}{
							"hostname": hostname,
							"old_ips":  oldIPs,
							"new_ips":  newIPs,
						}).Info("DNS IPs changed, triggering callback")
						callback(ctx, hostname, oldIPs, newIPs)
					}
				}
			}
		}
	}()
}

// GetCachedIPv4IPs returns cached IPv4 IPs for hostname if available
func (r *Resolver) GetCachedIPv4IPs(hostname string) ([]string, bool) {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()

	entry, exists := r.cache[hostname]
	if !exists {
		return nil, false
	}

	// Check if entry is expired
	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	// Update IPv4 cache hit metrics
	if len(entry.IPv4IPs) > 0 {
		r.metrics.IPv4CacheHits.Add(1)
	}

	return entry.IPv4IPs, len(entry.IPv4IPs) > 0
}

// GetCachedIPv6IPs returns cached IPv6 IPs for hostname if available
func (r *Resolver) GetCachedIPv6IPs(hostname string) ([]string, bool) {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()

	entry, exists := r.cache[hostname]
	if !exists {
		return nil, false
	}

	// Check if entry is expired
	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	// Update IPv6 cache hit metrics
	if len(entry.IPv6IPs) > 0 {
		r.metrics.IPv6CacheHits.Add(1)
	}

	return entry.IPv6IPs, len(entry.IPv6IPs) > 0
}

// GetMetrics returns a snapshot of current DNS resolution metrics
func (r *Resolver) GetMetrics() DNSMetrics {
	return DNSMetrics{
		IPv4Lookups:    atomic.Uint64{},
		IPv6Lookups:    atomic.Uint64{},
		IPv4Successes:  atomic.Uint64{},
		IPv6Successes:  atomic.Uint64{},
		IPv4CacheHits:  atomic.Uint64{},
		IPv6CacheHits:  atomic.Uint64{},
		DualStackHosts: atomic.Uint64{},
		IPv6OnlyHosts:  atomic.Uint64{},
	}
}

// LogMetrics logs current DNS resolution metrics
func (r *Resolver) LogMetrics() {
	r.log.WithFields(logrus.Fields{
		"ipv4_lookups":     r.metrics.IPv4Lookups.Load(),
		"ipv6_lookups":     r.metrics.IPv6Lookups.Load(),
		"ipv4_successes":   r.metrics.IPv4Successes.Load(),
		"ipv6_successes":   r.metrics.IPv6Successes.Load(),
		"ipv4_cache_hits":  r.metrics.IPv4CacheHits.Load(),
		"ipv6_cache_hits":  r.metrics.IPv6CacheHits.Load(),
		"dual_stack_hosts": r.metrics.DualStackHosts.Load(),
		"ipv6_only_hosts":  r.metrics.IPv6OnlyHosts.Load(),
	}).Info("DNS resolution metrics")
}

// updateCacheHitMetrics updates cache hit metrics based on entry content
func (r *Resolver) updateCacheHitMetrics(entry *CacheEntry) {
	if len(entry.IPv4IPs) > 0 {
		r.metrics.IPv4CacheHits.Add(1)
	}
	if len(entry.IPv6IPs) > 0 {
		r.metrics.IPv6CacheHits.Add(1)
	}
}

// updateCacheWithSeparatedIPs atomically updates cache entry with IPv4/IPv6 separation
func (r *Resolver) updateCacheWithSeparatedIPs(hostname string, ipv4IPs, ipv6IPs, allIPs []string) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	now := time.Now()
	r.cache[hostname] = &CacheEntry{
		IPv4IPs:     ipv4IPs,
		IPv6IPs:     ipv6IPs,
		AllIPs:      allIPs,
		LastUpdated: now,
		ExpiresAt:   now.Add(1 * time.Hour), // Default TTL: 1 hour
	}
}

// updateResolutionMetrics updates metrics based on resolution results
func (r *Resolver) updateResolutionMetrics(hostname string, ipv4IPs, ipv6IPs []string) {
	// Track lookup attempts and successes
	if len(ipv4IPs) > 0 {
		r.metrics.IPv4Lookups.Add(1)
		r.metrics.IPv4Successes.Add(1)
	} else {
		r.metrics.IPv4Lookups.Add(1)
	}

	if len(ipv6IPs) > 0 {
		r.metrics.IPv6Lookups.Add(1)
		r.metrics.IPv6Successes.Add(1)
	} else {
		r.metrics.IPv6Lookups.Add(1)
	}

	// Track dual-stack and IPv6-only hosts
	if len(ipv4IPs) > 0 && len(ipv6IPs) > 0 {
		r.metrics.DualStackHosts.Add(1)
		r.log.WithField("hostname", hostname).Debug("Detected dual-stack hostname")
	} else if len(ipv4IPs) == 0 && len(ipv6IPs) > 0 {
		r.metrics.IPv6OnlyHosts.Add(1)
		r.log.WithField("hostname", hostname).Debug("Detected IPv6-only hostname")
	}
}

// cleanExpiredEntries removes expired cache entries
func (r *Resolver) cleanExpiredEntries() {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	now := time.Now()
	for hostname, entry := range r.cache {
		if now.After(entry.ExpiresAt) {
			delete(r.cache, hostname)
			r.log.WithField("hostname", hostname).Debug("Removed expired cache entry")
		}
	}
}

// ipsChanged compares two IP slices to detect changes
func (r *Resolver) ipsChanged(oldIPs, newIPs []string) bool {
	if len(oldIPs) != len(newIPs) {
		return true
	}

	// Create maps for O(1) lookup
	oldMap := make(map[string]bool)
	for _, ip := range oldIPs {
		oldMap[ip] = true
	}

	for _, ip := range newIPs {
		if !oldMap[ip] {
			return true
		}
	}

	return false
}

// createJobKey creates a unique key for a resolution job
func (r *Resolver) createJobKey(hostnames []string, interval time.Duration) string {
	return fmt.Sprintf("%v:%v", hostnames, interval)
}

// cleanupLoop runs periodic cache cleanup and metrics logging
func (r *Resolver) cleanupLoop(ctx context.Context) {
	cleanupTicker := time.NewTicker(10 * time.Minute) // Cleanup every 10 minutes
	metricsTicker := time.NewTicker(1 * time.Hour)    // Log metrics every hour
	defer cleanupTicker.Stop()
	defer metricsTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cleanupTicker.C:
			r.cleanExpiredEntries()
		case <-metricsTicker.C:
			r.LogMetrics()
		}
	}
}
