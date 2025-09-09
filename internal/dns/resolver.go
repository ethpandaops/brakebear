package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// CacheEntry represents cached DNS resolution results
type CacheEntry struct {
	IPs         []string
	LastUpdated time.Time
	ExpiresAt   time.Time
}

// Resolver implements DNS resolution with caching
type Resolver struct {
	cache    map[string]*CacheEntry
	cacheMu  sync.RWMutex
	log      logrus.FieldLogger
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	resolver *net.Resolver
}

// NewResolver creates a new DNS resolver
func NewResolver(log logrus.FieldLogger) *Resolver {
	return &Resolver{
		cache:    make(map[string]*CacheEntry),
		log:      log.WithField("package", "dns.resolver"),
		resolver: &net.Resolver{},
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

	return entry.IPs, true
}

// StartPeriodicResolution starts periodic resolution for given hostnames
func (r *Resolver) StartPeriodicResolution(ctx context.Context, hostnames []string, interval time.Duration) {
	if len(hostnames) == 0 {
		return
	}

	r.log.WithField("hostnames", hostnames).WithField("interval", interval).Info("Starting periodic DNS resolution")
	r.startPeriodicResolution(ctx, hostnames, interval)
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

	ipStrings := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		ipStrings = append(ipStrings, addr.IP.String())
	}

	// Update cache
	r.updateCache(hostname, ipStrings)

	r.log.WithField("hostname", hostname).WithField("ips", ipStrings).Debug("Resolved hostname")

	return ipStrings, nil
}

// startPeriodicResolution starts background DNS resolution
func (r *Resolver) startPeriodicResolution(ctx context.Context, hostnames []string, interval time.Duration) {
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
					_, err := r.resolveHost(ctx, hostname)
					if err != nil {
						r.log.WithError(err).WithField("hostname", hostname).Warn("Periodic DNS resolution failed")
					}
				}
			}
		}
	}()
}

// updateCache atomically updates cache entry
func (r *Resolver) updateCache(hostname string, ips []string) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	now := time.Now()
	r.cache[hostname] = &CacheEntry{
		IPs:         ips,
		LastUpdated: now,
		ExpiresAt:   now.Add(1 * time.Hour), // Default TTL: 1 hour
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

// cleanupLoop runs periodic cache cleanup
func (r *Resolver) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute) // Cleanup every 10 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.cleanExpiredEntries()
		}
	}
}
