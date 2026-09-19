package router

import (
	"slices"
	"sort"
	"time"

	"github.com/worldiety/bacnet/common/errors"
	"github.com/worldiety/bacnet/common/netprim"
	"github.com/worldiety/bacnet/internal/util"
	"github.com/worldiety/bacnet/npdu"
)

func (r *routerImpl) ensureNetworkRoutesLocked(network netprim.NetworkNumber) map[PortID]routeRecord {
	ports, ok := r.routes[network]
	if ok {
		return ports
	}
	ports = make(map[PortID]routeRecord)
	r.routes[network] = ports
	return ports
}

func (r *routerImpl) upsertRouteLocked(rec routeRecord) {
	ports := r.ensureNetworkRoutesLocked(rec.network)
	existing, exists := ports[rec.port]

	if exists {
		// Duplicate learned advertisements refresh ageing state for the same network+port.
		if existing.kind == RouteKindLearned && rec.kind == RouteKindLearned {
			existing.lastSeen = rec.lastSeen
			existing.expiresAt = util.CopyPointersValue(rec.expiresAt)
			ports[rec.port] = existing
			return
		}

		// Do not downgrade a directly-connected route when a learned advertisement arrives.
		if existing.kind == RouteKindConnected && rec.kind == RouteKindLearned {
			return
		}
	}

	ports[rec.port] = cloneRouteRecord(rec)
}

// AddConnectedRoute adds or replaces a directly connected route.
func (r *routerImpl) AddConnectedRoute(port PortID, network netprim.NetworkNumber, portInfo []byte) error {
	if err := validateRoute(network, port, portInfo); err != nil {
		return err
	}

	now := r.clock.Now()
	r.upsertRouteLocked(routeRecord{
		network:  network,
		port:     port,
		portInfo: slices.Clone(portInfo),
		kind:     RouteKindConnected,
		lastSeen: now,
		// Connected routes do not expire.
		expiresAt: nil,
	})
	return nil
}

// AddLearnedRoute adds or replaces a learned route with the given TTL.
func (r *routerImpl) AddLearnedRoute(port PortID, network netprim.NetworkNumber, ttl time.Duration) error {
	if err := validateRoute(network, port, nil); err != nil {
		return err
	}

	if ttl <= 0 {
		return errors.NewValidationError("ttl", ttl, ErrInvalidRoute)
	}

	now := r.clock.Now()
	r.upsertRouteLocked(routeRecord{
		network:   network,
		port:      port,
		portInfo:  nil,
		kind:      RouteKindLearned,
		lastSeen:  now,
		expiresAt: ptr(now.Add(ttl)),
	})

	return nil
}

// RemoveRoute removes the route for network if present.
func (r *routerImpl) RemoveRoute(network netprim.NetworkNumber) {
	delete(r.routes, network)
}

// RemoveRouteOnPort removes the route for network on a specific port if present.
func (r *routerImpl) RemoveRouteOnPort(network netprim.NetworkNumber, port PortID) {
	ports, ok := r.routes[network]
	if !ok {
		return
	}
	delete(ports, port)
	if len(ports) == 0 {
		delete(r.routes, network)
	}
}

// Lookup returns a snapshot of the route for network.
func (r *routerImpl) Lookup(network netprim.NetworkNumber) (*RouteEntry, bool) {
	route, ok := r.bestRouteLocked(network)
	if !ok {
		return nil, false
	}
	return &RouteEntry{
		Network:   route.network,
		Port:      route.port,
		PortInfo:  slices.Clone(route.portInfo),
		Kind:      route.kind,
		ExpiresAt: util.CopyPointersValue(route.expiresAt),
	}, true
}

// LookupAll returns all active routes for network in stable preference order.
func (r *routerImpl) LookupAll(network netprim.NetworkNumber) []RouteEntry {
	r.pruneExpiredLocked()
	ports, ok := r.routes[network]
	if !ok || len(ports) == 0 {
		return nil
	}

	all := make([]routeRecord, 0, len(ports))
	for _, rec := range ports {
		all = append(all, cloneRouteRecord(rec))
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].kind != all[j].kind {
			return all[i].kind == RouteKindConnected
		}
		if all[i].kind == RouteKindLearned && !all[i].lastSeen.Equal(all[j].lastSeen) {
			return all[i].lastSeen.After(all[j].lastSeen)
		}
		return all[i].port < all[j].port
	})

	out := make([]RouteEntry, 0, len(all))
	for _, rec := range all {
		out = append(out, RouteEntry{
			Network:   rec.network,
			Port:      rec.port,
			PortInfo:  slices.Clone(rec.portInfo),
			Kind:      rec.kind,
			ExpiresAt: util.CopyPointersValue(rec.expiresAt),
		})
	}
	return out
}

// Snapshot returns a stable-order snapshot of active routes.
func (r *routerImpl) Snapshot() []RouteEntry {
	r.pruneExpiredLocked()

	type key struct {
		network netprim.NetworkNumber
		port    PortID
	}

	keys := make([]key, 0)
	for network, byPort := range r.routes {
		for port := range byPort {
			keys = append(keys, key{network: network, port: port})
		}
	}

	slices.SortStableFunc(keys, func(a, b key) int {
		if a.network < b.network {
			return -1
		}

		if a.network > b.network {
			return 1
		}

		if a.port < b.port {
			return -1
		}

		if a.port > b.port {
			return 1
		}

		return 0
	})

	out := make([]RouteEntry, 0, len(keys))
	for _, k := range keys {
		route := r.routes[k.network][k.port]
		out = append(out, RouteEntry{
			Network:   route.network,
			Port:      route.port,
			PortInfo:  slices.Clone(route.portInfo),
			Kind:      route.kind,
			ExpiresAt: util.CopyPointersValue(route.expiresAt),
		})
	}

	return out
}

// RoutingTableEntries exports active routes as NPDU routing-table entries.
func (r *routerImpl) RoutingTableEntries() ([]npdu.RoutingTablePortEntry, error) {
	routeEntries := r.Snapshot()
	entries := make([]npdu.RoutingTablePortEntry, 0, len(routeEntries))
	for _, rEntry := range routeEntries {
		entry, err := npdu.NewRoutingTablePortEntry(rEntry.Network, uint8(rEntry.Port), rEntry.PortInfo)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}

	return entries, nil
}
