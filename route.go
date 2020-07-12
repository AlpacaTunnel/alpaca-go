package main

import (
	"errors"
	"time"

	"github.com/vishvananda/netlink"
)

const (
	ROUTE_CACHE_DURATION = 1
	TABLE_SIZE           = 1024
)

type RouteTableV4 struct {
	LastCleared int64
	Cache       map[uint32]uint32
}

func (t *RouteTableV4) Init() {
	t.LastCleared = 0
	t.clearCache()
}

func (t *RouteTableV4) clearCache() {
	// If system route changed, must clear route cache, otherwise may get wrong(old) route.
	// Use another goroutine to monitor system route change is more accurate, but also more complicated.
	if time.Now().Unix()-t.LastCleared < ROUTE_CACHE_DURATION {
		return
	}
	t.LastCleared = time.Now().Unix()
	t.Cache = make(map[uint32]uint32, TABLE_SIZE)
}

func (t *RouteTableV4) GetRoute(dstIP uint32) (uint32, error) {
	t.clearCache()

	gwIP, ok := t.getRouteFromCache(dstIP)
	if ok {
		return gwIP, nil
	}

	routes, err := netlink.RouteGet(InetNtoa(dstIP))

	if err != nil {
		log.Error("netlink failed query %v, error: %v\n", InetNtoa(dstIP), err)
		return 0, err
	}

	if len(routes) < 1 {
		log.Error("empty route found to %v\n", InetNtoa(dstIP))
		return 0, errors.New("empty route")
	}

	gwIP = InetAton(routes[0].Gw)
	t.addRouteToCache(dstIP, gwIP)

	return gwIP, nil
}

func (t *RouteTableV4) getRouteFromCache(dstIP uint32) (uint32, bool) {
	gwIP, ok := t.Cache[dstIP]
	return gwIP, ok
}

func (t *RouteTableV4) addRouteToCache(dstIP, gwIP uint32) {
	t.Cache[dstIP] = gwIP
	log.Debug("%v\n", t.Cache)
}
