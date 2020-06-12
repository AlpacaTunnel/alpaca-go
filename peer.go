package main

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	MAX_ID         = 65535
	MAX_ADDR       = 4
	ACTIVE_PERIOD  = 60
	CACHE_DURATION = 10
)

type Peer struct {
	ID        uint16
	PSK       [AES_BLOCK_SIZE]byte
	Addrs     []*PeerAddr
	PktFilter PktFilter

	// cache Addr entities
	lastCleared           int64
	allStaticDynamicAddrs []*net.UDPAddr
	allStaticAddrs        []*net.UDPAddr
	allDynamicAddrs       []*net.UDPAddr
	allActiveAddrs        []*net.UDPAddr
}

type PeerAddr struct {
	Static     bool
	Version    int
	Addr       net.UDPAddr
	LastActive int64
}

func (addr *PeerAddr) Clear() {
	if addr == nil {
		return
	}
	addr.Addr.Port = 0
	addr.LastActive = 0
}

func (addr *PeerAddr) IsEmpty() bool {
	if addr == nil || addr.Addr.Port == 0 {
		return true
	}
	return false
}

func (addr *PeerAddr) IsStatic() bool {
	if addr.IsEmpty() {
		return false
	}
	return addr.Static
}

func (addr *PeerAddr) IsDynamic() bool {
	if addr.IsEmpty() {
		return false
	}
	return !addr.Static
}

func (addr *PeerAddr) IsActive() bool {
	if addr.IsEmpty() {
		return false
	}
	if time.Now().Unix()-addr.LastActive < ACTIVE_PERIOD {
		return true
	}
	return false
}

func (addr *PeerAddr) IsInactive() bool {
	if addr.IsEmpty() {
		return false
	}
	if time.Now().Unix()-addr.LastActive > ACTIVE_PERIOD {
		return true
	}
	return false
}

func (addr *PeerAddr) Activate() {
	if addr.IsEmpty() {
		return
	}
	addr.LastActive = time.Now().Unix()
}

func (addr *PeerAddr) Equal(other *PeerAddr) bool {
	if addr == nil || other == nil {
		return false
	}
	if (addr.Version == other.Version) && (addr.Addr.Port == other.Addr.Port) && (bytes.Equal(addr.Addr.IP, other.Addr.IP)) {
		return true
	}
	return false
}

// TODO: add lock? seems OK without a lock.
func (p *Peer) AddAddr(newAddr *PeerAddr) {
	for _, addr := range p.Addrs {
		if addr.Equal(newAddr) {
			addr.Activate()
			return
		}
	}

	for index, addr := range p.Addrs {
		if addr.IsEmpty() {
			p.Addrs[index] = newAddr
			newAddr.Activate()
			p.updateAddrCache()
			return
		}
	}
}

func (p *Peer) GetAddr(static, inactiveDownwardStatic bool) []*net.UDPAddr {
	p.clearPeriodically()

	if static {
		return p.allStaticAddrs
	}

	if inactiveDownwardStatic {
		return p.allStaticDynamicAddrs
	}

	if len(p.allActiveAddrs) > 0 {
		return p.allActiveAddrs
	}

	return p.allStaticDynamicAddrs
}

// Clear inactive addrs, and update cache every 10s
func (p *Peer) clearPeriodically() {
	if time.Now().Unix()-p.lastCleared < CACHE_DURATION {
		return
	}
	p.lastCleared = time.Now().Unix()

	for _, addr := range p.Addrs {
		if addr.IsDynamic() && addr.IsInactive() {
			addr.Clear()
		}
	}

	p.updateAddrCache()
}

func (p *Peer) updateAddrCache() {
	p.allStaticDynamicAddrs = make([]*net.UDPAddr, 0, MAX_ADDR)
	p.allStaticAddrs = make([]*net.UDPAddr, 0, MAX_ADDR)
	p.allDynamicAddrs = make([]*net.UDPAddr, 0, MAX_ADDR)
	p.allActiveAddrs = make([]*net.UDPAddr, 0, MAX_ADDR)

	for _, addr := range p.Addrs {
		if !addr.IsEmpty() {
			p.allStaticDynamicAddrs = append(p.allStaticDynamicAddrs, &addr.Addr)
		}

		if addr.IsStatic() {
			p.allStaticAddrs = append(p.allStaticAddrs, &addr.Addr)
		}

		if addr.IsDynamic() {
			p.allDynamicAddrs = append(p.allDynamicAddrs, &addr.Addr)
		}

		if addr.IsActive() {
			p.allActiveAddrs = append(p.allActiveAddrs, &addr.Addr)
		}
	}
}

func GetPeerPool(path string) ([]Peer, error) {
	pool := make([]Peer, MAX_ID+2)

	lines, err := GetLines(path)
	if err != nil {
		return nil, err
	}

	for _, line := range lines {
		p := getPeer(line)
		if p == nil {
			log.Warning("Ignore this line: %v\n", line)
			continue
		}

		if pool[p.ID].ID != 0 {
			log.Warning("Ignore duplicated ID: %v\n", p.ID)
			continue
		}

		pool[p.ID] = *p
	}

	return pool, nil
}

func FormatPeerPool(pool []Peer) string {
	output := "\n"
	for _, p := range pool {
		output += p.Format()
	}
	return output
}

func (p *Peer) Format() string {
	if p == nil || p.ID == 0 {
		return ""
	}
	output := ""
	output += fmt.Sprintf("%5v: ", p.ID)
	output += fmt.Sprintf("%x ", p.PSK)
	for _, addr := range p.Addrs {
		if addr.IsEmpty() {
			continue
		}
		if addr.Static {
			output += fmt.Sprintf("Static-")
		} else {
			output += fmt.Sprintf("Dynamic-")
		}
		output += fmt.Sprintf("%v:%v ", addr.Addr.IP, addr.Addr.Port)
	}
	output += "\n"
	return output
}

func getPeer(line string) *Peer {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}

	if IdPton(fields[0]) == 0 {
		return nil
	}

	p := Peer{
		ID:        IdPton(fields[0]),
		PSK:       TruncateKey(fields[1]),
		Addrs:     make([]*PeerAddr, MAX_ADDR),
		PktFilter: PktFilter{},
	}

	p.PktFilter.Init()

	if len(fields) < 5 {
		return &p
	}

	port, err := strconv.Atoi(fields[4])
	ip := net.ParseIP(fields[2])
	if err != nil || ip == nil {
		log.Warning("Failed to parse IP:Port - %v:%v\n", fields[2], fields[4])
		return &p
	}

	addr := PeerAddr{
		Static:  true,
		Version: 4,
		Addr:    net.UDPAddr{IP: ip, Port: port},
	}
	p.AddAddr(&addr)

	return &p
}
