package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const (
	MAX_ID              = 65535
	MAX_ADDR            = 4
	ADDR_CACHE_DURATION = 10
)

type Peer struct {
	ID         uint16
	PSK        [AES_BLOCK_SIZE]byte
	Addrs      []*PeerAddr
	Forwarders []uint16
	PktFilter  PktFilter

	// cache Addr entities
	lastCleared           int64
	allStaticDynamicAddrs []*net.UDPAddr
	allStaticAddrs        []*net.UDPAddr
	allDynamicAddrs       []*net.UDPAddr
	allActiveAddrs        []*net.UDPAddr
}

// It should be OK to activate/replace an address without a lock.
func (p *Peer) AddAddr(newAddr *PeerAddr) bool {
	for _, addr := range p.Addrs {
		if addr.Equal(newAddr) {
			addr.Activate()
			return false
		}
	}

	for index, addr := range p.Addrs {
		if addr.IsEmpty() {
			newAddr.Activate()
			p.Addrs[index] = newAddr
			return true
		}
	}

	return false
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

// Clear inactive addrs, and update cache every 10s.
func (p *Peer) clearPeriodically() {
	if time.Now().Unix()-p.lastCleared < ADDR_CACHE_DURATION {
		return
	}
	p.lastCleared = time.Now().Unix()

	for _, addr := range p.Addrs {
		if addr.IsDynamic() && addr.IsInactive() {
			addr.Clear()
		}
	}

	p.UpdateAddrCache()
}

func (p *Peer) UpdateAddrCache() {
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

func GetPeerPool(path string, myID uint16) ([]Peer, error) {
	pool := make([]Peer, MAX_ID+2)

	lines, err := GetLines(path)
	if err != nil {
		return nil, errors.Wrap(err, "get peer pool failed")
	}

	for _, line := range lines {
		p := getPeer(line, myID)
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

	if pool[myID].ID == 0 {
		return pool, errors.New("self ID missing in secrets")
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
			output += "Static-"
		} else {
			output += "Dynamic-"
		}
		output += fmt.Sprintf("%v:%v ", addr.Addr.IP, addr.Addr.Port)
	}

	for _, fID := range p.Forwarders {
		output += fmt.Sprintf("F-%v ", fID)
	}

	output += "\n"
	return output
}

func getPeer(line string, myID uint16) *Peer {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}

	if IdPton(fields[0]) == 0 {
		return nil
	}

	if IdPton(fields[0]) == 1 || IdPton(fields[0]) == 255*255 {
		log.Warning("Reserved ID: %v\n", fields[0])
		return nil
	}

	p := Peer{
		ID:         IdPton(fields[0]),
		PSK:        TruncateKey(fields[1]),
		Addrs:      make([]*PeerAddr, MAX_ADDR),
		Forwarders: make([]uint16, 0, MAX_ADDR),
		PktFilter:  PktFilter{},
	}

	p.PktFilter.Init()

	if len(fields) < 3 {
		return &p
	}

	if p.ID == myID {
		return &p
	}

	ipPort := strings.Split(fields[2], ":")
	if len(ipPort) != 2 {
		log.Warning("Failed to parse IP:Port - %v\n", fields[2])
		return &p
	}

	ip := net.ParseIP(ipPort[0])
	port, err := strconv.Atoi(ipPort[1])
	if err != nil || ip == nil {
		log.Warning("Failed to parse IP:Port - %v\n", fields[2])
		return &p
	}

	addr := PeerAddr{
		Static:  true,
		Version: 4,
		Addr:    net.UDPAddr{IP: ip, Port: port},
	}
	p.AddAddr(&addr)

	if len(fields) < 4 {
		return &p
	}

	if !strings.EqualFold(fields[3], "null") {
		log.Warning("IPv6 not supported now, skip it.\n")
	}

	if len(fields) < 5 {
		return &p
	}

	forwarders := strings.Split(fields[4], "/")
	for _, forwarder := range forwarders {
		fID := IdPton(forwarder)
		if fID == 0 {
			log.Warning("Invalid forwarder, ignore: %v.\n", forwarder)
			continue
		}
		if fID == myID {
			log.Warning("Forwarder is self, ignore: %v.\n", forwarder)
			continue
		}
		p.Forwarders = append(p.Forwarders, fID)
	}

	return &p
}
