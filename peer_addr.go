package main

import (
	"bytes"
	"net"
	"time"
)

const ACTIVE_PERIOD = 60

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
