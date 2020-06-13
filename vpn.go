package main

import (
	"crypto/aes"
	"crypto/cipher"
	"net"
	"sync"
)

const (
	MAGIC   = 8964
	NETMASK = 0xFFFF0000
	IDMASK  = 0x0000FFFF
	MAX_MTU = 1500
	TUN_MTU = 1408
)

type VPNCtx struct {
	GroupPSK    [16]byte
	GroupCipher cipher.Block
	Config      Config
	MyID        uint16
	Gateway     uint16
	Network     uint32
	PeerPool    []Peer
	Forwarders  []uint16
	AddrLock    sync.Mutex // To avoid creating too many locks, use a global lock
}

func (v *VPNCtx) InitCtx() error {
	v.GroupPSK = TruncateKey(v.Config.Group)
	cipher, err := aes.NewCipher(v.GroupPSK[:])
	if err != nil {
		return err
	}

	v.GroupCipher = cipher
	v.MyID = IdPton(v.Config.Id)
	v.Gateway = IdPton(v.Config.Gateway)
	v.Network = uint32(IdPton(v.Config.Net)) << 16

	v.Forwarders = make([]uint16, 0, MAX_ADDR)
	for _, forwarder := range v.Config.Forwarders {
		if IdPton(forwarder) == v.MyID {
			log.Warning("Forwarder is self, ignore: %v.\n", forwarder)
			continue
		}
		v.Forwarders = append(v.Forwarders, IdPton(forwarder))
	}

	return nil
}

func (v *VPNCtx) AddAddr(srcId uint16, addr *net.UDPAddr) {
	peerAddr := PeerAddr{
		Version: 4,
		Static:  false,
		Addr:    *addr,
	}

	added := v.PeerPool[srcId].AddAddr(&peerAddr)

	if added {
		v.AddrLock.Lock()
		defer v.AddrLock.Unlock()
		v.PeerPool[srcId].UpdateAddrCache()
	}
}

func (v *VPNCtx) GetDstAddrs(srcId, dstId uint16) []*net.UDPAddr {
	// add lock here, otherwise the returned cache may be empty slice
	v.AddrLock.Lock()
	defer v.AddrLock.Unlock()

	// 1) From server to client, don't send to forwarder (in the view of the working ID).
	//    If client has static address, will send to both static and dynamic.
	if srcId < dstId {
		return v.PeerPool[dstId].GetAddr(false, v.Config.InactiveDownwardStatic)
	}

	// 2) followings are from client to server
	//    Servers must have static addresses, only send to static.

	// 2.1) empty forwarder, send to server's static
	if len(v.Forwarders) == 0 && len(v.PeerPool[dstId].Forwarders) == 0 {
		return v.PeerPool[dstId].GetAddr(true, false)
	}

	// 2.2) send to forwarders, peer's custom forwarders have higher priority
	forwarders := v.Forwarders
	if len(v.PeerPool[dstId].Forwarders) != 0 {
		forwarders = v.PeerPool[dstId].Forwarders
	}

	dstAddrs := make([]*net.UDPAddr, 0, MAX_ADDR*2)
	for _, fId := range forwarders {
		addrs := v.PeerPool[fId].GetAddr(true, false)
		dstAddrs = append(dstAddrs, addrs...)
	}

	return dstAddrs
}
