package main

import (
	"crypto/aes"
	"crypto/cipher"
	"net"
)

const (
	MAGIC   = 8964
	NETMASK = 0xFFFF0000
	IDMASK  = 0x0000FFFF
	MAX_MTU = 1500
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
		v.Forwarders = append(v.Forwarders, IdPton(forwarder))
	}

	return nil
}

func (v *VPNCtx) GetDstAddrs(srcId, dstId uint16) []*net.UDPAddr {
	if srcId < dstId {
		return v.PeerPool[dstId].GetAddr(false, v.Config.InactiveDownwardStatic)
	}

	if len(v.Forwarders) == 0 {
		return v.PeerPool[dstId].GetAddr(true, false)
	}

	dstAddrs := make([]*net.UDPAddr, 0, MAX_ADDR*2)
	for _, fId := range v.Forwarders {
		addrs := v.PeerPool[fId].GetAddr(true, false)
		dstAddrs = append(dstAddrs, addrs...)
	}

	return dstAddrs
}
