package main

import (
	"crypto/aes"
	"crypto/cipher"
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
	MyID        int
	Gateway     int
	Network     int
	PeerPool    []Peer
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
	v.Network = IdPton(v.Config.Net) << 16

	return nil
}
