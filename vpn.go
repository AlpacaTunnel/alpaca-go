package main

const (
	MAGIC   = 8964
	NETMASK = 0xFFFF0000
	IDMASK  = 0x0000FFFF
	MAX_MTU = 1500
)

type VPNCtx struct {
	Buffer   []byte
	Config   Config
	MyID     int
	Gateway  int
	Network  int
	PeerPool []Peer
}

func (v *VPNCtx) InitCtx() {
	v.Buffer = make([]byte, MAX_MTU)
	v.MyID = IdPton(v.Config.Id)
	v.Gateway = IdPton(v.Config.Gateway)
	v.Network = IdPton(v.Config.Net) << 16
}
