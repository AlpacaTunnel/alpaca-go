package main

import "net"

type PktIn struct {
	OutterLen int
	Buffer    []byte
	UdpBuffer []byte
	TunBuffer []byte
	Vpn       *VPNCtx
	Valid     bool
	Addr      *net.UDPAddr
	h         Header
}

func (pkt *PktIn) Init() {
	pkt.Buffer = make([]byte, MAX_MTU)
	pkt.UdpBuffer = pkt.Buffer[:]
	pkt.TunBuffer = pkt.UdpBuffer[HEADER_LEN:]
	pkt.h = Header{}
}

func (pkt *PktIn) Process() {
	pkt.Valid = true

	h := &pkt.h

	h.FromNetwork(pkt.UdpBuffer)
	if pkt.OutterLen < (HEADER_LEN + int(h.Length)) {
		log.Debug("invalid packet: %v -> %v\n", h.SrcID, h.DstID)
		pkt.Valid = false
		return
	}
	log.Debug("%+v\n", h)

	pkt.TunBuffer = pkt.Buffer[HEADER_LEN : HEADER_LEN+h.Length]
}
