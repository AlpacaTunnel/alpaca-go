package main

import (
	"net"
)

type PktOut struct {
	InnerLen  int
	Buffer    []byte
	UdpBuffer []byte
	TunBuffer []byte
	Vpn       *VPNCtx
	Valid     bool
	Addr      *net.UDPAddr
	h         Header
	ip        IPHeader
	DstAddr   net.UDPAddr
}

func (pkt *PktOut) Init() {
	pkt.Buffer = make([]byte, MAX_MTU)
	pkt.UdpBuffer = pkt.Buffer[:]
	pkt.TunBuffer = pkt.UdpBuffer[HEADER_LEN:]
	pkt.ip = IPHeader{}
	pkt.h = Header{Magic: MAGIC}
}

func (pkt *PktOut) Process() {
	pkt.Valid = true

	ip := &pkt.ip
	h := &pkt.h

	ip.FromNetwork(pkt.TunBuffer)
	log.Debug("%+v\n", ip)

	h.Length = uint16(pkt.InnerLen)
	h.SrcID = uint16(ip.SrcIP & 0x0000FFFF)
	h.DstID = uint16(ip.DstIP & 0x0000FFFF)
	log.Debug("%+v\n", h)
	log.Debug("%+v\n", pkt.Vpn.PeerPool[h.DstID])

	if len(pkt.Vpn.PeerPool[h.DstID].Addrs) == 0 {
		pkt.Valid = false
		log.Debug("Invalid peer addr: %v\n", h.DstID)
		return
	}

	pkt.DstAddr = pkt.Vpn.PeerPool[h.DstID].Addrs[0].Addr

	UpdateTimestampSeq()
	h.Timestamp = TIMESTAMP
	h.Sequence = GLOBAL_SEQUENCE

	copy(pkt.Buffer, h.ToNetwork())
	pkt.UdpBuffer = pkt.Buffer[:HEADER_LEN+h.Length]
}
