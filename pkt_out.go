package main

import (
	"crypto/aes"
	"crypto/cipher"
	"net"
)

type PktOut struct {
	InnerLen     int
	OutterBuffer []byte
	UdpBuffer    []byte
	TunBuffer    []byte
	Vpn          *VPNCtx
	Valid        bool
	Addr         *net.UDPAddr
	h            Header
	ip           IPHeader
	DstAddr      net.UDPAddr
}

func (pkt *PktOut) Init() {
	pkt.OutterBuffer = make([]byte, MAX_MTU)
	pkt.UdpBuffer = pkt.OutterBuffer[:]
	pkt.TunBuffer = make([]byte, MAX_MTU)
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

	pkt.Vpn.GroupCipher.Encrypt(pkt.OutterBuffer, h.ToNetwork())

	aesBlockLen := pkt.encryptBody()

	pkt.UdpBuffer = pkt.OutterBuffer[:HEADER_LEN+aesBlockLen]
}

func (pkt *PktOut) encryptBody() uint16 {
	h := &pkt.h

	biggerId := MaxInt(int(h.DstID), int(h.SrcID))
	psk := pkt.Vpn.PeerPool[biggerId].PSK

	block, err := aes.NewCipher(psk[:])
	if err != nil {
		pkt.Valid = false
		return 0
	}

	mode := cipher.NewCBCEncrypter(block, h.ToNetwork())

	aesBlockLen := ((h.Length + 15) / 16) * 16

	mode.CryptBlocks(
		pkt.OutterBuffer[HEADER_LEN:],
		pkt.TunBuffer[:aesBlockLen],
	)

	return aesBlockLen
}
