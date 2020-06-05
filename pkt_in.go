package main

import (
	"crypto/aes"
	"crypto/cipher"
	"net"
)

type PktIn struct {
	OutterLen   int
	UdpBuffer   []byte
	InnerBuffer []byte
	TunBuffer   []byte
	Vpn         *VPNCtx
	Valid       bool
	Addr        *net.UDPAddr
	h           Header
}

func (pkt *PktIn) Init() {
	pkt.UdpBuffer = make([]byte, MAX_MTU)
	pkt.InnerBuffer = make([]byte, MAX_MTU)
	pkt.TunBuffer = pkt.InnerBuffer[HEADER_LEN:]
	pkt.h = Header{}
}

func (pkt *PktIn) Process() {
	pkt.Valid = true

	pkt.Vpn.GroupCipher.Decrypt(pkt.InnerBuffer, pkt.UdpBuffer[:HEADER_LEN])

	h := &pkt.h

	h.FromNetwork(pkt.InnerBuffer)
	if pkt.OutterLen < (HEADER_LEN + int(h.Length)) {
		log.Debug("invalid length: %v -> %v\n", h.SrcID, h.DstID)
		pkt.Valid = false
		return
	}
	if h.Magic != MAGIC {
		log.Debug("invalid magic: %v -> %v\n", h.SrcID, h.DstID)
		pkt.Valid = false
		return
	}
	log.Debug("%+v\n", h)

	pkt.decryptBody()

	pkt.TunBuffer = pkt.InnerBuffer[HEADER_LEN : HEADER_LEN+h.Length]
}

func (pkt *PktIn) decryptBody() {
	h := &pkt.h

	biggerId := MaxInt(int(h.DstID), int(h.SrcID))
	psk := pkt.Vpn.PeerPool[biggerId].PSK

	block, err := aes.NewCipher(psk[:])
	if err != nil {
		pkt.Valid = false
		return
	}

	mode := cipher.NewCBCDecrypter(block, h.ToNetwork())

	aesBlockLen := ((h.Length + 15) / 16) * 16

	mode.CryptBlocks(
		pkt.InnerBuffer[HEADER_LEN:],
		pkt.UdpBuffer[HEADER_LEN:HEADER_LEN+aesBlockLen],
	)
}
