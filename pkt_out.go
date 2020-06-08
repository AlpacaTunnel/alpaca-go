package main

import (
	"crypto/aes"
	"crypto/cipher"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
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
	DstAddrs     []*net.UDPAddr
}

func (pkt *PktOut) Init() {
	pkt.OutterBuffer = make([]byte, MAX_MTU)
	pkt.UdpBuffer = pkt.OutterBuffer[:]
	pkt.TunBuffer = make([]byte, MAX_MTU)
	pkt.h = Header{Magic: MAGIC}
}

func (pkt *PktOut) Process() {
	pkt.Valid = true

	pkt.fillHeader()

	pkt.DstAddrs = pkt.Vpn.GetDstAddrs(pkt.h.SrcID, pkt.h.DstID)
	log.Debug("%+v\n", pkt.DstAddrs)

	pkt.Vpn.GroupCipher.Encrypt(pkt.OutterBuffer, pkt.h.ToNetwork())

	// Benchmarks: (only encryption, no pkt filter)
	// bodyLen := pkt.aesEncrypt() // 210 Mbps
	// bodyLen := pkt.xorBody() // 460 Mbps
	bodyLen := pkt.chacha20Encrypt() // 390 Mbps

	pkt.UdpBuffer = pkt.OutterBuffer[:HEADER_LEN+bodyLen]
}

func (pkt *PktOut) fillHeader() {
	var ip IPHeader
	ip.FromNetwork(pkt.TunBuffer)
	log.Debug("%+v\n", ip)

	if ip.Version != 4 {
		log.Debug("not support version: %v\n", ip.Version)
		pkt.Valid = false
		return
	}

	h := &pkt.h

	h.Length = uint16(pkt.InnerLen)
	h.SrcID = pkt.Vpn.MyID

	if pkt.Vpn.Network == (ip.DstIP & NETMASK) {
		h.DstID = uint16(ip.DstIP & 0x0000FFFF)
	} else {
		h.DstID = pkt.Vpn.Gateway
	}

	UpdateTimestampSeq()
	h.Timestamp = TIMESTAMP
	h.Sequence = GLOBAL_SEQUENCE

	log.Debug("%+v\n", h)
	// log.Debug("dst: %+v\n", pkt.Vpn.PeerPool[h.DstID].Format())
}

func (pkt *PktOut) chacha20Encrypt() uint16 {
	nonce := pkt.h.ToNetwork()[4:16]

	psk := GetPsk(pkt.Vpn.PeerPool, &pkt.h)
	key := DeriveKey(psk, pkt.Vpn.GroupPSK[:], nonce)

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		log.Warning("Error new chacha20: %v\n", err)
		pkt.Valid = false
		return 0
	}

	aead.Seal(pkt.OutterBuffer[:HEADER_LEN], nonce, pkt.TunBuffer[:pkt.h.Length], nil)

	return pkt.h.Length + uint16(aead.Overhead())
}

func (pkt *PktOut) xorBody() uint16 {
	psk := GetPsk(pkt.Vpn.PeerPool, &pkt.h)

	for i := 0; i < int(pkt.h.Length); i++ {
		pkt.OutterBuffer[HEADER_LEN+i] = pkt.TunBuffer[i] ^ psk[i%AES_BLOCK_SIZE]
	}

	return pkt.h.Length
}

func (pkt *PktOut) aesEncrypt() uint16 {
	psk := GetPsk(pkt.Vpn.PeerPool, &pkt.h)

	block, err := aes.NewCipher(psk)
	if err != nil {
		pkt.Valid = false
		return 0
	}

	mode := cipher.NewCBCEncrypter(block, pkt.h.ToNetwork())

	aesBlockLen := ((pkt.h.Length + 15) / 16) * 16

	mode.CryptBlocks(
		pkt.OutterBuffer[HEADER_LEN:],
		pkt.TunBuffer[:aesBlockLen],
	)

	return aesBlockLen
}
