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

	// Benchmarks:
	// bodyLen := pkt.aesEncrypt() // 210 Mbps
	// bodyLen := pkt.xorBody() // 460 Mbps
	bodyLen := pkt.chacha20Encrypt() // 390 Mbps

	pkt.UdpBuffer = pkt.OutterBuffer[:HEADER_LEN+bodyLen]
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
