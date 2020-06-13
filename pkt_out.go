package main

import (
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
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
	H            Header
	DstAddrs     []*net.UDPAddr
}

func (pkt *PktOut) Init() {
	pkt.OutterBuffer = make([]byte, MAX_MTU)
	rand.Read(pkt.OutterBuffer)
	pkt.UdpBuffer = pkt.OutterBuffer[:]
	pkt.TunBuffer = make([]byte, MAX_MTU)
}

func (pkt *PktOut) Process() {
	pkt.Valid = true

	pkt.fillHeader()
	if !pkt.Valid {
		return
	}

	pkt.DstAddrs = pkt.Vpn.GetDstAddrs(pkt.H.SrcID, pkt.H.DstID)
	log.Debug("%+v\n", pkt.DstAddrs)

	pkt.Vpn.GroupCipher.Encrypt(pkt.OutterBuffer, pkt.H.ToNetwork())

	// Benchmarks: (only encryption, no pkt filter)
	// bodyLen := pkt.aesEncrypt() // 210 Mbps
	// bodyLen := pkt.xorBody() // 460 Mbps
	bodyLen := pkt.chacha20Encrypt() // 390 Mbps

	obfsLen := ObfsLength(bodyLen)
	// feed random data for the obfs part
	rand.Read(pkt.OutterBuffer[HEADER_LEN+bodyLen : HEADER_LEN+obfsLen])

	pkt.UdpBuffer = pkt.OutterBuffer[:HEADER_LEN+obfsLen]
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

	h := &pkt.H

	h.Type = TYPE_DATA
	h.TTL = MAX_TTL
	h.Magic = MAGIC
	h.Length = uint16(pkt.InnerLen)
	h.Random = uint32(rand.Intn(4096))
	h.SrcID = pkt.Vpn.MyID

	if pkt.Vpn.Network == (ip.SrcIP & NETMASK) {
		h.SrcInside = 1
	} else {
		h.SrcInside = 0
	}

	if pkt.Vpn.Network == (ip.DstIP & NETMASK) {
		h.DstInside = 1
		h.DstID = uint16(ip.DstIP & 0x0000FFFF)
	} else {
		h.DstInside = 0
		h.DstID = pkt.Vpn.Gateway
	}

	pkt.Vpn.PeerPool[h.DstID].UpdateTimestampSeq()
	h.Timestamp = pkt.Vpn.PeerPool[h.DstID].Timestamp
	h.Sequence = pkt.Vpn.PeerPool[h.DstID].Sequence

	log.Debug("%+v\n", h)
	// log.Debug("dst: %+v\n", pkt.Vpn.PeerPool[h.DstID].Format())
}

func (pkt *PktOut) chacha20Encrypt() uint16 {
	nonce := pkt.H.ToNetwork()[4:16]

	psk := GetPsk(pkt.Vpn.PeerPool, &pkt.H)
	key := DeriveKey(psk, pkt.Vpn.GroupPSK[:], nonce)

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		log.Warning("Error new chacha20: %v\n", err)
		pkt.Valid = false
		return 0
	}

	aead.Seal(pkt.OutterBuffer[:HEADER_LEN], nonce, pkt.TunBuffer[:pkt.H.Length], nil)

	return pkt.H.Length + uint16(aead.Overhead())
}

func (pkt *PktOut) xorBody() uint16 {
	psk := GetPsk(pkt.Vpn.PeerPool, &pkt.H)

	for i := 0; i < int(pkt.H.Length); i++ {
		pkt.OutterBuffer[HEADER_LEN+i] = pkt.TunBuffer[i] ^ psk[i%AES_BLOCK_SIZE]
	}

	return pkt.H.Length
}

func (pkt *PktOut) aesEncrypt() uint16 {
	psk := GetPsk(pkt.Vpn.PeerPool, &pkt.H)

	block, err := aes.NewCipher(psk)
	if err != nil {
		pkt.Valid = false
		return 0
	}

	mode := cipher.NewCBCEncrypter(block, pkt.H.ToNetwork())

	aesBlockLen := ((pkt.H.Length + 15) / 16) * 16

	mode.CryptBlocks(
		pkt.OutterBuffer[HEADER_LEN:],
		pkt.TunBuffer[:aesBlockLen],
	)

	return aesBlockLen
}
