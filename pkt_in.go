package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ActionForward = 1
	ActionWrite   = 2
)

type PktIn struct {
	OutterLen   int
	UdpBuffer   []byte
	InnerBuffer []byte
	TunBuffer   []byte
	Vpn         *VPNCtx
	Valid       bool
	SrcAddr     *net.UDPAddr
	DstAddrs    []*net.UDPAddr
	h           Header
	Action      int
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
	log.Debug("%+v\n", h)

	if !pkt.isHeaderValid() {
		pkt.Valid = false
		return
	}

	addr := PeerAddr{
		Version: 4,
		Static:  false,
		Addr:    *pkt.SrcAddr,
	}
	pkt.Vpn.PeerPool[h.SrcID].AddAddr(&addr)

	if !pkt.isPktValid() {
		pkt.Valid = false
		return
	}

	if h.DstID != pkt.Vpn.MyID {
		pkt.Action = ActionForward
		pkt.DstAddrs = pkt.getDstAddrs()
		log.Debug("%+v\n", pkt.DstAddrs)
		return
	}

	pkt.Action = ActionWrite
	// pkt.aesDecrypt()
	// pkt.xorBody()
	pkt.chacha20Decrypt()

	pkt.TunBuffer = pkt.InnerBuffer[HEADER_LEN : HEADER_LEN+h.Length]
}

func (pkt *PktIn) isHeaderValid() bool {
	h := &pkt.h

	if h.Magic != MAGIC {
		log.Debug("Invalid magic, ignore the packet: (%v -> %v)\n", h.SrcID, h.DstID)
		return false
	}

	if pkt.Vpn.PeerPool[h.DstID].ID == 0 || pkt.Vpn.PeerPool[h.SrcID].ID == 0 {
		log.Debug("Not found srd_id or dst_id: (%v -> %v)\n", h.SrcID, h.DstID)
		return false
	}

	if h.DstID == h.SrcID {
		log.Debug("The same srd_id and dst_id: (%v -> %v)\n", h.SrcID, h.DstID)
		return false
	}

	return true
}

func (pkt *PktIn) isPktValid() bool {
	h := &pkt.h

	if !pkt.Vpn.PeerPool[h.SrcID].PktFilter.IsValid(h.Timestamp, h.Sequence) {
		log.Debug("Packet is filtered as invalid, drop it: (%v -> %v)\n", h.SrcID, h.DstID)
		return false
	}

	return true
}

func (pkt *PktIn) getDstAddrs() []*net.UDPAddr {
	dstAddrs := make([]*net.UDPAddr, 0, MAX_ADDR*2)
	for _, addr := range pkt.Vpn.GetDstAddrs(pkt.h.SrcID, pkt.h.DstID) {
		if bytes.Equal(addr.IP, pkt.SrcAddr.IP) {
			// split horizon
			log.Debug("Can not resend to the receiving address.\n")
		} else {
			dstAddrs = append(dstAddrs, addr)
		}
	}
	return dstAddrs
}

func (pkt *PktIn) chacha20Decrypt() {
	nonce := pkt.InnerBuffer[4:16]

	psk := GetPsk(pkt.Vpn.PeerPool, &pkt.h)
	key := DeriveKey(psk, pkt.Vpn.GroupPSK[:], nonce)

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		log.Warning("Error new chacha20: %v\n", err)
		pkt.Valid = false
		return
	}

	cipherBody := pkt.UdpBuffer[HEADER_LEN : HEADER_LEN+int(pkt.h.Length)+aead.Overhead()]

	_, err = aead.Open(pkt.InnerBuffer[:HEADER_LEN], nonce, cipherBody, nil)
	if err != nil {
		log.Debug("Error open chacha20: %v\n", err)
		pkt.Valid = false
		return
	}
}

func (pkt *PktIn) xorBody() {
	psk := GetPsk(pkt.Vpn.PeerPool, &pkt.h)

	for i := 0; i < int(pkt.h.Length); i++ {
		pkt.InnerBuffer[HEADER_LEN+i] = pkt.UdpBuffer[HEADER_LEN+i] ^ psk[i%AES_BLOCK_SIZE]
	}
}

func (pkt *PktIn) aesDecrypt() {
	psk := GetPsk(pkt.Vpn.PeerPool, &pkt.h)

	block, err := aes.NewCipher(psk)
	if err != nil {
		pkt.Valid = false
		return
	}

	mode := cipher.NewCBCDecrypter(block, pkt.h.ToNetwork())

	aesBlockLen := ((pkt.h.Length + 15) / 16) * 16

	mode.CryptBlocks(
		pkt.InnerBuffer[HEADER_LEN:],
		pkt.UdpBuffer[HEADER_LEN:HEADER_LEN+aesBlockLen],
	)
}
