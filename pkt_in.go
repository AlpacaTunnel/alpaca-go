package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
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

	// pkt.aesDecrypt()
	// pkt.xorBody()
	pkt.chacha20Decrypt()

	pkt.TunBuffer = pkt.InnerBuffer[HEADER_LEN : HEADER_LEN+h.Length]
}

func (pkt *PktIn) chacha20Decrypt() {
	psk := GetPsk(pkt.Vpn.PeerPool, &pkt.h)
	key := sha256.Sum256(psk)

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		log.Warning("Error new chacha20: %v\n", err)
		pkt.Valid = false
		return
	}

	nonce := pkt.InnerBuffer[4:16]

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
