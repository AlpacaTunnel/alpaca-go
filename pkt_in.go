package main

import (
	"bytes"
	"fmt"
	"net"

	"github.com/pkg/errors"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ACTION_FORWARD = 1
	ACTION_WRITE   = 2
)

type PktIn struct {
	OutterLen   int
	UdpBuffer   []byte
	InnerBuffer []byte
	TunBuffer   []byte
	Vpn         *VPNCtx
	SrcAddr     *net.UDPAddr
	DstAddrs    []*net.UDPAddr
	H           Header
	Action      int
}

func (pkt *PktIn) Init() {
	pkt.UdpBuffer = make([]byte, MAX_MTU)
	pkt.InnerBuffer = make([]byte, MAX_MTU)
	pkt.TunBuffer = pkt.InnerBuffer[HEADER_LEN:]
	pkt.H = Header{}
}

func (pkt *PktIn) Process() error {
	pkt.Vpn.GroupCipher.Decrypt(pkt.InnerBuffer, pkt.UdpBuffer[:HEADER_LEN])

	h := &pkt.H
	h.FromNetwork(pkt.InnerBuffer)
	log.Debug("%+v\n", h)

	if !pkt.isHeaderValid() {
		return errors.New("invalid header")
	}

	if h.DstID == pkt.Vpn.MyID {
		pkt.Action = ACTION_WRITE
	} else {
		pkt.Action = ACTION_FORWARD
	}

	if pkt.Action == ACTION_WRITE {
		err := pkt.chacha20Decrypt()
		if err != nil {
			return errors.Wrap(err, "decrypt packet failed")
		}
		pkt.TunBuffer = pkt.InnerBuffer[HEADER_LEN : HEADER_LEN+h.Length]
		pkt.doNat()
	}

	// For a forwarder, if the pkt is faked, its src addr is still stored.
	// If the real client uses the same forwarder, the fake peer can receive the downstream pkt.
	// To make it safer, let the forwarder decrypt before store src addr. But it's unnecessary overload.
	pkt.Vpn.AddAddr(h.SrcID, pkt.SrcAddr)

	if pkt.isPktFiltered() {
		return errors.New("packet is filtered")
	}

	if pkt.Action == ACTION_FORWARD {
		return pkt.processForward()
	}

	return nil
}

func (pkt *PktIn) processForward() error {
	h := &pkt.H

	if h.TTL == 0 {
		return errors.New(fmt.Sprintf("TTL expired: (%v -> %v)\n", h.SrcID, h.DstID))
	}
	h.TTL -= 1

	pkt.DstAddrs = pkt.getDstAddrs()
	log.Debug("%+v\n", pkt.DstAddrs)

	pkt.Vpn.GroupCipher.Encrypt(pkt.UdpBuffer, h.ToNetwork())
	return nil
}

func (pkt *PktIn) isHeaderValid() bool {
	h := &pkt.H

	if h.Magic != MAGIC {
		log.Debug("Invalid magic, group may mismatch.\n")
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

func (pkt *PktIn) isPktFiltered() bool {
	h := &pkt.H

	if !pkt.Vpn.PeerPool[h.SrcID].PktFilter.IsValid(h.Timestamp, h.Sequence) {
		log.Debug("Packet is filtered as invalid, drop it: (%v -> %v)\n", h.SrcID, h.DstID)
		return true
	}

	return false
}

func (pkt *PktIn) getDstAddrs() []*net.UDPAddr {
	dstAddrs := make([]*net.UDPAddr, 0, MAX_ADDR*2)
	for _, addr := range pkt.Vpn.GetDstAddrs(pkt.H.SrcID, pkt.H.DstID) {
		if bytes.Equal(addr.IP, pkt.SrcAddr.IP) {
			// split horizon
			log.Debug("Can not resend to the receiving address.\n")
		} else {
			dstAddrs = append(dstAddrs, addr)
		}
	}
	return dstAddrs
}

func (pkt *PktIn) chacha20Decrypt() error {
	nonce := pkt.InnerBuffer[4:16]

	psk := GetPsk(pkt.Vpn.PeerPool, &pkt.H)
	key := DeriveKey(psk, pkt.Vpn.GroupPSK[:], nonce)

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		log.Warning("Error new chacha20: %v\n", err)
		return err
	}

	cipherBody := pkt.UdpBuffer[HEADER_LEN : HEADER_LEN+int(pkt.H.Length)+aead.Overhead()]

	_, err = aead.Open(pkt.InnerBuffer[:HEADER_LEN], nonce, cipherBody, nil)
	if err != nil {
		return errors.Wrap(err, "open chacha20 failed")
	}

	return nil
}

func (pkt *PktIn) doNat() {
	if !pkt.Vpn.DoNat {
		return
	}

	var ip IPPacket
	if err := ip.Load(pkt.TunBuffer); err != nil {
		log.Debug("Load IP failed\n")
	}

	if pkt.H.SrcInside == 1 {
		ip.Snat(pkt.Vpn.Network + uint32(pkt.H.SrcID))
	}

	if pkt.H.DstInside == 1 {
		ip.Dnat(pkt.Vpn.Network + uint32(pkt.H.DstID))
	}

	log.Debug("IP: %v -> %v, Proto: %v\n", ip.H.SrcIP, ip.H.DstIP, ip.H.Protocol)
}
