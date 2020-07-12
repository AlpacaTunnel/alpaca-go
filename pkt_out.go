package main

import (
	"math/rand"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/crypto/chacha20poly1305"
)

type PktOut struct {
	InnerLen     int
	OutterBuffer []byte
	UdpBuffer    []byte
	TunBuffer    []byte
	Vpn          *VPNCtx
	Addr         *net.UDPAddr
	H            Header
	IP           IPPacket
	DstAddrs     []*net.UDPAddr
}

func (pkt *PktOut) Init() {
	pkt.OutterBuffer = make([]byte, MAX_MTU)
	rand.Read(pkt.OutterBuffer)
	pkt.UdpBuffer = pkt.OutterBuffer[:]
	pkt.TunBuffer = make([]byte, MAX_MTU)
}

func (pkt *PktOut) Process() bool {
	if !pkt.fillHeader() {
		return false
	}

	pkt.DstAddrs = pkt.Vpn.GetDstAddrs(pkt.H.SrcID, pkt.H.DstID)
	log.Debug("%+v\n", pkt.DstAddrs)

	pkt.Vpn.GroupCipher.Encrypt(pkt.OutterBuffer, pkt.H.ToNetwork())

	bodyLen, err := pkt.chacha20Encrypt()
	if err != nil {
		return false
	}

	obfsLen := ObfsLength(bodyLen)
	// feed random data for the obfs part
	rand.Read(pkt.OutterBuffer[HEADER_LEN+bodyLen : HEADER_LEN+obfsLen])

	pkt.UdpBuffer = pkt.OutterBuffer[:HEADER_LEN+obfsLen]
	return true
}

func (pkt *PktOut) fillHeader() bool {
	ip := &pkt.IP
	ip.Load(pkt.TunBuffer)
	ipH := ip.H

	if ipH.Version != 4 {
		log.Debug("not support version: %v\n", ipH.Version)
		return false
	}

	log.Debug("IPHeader: %v -> %v, IHL: %v, Proto: %v\n", InetNtoa(ipH.SrcIP), InetNtoa(ipH.DstIP), ipH.IHL, ipH.Protocol)

	h := &pkt.H

	h.Type = TYPE_DATA
	h.TTL = MAX_TTL
	h.Magic = MAGIC
	h.Length = uint16(pkt.InnerLen)
	h.Random = uint32(rand.Intn(4096))
	h.SrcID = pkt.Vpn.MyID

	if pkt.Vpn.Network == (ipH.SrcIP & NETMASK) {
		h.SrcInside = 1
		if pkt.Vpn.DoNat {
			ip.Snat(pkt.Vpn.VirtualNet + uint32(h.SrcID))
		}
	} else {
		h.SrcInside = 0
	}

	if (pkt.Vpn.Network != (ipH.DstIP & NETMASK)) && (pkt.Vpn.Network != (ipH.SrcIP & NETMASK)) {
		log.Debug("both src_ip and dst_ip not in tunnel network, ignore the pkt: %v -> %v\n", InetNtoa(ipH.SrcIP), InetNtoa(ipH.DstIP))
		return false
	}

	if pkt.Vpn.Network == (ipH.DstIP & NETMASK) {
		h.DstInside = 1
		h.DstID = uint16(ipH.DstIP & 0x0000FFFF)
		if pkt.Vpn.DoNat {
			ip.Dnat(pkt.Vpn.VirtualNet + uint32(h.DstID))
		}

	} else {

		// TODO: bad performance, add cache?
		routes, err := netlink.RouteGet(InetNtoa(ipH.DstIP))
		if err != nil {
			log.Error("failed to get route: %v -> %v, error: %v\n", InetNtoa(ipH.SrcIP), InetNtoa(ipH.DstIP), err)
			return false
		}
		if len(routes) < 1 {
			log.Error("empty route found: %v -> %v\n", InetNtoa(ipH.SrcIP), InetNtoa(ipH.DstIP))
			return false
		}

		gwIP := InetAton(routes[0].Gw)
		if pkt.Vpn.Network != (gwIP & NETMASK) {
			log.Error("route not in tunnel network: %v -> %v\n", InetNtoa(ipH.SrcIP), InetNtoa(ipH.DstIP))
			return false
		}

		h.DstInside = 0
		h.DstID = uint16(gwIP & 0x0000FFFF)
		log.Debug("%v -> %v, dst ID: %v\n", InetNtoa(ipH.SrcIP), InetNtoa(ipH.DstIP), h.DstID)
	}

	pkt.Vpn.UpdateTimestampSeq()
	h.Timestamp = pkt.Vpn.Timestamp
	h.Sequence = pkt.Vpn.Sequence

	log.Debug("%+v\n", h)
	// log.Debug("dst: %+v\n", pkt.Vpn.PeerPool[h.DstID].Format())

	return true
}

func (pkt *PktOut) chacha20Encrypt() (uint16, error) {
	nonce := pkt.H.ToNetwork()[4:16]

	psk := GetPsk(pkt.Vpn.PeerPool, &pkt.H)
	key := DeriveKey(psk, pkt.Vpn.GroupPSK[:], nonce)

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		log.Warning("Error new chacha20: %v\n", err)
		return 0, err
	}

	aead.Seal(pkt.OutterBuffer[:HEADER_LEN], nonce, pkt.TunBuffer[:pkt.H.Length], nil)

	return pkt.H.Length + uint16(aead.Overhead()), nil
}
