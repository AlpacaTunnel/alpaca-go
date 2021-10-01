package main

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

const (
	IPHEADER_LEN_DEFAULT = 20
	UDPHEADER_LEN        = 8
	TCPHEADER_LEN        = 20 // Only interprate first 20 bytes
	PROTO_ICMP           = 1
	PROTO_TCP            = 6
	PROTO_UDP            = 17
)

type IPHeader struct {
	Data     []byte
	Version  uint
	IHL      int
	Offset   uint16 // fragment offset
	Protocol uint8
	Checksum uint16
	SrcIP    uint32
	DstIP    uint32
}

type L4Header interface {
	Snat(oldIP, newIP uint32)
	Dnat(oldIP, newIP uint32)
}

type EmptyL4Header struct {
}

type UDPHeader struct {
	Data     []byte
	Checksum uint16
}

type TCPHeader struct {
	Data     []byte
	Checksum uint16
}

type IPPacket struct {
	Packet []byte
	H      IPHeader
	L4     L4Header
}

func (h *IPHeader) FromNetwork(data []byte) {
	h.Data = data
	h.Version = uint(data[0]) >> 4
	h.IHL = int(data[0]) & 0x0F
	h.Offset = binary.BigEndian.Uint16(data[6:8]) & 0x1FFF
	h.Protocol = data[9]
	h.Checksum = binary.BigEndian.Uint16(data[10:12])
	h.SrcIP = binary.BigEndian.Uint32(data[12:16])
	h.DstIP = binary.BigEndian.Uint32(data[16:20])
}

func (ip *IPPacket) Load(data []byte) error {
	if len(data) <= IPHEADER_LEN_DEFAULT {
		return errors.New("invalid IP length")
	}

	ip.Packet = data
	ip.H.FromNetwork(data)
	ipHLen := ip.H.IHL * 4

	if ip.H.Protocol == PROTO_UDP {

		if len(data) <= ipHLen+UDPHEADER_LEN {
			return errors.New("invalid UDP length")
		}

		ip.L4 = &UDPHeader{Data: data[ipHLen:]}

	} else if ip.H.Protocol == PROTO_TCP {

		if len(data) <= ipHLen+TCPHEADER_LEN {
			return errors.New("invalid TCP length")
		}

		ip.L4 = &TCPHeader{Data: data[ipHLen:]}

	} else {
		ip.L4 = &EmptyL4Header{}
	}

	return nil
}

func (ip *IPPacket) Snat(newIP uint32) {
	if ip.H.Offset == 0 {
		ip.L4.Snat(ip.H.SrcIP, newIP)
	}
	ip.H.Snat(newIP)
}

func (ip *IPPacket) Dnat(newIP uint32) {
	if ip.H.Offset == 0 {
		ip.L4.Dnat(ip.H.DstIP, newIP)
	}
	ip.H.Dnat(newIP)
}

func (h *IPHeader) Snat(newIP uint32) {
	h.Checksum = doCsum(h.Checksum, h.SrcIP, newIP)
	h.SrcIP = newIP

	binary.BigEndian.PutUint16(h.Data[10:12], h.Checksum)
	binary.BigEndian.PutUint32(h.Data[12:16], h.SrcIP)
}

func (h *IPHeader) Dnat(newIP uint32) {
	h.Checksum = doCsum(h.Checksum, h.DstIP, newIP)
	h.DstIP = newIP

	binary.BigEndian.PutUint16(h.Data[10:12], h.Checksum)
	binary.BigEndian.PutUint32(h.Data[16:20], h.DstIP)
}

func (udp *EmptyL4Header) Snat(oldIP, newIP uint32) {
}

func (udp *EmptyL4Header) Dnat(oldIP, newIP uint32) {
}

func (udp *UDPHeader) Snat(oldIP, newIP uint32) {
	doNat(udp.Data[6:8], oldIP, newIP)
}

func (udp *UDPHeader) Dnat(oldIP, newIP uint32) {
	doNat(udp.Data[6:8], oldIP, newIP)
}

func (tcp *TCPHeader) Snat(oldIP, newIP uint32) {
	doNat(tcp.Data[16:18], oldIP, newIP)
}

func (tcp *TCPHeader) Dnat(oldIP, newIP uint32) {
	doNat(tcp.Data[16:18], oldIP, newIP)
}

func doNat(checkSum []byte, oldIP, newIP uint32) {
	oldSum := binary.BigEndian.Uint16(checkSum)
	newSum := doCsum(oldSum, oldIP, newIP)
	binary.BigEndian.PutUint16(checkSum, newSum)
}

func doCsum(oldSum uint16, oldIP uint32, newIP uint32) uint16 {
	if oldSum == 0 || oldIP == newIP {
		return oldSum
	}

	oldIP = ^oldIP
	oldIP = (oldIP >> 16) + (oldIP & 0x0000FFFF)
	oldIP = (oldIP >> 16) + (oldIP & 0x0000FFFF)

	newIP = ^newIP
	newIP = (newIP >> 16) + (newIP & 0x0000FFFF)
	newIP = (newIP >> 16) + (newIP & 0x0000FFFF)

	var newSum uint32

	// move one bit to left. old_sum must be bigger than 0.
	newSum = 0x00010000 | uint32(oldSum-0x00000001)
	newSum = newSum - oldIP + newIP
	newSum = (newSum >> 16) + (newSum & 0x0000FFFF)
	newSum = (newSum >> 16) + (newSum & 0x0000FFFF)

	return uint16(newSum & 0x0000FFFF)
}
