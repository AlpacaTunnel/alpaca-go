package main

import (
	"encoding/binary"
)

const IPHEADER_LEN = 20

type IPHeader struct {
	Version  uint
	Offset   uint16 // fragment offset
	Protocol uint8
	Checksum uint16
	SrcIP    uint32
	DstIP    uint32
}

func (h *IPHeader) FromNetwork(data []byte) {
	h.Version = uint(data[0]) >> 4
	h.Offset = binary.BigEndian.Uint16(data[6:8]) & 0x1FFF
	h.Protocol = data[9]
	h.Checksum = binary.BigEndian.Uint16(data[10:12])
	h.SrcIP = binary.BigEndian.Uint32(data[12:16])
	h.DstIP = binary.BigEndian.Uint32(data[16:20])
}
