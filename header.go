package main

import (
	"encoding/binary"
	"time"
)

const HEADER_LEN = 16

// TODO: each peer should use its own sequence var
var GLOBAL_SEQUENCE uint32
var TIMESTAMP uint32

type Header struct {
	Length    uint16
	Magic     uint16
	SrcID     uint16
	DstID     uint16
	Timestamp uint32
	Sequence  uint32
}

func (h *Header) FromNetwork(data []byte) {
	h.Length = binary.BigEndian.Uint16(data[0:2])
	h.Magic = binary.BigEndian.Uint16(data[2:4])
	h.SrcID = binary.BigEndian.Uint16(data[4:6])
	h.DstID = binary.BigEndian.Uint16(data[6:8])
	h.Timestamp = binary.BigEndian.Uint32(data[8:12])
	h.Sequence = binary.BigEndian.Uint32(data[12:16])
}

func (h *Header) ToNetwork() []byte {
	data := make([]byte, HEADER_LEN)
	binary.BigEndian.PutUint16(data[0:2], h.Length)
	binary.BigEndian.PutUint16(data[2:4], h.Magic)
	binary.BigEndian.PutUint16(data[4:6], h.SrcID)
	binary.BigEndian.PutUint16(data[6:8], h.DstID)
	binary.BigEndian.PutUint32(data[8:12], h.Timestamp)
	binary.BigEndian.PutUint32(data[12:16], h.Sequence)
	return data
}

func UpdateTimestampSeq() {
	now := uint32(time.Now().Unix())
	if now == TIMESTAMP {
		GLOBAL_SEQUENCE += 1
	} else {
		TIMESTAMP = now
		GLOBAL_SEQUENCE = 0

	}
}
