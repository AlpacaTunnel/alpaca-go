package main

import (
	"encoding/binary"
	"time"
)

const HEADER_LEN = AES_BLOCK_SIZE

// TODO: each peer should use its own sequence var
var GLOBAL_SEQUENCE uint32
var TIMESTAMP uint32

type Header struct {
	Type      uint16 // 3 bits
	SrcInside uint16 // 1 bit
	DstInside uint16 // 1 bit
	Length    uint16 // 11 bits
	TTL       uint16 // 4 bits
	Magic     uint16 // 12 bits
	SrcID     uint16
	DstID     uint16
	Timestamp uint32
	Sequence  uint32 // 20 bits
	Random    uint32 // 12 bits
}

func (h *Header) FromNetwork(data []byte) {
	typeSDLen := binary.BigEndian.Uint16(data[0:2])
	h.Type = typeSDLen >> 13
	h.SrcInside = (typeSDLen & 0x1000) >> 12
	h.DstInside = (typeSDLen & 0x0800) >> 11
	h.Length = typeSDLen & 0x07FF

	ttlMagic := binary.BigEndian.Uint16(data[2:4])
	h.TTL = (ttlMagic & 0xF000) >> 12
	h.Magic = ttlMagic & 0x0FFF

	h.SrcID = binary.BigEndian.Uint16(data[4:6])
	h.DstID = binary.BigEndian.Uint16(data[6:8])
	h.Timestamp = binary.BigEndian.Uint32(data[8:12])

	seqRand := binary.BigEndian.Uint32(data[12:16])
	h.Sequence = (seqRand & 0xFFFFF000) >> 12
	h.Random = seqRand & 0x00000FFF
}

func (h *Header) ToNetwork() []byte {
	data := make([]byte, HEADER_LEN)

	typeSDLen := h.Type<<13 + h.SrcInside<<12 + h.DstInside<<11 + h.Length
	binary.BigEndian.PutUint16(data[0:2], typeSDLen)

	ttlMagic := h.TTL<<12 + h.Magic
	binary.BigEndian.PutUint16(data[2:4], ttlMagic)

	binary.BigEndian.PutUint16(data[4:6], h.SrcID)
	binary.BigEndian.PutUint16(data[6:8], h.DstID)
	binary.BigEndian.PutUint32(data[8:12], h.Timestamp)

	seqRand := h.Sequence<<12 + h.Random
	binary.BigEndian.PutUint32(data[12:16], seqRand)

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
