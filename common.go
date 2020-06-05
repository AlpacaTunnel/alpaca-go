package main

import (
	"strconv"
	"strings"
)

const AES_BLOCK_SIZE = 16

// convert 1.1 to 257
func IdPton(idStr string) int {
	len := len(strings.Split(idStr, "."))
	if len != 2 {
		log.Warning("ID length is not 2: %v\n", idStr)
		return 0
	}
	idA := strings.Split(idStr, ".")[0]
	idB := strings.Split(idStr, ".")[1]

	intA, err := strconv.Atoi(idA)
	if err != nil {
		log.Warning("Failed to convert ID: %v\n", idStr)
		return 0
	}

	intB, err := strconv.Atoi(idB)
	if err != nil {
		log.Warning("Failed to convert ID: %v\n", idStr)
		return 0
	}

	return intA*256 + intB
}

func TruncateKey(key string) [AES_BLOCK_SIZE]byte {
	s := []byte(key)
	var b [AES_BLOCK_SIZE]byte
	copy(b[:], s)
	return b
}

func MaxInt(x, y int) int {
	if x > y {
		return x
	}
	return y
}
