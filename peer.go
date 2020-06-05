package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
)

const MAX_ID = 65535

type Peer struct {
	ID    int
	PSK   [AES_BLOCK_SIZE]byte
	Addrs []PeerAddr
}

type PeerAddr struct {
	Static     bool
	Version    int
	Addr       net.UDPAddr
	LastActive int
}

func GetPeerPool(path string) ([]Peer, error) {
	pool := make([]Peer, MAX_ID+2)

	lines, err := getLines(path)
	if err != nil {
		return nil, err
	}

	for _, line := range lines {
		p := getPeer(line)
		if p == nil {
			log.Warning("Ignore this line: %v\n", line)
			continue
		}

		if pool[p.ID].ID != 0 {
			log.Warning("Ignore duplicated ID: %v\n", p.ID)
			continue
		}

		pool[p.ID] = *p
	}

	return pool, nil
}

func FormatPeerPool(pool []Peer) string {
	output := "\n"
	for _, p := range pool {
		if p.ID != 0 {
			s := fmt.Sprintf("%v\n", p)
			output += s
		}
	}
	return output
}

func getPeer(line string) *Peer {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}

	p := Peer{
		ID:  IdPton(fields[0]),
		PSK: TruncateKey(fields[1]),
	}

	if p.ID == 0 {
		return nil
	}

	if len(fields) < 5 {
		return &p
	}

	port, err := strconv.Atoi(fields[4])
	ip := net.ParseIP(fields[2])
	if err != nil || ip == nil {
		log.Warning("Failed to parse IP:Port - %v:%v\n", fields[2], fields[4])
		return &p
	}

	addr := PeerAddr{
		Static:  true,
		Version: 4,
		Addr:    net.UDPAddr{IP: ip, Port: port},
	}
	p.Addrs = append(p.Addrs, addr)

	return &p
}

func getLines(path string) ([]string, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw_lines := strings.Split(string(content), "\n")

	var lines []string

	for _, raw_line := range raw_lines {
		line := strings.Trim(raw_line, " \t\r")
		if line == "" || line[0] == '#' {
			continue
		}
		lines = append(lines, line)
	}

	return lines, nil
}
