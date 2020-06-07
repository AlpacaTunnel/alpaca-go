/*
  A simple user-space peer-to-peer UDP-based tunnel.

  sudo ip tuntap add dev tun9 mode tun
  sudo ip link set tun9 up
  sudo ip addr add 10.0.1.2/24 dev tun9
  sudo ip link set tun9 mtu 1408

  go run udptun.go tun9 8964 172.16.89.64 1984
*/

package main

import (
	"net"
	"os"
	"time"
)

var log = Logger{Level: LevelDebug}

func workerSend(tunFd *os.File, conn *net.UDPConn, vpn *VPNCtx) {
	pkt := PktOut{
		Vpn: vpn,
	}
	pkt.Init()

	var err error
	for {
		pkt.InnerLen, err = tunFd.Read(pkt.TunBuffer)
		if err != nil {
			log.Warning("error read: %v\n", err)
		}

		pkt.Process()

		if !pkt.Valid {
			continue
		}

		for _, addr := range pkt.DstAddrs {
			_, err = conn.WriteToUDP(pkt.UdpBuffer, addr)
			if err != nil {
				log.Warning("error send: %v\n", err)
			}
		}
	}
}

func workerRecv(tunFd *os.File, conn *net.UDPConn, vpn *VPNCtx) {
	pkt := PktIn{
		Vpn: vpn,
	}
	pkt.Init()

	for {
		length, addr, err := conn.ReadFromUDP(pkt.UdpBuffer)
		if err != nil {
			log.Warning("error recv: %v\n", err)
		}
		pkt.OutterLen = length
		pkt.SrcAddr = addr

		pkt.Process()

		if !pkt.Valid {
			continue
		}

		if pkt.Action == ActionForward {
			for _, addr := range pkt.DstAddrs {
				_, err = conn.WriteToUDP(pkt.UdpBuffer[:length], addr)
				if err != nil {
					log.Warning("error send: %v\n", err)
				}
			}
			continue
		}

		_, err = tunFd.Write(pkt.TunBuffer)
		if err != nil {
			log.Warning("error write: %v\n", err)
		}
	}
}

func main() {
	path := os.Args[1]
	conf, err := GetConfig(path)
	if err != nil {
		log.Error("Error get config: %v\n", err)
		return
	}
	log.Info("%+v\n", conf.Format())

	pool, err := GetPeerPool(conf.SecretFile)
	if err != nil {
		log.Error("Error get pool: %v\n", err)
		return
	}
	log.Debug(FormatPeerPool(pool))

	vpn := VPNCtx{
		Config:   conf,
		PeerPool: pool,
	}
	err = vpn.InitCtx()
	if err != nil {
		log.Error("Error init VPN: %v\n", err)
		return
	}

	_, tunFd, err := OpenTun(conf.Name)
	if err != nil {
		log.Error("Error open: %v\n", err)
		return
	}

	localAddr := net.UDPAddr{
		Port: conf.Port,
		IP:   net.ParseIP("0.0.0.0"),
	}

	conn, err := net.ListenUDP("udp", &localAddr)
	if err != nil {
		log.Info("error listen: %v\n", err)
		return
	}

	go workerSend(tunFd, conn, &vpn)
	go workerRecv(tunFd, conn, &vpn)

	for {
		time.Sleep(time.Second)
	}
}
