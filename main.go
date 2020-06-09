//  A simple user-space peer-to-peer UDP-based tunnel.

package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var log = Logger{Level: LevelInfo}

func workerSend(tunFd *os.File, conn *net.UDPConn, vpn *VPNCtx, running *bool) {
	pkt := PktOut{
		Vpn: vpn,
	}
	pkt.Init()

	var err error
	for *running {
		pkt.InnerLen, err = tunFd.Read(pkt.TunBuffer)

		switch err := err.(type) {
		case nil:
			// no error
		case *os.PathError:
			log.Error("Error read: %T: %v\n", err, err)
			log.Error("Tunnel interface may have been deleted, exit now.\n")
			*running = false
			return
		default:
			log.Warning("error read: %T: %v\n", err, err)
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

func workerRecv(tunFd *os.File, conn *net.UDPConn, vpn *VPNCtx, running *bool) {
	pkt := PktIn{
		Vpn: vpn,
	}
	pkt.Init()

	for *running {
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
				_, err = conn.WriteToUDP(pkt.UdpBuffer[:ObfsLength(pkt.h.Length)], addr)
				if err != nil {
					log.Warning("error send: %v\n", err)
				}
			}
			continue
		}

		if strings.EqualFold(pkt.Vpn.Config.Mode, MODE_FORWARDER) {
			log.Error("Can not write to forwarder.\n")
			continue
		}

		_, err = tunFd.Write(pkt.TunBuffer)
		if err != nil {
			log.Warning("error write: %v\n", err)
		}
	}
}

func signalHandler(sigCh chan os.Signal, system System, running *bool) {
	sig := <-sigCh
	log.Info("Got signal: %v\n", sig)
	system.Restore()
	*running = false

	for {
		sig = <-sigCh
		log.Info("Got signal: %v\n", sig)
		*running = false
	}
}

func main() {
	var err error
	var conn *net.UDPConn
	var tunFd *os.File
	var conf Config
	var pool []Peer
	var vpn VPNCtx
	var system System
	running := true
	rand.Seed(time.Now().UnixNano())

	path := flag.String("c", "/usr/local/etc/alpaca-tunnel.d/config.json", "Path to config.json")
	flag.Parse()

	// path := os.Args[1]
	conf, err = GetConfig(*path)
	if err != nil {
		log.Error("Error get config: %v\n", err)
		return
	}

	log.SetLevel(conf.LogLevel)
	log.Info("%+v\n", conf.Format())

	pool, err = GetPeerPool(conf.SecretFile)
	if err != nil {
		log.Error("Error get pool: %v\n", err)
		return
	}
	log.Debug(FormatPeerPool(pool))

	vpn = VPNCtx{
		Config:   conf,
		PeerPool: pool,
	}
	err = vpn.InitCtx()
	if err != nil {
		log.Error("Error init VPN: %v\n", err)
		return
	}

	if !strings.EqualFold(conf.Mode, MODE_FORWARDER) {
		conf.Name, tunFd, err = OpenTun(conf.Name)
		if err != nil {
			log.Error("Error open: %v\n", err)
			return
		}
	}

	localAddr := net.UDPAddr{
		Port: conf.Port,
		IP:   net.ParseIP("0.0.0.0"),
	}

	conn, err = net.ListenUDP("udp", &localAddr)
	if err != nil {
		log.Info("error listen: %v\n", err)
		return
	}

	system = System{
		Conf:        conf,
		PeerPool:    pool,
		DefautRoute: "",
		MyIP:        fmt.Sprintf("%v.%v", conf.Net, conf.Id),
		Gateway:     fmt.Sprintf("%v.%v", conf.Net, conf.Gateway),
	}

	err = system.Init()
	if err != nil {
		log.Error("Init system failed.\n")
		system.Restore()
		return
	}

	sigCh := make(chan os.Signal)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go signalHandler(sigCh, system, &running)

	if !strings.EqualFold(conf.Mode, MODE_FORWARDER) {
		go workerSend(tunFd, conn, &vpn, &running)
	}

	go workerRecv(tunFd, conn, &vpn, &running)

	log.Info("VPN started...\n")

	for running {
		time.Sleep(time.Second)
	}

	log.Info("The main progress has ended.\n")
}
