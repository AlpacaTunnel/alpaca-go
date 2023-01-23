//  A simple user-space peer-to-peer UDP-based tunnel.

package main

import (
	"context"
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

var log = Logger{}

func main() {
	var err error
	var conn *net.UDPConn
	var tunFd *os.File
	var conf Config
	var pool []Peer
	var vpn VPNCtx
	var system System
	rand.Seed(time.Now().UnixNano())

	path := flag.String("c", "/usr/local/etc/alpaca-tunnel.d/config.json", "Path to config.json")
	flag.Parse()

	conf, err = GetConfig(*path)
	if err != nil {
		log.Error("Error get config: %+v\n", err)
		return
	}

	log.SetLevel(conf.LogLevel)
	log.Info("%+v\n", conf.Format())

	pool, err = GetPeerPool(conf.SecretFile, IdPton(conf.ID))
	if err != nil {
		log.Error("Error get pool: %+v\n", err)
		return
	}
	log.Debug(FormatPeerPool(pool))

	vpn = VPNCtx{
		Config:   conf,
		PeerPool: pool,
	}
	err = vpn.InitCtx()
	if err != nil {
		log.Error("Error init VPN: %+v\n", err)
		return
	}

	if !strings.EqualFold(conf.Mode, MODE_FORWARDER) {
		conf.Name, tunFd, err = OpenTun(conf.Name)
		if err != nil {
			log.Error("Error open: %+v\n", err)
			return
		}
	}

	localAddr := net.UDPAddr{
		Port: conf.Port,
		IP:   net.ParseIP("0.0.0.0"),
	}

	conn, err = net.ListenUDP("udp", &localAddr)
	if err != nil {
		log.Info("error listen: %+v\n", err)
		return
	}

	system = System{
		Conf:        conf,
		PeerPool:    pool,
		DefautRoute: "",
		MyIP:        fmt.Sprintf("%v.%v", conf.Net, conf.ID),
		Gateway:     fmt.Sprintf("%v.%v", conf.Net, conf.Gateway),
	}

	err = system.Init()
	if err != nil {
		log.Error("Init system failed: %+v.\n", err)
		system.Restore()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	ctxMain, cancelMain := context.WithCancel(context.Background())

	sigs := make(chan os.Signal)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		sig := <-sigs
		log.Info("Got signal: %v\n", sig)
		cancel()
		system.Restore()
		cancelMain()
	}()

	if !strings.EqualFold(conf.Mode, MODE_FORWARDER) {
		go workerSend(ctx, tunFd, conn, &vpn)
	}

	go workerRecv(ctx, tunFd, conn, &vpn)

	if strings.EqualFold(conf.Mode, MODE_CLIENT) {
		go workerMoniterRoute(ctx, system)
	}

	log.Info("VPN started...\n")

	<-ctxMain.Done()

	log.Info("The main progress has ended.\n")
}

func hasLoop(pkt *PktOut) bool {
	for _, addr := range pkt.DstAddrs {
		if InetAton(addr.IP) == pkt.IP.H.DstIP {
			log.Error("local route loop: %v\n", addr.IP)
			return true
		}
	}
	return false
}

func workerSend(ctx context.Context, tunFd *os.File, conn *net.UDPConn, vpn *VPNCtx) {
	pkt := PktOut{
		Vpn: vpn,
	}
	pkt.Init()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			handleSend(tunFd, conn, vpn, &pkt)
		}
	}
}

func handleSend(tunFd *os.File, conn *net.UDPConn, vpn *VPNCtx, pkt *PktOut) {
	var err error
	pkt.InnerLen, err = tunFd.Read(pkt.TunBuffer)

	switch err := err.(type) {
	case nil:
	case *os.PathError:
		log.Error("Error read: %T: %v\n", err, err)
		panic("Tunnel interface may have been deleted, exit now.")
	default:
		log.Warning("error read: %T: %v\n", err, err)
		return
	}

	if err := pkt.Process(); err != nil {
		log.Debug("Process pakcet failed: %+v\n", err)
		return
	}

	if hasLoop(pkt) {
		return
	}

	for _, addr := range pkt.DstAddrs {
		_, err = conn.WriteToUDP(pkt.UdpBuffer, addr)
		if err != nil {
			log.Warning("error send: %v\n", err)
		}
	}
}

func workerRecv(ctx context.Context, tunFd *os.File, conn *net.UDPConn, vpn *VPNCtx) {
	pkt := PktIn{
		Vpn: vpn,
	}
	pkt.Init()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			handleRecv(tunFd, conn, vpn, &pkt)
		}
	}
}

func handleRecv(tunFd *os.File, conn *net.UDPConn, vpn *VPNCtx, pkt *PktIn) {
	length, addr, err := conn.ReadFromUDP(pkt.UdpBuffer)
	if err != nil {
		log.Warning("error recv: %v\n", err)
		return
	}
	pkt.OutterLen = length
	pkt.SrcAddr = addr

	if err := pkt.Process(); err != nil {
		log.Debug("Process pakcet failed: %+v\n", err)
		return
	}

	if pkt.Action == ACTION_FORWARD {
		for _, addr := range pkt.DstAddrs {
			// TODO: re-encrypt? otherwise bytes data are the same
			fwdLen := HEADER_LEN + CHACHA20_OVERHEAD + ObfsLength(pkt.H.Length)
			_, err = conn.WriteToUDP(pkt.UdpBuffer[:fwdLen], addr)
			if err != nil {
				log.Warning("error send: %v\n", err)
			}
		}
		return
	}

	if strings.EqualFold(pkt.Vpn.Config.Mode, MODE_FORWARDER) {
		log.Error("Can not write to forwarder.\n")
		return
	}

	_, err = tunFd.Write(pkt.TunBuffer)
	if err != nil {
		log.Warning("error write: %v\n", err)
	}
}

func workerMoniterRoute(ctx context.Context, system System) {
	time.Sleep(10 * time.Second)
	interval := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
			if system.HasDefaultRoute() {
				system.ReRouteToTunnel()
				// avoid conflict with network-manager dhcp client
				interval = 10 * time.Second
			} else {
				interval = time.Second
			}
		}
	}
}
