package main

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const (
	TCP_MSS        = 1300
	MODE_SERVER    = "server"
	MODE_CLIENT    = "client"
	MODE_FORWARDER = "forwarder"
)

type System struct {
	Conf        Config
	PeerPool    []Peer
	DefautRoute string
	MyIP        string
	Gateway     string
}

func (s *System) getAddRoutesCmds() []string {
	var cmds []string
	cmds = append(cmds, "ip route delete default")

	for _, peer := range s.PeerPool {
		if peer.ID == 0 {
			continue
		}
		for _, addr := range peer.GetAddr(true, false) {
			route := fmt.Sprintf("ip route add %v via %v table default | true", addr.IP, s.DefautRoute)
			cmds = append(cmds, route)
		}
	}

	for _, ip := range s.Conf.LocalRoutes {
		route := fmt.Sprintf("ip route add %v via %v table default", ip, s.DefautRoute)
		cmds = append(cmds, route)
	}

	defaultRoute := fmt.Sprintf("ip route add default via %v table default", s.Gateway)
	cmds = append(cmds, defaultRoute)

	return cmds
}

func (s *System) getDelRoutesCmds() []string {
	var cmds []string
	defaultRoute := fmt.Sprintf("ip route add default via %v", s.DefautRoute)
	cmds = append(cmds, defaultRoute)

	for _, peer := range s.PeerPool {
		if peer.ID == 0 {
			continue
		}
		for _, addr := range peer.GetAddr(true, false) {
			route := fmt.Sprintf("ip route delete %v via %v table default", addr.IP, s.DefautRoute)
			cmds = append(cmds, route)
		}
	}

	for _, ip := range s.Conf.LocalRoutes {
		route := fmt.Sprintf("ip route delete %v via %v table default", ip, s.DefautRoute)
		cmds = append(cmds, route)
	}

	cmds = append(cmds, "ip route delete default table default")

	return cmds
}

func (s *System) getDefaultRoute() string {
	output, _ := ExecCmd("ip route show default")
	re := regexp.MustCompile(`default\s+via\s+([\.\d]+)\s*`)
	route := re.FindSubmatch([]byte(output))
	if len(route) != 2 {
		return ""
	}
	return string(route[1])
}

func (s *System) waitDefaultRoute() {
	for len(s.getDefaultRoute()) == 0 {
		log.Warning("No default route yet, wait 1s and try again...\n")
		time.Sleep(1 * time.Second)
	}
	s.DefautRoute = s.getDefaultRoute()
}

func (s *System) getChnrouteFile(action string) string {
	if len(s.Conf.Chnroute.Data) == 0 {
		return ""
	}

	raw_lines, err := GetLines(s.Conf.Chnroute.Data)
	if err != nil {
		log.Warning("Error open Chnroute: %v\n", s.Conf.Chnroute.Data)
		return ""
	}

	data := ""
	for _, line := range raw_lines {
		route := fmt.Sprintf("route %v %v via %v table %v\n", action, line, s.DefautRoute, s.Conf.Chnroute.Table)
		data += route
	}

	tmpFile := "/tmp/chnroute-" + action + "-1984"

	err = ioutil.WriteFile(tmpFile, []byte(data), 0644)
	if err != nil {
		log.Warning("Error write temp Chnroute script: %v: %v\n", tmpFile, err)
		return ""
	}

	return tmpFile
}

func (s *System) chnroute() error {
	chnFile := s.getChnrouteFile("add")
	if len(chnFile) == 0 {
		return nil
	}

	cmd := "ip -force -batch " + chnFile
	log.Info("%v\n", cmd)
	_, err := ExecCmd(cmd)
	return errors.Wrap(err, "chnroute failed")
}

func (s *System) chnrouteRestore() {
	chnFile := s.getChnrouteFile("del")
	if len(chnFile) == 0 {
		return
	}

	cmd := fmt.Sprintf("ip -force -batch %v > %v.log 2>&1", chnFile, chnFile)
	log.Info("%v\n", cmd)
	ExecCmd(cmd)
}

func (s *System) initClient() error {
	s.waitDefaultRoute()
	cmds := s.getAddRoutesCmds()

	cmds = append(cmds, "sysctl net.ipv4.ip_forward=1")
	cmds = append(cmds, fmt.Sprintf("iptables -A FORWARD -s %v.0.0/16 -j ACCEPT", s.Conf.Net))
	cmds = append(cmds, fmt.Sprintf("iptables -A FORWARD -d %v.0.0/16 -j ACCEPT", s.Conf.Net))
	cmds = append(cmds, fmt.Sprintf("iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %v", TCP_MSS))

	for _, cmd := range cmds {
		_, err := ExecCmd(cmd)
		if err != nil {
			return errors.Wrap(err, "initClient failed")
		}
	}
	log.Info("default route changed to tunnel\n")

	return s.chnroute()
}

func (s *System) restoreClient() {
	cmds := s.getDelRoutesCmds()

	cmds = append(cmds, fmt.Sprintf("iptables -D FORWARD -s %v.0.0/16 -j ACCEPT", s.Conf.Net))
	cmds = append(cmds, fmt.Sprintf("iptables -D FORWARD -d %v.0.0/16 -j ACCEPT", s.Conf.Net))
	cmds = append(cmds, fmt.Sprintf("iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %v", TCP_MSS))

	for _, cmd := range cmds {
		ExecCmd(cmd)
	}

	s.chnrouteRestore()
}

func (s *System) initServer() error {
	var cmds []string
	cmds = append(cmds, "sysctl net.ipv4.ip_forward=1")
	cmds = append(cmds, fmt.Sprintf("iptables -A FORWARD -s %v.0.0/16 -j ACCEPT", s.Conf.Net))
	cmds = append(cmds, fmt.Sprintf("iptables -A FORWARD -d %v.0.0/16 -j ACCEPT", s.Conf.Net))
	cmds = append(cmds, fmt.Sprintf("iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %v", TCP_MSS))
	cmds = append(cmds, fmt.Sprintf("iptables -A POSTROUTING -t nat -s %v.0.0/16 -j MASQUERADE", s.Conf.Net))

	for _, cmd := range cmds {
		_, err := ExecCmd(cmd)
		if err != nil {
			return errors.Wrap(err, "initServer failed")
		}
	}
	return nil
}

func (s *System) restoreServer() {
	var cmds []string
	cmds = append(cmds, fmt.Sprintf("iptables -D FORWARD -s %v.0.0/16 -j ACCEPT", s.Conf.Net))
	cmds = append(cmds, fmt.Sprintf("iptables -D FORWARD -d %v.0.0/16 -j ACCEPT", s.Conf.Net))
	cmds = append(cmds, fmt.Sprintf("iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %v", TCP_MSS))
	cmds = append(cmds, fmt.Sprintf("iptables -D POSTROUTING -t nat -s %v.0.0/16 -j MASQUERADE", s.Conf.Net))

	for _, cmd := range cmds {
		ExecCmd(cmd)
	}
}

func (s *System) execPostUp() error {
	for _, cmd := range s.Conf.PostUpCmds {
		_, err := ExecCmd(cmd)
		if err != nil {
			return errors.Wrap(err, "execPostUp failed")
		}
	}
	return nil
}

func (s *System) execPostDown() {
	for _, cmd := range s.Conf.PostDownCmds {
		ExecCmd(cmd)
	}
}

func (s *System) AddIP() error {
	var cmds []string
	cmds = append(cmds, fmt.Sprintf("ip link set %v up", s.Conf.Name))
	cmds = append(cmds, fmt.Sprintf("ip link set %v mtu %v", s.Conf.Name, TUN_MTU))
	cmds = append(cmds, fmt.Sprintf("ip addr add %v/16 dev %v", s.MyIP, s.Conf.Name))

	for _, cmd := range cmds {
		_, err := ExecCmd(cmd)
		if err != nil {
			return errors.Wrap(err, "AddIP failed")
		}
	}
	return nil
}

func (s *System) Init() error {
	log.Info("Init system...\n")

	var err error

	if !strings.EqualFold(s.Conf.Mode, MODE_FORWARDER) {
		err = s.AddIP()
		if err != nil {
			return errors.Wrap(err, "Init system failed")
		}
	}

	if strings.EqualFold(s.Conf.Mode, MODE_CLIENT) {
		err = s.initClient()
		if err != nil {
			return errors.Wrap(err, "Init system failed")
		}
	} else {
		err := s.initServer()
		if err != nil {
			return errors.Wrap(err, "Init system failed")
		}
	}
	return s.execPostUp()
}

func (s *System) Restore() {
	log.Info("Restore system...\n")
	if strings.EqualFold(s.Conf.Mode, MODE_CLIENT) {
		s.restoreClient()
	} else {
		s.restoreServer()
	}
	s.execPostDown()
}
