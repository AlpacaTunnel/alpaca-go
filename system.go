package main

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"time"
)

type System struct {
	Conf        Config
	pool        []Peer
	DefautRoute string
	Gateway     string
}

func (s *System) getAddRoutesCmds() []string {
	var cmds []string
	cmds = append(cmds, "ip route delete default")

	for _, peer := range s.pool {
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

	defaultRoute := fmt.Sprintf("ip route add default via %v table default", s.DefautRoute)
	cmds = append(cmds, defaultRoute)

	return cmds
}

func (s *System) getDelRoutesCmds() []string {
	var cmds []string
	defaultRoute := fmt.Sprintf("ip route add default via %v", s.DefautRoute)
	cmds = append(cmds, defaultRoute)

	for _, peer := range s.pool {
		if peer.ID == 0 {
			continue
		}
		for _, addr := range peer.GetAddr(true, false) {
			route := fmt.Sprintf("ip route delete %v via %v table default | true", addr.IP, s.DefautRoute)
			cmds = append(cmds, route)
		}
	}

	for _, ip := range s.Conf.LocalRoutes {
		route := fmt.Sprintf("ip route delete %v via %v table default", ip, s.DefautRoute)
		cmds = append(cmds, route)
	}

	cmds = append(cmds, "ip route add default table default")

	return cmds
}

func (s *System) getDefaultRoute() string {
	output, _ := ExecCmd("ip route show default table default")
	re := regexp.MustCompile(`default\s+via\s+([\.\d]+)\s*`)
	route := re.FindSubmatch([]byte(output))
	if len(route) != 2 {
		return ""
	}
	return string(route[1])
}

func (s *System) waitDefaultRoute() {
	for route := s.getDefaultRoute(); len(route) == 0; {
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

func (s *System) Chnroute() {
	chnFile := s.getChnrouteFile("add")
	if len(chnFile) == 0 {
		return
	}

	cmd := "ip -force -batch " + chnFile
	log.Debug("%v\n", cmd)
	ExecCmd(cmd)
}

func (s *System) ChnrouteRestore() {
	chnFile := s.getChnrouteFile("del")
	if len(chnFile) == 0 {
		return
	}

	cmd := "ip -force -batch " + chnFile
	log.Debug("%v\n", cmd)
	ExecCmd(cmd)
}
