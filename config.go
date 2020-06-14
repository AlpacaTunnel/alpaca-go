package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"path/filepath"
	"strings"
)

const DEFAULT_CONFIG = "config.json"
const DEFAULT_SECRET = "secrets.txt"

type Config struct {
	Path                   string
	Name                   string   `json:"name"`
	Mode                   string   `json:"mode"`
	Group                  string   `json:"group"`
	Net                    string   `json:"net"`
	VirtualNet             string   `json:"virtual_net"`
	ID                     string   `json:"id"`
	Gateway                string   `json:"gateway"`
	Port                   int      `json:"port"`
	Mtu                    int      `json:"mtu"`
	Duplicate              int      `json:"duplicate"`
	SecretFile             string   `json:"secret_file"`
	LogLevel               string   `json:"log_level"`
	InactiveDownwardStatic bool     `json:"inactive_downward_static"`
	Forwarders             []string `json:"forwarders"`
	PostUpCmds             []string `json:"post_up_cmds"`
	PostDownCmds           []string `json:"post_down_cmds"`
	LocalRoutes            []string `json:"local_routes"`
	Chnroute               Chnroute `json:"chnroute"`
}

type Chnroute struct {
	Table   string `json:"table"`
	Gateway string `json:"gateway"`
	Data    string `json:"data"`
}

func GetConfig(path string) (Config, error) {
	var c Config

	file, err := ioutil.ReadFile(path)
	if err != nil {
		return c, err
	}

	err = json.Unmarshal(file, &c)
	if err != nil {
		return c, err
	}

	c.Path, err = filepath.Abs(path)
	if err != nil {
		return c, err
	}

	if c.SecretFile == "" {
		c.SecretFile = filepath.Join(filepath.Dir(c.Path), DEFAULT_SECRET)
	} else {
		c.SecretFile = filepath.Join(filepath.Dir(c.Path), c.SecretFile)
	}

	if c.Chnroute.Data != "" {
		c.Chnroute.Data = filepath.Join(filepath.Dir(c.Path), c.Chnroute.Data)
	}

	if !strings.EqualFold("server", c.Mode) && !strings.EqualFold("client", c.Mode) && !strings.EqualFold("forwarder", c.Mode) {
		return c, errors.New("Mode can only be server/client/forwarder")
	}

	if strings.EqualFold("client", c.Mode) && len(c.Gateway) == 0 {
		return c, errors.New("Client must have a gateway")
	}

	return c, nil
}

func (c *Config) Format() string {
	pretty, _ := json.MarshalIndent(c, "", "\t")
	return "\n" + string(pretty)
}
