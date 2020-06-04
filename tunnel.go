package main

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const (
	cIFF_TUN   = 0x0001
	cIFF_TAP   = 0x0002
	cIFF_NO_PI = 0x1000
	cIFNAMSIZ  = 15
)

type ifReq struct {
	Name  [0x10]byte
	Flags uint16
	pad   [0x28 - 0x10 - 2]byte
}

func createTun(tunFd *os.File, namePattern string) (string, error) {
	var req ifReq
	copy(req.Name[:cIFNAMSIZ], namePattern)
	req.Flags = 0
	req.Flags |= cIFF_TUN
	req.Flags |= cIFF_NO_PI

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, tunFd.Fd(), uintptr(syscall.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return "", os.NewSyscallError("ioctl", errno)
	}

	tunName := strings.Trim(string(req.Name[:]), "\x00")

	return tunName, nil
}

func OpenTun(namePattern string) (string, *os.File, error) {
	tunFd, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return "", nil, err
	}

	tunName, err := createTun(tunFd, namePattern)
	if err != nil {
		tunFd.Close()
		return "", nil, err
	}

	return tunName, tunFd, nil
}
