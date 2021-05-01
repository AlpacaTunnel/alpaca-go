package main

import (
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	cIFF_TUN   = 0x0001
	cIFF_TAP   = 0x0002
	cIFF_NO_PI = 0x1000
	cIFNAMSIZ  = 15
	cTunDevice = "/dev/net/tun"
)

type ifReq struct {
	Name  [0x10]byte
	Flags uint16
	pad   [0x28 - 0x10 - 2]byte
}

func createTun(tunFd int, namePattern string) (string, error) {
	var req ifReq
	copy(req.Name[:cIFNAMSIZ], namePattern)
	req.Flags = 0
	req.Flags |= cIFF_TUN
	req.Flags |= cIFF_NO_PI

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(tunFd),
		uintptr(syscall.TUNSETIFF),
		uintptr(unsafe.Pointer(&req)),
	)

	if errno != 0 {
		return "", os.NewSyscallError("ioctl", errno)
	}

	err := unix.SetNonblock(tunFd, true)
	if err != nil {
		return "", nil
	}

	tunName := strings.Trim(string(req.Name[:]), "\x00")

	return tunName, nil
}

func OpenTun(namePattern string) (string, *os.File, error) {
	tunFd, err := unix.Open(cTunDevice, os.O_RDWR, 0)
	if err != nil {
		return "", nil, err
	}

	tunName, err := createTun(tunFd, namePattern)
	if err != nil {
		unix.Close(tunFd)
		return "", nil, err
	}

	fd := os.NewFile(uintptr(tunFd), cTunDevice)

	return tunName, fd, nil
}
