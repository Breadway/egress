//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

var (
	iphlpapi           = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreateFile = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpSendEcho   = iphlpapi.NewProc("IcmpSendEcho")
	procIcmpClose      = iphlpapi.NewProc("IcmpCloseHandle")
)

type ipOptionInformation struct {
	Ttl         byte
	Tos         byte
	Flags       byte
	OptionsSize uint32
	OptionsData uintptr
}

// pingHost sends one ICMP echo and returns the round trip. It needs no admin
// rights: IcmpSendEcho uses the ICMP helper, not a raw socket.
func pingHost(host string, timeout time.Duration) (time.Duration, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return 0, err
	}
	var v4 net.IP
	for _, ip := range ips {
		if candidate := ip.To4(); candidate != nil {
			v4 = candidate
			break
		}
	}
	if v4 == nil {
		return 0, fmt.Errorf("no IPv4 address for %s", host)
	}
	addr := binary.LittleEndian.Uint32(v4)

	handle, _, callErr := procIcmpCreateFile.Call()
	if handle == 0 || handle == uintptr(syscall.InvalidHandle) {
		return 0, callErr
	}
	defer procIcmpClose.Call(handle)

	var payload [32]byte
	var options ipOptionInformation
	reply := make([]byte, 64)
	got, _, sendErr := procIcmpSendEcho.Call(
		handle,
		uintptr(addr),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(unsafe.Pointer(&options)),
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(len(reply)),
		uintptr(timeout.Milliseconds()),
	)
	if got == 0 {
		return 0, sendErr
	}
	status := *(*uint32)(unsafe.Pointer(&reply[0]))
	if status != 0 {
		return 0, fmt.Errorf("icmp status %d", status)
	}
	rtt := *(*uint32)(unsafe.Pointer(&reply[8]))
	return time.Duration(rtt) * time.Millisecond, nil
}
