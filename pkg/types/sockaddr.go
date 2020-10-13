package types

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"syscall"
	"unsafe"
)

// SockAddr our local version of RawSockadddr that we can manipulate
type SockAddr syscall.RawSockaddr

func ntohs(port uint16) uint16 {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, port)
	return binary.LittleEndian.Uint16(buf)
}

func parseSockAddr(s *SockAddr) (string, int) {
	switch s.Family {
	case syscall.AF_INET:
		pp := (*syscall.RawSockaddrInet4)(unsafe.Pointer(s))

		port := ntohs(pp.Port)
		addr := fmt.Sprintf("ipv4:%d.%d.%d.%d", pp.Addr[0],
			pp.Addr[1], pp.Addr[2], pp.Addr[3])

		return addr, int(port)
	case syscall.AF_INET6:
		pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(s))

		port := pp.Port
		addr := fmt.Sprintf("ipv6:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			pp.Addr[0],
			pp.Addr[1],
			pp.Addr[2],
			pp.Addr[3],
			pp.Addr[4],
			pp.Addr[5],
			pp.Addr[6],
			pp.Addr[7],
			pp.Addr[8],
			pp.Addr[9],
			pp.Addr[10],
			pp.Addr[11],
			pp.Addr[12],
			pp.Addr[13],
			pp.Addr[14],
			pp.Addr[15])

		return addr, int(port)
	case syscall.AF_UNIX:
		pp := (*syscall.RawSockaddrUnix)(unsafe.Pointer(s))

		return fmt.Sprintf("unix:%v", MakeCString(unsafe.Pointer(&pp.Path), len(pp.Path))), 0 //C.GoString((*C.char)(unsafe.Pointer(&pp.Path)))), 0
	case syscall.AF_UNSPEC:
		return fmt.Sprintf("unspec:%v", s.Data), 0

	}

	return fmt.Sprintf("%d", s.Family), 0
}

func (s *SockAddr) String() string {
	addr, port := parseSockAddr(s)

	if addr != "" {
		return fmt.Sprintf("%v:%v", addr, port)
	}

	return ""
}

func (s *SockAddr) MarshalJSON() ([]byte, error) {
	addr, port := parseSockAddr(s)

	type Alias SockAddr
	n := &struct {
		*Alias
		Decoded string `json:"decoded,omitempty"`
	}{
		Alias:   (*Alias)(s),
		Decoded: fmt.Sprintf("%s:%d", addr, port),
	}

	return json.Marshal(n)
}
