package call

import (
	"encoding/json"
	"fmt"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
	"golang.org/x/sys/unix"
)

type SockoptLevel int

// SockoptName is a combination of the type and level for easier marshalling and
// unmarshalling.
type SockoptName struct {
	Tp int `json:"tp"` // socket type
	Lv int `json:"lv"` // level
}

type Sockopt struct {
	FD    types.InputFD `json:"fd"`
	Level SockoptLevel  `json:"level"`
	Name  *SockoptName  `json:"name"`
	Val   []byte        `json:"val"`
	Len   int           `json:"len"`
}

func (g *Sockopt) DecodeArguments(data []*byte, arglen int) error {
	g.FD = types.InputFD(types.MakeC32(unsafe.Pointer(data[0])))
	lvl := SockoptLevel(int(types.MakeC32(unsafe.Pointer(data[1]))))
	g.Level = lvl
	//g.Level = &SockoptLevel(types.MakeC32(unsafe.Pointer(data[1])))
	g.Name = &SockoptName{
		Tp: int(types.MakeC32(unsafe.Pointer(data[2]))),
		Lv: int(g.Level),
	}
	// technically, we should be getting the length from data[4]
	// but, it can't be fully trusted, and in reality, the most
	// used data is 4 bytes.
	g.Val = types.MakeCBytes(unsafe.Pointer(data[3]), 4)
	g.Len = int(types.MakeC32(unsafe.Pointer(data[4])))

	return nil
}

func (g *Sockopt) Arguments() Arguments {
	return Arguments{
		{"sockfd", "int", g.FD},
		{"level", "int", g.Level},
		{"optname", "int", g.Name},
		{"optval", "void *", g.Val},
		// XXX[lz]: we should probably think about denoting variables as
		// 'dereferenced' when we actualy evaluate the data into the pointer
		// like we do here (socklen_t POINTER versus the actual value of that
		// pointer that we display here). What I mean is, socklen in the kernel
		// is a pointer, but we display the actual value of that pointer, but
		// still display the TYPE as a pointer.
		//
		// For now I have prepended (*) to the socklen_t type to designate
		// this is a dereferenced value.
		{"optlen", "(*)socklen_t *", g.Len},
	}
}

var sockLevelKeys map[string]int
var sockLevelMap = map[int]string{
	syscall.SOL_AAL:    "SOL_AAL",
	syscall.SOL_ATM:    "SOL_ATM",
	syscall.SOL_DECNET: "SOL_DECNET",
	syscall.SOL_ICMPV6: "SOL_ICMPV6",
	syscall.SOL_IP:     "SOL_IP",
	syscall.SOL_IPV6:   "SOL_IPV6",
	syscall.SOL_IRDA:   "SOL_IRDA",
	syscall.SOL_PACKET: "SOL_PACKET",
	syscall.SOL_RAW:    "SOL_RAW",
	syscall.SOL_SOCKET: "SOL_SOCKET",
	syscall.SOL_TCP:    "SOL_TCP",
	syscall.SOL_X25:    "SOL_X25",
}

func (s SockoptLevel) Parse() string {
	if v, ok := sockLevelMap[int(s)]; ok {
		return v
	}

	return fmt.Sprintf("%d", s)
}

func (s SockoptLevel) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Parse())
}

func (s *SockoptLevel) UnmarshalJSON(data []byte) error {
	var a string

	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}

	if v, ok := sockLevelKeys[a]; ok {
		*s = SockoptLevel(v)
	} else {
		if n, err := strconv.Atoi(a); err != nil {
			return err
		} else {
			*s = SockoptLevel(n)
		}
	}

	return nil
}

func (s SockoptLevel) String() string {
	return s.Parse()
}

var socketOpKeys map[string]int
var socketOpMasks = map[int]string{
	unix.SO_ACCEPTCONN:            "SO_ACCEPTCONN",
	unix.SO_ATTACH_FILTER:         "SO_ATTACH_FILTER",
	unix.SO_ATTACH_BPF:            "SO_ATTACH_BPF",
	unix.SO_ATTACH_REUSEPORT_CBPF: "SO_ATTACH_REUSEPORT_CBPF",
	unix.SO_ATTACH_REUSEPORT_EBPF: "SO_ATTACH_REUSEPORT_EBPF",
	unix.SO_BINDTODEVICE:          "SO_BINDTODEVICE",
	unix.SO_BROADCAST:             "SO_BROADCAST",
	unix.SO_BSDCOMPAT:             "SO_BSDCOMPAT",
	unix.SO_DEBUG:                 "SO_DEBUG",
	unix.SO_DETACH_FILTER:         "SO_DETACH_FILTER",
	unix.SO_DOMAIN:                "SO_DOMAIN",
	unix.SO_ERROR:                 "SO_ERROR",
	unix.SO_DONTROUTE:             "SO_DONTROUTE",
	unix.SO_INCOMING_CPU:          "SO_INCOMING_CPU",
	unix.SO_KEEPALIVE:             "SO_KEEPALIVE",
	unix.SO_LINGER:                "SO_LINGER",
	unix.SO_LOCK_FILTER:           "SO_LOCK_FILTER",
	unix.SO_MARK:                  "SO_MARK",
	unix.SO_OOBINLINE:             "SO_OOBINLINE",
	unix.SO_PASSCRED:              "SO_PASSCRED",
	unix.SO_PEEK_OFF:              "SO_PEEK_OFF",
	unix.SO_PEERCRED:              "SO_PEERCRED",
	unix.SO_PRIORITY:              "SO_PRIORITY",
	unix.SO_PROTOCOL:              "SO_PROTOCOL",
	unix.SO_RCVBUF:                "SO_RCVBUF",
	unix.SO_RCVBUFFORCE:           "SO_RCVBUFFORCE",
	unix.SO_RCVLOWAT:              "SO_RCVLOWAT",
	unix.SO_SNDLOWAT:              "SO_SNDLOWAT",
	unix.SO_RCVTIMEO:              "SO_RCVTIMEO",
	unix.SO_SNDTIMEO:              "SO_SNDTIMEO",
	unix.SO_REUSEADDR:             "SO_REUSEADDR",
	unix.SO_REUSEPORT:             "SO_REUSEPORT",
	unix.SO_RXQ_OVFL:              "SO_RXQ_OVFL",
	unix.SO_SNDBUF:                "SO_SNDBUF",
	unix.SO_PEERSEC:               "SO_PEERSEC",
	unix.SO_SNDBUFFORCE:           "SO_SNDBUFFORCE",
	unix.SO_TIMESTAMP:             "SO_TIMESTAMP",
	unix.SO_TYPE:                  "SO_TYPE",
	unix.SO_BUSY_POLL:             "SO_BUSY_POLL",
	unix.SO_PEERGROUPS:            "SO_PEERGROUPS",
	unix.SO_PEERNAME:              "SO_PEERNAME",
}

func (s *SockoptName) parseSocketOpt() string {
	if v, ok := socketOpMasks[int(s.Tp)]; ok {
		return v
	}

	return fmt.Sprintf("%d", s.Tp)
}

var tcpOpKeys map[string]int
var tcpOpMasks = map[int]string{
	unix.TCP_CONGESTION:   "TCP_CONGESTION",
	unix.TCP_CORK:         "TCP_CORK",
	unix.TCP_DEFER_ACCEPT: "TCP_DEFER_ACCEPT",
	unix.TCP_INFO:         "TCP_INFO",
	unix.TCP_KEEPCNT:      "TCP_KEEPCNT",
	unix.TCP_KEEPIDLE:     "TCP_KEEPIDLE",
	unix.TCP_KEEPINTVL:    "TCP_KEEPINTVL",
	unix.TCP_LINGER2:      "TCP_LINGER2",
	unix.TCP_MAXSEG:       "TCP_MAXSEG",
	unix.TCP_NODELAY:      "TCP_NODELAY",
	unix.TCP_QUICKACK:     "TCP_QUICKACK",
	unix.TCP_SYNCNT:       "TCP_SYNCNT",
	unix.TCP_USER_TIMEOUT: "TCP_USER_TIMEOUT",
	unix.TCP_WINDOW_CLAMP: "TCP_WINDOW_CLAMP",
	unix.TCP_THIN_DUPACK:  "TCP_THIN_DUPACK",
}

func (s *SockoptName) parseTcpOpt() string {
	if v, ok := tcpOpMasks[int(s.Tp)]; ok {
		return v
	}

	return fmt.Sprintf("%d", s.Tp)
}

var ipOpKeys map[string]int
var ipOpMasks = map[int]string{
	unix.IP_ADD_MEMBERSHIP:         "IP_ADD_MEMBERSHIP",
	unix.IP_ADD_SOURCE_MEMBERSHIP:  "IP_ADD_SOURCE_MEMBERSHIP",
	unix.IP_BIND_ADDRESS_NO_PORT:   "IP_BIND_ADDRESS_NO_PORT",
	unix.IP_BLOCK_SOURCE:           "IP_BLOCK_SOURCE",
	unix.IP_DROP_MEMBERSHIP:        "IP_DROP_MEMBERSHIP",
	unix.IP_DROP_SOURCE_MEMBERSHIP: "IP_DROP_SOURCE_MEMBERSHIP",
	unix.IP_FREEBIND:               "IP_FREEBIND",
	unix.IP_HDRINCL:                "IP_HDRINCL",
	unix.IP_MSFILTER:               "IP_MSFILTER",
	unix.IP_MTU:                    "IP_MTU",
	unix.IP_MTU_DISCOVER:           "IP_MTU_DISCOVER",
	unix.IP_MULTICAST_ALL:          "IP_MULTICAST_ALL",
	unix.IP_MULTICAST_IF:           "IP_MULTICAST_IF",
	unix.IP_MULTICAST_LOOP:         "IP_MULTICAST_LOOP",
	unix.IP_MULTICAST_TTL:          "IP_MULTICAST_TTL",
	unix.IP_NODEFRAG:               "IP_NODEFRAG",
	unix.IP_OPTIONS:                "IP_OPTIONS",
	unix.IP_PKTINFO:                "IP_PKTINFO",
	unix.IP_RECVERR:                "IP_RECVERR",
	unix.IP_RECVOPTS:               "IP_RECVOPTS",
	unix.IP_RECVORIGDSTADDR:        "IP_RECVORIGDSTADDR",
	unix.IP_RECVTOS:                "IP_RECVTOS",
	unix.IP_RECVTTL:                "IP_RECVTTL",
	unix.IP_RETOPTS:                "IP_RETOPTS",
	unix.IP_ROUTER_ALERT:           "IP_ROUTER_ALERT",
	unix.IP_TOS:                    "IP_TOS",
	unix.IP_TRANSPARENT:            "IP_TRANSPARENT",
	unix.IP_UNBLOCK_SOURCE:         "IP_UNBLOCK_SOURCE",
	unix.IP_TTL:                    "IP_TTL",
	unix.IP_UNICAST_IF:             "IP_UNICAST_IF",
}

func (s *SockoptName) parseIpOpt() string {
	if v, ok := ipOpMasks[s.Tp]; ok {
		return v
	}

	return fmt.Sprintf("%d", s.Tp)
}

var ip6OpKeys map[string]int
var ip6OpMasks = map[int]string{
	//unix.IPV6_FLOWINFO:        "IPV6_FLOWINFO",
	unix.IPV6_ADDRFORM:        "IPV6_ADDRFORM",
	unix.IPV6_ADD_MEMBERSHIP:  "IPV6_ADD_MEMBERSHIP",
	unix.IPV6_DROP_MEMBERSHIP: "IPV6_DROP_MEMBERSHIP",
	unix.IPV6_MTU:             "IPV6_MTU",
	unix.IPV6_MTU_DISCOVER:    "IPV6_MTU_DISCOVER",
	unix.IPV6_MULTICAST_HOPS:  "IPV6_MULTICAST_HOPS",
	unix.IPV6_MULTICAST_IF:    "IPV6_MULTICAST_IF",
	unix.IPV6_MULTICAST_LOOP:  "IPV6_MULTICAST_LOOP",
	unix.IPV6_RECVPKTINFO:     "IPV6_RECVPKTINFO",
	unix.IPV6_RTHDR:           "IPV6_RTHDR",
	unix.IPV6_AUTHHDR:         "IPV6_AUTHHDR",
	unix.IPV6_DSTOPTS:         "IPV6_DSTOPTS",
	unix.IPV6_HOPOPTS:         "IPV6_HOPOPTS",
	unix.IPV6_HOPLIMIT:        "IPV6_HOPLIMIT",
	unix.IPV6_RECVERR:         "IPV6_RECVERR",
	unix.IPV6_ROUTER_ALERT:    "IPV6_ROUTER_ALERT",
	unix.IPV6_UNICAST_HOPS:    "IPV6_UNICAST_HOPS",
	unix.IPV6_V6ONLY:          "IPV6_V6ONLY",
}

func (s *SockoptName) parseIp6Opt() string {
	if v, ok := ip6OpMasks[s.Tp]; ok {
		return v
	}

	return fmt.Sprintf("%d", s.Tp)
}

func (s *SockoptName) Parse() string {
	switch s.Lv {
	case syscall.SOL_SOCKET:
		return s.parseSocketOpt()
	case syscall.SOL_TCP:
		return s.parseTcpOpt()
	case syscall.SOL_IP:
		return s.parseIpOpt()
	case syscall.SOL_IPV6:
		return s.parseIp6Opt()
	}

	return fmt.Sprintf("%d", s.Tp)
}

func (s *SockoptName) String() string {
	return s.Parse()
}

func (s *SockoptName) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Parse())
}

func (s *SockoptName) UnmarshalJSON(b []byte) error {
	var a string

	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}

	if v, ok := socketOpKeys[a]; ok {
		s.Lv = syscall.SOL_SOCKET
		s.Tp = v

		return nil
	}

	if v, ok := tcpOpKeys[a]; ok {
		s.Lv = syscall.SOL_TCP
		s.Tp = v

		return nil
	}

	if v, ok := ipOpKeys[a]; ok {
		s.Lv = syscall.SOL_IP
		s.Tp = v

		return nil
	}

	if v, ok := ip6OpKeys[a]; ok {
		s.Lv = syscall.SOL_IPV6
		s.Tp = v
	}

	if tp, err := strconv.Atoi(a); err != nil {
		return err
	} else {
		s.Lv = 0
		s.Tp = tp
	}

	return nil
}

func init() {
	tcpOpKeys = make(map[string]int)
	for k, v := range tcpOpMasks {
		tcpOpKeys[v] = k
	}

	ipOpKeys = make(map[string]int)
	for k, v := range ipOpMasks {
		ipOpKeys[v] = k
	}

	ip6OpKeys = make(map[string]int)
	for k, v := range ip6OpMasks {
		ip6OpKeys[v] = k
	}

	socketOpKeys = make(map[string]int)
	for k, v := range socketOpMasks {
		socketOpKeys[v] = k
	}

	sockLevelKeys = make(map[string]int)
	for k, v := range sockLevelMap {
		sockLevelKeys[v] = k
	}
}
