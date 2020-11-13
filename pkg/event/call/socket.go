package call

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
	"golang.org/x/sys/unix"
)

type SockFamily int
type SockType int
type SockProtocol int

type Socket struct {
	Family   SockFamily   `json:"family"`
	Type     SockType     `json:"type"`
	Protocol SockProtocol `json:"protocol"`
}

func (s *Socket) CallName() string  { return "socket" }
func (s *Socket) Return() *Argument { return nil }
func (s *Socket) DecodeArguments(data []*byte, arglen int) error {
	s.Family = SockFamily(types.MakeC32(unsafe.Pointer(data[0])))
	s.Type = SockType(types.MakeC32(unsafe.Pointer(data[1])))
	s.Protocol = SockProtocol(types.MakeC32(unsafe.Pointer(data[2])))
	//b := syscall.IPPROTO_IP
	return nil
}

func (s *Socket) Arguments() Arguments {
	return Arguments{
		{"domain", "int", s.Family},
		{"type", "int", s.Type},
		{"protocol", "int", s.Protocol},
	}
}

func (t SockType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.Parse())
}

func (t *SockType) UnmarshalJSON(data []byte) error {
	a := make([]string, 0)
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}

	sType := int(0)
	sFlags := int(0)

	for _, val := range a {
		switch val {
		case "SOCK_STREAM":
			sType = unix.SOCK_STREAM
		case "SOCK_DGRAM":
			sType = unix.SOCK_DGRAM
		case "SOCK_SEQPACKET":
			sType = unix.SOCK_SEQPACKET
		case "SOCK_RAW":
			sType = unix.SOCK_RAW
		case "SOCK_RDM":
			sType = unix.SOCK_RDM
		case "SOCK_PACKET":
			sType = unix.SOCK_PACKET
		case "SOCK_CLOEXEC":
			sFlags |= unix.SOCK_CLOEXEC
		case "SOCK_NONBLOCK":
			sFlags |= unix.SOCK_NONBLOCK
		}
	}

	*t = SockType(sType | sFlags)

	return nil
}

func (t SockType) Parse() []string {
	flags := int(t) & (^0xf)
	ttype := int(t) & 0xf

	ret := []string{}

	switch ttype {
	case unix.SOCK_STREAM:
		ret = append(ret, "SOCK_STREAM")
	case unix.SOCK_DGRAM:
		ret = append(ret, "SOCK_DGRAM")
	case unix.SOCK_SEQPACKET:
		ret = append(ret, "SOCK_SEQPACKET")
	case unix.SOCK_RAW:
		ret = append(ret, "SOCK_RAW")
	case unix.SOCK_RDM:
		ret = append(ret, "SOCK_RDM")
	case unix.SOCK_PACKET:
		ret = append(ret, "SOCK_PACKET")
	default:
		ret = append(ret, fmt.Sprintf("<%d>", ttype))
	}

	if flags&unix.SOCK_CLOEXEC > 0 {
		ret = append(ret, "SOCK_CLOEXEC")
	}

	if flags&unix.SOCK_NONBLOCK > 0 {
		ret = append(ret, "SOCK_NONBLOCK")
	}

	return ret
}

func (t SockType) String() string {
	return strings.Join(t.Parse(), "|")
}

func (f SockFamily) String() string {
	return f.Parse()
}

var sockFamilyKeys map[string]int
var sockFamilyMap = map[int]string{
	unix.AF_INET:      "AF_INET",
	unix.AF_INET6:     "AF_INET6",
	unix.AF_NETLINK:   "AF_NETLINK",
	unix.AF_ALG:       "AF_ALG",
	unix.AF_APPLETALK: "AF_APPLETALK",
	unix.AF_ASH:       "AF_ASH",
	unix.AF_ATMPVC:    "AF_ATMPVC",
	unix.AF_ATMSVC:    "AF_ATMSVC",
	unix.AF_AX25:      "AF_AX25",
	unix.AF_BLUETOOTH: "AF_BLUETOOTH",
	unix.AF_BRIDGE:    "AF_BRIDGE",
	unix.AF_CAIF:      "AF_CAIF",
	unix.AF_CAN:       "AF_CAN",
	unix.AF_DECnet:    "AF_DECnet",
	unix.AF_ECONET:    "AF_ECONET",
	unix.AF_IB:        "AF_IB",
	unix.AF_IPX:       "AF_IPX",
	unix.AF_IRDA:      "AF_IRDA",
	unix.AF_ISDN:      "AF_ISDN",
	unix.AF_KCM:       "AF_KCM",
	unix.AF_KEY:       "AF_KEY",
	unix.AF_MPLS:      "AF_MPLS",
	unix.AF_NETBEUI:   "AF_NETBEUI",
	unix.AF_TIPC:      "AF_TIPC",
	unix.AF_PACKET:    "AF_PACKET",
	unix.AF_UNIX:      "AF_UNIX",
	unix.AF_VSOCK:     "AF_VSOCK",
	unix.AF_XDP:       "AF_XDP",
}

func (f SockFamily) Parse() string {
	if v, ok := sockFamilyMap[int(f)]; ok {
		return v
	}

	return fmt.Sprintf("%d", f)
}

func (f SockFamily) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.Parse())
}

func (f *SockFamily) UnmarshalJSON(data []byte) error {
	var a string

	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}

	if v, ok := sockFamilyKeys[a]; ok {
		*f = SockFamily(v)
	} else {
		if fam, err := strconv.Atoi(a); err != nil {
			return err
		} else {
			*f = SockFamily(fam)
		}
	}

	return nil
}

var sockProtoKeys map[string]int

// XXX[lz]: this is a little inaccurate as we are assuming the AF_FAMILY type.
//          but 99.99999% of the time this is correct. In the future we should
//          render this along with the family type.
var sockProtoMap = map[int]string{
	syscall.IPPROTO_AH:       "IPPROTO_AH",
	syscall.IPPROTO_COMP:     "IPPROTO_COMP",
	syscall.IPPROTO_DCCP:     "IPPROTO_DCCP",
	syscall.IPPROTO_DSTOPTS:  "IPPROTO_DSTOPTS",
	syscall.IPPROTO_EGP:      "IPPROTO_EGP",
	syscall.IPPROTO_ENCAP:    "IPPROTO_ENCAP",
	syscall.IPPROTO_ESP:      "IPPROTO_ESP",
	syscall.IPPROTO_FRAGMENT: "IPPROTO_FRAGMENT",
	syscall.IPPROTO_GRE:      "IPPROTO_GRE",
	syscall.IPPROTO_ICMP:     "IPPROTO_ICMP",
	syscall.IPPROTO_ICMPV6:   "IPPROTO_ICMPV6",
	syscall.IPPROTO_IDP:      "IPPROTO_IDP",
	syscall.IPPROTO_IGMP:     "IPPROTO_IGMP",
	syscall.IPPROTO_IP:       "IPPROTO_IP",
	syscall.IPPROTO_IPIP:     "IPPROTO_IPIP",
	syscall.IPPROTO_IPV6:     "IPPROTO_IPV6",
	syscall.IPPROTO_MTP:      "IPPROTO_MTP",
	syscall.IPPROTO_NONE:     "IPPROTO_NONE",
	syscall.IPPROTO_RAW:      "IPPROTO_RAW",
	syscall.IPPROTO_ROUTING:  "IPPROTO_ROUTING",
	syscall.IPPROTO_RSVP:     "IPPROTO_RSVP",
	syscall.IPPROTO_SCTP:     "IPPROTO_SCTP",
	syscall.IPPROTO_TCP:      "IPPROTO_TCP",
	syscall.IPPROTO_TP:       "IPPROTO_TP",
	syscall.IPPROTO_UDP:      "IPPROTO_UDP",
	syscall.IPPROTO_UDPLITE:  "IPPROTO_UDPLITE",
}

func (p SockProtocol) Parse() string {
	if v, ok := sockProtoMap[int(p)]; ok {
		return v
	}

	return fmt.Sprintf("%d", p)
}

func (p SockProtocol) String() string {
	return p.Parse()
}

func (p SockProtocol) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.Parse())
}

func (p *SockProtocol) UnmarshalJSON(data []byte) error {
	var a string

	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}

	if v, ok := sockProtoKeys[a]; ok {
		*p = SockProtocol(v)
	} else {
		if prot, err := strconv.Atoi(a); err != nil {
			return err
		} else {
			*p = SockProtocol(prot)
		}
	}

	return nil
}

func init() {
	sockFamilyKeys = make(map[string]int)
	for k, v := range sockFamilyMap {
		sockFamilyKeys[v] = k
	}

	sockProtoKeys = make(map[string]int)
	for k, v := range sockProtoMap {
		sockProtoKeys[v] = k
	}
}
