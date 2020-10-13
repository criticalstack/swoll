package call

import (
	"encoding/json"
	"strings"
	"syscall"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type AcceptFlags int

type Accept struct {
	FD    types.InputFD   `json:"fd"`
	Saddr *types.SockAddr `json:"saddr"`
}

type Accept4 struct {
	FD    types.InputFD   `json:"fd"`
	Saddr *types.SockAddr `json:"saddr"`
	Flags AcceptFlags     `json:"flags"`
}

var masks = map[int]string{
	syscall.SOCK_NONBLOCK: "SOCK_NONBLOCK",
	syscall.SOCK_CLOEXEC:  "SOCK_CLOEXEC",
}

func (flags AcceptFlags) Parse() []string {
	ret := make([]string, 0)
	fint := int(flags)

	for flag, fstr := range masks {
		if fint&flag != 0 {
			ret = append(ret, fstr)
		}
	}

	return ret
}

func (flags AcceptFlags) String() string {
	return strings.Join(flags.Parse(), "|")
}

func (f AcceptFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.Parse())
}

func (f *AcceptFlags) UnmarshalJSON(b []byte) error {
	a := make([]string, 0)
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	for _, val := range a {
		switch val {
		case "SOCK_NONBLOCK":
			*f |= syscall.SOCK_NONBLOCK
		case "SOCK_CLOEXEC":
			*f |= syscall.SOCK_CLOEXEC
		}
	}

	return nil
}

func (e *Accept) CallName() string  { return "accept" }
func (e *Accept) Return() *Argument { return nil }
func (e *Accept) DecodeArguments(data []*byte, arglen int) error {
	e.FD = types.InputFD(types.MakeC32(unsafe.Pointer(data[0])))
	e.Saddr = (*types.SockAddr)(unsafe.Pointer(data[1]))

	return nil
}

func (e *Accept) Arguments() Arguments {
	return Arguments{
		{"sockfd", "int", e.FD},
		{"addr", "struct sockaddr *", e.Saddr},
	}
}

func (e *Accept4) CallName() string  { return "accept4" }
func (e *Accept4) Return() *Argument { return nil }
func (e *Accept4) Arguments() Arguments {
	return Arguments{
		{"sockfd", "int", e.FD},
		{"addr", "struct sockaddr *", e.Saddr},
		{"flags", "int", e.Flags},
	}
}

func (e *Accept4) DecodeArguments(data []*byte, arglen int) error {
	e.FD = types.InputFD(types.MakeC32(unsafe.Pointer(data[0])))
	e.Saddr = (*types.SockAddr)(unsafe.Pointer(data[1]))
	e.Flags = AcceptFlags(types.MakeC32(unsafe.Pointer(data[2])))
	return nil
}
