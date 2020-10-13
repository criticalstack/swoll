package types

import (
	"encoding/json"
	"fmt"
	"strings"
	"syscall"
)

type MsgFlags int

var msgFlagMasks = map[int]string{
	syscall.MSG_CMSG_CLOEXEC: "MSG_CMSG_CLOEXEC",
	syscall.MSG_DONTWAIT:     "MSG_DONTWAIT",
	syscall.MSG_ERRQUEUE:     "MSG_ERRQUEUE",
	syscall.MSG_OOB:          "MSG_OOB",
	syscall.MSG_PEEK:         "MSG_PEEK",
	syscall.MSG_TRUNC:        "MSG_TRUNC",
	syscall.MSG_WAITALL:      "MSG_WAITALL",
	syscall.MSG_NOSIGNAL:     "MSG_NOSIGNAL",
}

func (flags MsgFlags) Parse() []string {
	ret := []string{}
	fint := int(flags)

	for flag, fstr := range msgFlagMasks {
		if flag&fint != 0 {
			ret = append(ret, fstr)
		}
	}

	return ret
}

func (flags MsgFlags) String() string {
	parsed := flags.Parse()

	if len(parsed) == 0 {
		return fmt.Sprintf("%d", flags)
	}

	return strings.Join(parsed, "|")
}

func (flags MsgFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(flags.Parse())
}

func (f *MsgFlags) UnmarshalJSON(data []byte) error {
	var a []string

	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}

	for _, v := range a {
		switch v {
		case "MSG_CMSG_CLOEXEC":
			*f |= syscall.MSG_CMSG_CLOEXEC
		case "MSG_DONTWAIT":
			*f |= syscall.MSG_DONTWAIT
		case "MSG_ERRQUEUE":
			*f |= syscall.MSG_ERRQUEUE
		case "MSG_OOB":
			*f |= syscall.MSG_OOB
		case "MSG_PEEK":
			*f |= syscall.MSG_PEEK
		case "MSG_TRUNC":
			*f |= syscall.MSG_TRUNC
		case "MSG_WAITALL":
			*f |= syscall.MSG_WAITALL
		case "MSG_NOSIGNAL":
			*f |= syscall.MSG_NOSIGNAL
		}
	}

	return nil
}
