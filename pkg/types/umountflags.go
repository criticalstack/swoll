package types

import (
	"encoding/json"
	"strings"
	"syscall"
)

type UmountFlags int

var umountFlags = map[int]string{
	syscall.MNT_FORCE:  "MNT_FORCE",
	syscall.MNT_DETACH: "MNT_DETACH",
	syscall.MNT_EXPIRE: "MNT_EXPIRE",
}

func (flags UmountFlags) Parse() []string {
	ret := []string{}
	fint := int(flags)

	for flag, fstr := range umountFlags {
		if fint&flag != 0 {
			ret = append(ret, fstr)
		}
	}

	return ret
}

func (flags UmountFlags) String() string {
	return strings.Join(flags.Parse(), "|")
}

func (flags UmountFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(flags.Parse())
}

func (f *UmountFlags) UnmarshalJSON(data []byte) error {
	var a []string

	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}

	for _, v := range a {
		switch v {
		case "MNT_FORCE":
			*f |= syscall.MNT_FORCE
		case "MNT_DETACH":
			*f |= syscall.MNT_DETACH
		case "MNT_EXPIRE":
			*f |= syscall.MNT_EXPIRE
		}
	}

	return nil
}
