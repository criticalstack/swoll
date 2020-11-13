package types

import (
	"strings"

	"golang.org/x/sys/unix"
)

type XmodeFlags int

var xModeMasks = map[int]string{
	unix.R_OK: "R_OK",
	unix.W_OK: "W_OK",
	unix.X_OK: "X_OK",
}

func (flags XmodeFlags) Parse() []string {
	if flags == 0 {
		return []string{"F_OK"}
	}

	ret := []string{}
	fint := int(flags)
	for flag, fstr := range xModeMasks {
		if flag&fint != 0 {
			ret = append(ret, fstr)
		}
	}

	return ret
}

func (flags XmodeFlags) String() string {
	return strings.Join(flags.Parse(), "|")
}

/*
func (flags XmodeFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(flags.Parse())
}
*/
