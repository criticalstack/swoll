package types

import (
	"fmt"
)

type DirFD int

func (d DirFD) String() string {
	if d == -100 {
		return "AT_FDCWD"
	}

	return fmt.Sprintf("%d", d)
}

/*
func (d DirFD) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}
*/
