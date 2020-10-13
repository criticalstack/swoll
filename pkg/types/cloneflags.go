package types

import (
	"strings"
	"syscall"
)

type CloneFlags int

const CLONE_NEWCGROUP = 0x02000000

var cloneFlagMasks = map[int]string{
	syscall.CLONE_CHILD_CLEARTID: "CLONE_CHILD_CLEARTID",
	syscall.CLONE_CHILD_SETTID:   "CLONE_CHILD_SETTID",
	syscall.CLONE_FILES:          "CLONE_FILES",
	syscall.CLONE_FS:             "CLONE_FS",
	syscall.CLONE_IO:             "CLONE_IO",
	CLONE_NEWCGROUP:              "CLONE_NEWCGROUP",
	syscall.CLONE_NEWIPC:         "CLONE_NEWIPC",
	syscall.CLONE_NEWNET:         "CLONE_NEWNET",
	syscall.CLONE_NEWNS:          "CLONE_NEWNS",
	syscall.CLONE_NEWPID:         "CLONE_NEWPID",
	syscall.CLONE_NEWUSER:        "CLONE_NEWUSER",
	syscall.CLONE_NEWUTS:         "CLONE_NEWUTS",
	syscall.CLONE_PARENT:         "CLONE_PARENT",
	syscall.CLONE_PARENT_SETTID:  "CLONE_PARENT_SETTID",
	syscall.CLONE_PTRACE:         "CLONE_PTRACE",
	syscall.CLONE_SETTLS:         "CLONE_SETTLS",
	syscall.CLONE_SIGHAND:        "CLONE_SIGHAND",
	syscall.CLONE_SYSVSEM:        "CLONE_SYSVSEM",
	syscall.CLONE_THREAD:         "CLONE_THREAD",
	syscall.CLONE_UNTRACED:       "CLONE_UNTRACED",
	syscall.CLONE_VFORK:          "CLONE_VFORK",
	syscall.CLONE_VM:             "CLONE_VM",
}

func (flags CloneFlags) Parse() []string {
	ret := []string{}
	fint := int(flags)

	for m, fstr := range cloneFlagMasks {
		if fint&m != 0 {
			ret = append(ret, fstr)
		}
	}
	return ret
}

func (flags CloneFlags) String() string {
	return strings.Join(flags.Parse(), "|")
}

/*
func (flags CloneFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(flags.Parse())
}
*/
