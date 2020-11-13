package types

import (
	"encoding/json"
	"strings"
	"syscall"
)

type FileFlags int

var fileCreationMasks = map[int]string{
	syscall.O_RDWR:      "O_RDWR",
	syscall.O_WRONLY:    "O_WRONLY",
	syscall.O_RDONLY:    "O_RDONLY",
	syscall.O_APPEND:    "O_APPEND",
	syscall.O_ASYNC:     "O_ASYNC",
	syscall.O_CLOEXEC:   "O_CLOEXEC",
	syscall.O_CREAT:     "O_CREAT",
	syscall.O_DIRECT:    "O_DIRECT",
	syscall.O_DIRECTORY: "O_DIRECTORY",
	syscall.O_DSYNC:     "O_DSYNC",
	syscall.O_EXCL:      "O_EXCL",
	syscall.O_NOATIME:   "O_NOATIME",
	syscall.O_NOCTTY:    "O_NOCTTY",
	syscall.O_NOFOLLOW:  "O_NOFOLLOW",
	syscall.O_NONBLOCK:  "O_NONBLOCK",
	syscall.O_SYNC:      "O_SYNC",
	syscall.O_TRUNC:     "O_TRUNC",
}

func (flags FileFlags) Parse() []string {
	if flags == 0 {
		return []string{"O_RDONLY"}
	}

	ret := []string{}
	fint := int(flags)

	for flag, fstr := range fileCreationMasks {
		if flag&fint != 0 {
			ret = append(ret, fstr)
		}
	}

	return ret
}

func (flags FileFlags) String() string {
	return strings.Join(flags.Parse(), "|")
}

func (f FileFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.Parse())
}

func (f *FileFlags) UnmarshalJSON(data []byte) error {
	var a []string

	*f = 0

	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}

	for _, val := range a {
		switch val {
		case "O_RDWR":
			*f |= syscall.O_RDWR
		case "O_WRONLY":
			*f |= syscall.O_WRONLY
		case "O_RDONLY":
			*f |= syscall.O_RDONLY
		case "O_APPEND":
			*f |= syscall.O_APPEND
		case "O_ASYNC":
			*f |= syscall.O_ASYNC
		case "O_CLOEXEC":
			*f |= syscall.O_CLOEXEC
		case "O_CREAT":
			*f |= syscall.O_CREAT
		case "O_DIRECT":
			*f |= syscall.O_DIRECT
		case "O_DIRECTORY":
			*f |= syscall.O_DIRECTORY
		case "O_DSYNC":
			*f |= syscall.O_DSYNC
		case "O_EXCL":
			*f |= syscall.O_EXCL
		case "O_NOATIME":
			*f |= syscall.O_NOATIME
		case "O_NOCTTY":
			*f |= syscall.O_NOCTTY
		case "O_NOFOLLOW":
			*f |= syscall.O_NOFOLLOW
		case "O_NONBLOCK":
			*f |= syscall.O_NONBLOCK
		case "O_SYNC":
			*f |= syscall.O_SYNC
		case "O_TRUNC":
			*f |= syscall.O_TRUNC

		}
	}

	return nil
}

/*
func (flags FileFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(flags.Parse())
}
*/
