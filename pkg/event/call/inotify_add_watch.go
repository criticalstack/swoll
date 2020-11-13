package call

import (
	"encoding/json"
	"strings"
	"syscall"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type InotifyMask uint32

type INotifyAddWatch struct {
	FD       types.InputFD `json:"fd"`
	Pathname string        `json:"pathname"`
	Mask     InotifyMask   `json:"mask"`
}

func (m *INotifyAddWatch) CallName() string  { return "inotify_add_watch" }
func (m *INotifyAddWatch) Return() *Argument { return nil }
func (m *INotifyAddWatch) DecodeArguments(data []*byte, arglen int) error {
	m.FD = types.InputFD(types.MakeC32(unsafe.Pointer(data[0])))
	m.Pathname = types.MakeCString(unsafe.Pointer(data[1]), arglen)
	m.Mask = InotifyMask(types.MakeCU32(unsafe.Pointer(data[2])))
	return nil
}

func (m *INotifyAddWatch) Arguments() Arguments {
	return Arguments{
		{"fd", "int", m.FD},
		{"pathname", "const char *", m.Pathname},
		{"mask", "uint32_t", m.Mask},
	}
}

var inotMasks = map[int]string{
	syscall.IN_ACCESS:        "IN_ACCESS",
	syscall.IN_ATTRIB:        "IN_ATTRIB",
	syscall.IN_CLOSE_WRITE:   "IN_CLOSE_WRITE",
	syscall.IN_CLOSE_NOWRITE: "IN_CLOSE_NOWRITE",
	syscall.IN_CREATE:        "IN_CREATE",
	syscall.IN_DELETE:        "IN_DELETE",
	syscall.IN_DELETE_SELF:   "IN_DELETE_SELF",
	syscall.IN_MODIFY:        "IN_MODIFY",
	syscall.IN_MOVE_SELF:     "IN_MOVE_SELF",
	syscall.IN_MOVED_FROM:    "IN_MOVED_FROM",
	syscall.IN_MOVED_TO:      "IN_MOVED_TO",
	syscall.IN_OPEN:          "IN_OPEN",
	syscall.IN_DONT_FOLLOW:   "IN_DONT_FOLLOW",
	syscall.IN_EXCL_UNLINK:   "IN_EXCL_UNLINK",
	syscall.IN_MASK_ADD:      "IN_MASK_ADD",
	syscall.IN_ONESHOT:       "IN_ONESHOT",
	syscall.IN_ONLYDIR:       "IN_ONLYDIR",
}

func (flags InotifyMask) Parse() []string {
	if flags == syscall.IN_ALL_EVENTS {
		return []string{"IN_ALL_EVENTS"}
	}

	ret := []string{}
	fint := int(flags)

	for flag, fstr := range inotMasks {
		if flag&fint != 0 {
			ret = append(ret, fstr)
		}
	}

	return ret
}

func (flags InotifyMask) String() string {
	return strings.Join(flags.Parse(), "|")
}

func (f InotifyMask) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.Parse())
}

func (f *InotifyMask) UnmarshalJSON(data []byte) error {
	a := make([]string, 0)
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}

	for _, val := range a {
		switch val {
		case "IN_ALL_EVENTS":
			*f |= syscall.IN_ALL_EVENTS
		case "IN_ACCESS":
			*f |= syscall.IN_ACCESS
		case "IN_ATTRIB":
			*f |= syscall.IN_ATTRIB
		case "IN_CLOSE_WRITE":
			*f |= syscall.IN_CLOSE_WRITE
		case "IN_CLOSE_NOWRITE":
			*f |= syscall.IN_CLOSE_NOWRITE
		case "IN_CREATE":
			*f |= syscall.IN_CREATE
		case "IN_DELETE":
			*f |= syscall.IN_DELETE
		case "IN_DELETE_SELF":
			*f |= syscall.IN_DELETE_SELF
		case "IN_MODIFY":
			*f |= syscall.IN_MODIFY
		case "IN_MOVE_SELF":
			*f |= syscall.IN_MOVE_SELF
		case "IN_MOVED_FROM":
			*f |= syscall.IN_MOVED_FROM
		case "IN_MOVED_TO":
			*f |= syscall.IN_MOVED_TO
		case "IN_OPEN":
			*f |= syscall.IN_OPEN
		case "IN_DONT_FOLLOW":
			*f |= syscall.IN_DONT_FOLLOW
		case "IN_EXCL_UNLINK":
			*f |= syscall.IN_EXCL_UNLINK
		case "IN_MASK_ADD":
			*f |= syscall.IN_MASK_ADD
		case "IN_ONESHOT":
			*f |= syscall.IN_ONESHOT
		case "IN_ONLYDIR":
			*f |= syscall.IN_ONLYDIR
		}
	}

	return nil
}
