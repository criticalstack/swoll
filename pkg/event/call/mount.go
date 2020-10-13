package call

import (
	"encoding/json"
	"strings"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
	"golang.org/x/sys/unix"
)

type MountFlags int
type Mount struct {
	Device    string     `json:"device"`
	Directory string     `json:"directory"`
	Type      string     `json:"type"`
	Flags     MountFlags `json:"flags"`
}

func (m *Mount) CallName() string  { return "mount" }
func (m *Mount) Return() *Argument { return nil }
func (m *Mount) DecodeArguments(data []*byte, arglen int) error {
	m.Device = types.MakeCString(unsafe.Pointer(data[0]), arglen)
	m.Directory = types.MakeCString(unsafe.Pointer(data[1]), arglen)
	m.Type = types.MakeCString(unsafe.Pointer(data[2]), arglen)
	m.Flags = MountFlags(types.MakeCU64(unsafe.Pointer(data[3])))
	return nil
}

func (m *Mount) Arguments() Arguments {
	return Arguments{
		{"source", "const char *", m.Device},
		{"target", "const char *", m.Directory},
		{"filesystemtype", "const char *", m.Type},
		{"mountflags", "unsigned long", m.Flags},
	}
}

var mflagMasks = map[int]string{
	unix.MS_RDONLY:       "MS_RDONLY",
	unix.MS_NOSUID:       "MS_NOSUID",
	unix.MS_NODEV:        "MS_NODEV",
	unix.MS_NOEXEC:       "MS_NOEXEC",
	unix.MS_SYNCHRONOUS:  "MS_SYNCHRONOUS",
	unix.MS_REMOUNT:      "MS_REMOUNT",
	unix.MS_MANDLOCK:     "MS_MANDLOCK",
	unix.MS_DIRSYNC:      "MS_DIRSYNC",
	unix.MS_NOATIME:      "MS_NOATIME",
	unix.MS_NODIRATIME:   "MS_NODIRATIME",
	unix.MS_BIND:         "MS_BIND",
	unix.MS_MOVE:         "MS_MOVE",
	unix.MS_REC:          "MS_REC",
	unix.MS_VERBOSE:      "MS_VERBOSE",
	unix.MS_POSIXACL:     "MS_POSIXACL",
	unix.MS_UNBINDABLE:   "MS_UNBINDABLE",
	unix.MS_PRIVATE:      "MS_PRIVATE",
	unix.MS_SLAVE:        "MS_SLAVE",
	unix.MS_SHARED:       "MS_SHARED",
	unix.MS_RELATIME:     "MS_RELATIME",
	unix.MS_KERNMOUNT:    "MS_KERNMOUNT",
	unix.MS_I_VERSION:    "MS_I_VERSION",
	unix.MS_STRICTATIME:  "MS_STRICTATIME",
	unix.MS_LAZYTIME:     "MS_LAZYTIME",
	unix.MS_SUBMOUNT:     "MS_SUBMOUNT",
	unix.MS_NOREMOTELOCK: "MS_NOREMOTELOCK",
	unix.MS_NOSEC:        "MS_NOSEC",
	unix.MS_BORN:         "MS_BORN",
	unix.MS_ACTIVE:       "MS_ACTIVE",
	unix.MS_NOUSER:       "MS_NOUSER",
}

func (flags MountFlags) Parse() []string {
	if flags == 0 {
		return []string{"MS_NONE"}
	}

	ret := []string{}
	fint := int(flags)

	for flag, fstr := range mflagMasks {
		if fint&flag != 0 {
			ret = append(ret, fstr)
		}
	}

	return ret
}

func (flags MountFlags) String() string {
	return strings.Join(flags.Parse(), "|")
}

func (f MountFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.Parse())
}

func (f *MountFlags) UnmarshalJSON(data []byte) error {
	a := make([]string, 0)

	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}

	for _, val := range a {
		switch val {
		case "MS_NONE":
			*f = 0
		case "MS_LAZYTIME":
			*f |= unix.MS_LAZYTIME
		case "MS_SUBMOUNT":
			*f |= unix.MS_SUBMOUNT
		case "MS_NOREMOTELOCK":
			*f |= unix.MS_NOREMOTELOCK
		case "MS_NOSEC":
			*f |= unix.MS_NOSEC
		case "MS_BORN":
			*f |= unix.MS_BORN
		case "MS_ACTIVE":
			*f |= unix.MS_ACTIVE
		case "MS_NOUSER":
			*f |= unix.MS_NOUSER
		case "MS_STRICTATIME":
			*f |= unix.MS_STRICTATIME
		case "MS_RDONLY":
			*f |= unix.MS_RDONLY
		case "MS_NOSUID":
			*f |= unix.MS_NOSUID
		case "MS_NODEV":
			*f |= unix.MS_NODEV
		case "MS_NOEXEC":
			*f |= unix.MS_NOEXEC
		case "MS_SYNCHRONOUS":
			*f |= unix.MS_SYNCHRONOUS
		case "MS_REMOUNT":
			*f |= unix.MS_REMOUNT
		case "MS_MANDLOCK":
			*f |= unix.MS_MANDLOCK
		case "MS_DIRSYNC":
			*f |= unix.MS_DIRSYNC
		case "MS_NOATIME":
			*f |= unix.MS_NOATIME
		case "MS_NODIRATIME":
			*f |= unix.MS_NODIRATIME
		case "MS_BIND":
			*f |= unix.MS_BIND
		case "MS_MOVE":
			*f |= unix.MS_MOVE
		case "MS_REC":
			*f |= unix.MS_REC
		case "MS_VERBOSE":
			*f |= unix.MS_VERBOSE
		case "MS_POSIXACL":
			*f |= unix.MS_POSIXACL
		case "MS_UNBINDABLE":
			*f |= unix.MS_UNBINDABLE
		case "MS_PRIVATE":
			*f |= unix.MS_PRIVATE
		case "MS_SLAVE":
			*f |= unix.MS_SLAVE
		case "MS_SHARED":
			*f |= unix.MS_SHARED
		case "MS_RELATIME":
			*f |= unix.MS_RELATIME
		case "MS_KERNMOUNT":
			*f |= unix.MS_KERNMOUNT
		case "MS_I_VERSION":
			*f |= unix.MS_I_VERSION
		}
	}

	return nil
}
