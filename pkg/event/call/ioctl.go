// +build ignore

package call

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/types"
)

type ioctlCmd int

type Ioctl struct {
	FD  types.InputFD `json:"fd"`
	Cmd ioctlCmd      `json:"cmd"`
	Arg []byte        `json:"arg"`
}

func (i *Ioctl) CallName() string  { return "ioctl" }
func (i *Ioctl) Return() *Argument { return nil }
func (i *Ioctl) DecodeArguments(data []*byte, arglen int) error {
	i.FD = types.InputFD(types.MakeCU64(unsafe.Pointer(data[0])))
	i.Cmd = ioctlCmd(types.MakeCU64(unsafe.Pointer(data[1])))
	i.Arg = types.MakeCBytes(unsafe.Pointer(data[2]), arglen)

	return nil
}

func (i *Ioctl) Arguments() Arguments {
	return Arguments{
		{"fd", "long unsigned", i.FD},
		{"cmd", "long unsigned", i.Cmd},
		{"arg", "logn unsigned", i.Arg},
	}
}

type iocDir int

type ioc struct {
	dir iocDir `json:"dir"`
	typ int    `json:"typ"`
	nr  int    `json:"nr"`
	sz  int    `json:"sz"`
}

func _IOC_TYPE(nr int) int {
	return ((nr) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK
}

func _IOC_NR(nr int) int {
	return ((nr) >> _IOC_NRSHIFT) & _IOC_NRMASK
}

func _IOC_SIZE(nr int) int {
	return ((nr) >> _IOC_SIZESHIFT) & _IOC_SIZEMASK
}

func _IOC_DIR(nr int) int {
	return ((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK
}

func (d iocDir) Parse() interface{} {
	if d == 0 {
		return []string{"_IOC_NONE"}
	}

	nr := int(d)
	ret := []string{}

	if nr&_IOC_READ > 0 {
		ret = append(ret, "_IOC_READ")
	}

	if nr&_IOC_WRITE > 0 {
		ret = append(ret, "_IOC_WRITE")
	}

	return ret
}

func (c ioctlCmd) String() string {
	return strings.Join(string(c.Parse()), "|")
}

func (c ioctlCmd) Parse() interface{} {
	nr := int(c)

	ioc := &ioc{
		dir: iocDir(_IOC_DIR(nr)),
		typ: _IOC_TYPE(nr),
		nr:  _IOC_NR(nr),
		sz:  _IOC_SIZE(nr),
	}

	switch ioc.typ {
	case '$':
		// PERF_IOCTL
	case 'f':
		// FILE_IOCTL
	case 0x54:
		// TERM_IOCTL
	case 0x89:
		// SOCK_IOCTL
	case 'p':
		// RTC_IOCTL
	case 0x03:
		// HDIO_IOCTL
	case 0x12:
		// BLOCK_IOCTL
	case 'X':
		// FS_X_IOCTL
	case 0x22:
		// SCSI_IOCTL
	case 'L':
		// LOOP_IOCTL
	case 'E':
		// EVDEV_IOCTL
	case 0xaa:
		// UFFDIO_IOCTL
	case 0x94:
		// BTRFS_IOCTL
	case 0xb7:
		// NSFS_IOCTL
	case 0xfd:
		// DM_IOCTL

	case 0xae:
		// KVM_IOCTL
	case 'I':
		// INOTIFY_IOCTL
	case 0xab:
		// NBD_IOCTL
	case 'R':
		// RANDOM_IOCTL
	case 'M':
		// MTD_IOCTL
	case 'o':
		fallthrough
	case 'O':
		// UBI_IOCTL
	case 'V':
		// V4l2_IOCTL
	case '=':
		// PTP_IOCTL
	default:
		// UNKNOWN
	}

	return fmt.Sprintf("ioctl(fd=%v, _IOC(flags=%v, type=%#x, nr=%#x, sz=%#x), %#x)", e.FD,
		strings.Join(parseIOCflags(ioc.dir), "|"),
		ioc.typ, ioc.nr, ioc.sz, &e.Arg)

}

const (
	_IOC_NONE      = 0x0
	_IOC_WRITE     = 0x1
	_IOC_READ      = 0x2
	_IOC_NRBITS    = 8
	_IOC_TYPEBITS  = 8
	_IOC_SIZEBITS  = 14
	_IOC_DIRBITS   = 2
	_IOC_NRSHIFT   = 0
	_IOC_NRMASK    = (1 << _IOC_NRBITS) - 1
	_IOC_TYPEMASK  = (1 << _IOC_TYPEBITS) - 1
	_IOC_SIZEMASK  = (1 << _IOC_SIZEBITS) - 1
	_IOC_DIRMASK   = (1 << _IOC_DIRBITS) - 1
	_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
	_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
	_IOC_DIRSHIFT  = _IOC_SIZESHIFT + _IOC_SIZEBITS
	_IOC_IN        = _IOC_WRITE << _IOC_DIRSHIFT
	_IOC_OUT       = _IOC_READ << _IOC_DIRSHIFT
	_IOC_INOUT     = (_IOC_WRITE | _IOC_READ) << _IOC_DIRSHIFT
	_IOCSIZE_MASK  = _IOC_SIZEMASK << _IOC_SIZESHIFT
)
