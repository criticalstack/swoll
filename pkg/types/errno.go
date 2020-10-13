package types

import (
	"encoding/json"
	"fmt"
)

type Errno int

func (e Errno) String() string {
	return errnoToString(e)
}

func (e Errno) ColorString() string {
	if e == 0 {
		return fmt.Sprintf("\033[1;32m%s\033[0m", errnoToString(e))
	}

	return fmt.Sprintf("\033[1;31m%s\033[0m", errnoToString(e))
}

func (e *Errno) UnmarshalJSON(data []byte) error {
	var s string

	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	*e = stringToErrno(s)

	return nil
}

func stringToErrno(err string) Errno {
	if v, ok := errnoKeys[err]; ok {
		return Errno(v)
	}

	return Errno(-1)
}

func errnoToString(err Errno) string {
	if v, ok := errnoVals[int(err)]; ok {
		return v
	}

	return "UNK"
}

func (e Errno) MarshalJSON() ([]byte, error) {
	return json.Marshal(errnoToString(e))
}

func init() {
	errnoKeys = make(map[string]int)
	for k, v := range errnoVals {
		errnoKeys[v] = k
	}
}

const (
	UNK             = -1
	OK              = 0
	EPERM           = 1
	ENOENT          = 2
	ESRCH           = 3
	EINTR           = 4
	EIO             = 5
	ENXIO           = 6
	E2BIG           = 7
	ENOEXEC         = 8
	EBADF           = 9
	ECHILD          = 10
	EAGAIN          = 11
	ENOMEM          = 12
	EACCES          = 13
	EFAULT          = 14
	ENOTBLK         = 15
	EBUSY           = 16
	EEXIST          = 17
	EXDEV           = 18
	ENODEV          = 19
	ENOTDIR         = 20
	EISDIR          = 21
	EINVAL          = 22
	ENFILE          = 23
	EMFILE          = 24
	ENOTTY          = 25
	ETXTBSY         = 26
	EFBIG           = 27
	ENOSPC          = 28
	ESPIPE          = 29
	EROFS           = 30
	EMLINK          = 31
	EPIPE           = 32
	EDOM            = 33
	ERANGE          = 34
	EDEADLK         = 35
	ENAMETOOLONG    = 36
	ENOLCK          = 37
	ENOSYS          = 38
	ENOTEMPTY       = 39
	ELOOP           = 40
	EWOULDBLOCK     = 11
	ENOMSG          = 42
	EIDRM           = 43
	ECHRNG          = 44
	EL2NSYNC        = 45
	EL3HLT          = 46
	EL3RST          = 47
	ELNRNG          = 48
	EUNATCH         = 49
	ENOCSI          = 50
	EL2HLT          = 51
	EBADE           = 52
	EBADR           = 53
	EXFULL          = 54
	ENOANO          = 55
	EBADRQC         = 56
	EBADSLT         = 57
	EBFONT          = 59
	ENOSTR          = 60
	ENODATA         = 61
	ETIME           = 62
	ENOSR           = 63
	ENONET          = 64
	ENOPKG          = 65
	EREMOTE         = 66
	ENOLINK         = 67
	EADV            = 68
	ESRMNT          = 69
	ECOMM           = 70
	EPROTO          = 71
	EMULTIHOP       = 72
	EDOTDOT         = 73
	EBADMSG         = 74
	EOVERFLOW       = 75
	ENOTUNIQ        = 76
	EBADFD          = 77
	EREMCHG         = 78
	ELIBACC         = 79
	ELIBBAD         = 80
	ELIBSCN         = 81
	ELIBMAX         = 82
	ELIBEXEC        = 83
	EILSEQ          = 84
	ERESTART        = 85
	ESTRPIPE        = 86
	EUSERS          = 87
	ENOTSOCK        = 88
	EDESTADDRREQ    = 89
	EMSGSIZE        = 90
	EPROTOTYPE      = 91
	ENOPROTOOPT     = 92
	EPROTONOSUPPORT = 93
	ESOCKTNOSUPPORT = 94
	EOPNOTSUPP      = 95
	EPFNOSUPPORT    = 96
	EAFNOSUPPORT    = 97
	EADDRINUSE      = 98
	EADDRNOTAVAIL   = 99
	ENETDOWN        = 100
	ENETUNREACH     = 101
	ENETRESET       = 102
	ECONNABORTED    = 103
	ECONNRESET      = 104
	ENOBUFS         = 105
	EISCONN         = 106
	ENOTCONN        = 107
	ESHUTDOWN       = 108
	ETOOMANYREFS    = 109
	ETIMEDOUT       = 110
	ECONNREFUSED    = 111
	EHOSTDOWN       = 112
	EHOSTUNREACH    = 113
	EALREADY        = 114
	EINPROGRESS     = 115
	ESTALE          = 116
	EUCLEAN         = 117
	ENOTNAM         = 118
	ENAVAIL         = 119
	EISNAM          = 120
	EDQUOT          = 122
	ENOKEY          = 126
	ERFKILL         = 132
	ENOMEDIUM       = 123
	EREMOTEIO       = 121
	ECANCELED       = 125
	EHWPOISON       = 133
	EOWNERDEAD      = 130
	EMEDIUMTYPE     = 124
	EKEYEXPIRED     = 127
	EKEYREVOKED     = 128
	EKEYREJECTED    = 129
	ENOTRECOVERABLE = 131
	ERESTARTSYS     = 512
)

var errnoVals = map[int]string{
	UNK:             "UNK",
	OK:              "OK",
	EPERM:           "EPERM",
	ENOENT:          "ENOENT",
	ESRCH:           "ESRCH",
	EINTR:           "EINTR",
	EIO:             "EIO",
	ENXIO:           "ENXIO",
	E2BIG:           "E2BIG",
	ENOEXEC:         "ENOEXEC",
	EBADF:           "EBADF",
	ECHILD:          "ECHILD",
	EAGAIN:          "EAGAIN",
	ENOMEM:          "ENOMEM",
	EACCES:          "EACCES",
	EFAULT:          "EFAULT",
	ENOTBLK:         "ENOTBLK",
	EBUSY:           "EBUSY",
	EEXIST:          "EEXIST",
	EXDEV:           "EXDEV",
	ENODEV:          "ENODEV",
	ENOTDIR:         "ENOTDIR",
	EISDIR:          "EISDIR",
	EINVAL:          "EINVAL",
	ENFILE:          "ENFILE",
	EMFILE:          "EMFILE",
	ENOTTY:          "ENOTTY",
	ETXTBSY:         "ETXTBSY",
	EFBIG:           "EFBIG",
	ENOSPC:          "ENOSPC",
	ESPIPE:          "ESPIPE",
	EROFS:           "EROFS",
	EMLINK:          "EMLINK",
	EPIPE:           "EPIPE",
	EDOM:            "EDOM",
	ERANGE:          "ERANGE",
	EDEADLK:         "EDEADLK",
	ENAMETOOLONG:    "ENAMETOOLONG",
	ENOLCK:          "ENOLCK",
	ENOSYS:          "ENOSYS",
	ENOTEMPTY:       "ENOTEMPTY",
	ELOOP:           "ELOOP",
	ENOMSG:          "ENOMSG",
	EIDRM:           "EIDRM",
	ECHRNG:          "ECHRNG",
	EL2NSYNC:        "EL2NSYNC",
	EL3HLT:          "EL3HLT",
	EL3RST:          "EL3RST",
	ELNRNG:          "ELNRNG",
	EUNATCH:         "EUNATCH",
	ENOCSI:          "ENOCSI",
	EL2HLT:          "EL2HLT",
	EBADE:           "EBADE",
	EBADR:           "EBADR",
	EXFULL:          "EXFULL",
	ENOANO:          "ENOANO",
	EBADRQC:         "EBADRQC",
	EBADSLT:         "EBADSLT",
	EBFONT:          "EBFONT",
	ENOSTR:          "ENOSTR",
	ENODATA:         "ENODATA",
	ETIME:           "ETIME",
	ENOSR:           "ENOSR",
	ENONET:          "ENONET",
	ENOPKG:          "ENOPKG",
	EREMOTE:         "EREMOTE",
	ENOLINK:         "ENOLINK",
	EADV:            "EADV",
	ESRMNT:          "ESRMNT",
	ECOMM:           "ECOMM",
	EPROTO:          "EPROTO",
	EMULTIHOP:       "EMULTIHOP",
	EDOTDOT:         "EDOTDOT",
	EBADMSG:         "EBADMSG",
	EOVERFLOW:       "EOVERFLOW",
	ENOTUNIQ:        "ENOTUNIQ",
	EBADFD:          "EBADFD",
	EREMCHG:         "EREMCHG",
	ELIBACC:         "ELIBACC",
	ELIBBAD:         "ELIBBAD",
	ELIBSCN:         "ELIBSCN",
	ELIBMAX:         "ELIBMAX",
	ELIBEXEC:        "ELIBEXEC",
	EILSEQ:          "EILSEQ",
	ERESTART:        "ERESTART",
	ESTRPIPE:        "ESTRPIPE",
	EUSERS:          "EUSERS",
	ENOTSOCK:        "ENOTSOCK",
	EDESTADDRREQ:    "EDESTADDRREQ",
	EMSGSIZE:        "EMSGSIZE",
	EPROTOTYPE:      "EPROTOTYPE",
	ENOPROTOOPT:     "ENOPROTOOPT",
	EPROTONOSUPPORT: "EPROTONOSUPPORT",
	ESOCKTNOSUPPORT: "ESOCKTNOSUPPORT",
	EOPNOTSUPP:      "EOPNOTSUPP",
	EPFNOSUPPORT:    "EPFNOSUPPORT",
	EAFNOSUPPORT:    "EAFNOSUPPORT",
	EADDRINUSE:      "EADDRINUSE",
	EADDRNOTAVAIL:   "EADDRNOTAVAIL",
	ENETDOWN:        "ENETDOWN",
	ENETUNREACH:     "ENETUNREACH",
	ENETRESET:       "ENETRESET",
	ECONNABORTED:    "ECONNABORTED",
	ECONNRESET:      "ECONNRESET",
	ENOBUFS:         "ENOBUFS",
	EISCONN:         "EISCONN",
	ENOTCONN:        "ENOTCONN",
	ESHUTDOWN:       "ESHUTDOWN",
	ETOOMANYREFS:    "ETOOMANYREFS",
	ETIMEDOUT:       "ETIMEDOUT",
	ECONNREFUSED:    "ECONNREFUSED",
	EHOSTDOWN:       "EHOSTDOWN",
	EHOSTUNREACH:    "EHOSTUNREACH",
	EALREADY:        "EALREADY",
	EINPROGRESS:     "EINPROGRESS",
	ESTALE:          "ESTALE",
	EUCLEAN:         "EUCLEAN",
	ENOTNAM:         "ENOTNAM",
	ENAVAIL:         "ENAVAIL",
	EISNAM:          "EISNAM",
	EDQUOT:          "EDQUOT",
	ENOKEY:          "ENOKEY",
	ERFKILL:         "ERFKILL",
	ENOMEDIUM:       "ENOMEDIUM",
	EREMOTEIO:       "EREMOTEIO",
	ECANCELED:       "ECANCELED",
	EHWPOISON:       "EHWPOISON",
	EOWNERDEAD:      "EOWNERDEAD",
	EMEDIUMTYPE:     "EMEDIUMTYPE",
	EKEYEXPIRED:     "EKEYEXPIRED",
	EKEYREVOKED:     "EKEYREVOKED",
	EKEYREJECTED:    "EKEYREJECTED",
	ENOTRECOVERABLE: "ENOTRECOVERABLE",
	ERESTARTSYS:     "ERESTARTSYS",
}

var errnoKeys map[string]int
