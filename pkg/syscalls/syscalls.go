package syscalls

import (
	"fmt"
	"log"
	"strings"
)

type Syscall struct {
	Nr    int    `json:"nr"`
	Name  string `json:"name"`
	Class string `json:"class"`
	Group string `json:"group"`
}

type Syscalls struct {
	// reference a Syscall object by number.
	nr map[int]*Syscall
	// reference a Syscall object by its name
	name map[string]*Syscall
}

var (
	gSyscallsCtx *Syscalls
)

func (s *Syscall) String() string {
	if s != nil {
		return s.Name
	}

	return ""
}

func init() {
	var err error

	gSyscallsCtx, err = New()

	if err != nil {
		log.Fatal(err)
	}
}

type SyscallList []*Syscall

func (s SyscallList) GetByGroup(group string) SyscallList {
	ret := make(SyscallList, 0)

	for _, sc := range s {
		if sc.Group == group {
			ret = append(ret, sc)
		}
	}

	return ret
}

func (s *Syscalls) GetByClass(class string) SyscallList {
	ret := make(SyscallList, 0)

	for _, sc := range s.nr {
		if sc.Class == class {
			ret = append(ret, sc)
		}
	}

	return ret
}

func Classes() []string {
	ret := []string{}
	for class := range gClassMap {
		ret = append(ret, class)
	}
	return ret
}

func Groups(class string) []string {
	ret := []string{}
	for grp := range gClassMap[class] {
		ret = append(ret, grp)
	}
	return ret
}

func Calls(class, group string) []string {
	return gClassMap[class][group]
}

// init will iterate over the syscall class map, and initialize our
// nr and name lookup tables with this data.
func (s *Syscalls) init() error {
	for class, groups := range gClassMap {
		for group, syscalls := range groups {
			for _, scStr := range syscalls {
				nr, ok := gSyscallMap[scStr]
				if !ok {
					return fmt.Errorf("No matching NR for %s", scStr)
				}

				sc := &Syscall{nr, scStr, class, group}

				s.nr[nr] = sc
				s.name[scStr] = sc
			}
		}
	}

	return nil
}

// Lookup takes either a string or an int and attempts to find
// the corresponding Syscall where an int==NR and string==NameOfSyscall
func (s *Syscalls) Lookup(v interface{}) *Syscall {
	if s == nil {
		return nil
	}

	switch v := v.(type) {
	case string:
		// we always preface syscalls with sys_, if it is not
		// there, for convience, we add it.
		if !strings.HasPrefix(v, "sys_") {
			v = "sys_" + v
		}

		return s.name[v]
	case uint32:
		return s.nr[int(v)]
	case int:
		return s.nr[v]
	}

	return nil
}

func Lookup(v interface{}) *Syscall {
	return gSyscallsCtx.Lookup(v)
}

func GetByClass(class string) SyscallList {
	return gSyscallsCtx.GetByClass(class)
}

// New creates an initializes a Syscalls structure which can be used
// for looking up data about a specific syscall.
func New() (*Syscalls, error) {
	syscalls := &Syscalls{
		nr:   make(map[int]*Syscall),
		name: make(map[string]*Syscall),
	}

	if err := syscalls.init(); err != nil {
		return nil, err
	}

	return syscalls, nil
}
