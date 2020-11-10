//nolint:structcheck
package filter

// the filter API is a translation layer to interact with the
// BPF probe filter configuration. With this simple filter, we can
// either whitelist, or blacklist the following data:
//    pids
//    syscalls
//    namespaces (mnt/pid)

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/syscalls"
	"github.com/iovisor/gobpf/elf"
)

type Type uint16

// These values should only be modified if changes are made to the filtering
// logic in the kernel bpf.
const (
	ModeWhitelist       Type = 1 << 0
	ModeBlacklist       Type = 1 << 1
	ModeGlobalWhitelist Type = 1 << 2
	ModeGlobalBlacklist Type = 1 << 3
	TypeSyscall         Type = 1 << 13
	TypePid             Type = 1 << 14
	TypePidns           Type = 1 << 15
	gFilterConfig            = "swoll_filter_config"
	gFilter                  = "swoll_filter"
)

// Rule represents a rule which can be sent to the kernel probe in the rawest
// form
type Rule struct {
	Type      Type
	pad       uint16 // needed for alignment.
	Namespace uint32
	Key       uint32
}

// Filter contains all maps and elf modules to read and write
// filter information to the kernel probe.
type Filter struct {
	m      *elf.Module
	config *elf.Map
	fmap   *elf.Map
}

// NewFilter initializes the underlying gobpf structures for
// filling in rule data into the kernel bpf probe.
func NewFilter(m *elf.Module) (*Filter, error) {
	if m == nil {
		return nil, errors.New("nil elf module")
	}

	return &Filter{
		m:      m,
		config: m.Map(gFilterConfig),
		fmap:   m.Map(gFilter),
	}, nil
}

// NewRule creates a rule structure to be placed into the
// kernel filter set.
func NewRule(t Type, ns, k uint32) *Rule {
	return &Rule{
		Type:      t,
		Namespace: ns,
		Key:       k,
	}
}

// InitFilter works like NewFilter, but directly on an Filter instance.
// good if you want to embed *Filter somewhere else.
func (f Filter) InitFilter(m *elf.Module) error {
	if m == nil {
		return errors.New("nil elf module")
	}

	f.m = m
	f.config = m.Map(gFilterConfig)
	f.fmap = m.Map(gFilter)

	return nil
}

// addRule adds the rule to the actual bpf tables in the kernel.
func (f *Filter) addRule(rule *Rule) error {
	if rule == nil {
		return fmt.Errorf("nil rule")
	}

	val := uint8(1)

	if err := f.m.UpdateElement(f.config, unsafe.Pointer(&rule.Type), unsafe.Pointer(&val), 0); err != nil {
		return err
	}

	if err := f.m.UpdateElement(f.fmap, unsafe.Pointer(rule), unsafe.Pointer(&val), 0); err != nil {
		return err
	}

	return nil
}

// delRule removes said rule from the kernel filter tables.
func (f *Filter) delRule(rule *Rule) error {
	if rule == nil {
		return fmt.Errorf("nil rule")
	}

	return f.m.DeleteElement(f.fmap, unsafe.Pointer(rule))
}

// add will add a rule type of T from the actual filter table.
func (f *Filter) add(t Type, ns, key int) error {
	rule := NewRule(t, uint32(ns), uint32(key))

	if err := f.addRule(rule); err != nil {
		return err
	}

	return nil
}

// del will delete a rule of type T from the actual filter table.
func (f *Filter) del(t Type, ns, key int) error {
	rule := NewRule(t, uint32(ns), uint32(key))

	if err := f.delRule(rule); err != nil {
		return err
	}

	return nil
}

// lookupSyscall is a helper function that takes either an int or a string and
// attempts to find the matching Syscall structure.
func lookupSyscall(nr interface{}) (*syscalls.Syscall, error) {
	s, err := syscalls.New()
	if err != nil {
		return nil, err
	}

	sc := s.Lookup(nr)
	if sc == nil {
		return nil, fmt.Errorf("syscall %v not found", nr)
	}

	return sc, nil
}

// AddSyscall adds a syscall (either "sys_xxx" or (int)nr) to the
// filter table.
func (f *Filter) AddSyscall(nr interface{}, ns int) error {
	sc, err := lookupSyscall(nr)
	if err != nil {
		return err
	}

	if ns != -1 {
		return f.add(ModeWhitelist|TypeSyscall, ns, sc.Nr)
	} else {
		return f.add(ModeGlobalWhitelist|TypeSyscall, 0, sc.Nr)
	}
}

// RemoveSyscall removes a syscall (either "sys_xxx" or (int)nr)
// from the filter table.
func (f *Filter) RemoveSyscall(nr interface{}, ns int) error {
	sc, err := lookupSyscall(nr)
	if err != nil {
		return err
	}

	if ns != -1 {
		return f.del(ModeWhitelist|TypeSyscall, ns, sc.Nr)
	} else {
		return f.del(ModeGlobalWhitelist|TypeSyscall, 0, sc.Nr)
	}
}

// AddPid will whitelist a specific PID in the filter table.
func (f *Filter) AddPid(pid, ns int) error {
	if ns != -1 {
		return f.add(ModeWhitelist|TypePid, ns, pid)
	} else {
		return f.add(ModeGlobalWhitelist|TypePid, 0, pid)
	}
}

// DelPid will remove a whitelisted PID from the filter table.
func (f *Filter) DelPid(pid, ns int) error {
	if ns != -1 {
		return f.del(ModeWhitelist|TypePid, ns, pid)
	} else {
		return f.del(ModeGlobalWhitelist|TypePid, 0, pid)
	}
}

// AddPidNs will whitelist a PID namespace in the filter table.
func (f *Filter) AddPidNs(pidns, ns int) error {
	return f.add(ModeWhitelist|TypePidns, ns, pidns)
}

// DelPidNs will remove a whitelisted PID namespace from the filter table.
func (f *Filter) DelPidNs(pidns, ns int) error {
	return f.del(ModeWhitelist|TypePidns, ns, pidns)
}

func (f *Filter) FilterSelf() error {
	return f.add(ModeBlacklist|TypePid, 0, int(syscall.Getpid()))
}
