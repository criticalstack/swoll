package kernel

import (
	"fmt"
	"log"
	"strings"
	"unsafe"

	"github.com/criticalstack/swoll/pkg/syscalls"
	"github.com/iovisor/gobpf/elf"
)

type filterFlag uint16
type filterAction uint8

type filterKey struct {
	flags   filterFlag
	pad     uint16
	pidns   uint32
	thrid   uint32
	syscall int32
}

type filterVal struct {
	sampleRate  uint32
	sampleCount uint32
	hits        uint64
	pad1        uint16
	pad2        uint8
	action      filterAction
}

const (
	// filter modes
	fmodeEnabled filterFlag = 1 << 0
	fmodeSyscall filterFlag = 1 << 1
	fmodeMetrics filterFlag = 1 << 2
	// filter types
	ftypePid     filterFlag = 1 << 13
	ftypePidNS   filterFlag = 1 << 14
	ftypeSyscall filterFlag = 1 << 15
	// filter actions
	factionAllow filterAction = 0
	factionDrop  filterAction = 1
)

const (
	defaultFilterConfig = "swoll_filter_config"
	defaultFilterName   = "swoll_nfilter"
)

// FilterRule represents a single entry in the kernel-filter
type FilterRule struct {
	key filterKey
	val filterVal
}

// Filter contains all the bits to communicate with the kernel-filter
type Filter struct {
	mod    *elf.Module
	config *elf.Map
	filter *elf.Map
	rules  []*FilterRule
}

type FilterRuleOption func(*FilterRule) error

// NewFilter sets and initializes all the underlying BPF maps for working with
// the kernel-filter
func NewFilter(mod *elf.Module) *Filter {
	return &Filter{
		mod:    mod,
		config: mod.Map(defaultFilterConfig),
		filter: mod.Map(defaultFilterName),
		rules:  make([]*FilterRule, 0),
	}
}

func (f *Filter) GetRunning() ([]*FilterRule, error) {
	key := &filterKey{}
	val := &filterVal{}
	next := &filterKey{}
	ret := make([]*FilterRule, 0)

	for {
		more, err := f.mod.LookupNextElement(f.filter, unsafe.Pointer(key), unsafe.Pointer(next), unsafe.Pointer(val))
		if err != nil {
			return nil, err
		}

		if !more {
			break
		}

		key = next
		ret = append(ret, &FilterRule{*key, *val})
	}

	return ret, nil
}

func (f *Filter) AddRule(rule *FilterRule) error {
	if rule.key.flags&fmodeMetrics > 0 && rule.key.syscall == 0 {
		rule.key.syscall = -1
	}

	// first inform the filter we need to look at this type of message, if there
	// are no configurations matching this type, the bpf will not even try a
	// lookup
	enabled := uint8(1)

	// TODO: one issue with this is, if the second Update fails, then this is
	// still set. To do this properly, we must first check the value of this
	// bucket, and only set if the value doesn't already exist, and only remove
	// if the second conditional errors.
	//
	// I'm actually thinking this step may be a bit over-kill anyway, the
	// original idea was to have a small conditional the bpf could jump to to
	// see if a certain type of filter even exists before doing all the other
	// comparisons.
	if err := f.mod.UpdateElement(f.config,
		unsafe.Pointer(&rule.key.flags),
		unsafe.Pointer(&enabled), 0); err != nil {
		return fmt.Errorf("failed to update filter-config: %v", err)
	}

	// now write rule with contents to the filter map
	if err := f.mod.UpdateElement(f.filter,
		unsafe.Pointer(&rule.key),
		unsafe.Pointer(&rule.val), 0); err != nil {
		return fmt.Errorf("failed to add rule to filter: %v", err)
	}

	f.rules = append(f.rules, rule)

	return nil
}

func (f *Filter) DelRule(rule *FilterRule) error {
	return f.mod.DeleteElement(f.filter, unsafe.Pointer(&rule.key))
}

func (f *Filter) Enable() error {
	key := fmodeEnabled
	enabled := uint8(1)

	return f.mod.UpdateElement(f.config, unsafe.Pointer(&key), unsafe.Pointer(&enabled), 0)
}

func NewFilterRule(opts ...FilterRuleOption) (*FilterRule, error) {
	rule := new(FilterRule)

	for _, opt := range opts {
		if err := opt(rule); err != nil {
			return nil, err
		}
	}

	return rule, nil
}

// NewRuleN is an error-wrapper aound NewFilterRule
func NewFilterRuleN(opts ...FilterRuleOption) *FilterRule {
	rule, err := NewFilterRule(opts...)
	if err != nil {
		log.Fatal(err)
	}
	return rule
}

func FilterRuleSetSyscall(sc interface{}) FilterRuleOption {
	return func(rule *FilterRule) error {
		sysc := syscalls.Lookup(sc)
		if sysc == nil {
			return fmt.Errorf("syscall %v not found", sc)
		}

		rule.key.syscall = int32(sysc.Nr)
		rule.key.flags = rule.key.flags | ftypeSyscall
		return nil
	}
}

func FilterRuleSetSampleRate(rate int) FilterRuleOption {
	return func(rule *FilterRule) error {
		rule.val.sampleRate = uint32(rate)
		return nil
	}
}

func FilterRuleSetPidNamespace(ns int) FilterRuleOption {
	return func(rule *FilterRule) error {
		rule.key.pidns = uint32(ns)
		rule.key.flags = rule.key.flags | ftypePidNS
		return nil
	}
}

func FilterRuleSetPid(pid int) FilterRuleOption {
	return func(rule *FilterRule) error {
		rule.key.thrid = uint32(pid)
		rule.key.flags = rule.key.flags | ftypePid
		return nil
	}
}

func FilterRuleSetActionDrop() FilterRuleOption {
	return func(rule *FilterRule) error {
		rule.val.action = factionDrop
		return nil
	}
}

func FilterRuleSetActionAllow() FilterRuleOption {
	return func(rule *FilterRule) error {
		rule.val.action = factionAllow
		return nil
	}
}

func FilterRuleSetModeSyscall() FilterRuleOption {
	return func(rule *FilterRule) error {
		rule.key.flags = rule.key.flags | fmodeSyscall
		return nil
	}
}

func FilterRuleSetModeMetrics() FilterRuleOption {
	return func(rule *FilterRule) error {
		rule.key.flags = rule.key.flags | fmodeMetrics
		return nil
	}
}

// AddSyscall is a helper function which is backwards-compatible with the old
// filtering logic, but uses new filtering logic.
func (f *Filter) AddSyscall(nr interface{}, ns int) error {
	rule, err := NewFilterRule(
		FilterRuleSetModeSyscall(),
		FilterRuleSetSyscall(nr),
		FilterRuleSetPidNamespace(ns),
		FilterRuleSetActionAllow())
	if err != nil {
		return err
	}

	return f.AddRule(rule)
}

// AddSampledSyscall is a helper function which is backwards-compatible with the
// old filtering logic, but uses new filtering logic.
func (f *Filter) AddSampledSyscall(nr interface{}, ns int, rate uint64) error {
	rule, err := NewFilterRule(
		FilterRuleSetModeSyscall(),
		FilterRuleSetSyscall(nr),
		FilterRuleSetPidNamespace(ns),
		FilterRuleSetSampleRate(int(rate)),
		FilterRuleSetActionAllow())
	if err != nil {
		return err
	}

	return f.AddRule(rule)
}

// RemoveSyscall is a helper function which is backwards-compatible with the old
// filtering logic, but uses new filtering logic for deleting elements created
// by AddSyscall()
func (f *Filter) RemoveSyscall(nr interface{}, ns int) error {
	rule, err := NewFilterRule(
		FilterRuleSetModeSyscall(),
		FilterRuleSetSyscall(nr),
		FilterRuleSetPidNamespace(ns),
		FilterRuleSetActionAllow())
	if err != nil {
		return err
	}

	return f.DelRule(rule)
}

// AddMetrics is a helper function which is backwards-compatible with the old
// filtering logic, but uses new filtering logic for enabling metrics on a
// pid-namespace.
func (f *Filter) AddMetrics(ns int) error {
	rule, err := NewFilterRule(
		FilterRuleSetModeMetrics(),
		FilterRuleSetPidNamespace(ns),
		FilterRuleSetActionAllow())
	if err != nil {
		return err
	}

	return f.AddRule(rule)
}

// RemoveMetrics is a helper function which is backwards-compatible with the old
// filtering logic, but uses the new filtering logic for deleting metrics on a
// pid-namespace.
func (f *Filter) RemoveMetrics(ns int) error {
	rule, err := NewFilterRule(
		FilterRuleSetModeMetrics(),
		FilterRuleSetPidNamespace(ns),
		FilterRuleSetActionAllow())
	if err != nil {
		return err
	}

	return f.DelRule(rule)
}

// FilterSelf will make sure that no events are emitted from the kernel that
// have the same PID as the caller.
func (f *Filter) FilterSelf() error {
	/*
		rule, err := NewFilterRule(
			FIlterRuleSetModeSyscall(),
			FilterRuleSetPid(int(syscall.Getpid())),
			FilterRuleSetActionDrop())
		if err != nil {
			return err
		}

		return f.AddRule(rule)
	*/
	return nil
}

func (f filterFlag) String() string {
	out := []string{}
	if f&fmodeSyscall > 0 {
		out = append(out, "FILTER_MODE_SYSCALL")
	}

	if f&fmodeMetrics > 0 {
		out = append(out, "FILTER_MODE_METRICS")
	}

	if f&ftypePid > 0 {
		out = append(out, "FILTER_TYPE_PID")
	}

	if f&ftypePidNS > 0 {
		out = append(out, "FILTER_TYPE_PID_NS")
	}

	if f&ftypeSyscall > 0 {
		out = append(out, "FILTER_TYPE_SYSCALL")
	}

	return strings.Join(out, "|")
}

func (a filterAction) String() string {
	switch a {
	case factionAllow:
		return "ACTION_ALLOW"
	case factionDrop:
		return "ACTION_DROP"
	}
	return "ACTION_UNKNOWN"
}

func (k filterKey) String() string {
	var callName string

	if sc := syscalls.Lookup(int(k.syscall)); sc == nil {
		callName = "ALL"
	} else {
		callName = sc.Name
	}

	return fmt.Sprintf("flags=%s, pid-namespace=%v, thread-id=%d, syscall=%s",
		k.flags, k.pidns, k.thrid, callName)
}

func (v filterVal) String() string {
	return fmt.Sprintf("sample-rate=%d, current-sample-count=%d, hits=%d, action=%s",
		v.sampleRate, v.sampleCount, v.hits, v.action)
}

func (r *FilterRule) String() string {
	return fmt.Sprintf("{%s, %s}", r.key, r.val)
}
