package kernel

import (
	"fmt"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
)

type OffsetType uint8
type OffsetValue uint32

const (
	// ebpf configuration for the offset to task_struct's `nsproxy` member
	OffsetNSProxy OffsetType = 1
	// ebpf configuration for the offset to pid_namespace's `ns` member
	OffsetPidNSCommon OffsetType = 2
)

// The Offsetter class holds all the pertinent information to store offsets in
// the running kernel's offset lookup table.
type Offsetter struct {
	module    *elf.Module
	configMap *elf.Map
	offsets   map[OffsetType]*Offset
}

// Offset is a structure that represents a single offset configuration entry in
// the ebpf.
type Offset struct {
	Type  OffsetType
	Value OffsetValue
}

// NewOffsetter creates and initializes a new Offsetter context from the ebpf
// module.
func NewOffsetter(mod *elf.Module) (*Offsetter, error) {
	if smap := mod.Map("swoll_offsets_config"); smap != nil {
		return &Offsetter{
			module:    mod,
			configMap: smap,
			offsets:   make(map[OffsetType]*Offset),
		}, nil
	}
	return nil, fmt.Errorf("swoll_offsets_config nil map")
}

// NewOffset creates a new offset context
func NewOffset(t OffsetType, offs OffsetValue) *Offset {
	switch t {
	case OffsetNSProxy:
		break
	case OffsetPidNSCommon:
		break
	default:
		return nil
	}

	return &Offset{
		Type:  t,
		Value: offs,
	}
}

// Set will set the bpf offset configuration based on the type `t`. `t` can
// either be a string (nsproxy, pid_ns_common), or its native OffsetType.
// The value of which is the offset where this structure member lives.
func (o *Offsetter) Set(t interface{}, offset OffsetValue) error {
	var realType OffsetType

	switch t := t.(type) {
	case string:
		switch t {
		case "nsproxy":
			realType = OffsetNSProxy
		case "pid_ns_common":
			realType = OffsetPidNSCommon
		}
	case int:
		realType = OffsetType(t)
	case OffsetType:
		realType = t
	}

	if offs := NewOffset(realType, offset); offs != nil {
		o.offsets[realType] = offs
	} else {
		return fmt.Errorf("unknown offset type")
	}

	// set the value of this member in the bpf map.
	return o.module.UpdateElement(o.configMap,
		unsafe.Pointer(&realType),
		unsafe.Pointer(&offset), 0)
}
