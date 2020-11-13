package metrics

import (
	"fmt"
	"math"
)

// key is the structure in kernel memory that represents the
// key-value of a metric entry from the kernel.
type key struct {
	pidNs   uint32
	syscall uint32
	errno   uint16
	pad     uint16
}

// val is the structure that is the value of `key` as seen by
// the kernel.
type val struct {
	count    uint64
	time     uint64
	first    uint64
	last     uint64
	reserved uint64
}

// Metric is just an aggregate of the kernel key and value
type Metric struct {
	k *key
	v *val
}

// Metrics is an array of metric entries
type Metrics []Metric

func (k *key) String() string {
	return fmt.Sprintf("pidns=%v, , sc=%v, errno=%v", k.pidNs, k.syscall, k.errno)
}

func (v *val) String() string {
	return fmt.Sprintf("count=%v, time=%v, first=%v, last=%v", v.count, v.time, v.first, v.last)
}

func (m Metric) String() string {
	return fmt.Sprintf("key={%v}, val={%v}", m.k, m.v)
}

// copy makes a copy of the key.
func (k *key) copy() *key {
	return &key{
		pidNs:   k.pidNs,
		syscall: k.syscall,
		errno:   k.errno,
		pad:     k.pad,
	}
}

// copy makes a copy of the value
func (v *val) copy() *val {
	return &val{
		count:    v.count,
		time:     v.time,
		first:    v.first,
		last:     v.last,
		reserved: v.reserved,
	}
}

func (m *Metric) Count() uint64 {
	if m != nil && m.v != nil {
		return m.v.count
	}

	return 0
}

func (m *Metric) TimeSpent() uint64 {
	if m != nil && m.v != nil {
		return m.v.time
	}

	return 0
}

func (m *Metric) First() uint64 {
	if m != nil && m.v != nil {
		return m.v.first
	}

	return 0
}

func (m *Metric) Last() uint64 {
	if m != nil && m.v != nil {
		return m.v.last
	}

	return 0
}

func (m *Metric) PidNS() uint32 {
	if m != nil && m.k != nil {
		return m.k.pidNs
	}

	return 0
}

func (m *Metric) Syscall() uint32 {
	if m != nil && m.k != nil {
		return m.k.syscall
	}

	// if not found, since '0' can be seen as `read`, just return -1.
	return math.MaxUint32
}

func (m *Metric) Errno() uint16 {
	if m != nil && m.k != nil {
		return m.k.errno
	}

	return 0
}

// PidNamespace is for podmon.ResolverContext interface abstraction
func (m Metric) PidNamespace() int {
	return int(m.PidNS())
}
