package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	// probably a good idea not to muck around with these values unless changes
	// are made to the internal/bpf/probe.c code and you need to reflect those
	// changes.
	evArgLen   = 128 // the length of a single argument from the kernel
	evArgCount = 5   // the number of arguments of `evArgLen` size
	evCommLen  = 16  // the size of the `comm` field
)

// RawEvent is format of an event as seen by the kernel.
type RawEvent struct {
	Pid       uint32                      `json:"pid"`
	Tid       uint32                      `json:"tid"`
	UID       uint32                      `json:"uid"`
	Gid       uint32                      `json:"gid"`
	Syscall   uint32                      `json:"nr"`
	NsPid     uint32                      `json:"ns_pid"`
	Start     uint64                      `json:"start"`
	Finish    uint64                      `json:"finish"`
	Session   int32                       `json:"sid"`
	PidNS     uint32                      `json:"pid_ns"`
	UtsNS     uint32                      `json:"uts_ns"`
	MntNS     uint32                      `json:"mnt_ns"`
	IpcNS     uint32                      `json:"ipc_ns"`
	CgrNS     uint32                      `json:"cgr_ns"`
	ContextSw uint64                      `json:"context_sw"`
	Errno     uint32                      `json:"error"`
	Ret       uint32                      `json:"ret"`
	Comm      [evCommLen]uint8            `json:"comm,omitempty"`
	Arguments [evArgLen * evArgCount]byte `json:"buf,omitempty"`
}

// Args returns a cup up version of ev.Arguments, each
// slice representing a single argument.
func (ev *RawEvent) Args() []*byte {
	ret := []*byte{}

	for i := 0; i < evArgCount; i++ {
		ret = append(ret, &ev.Arguments[i*evArgLen])
	}

	return ret
}

// IngestBytes converts a []byte into a RawEvent
func (ev *RawEvent) IngestBytes(data []byte) (*RawEvent, error) {
	if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, ev); err != nil {
		return nil, err
	}

	return ev, nil
}

// IngestKernelEvent converts a KernelEvent into a RawEvent
func (ev *RawEvent) IngestKernelEvent(data KernelEvent) (*RawEvent, error) {
	return ev.IngestBytes([]byte(data))
}

// Ingest will take an input of various types (data), and attempts to convert
// it into a working RawEvent
func (ev *RawEvent) Ingest(data interface{}) (*RawEvent, error) {
	switch data := data.(type) {
	case KernelEvent:
		return ev.IngestKernelEvent(data)
	case []byte:
		return ev.IngestBytes(data)
	default:
		return nil, fmt.Errorf("invalid input: %T", data)
	}
}

// PidNamespace is for podmon.ResolverContext interface abstraction
func (ev *RawEvent) PidNamespace() int {
	return int(ev.PidNS)
}

// MntNamespace is for podmon.ResolverContext interface abstraction
func (ev *RawEvent) MntNamespace() int {
	return int(ev.MntNS)
}

// Commstr returns a stringified version of the process.
func (ev *RawEvent) Commstr() string {
	count := 0

	for _, b := range ev.Comm {
		if b == 0 {
			break
		}

		count++
	}

	return string(ev.Comm[:count])
}

// ArgLen is for interface abstraction of messages and their arguments,
// used to get the size of a single argument within this type of message.
func (ev *RawEvent) ArgLen() int {
	return evArgLen
}
