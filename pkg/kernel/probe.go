package kernel

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/iovisor/gobpf/elf"
)

// Config is uhh, configuration stuff.
type Config struct {
	// enable kernel metrics
	EnableMetrics bool
	// enable kernel trace events
	EnableTracer bool
	// the tracepoints (names) to enable by default
	Tracepoints []string
}

// Probe contains underlying structures to control the kernel probe.
type Probe struct {
	// configuration settings
	config *Config
	// the underlying bpf module
	module *elf.Module
	// is everything ready to run?
	initialized bool
	// are the tracepoints initialized?
	tpInitialized bool
}

const (
	enterTracepoint = "tracepoint/raw_syscalls/sys_enter"
	exitTracepoint  = "tracepoint/raw_syscalls/sys_exit"
	execTracepoint  = "tracepoint/syscalls/sys_enter_execve"
	perfmapName     = "swoll_perf_output"
)

// NewProbeConfig returns the default configuration for a kernel probe.
func NewProbeConfig() *Config {
	return &Config{
		EnableMetrics: true, // default
		EnableTracer:  true, // default on (yes?)
		// default tracepoints, should be enough, but we allow
		// the caller to override after-the-fact.
		Tracepoints: []string{enterTracepoint, exitTracepoint, execTracepoint},
	}
}

// NewProbe does all initializations of our BPF structures. This does
// NOT do any operation in which requires administrative rights. That
// Functionality is for the initialization.
func NewProbe(bpf *bytes.Reader, cfg *Config) (*Probe, error) {
	if bpf == nil {
		return nil, errors.New("bpf is nil")
	}

	if cfg == nil {
		cfg = NewProbeConfig()
	}

	// initialize the module structures.
	mod := elf.NewModuleFromReader(bpf)

	return &Probe{
		config: cfg,
		module: mod,
	}, nil

}

// DataCallback is the function called for every trace-event record,
// or if the lost channel had been signaled.
type DataCallback func(msg []byte, lost uint64) error

// InitProbe loads all the underlying bpf maps, allocates the perfevent buffer,
// sets the tracepoints, all of which are operations which require CAP_ADMIN
func (p *Probe) InitProbe() error {
	if p == nil || p.module == nil {
		return fmt.Errorf("nil probe")
	}

	if p.initialized {
		return nil
	}

	// read in our bpf sections, while also configuring the ring size for the
	// output perfmap.
	if err := p.module.Load(map[string]elf.SectionParams{
		"maps/" + perfmapName: {PerfRingBufferPageCount: 2048}}); err != nil {
		return err
	}

	p.initialized = true

	return nil
}

// InitTracePoints will set our tracepoints as on.
func (p *Probe) InitTracepoints() error {
	// initialize our tracepoints that we have setup to be configured.
	if p.tpInitialized {
		return nil
	}

	for _, tp := range p.config.Tracepoints {
		if err := p.module.EnableTracepoint(tp); err != nil {
			return err
		}
	}

	p.tpInitialized = true

	return nil
}

// Close will de-initialize and close all the underlying bpf modules.
func (p *Probe) Close() error {
	if p != nil {
		p.initialized = false
		p.tpInitialized = false

		return p.module.Close()
	}

	return nil
}

// Run will read raw kernel trace events, and for each incoming
// trace, will call the user-provided callback `DataCallback`
func (p *Probe) Run(ctx context.Context, cb DataCallback) error {
	if p == nil || p.module == nil {
		return fmt.Errorf("nil probe")
	}

	if !p.initialized {
		// don't rely on end-user to call init (as it could be sourced from
		// eventreader)
		if err := p.InitProbe(); err != nil {
			return err
		}
	}

	if !p.tpInitialized {
		// Init our tracepoints.
		if err := p.InitTracepoints(); err != nil {
			return err
		}
	}

	// The channel in which we recv raw data from the kernel into the perfmap
	eventCh := make(chan []byte)
	// If frames are dropped by gobpf, this channel will be signaled.
	lostCh := make(chan uint64)

	// initialize the bpf perfmap, where (raw) real-time events are written to.
	perfmap, err := elf.InitPerfMap(p.module, perfmapName, eventCh, lostCh)
	if err != nil {
		return err
	}

	// start our poller and enter our little loop
	perfmap.PollStart()

	for {
		select {
		case msg := <-eventCh:
			if cb != nil {
				// call the user-defined callback on this data if defined.
				if err := cb(msg, 0); err != nil {
					return err
				}
			}
		case <-ctx.Done():
			// shut down the bpf polling loop
			perfmap.PollStop()
			return ctx.Err()
		case lost := <-lostCh:
			if cb != nil {
				if err := cb(nil, lost); err != nil {
					return err
				}
			}
		}
	}

}

// Module returns the gobpf.elf module reference for use in other
// apis (like filtering)
func (p *Probe) Module() *elf.Module {
	if p != nil {
		return p.module
	}

	return nil
}
