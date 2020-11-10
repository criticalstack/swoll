package metrics

import (
	"unsafe"

	"github.com/iovisor/gobpf/elf"
)

type Handler struct {
	module *elf.Module
	table  *elf.Map
}

func NewHandler(mod *elf.Module) *Handler {
	return &Handler{
		module: mod,
		table:  mod.Map("swoll_metrics"),
	}
}

func (h *Handler) QueryAll() Metrics {
	ret := Metrics{}
	kkey := &key{}
	kval := &val{}
	next := &key{}

	for {
		more, _ := h.module.LookupNextElement(h.table,
			unsafe.Pointer(kkey),
			unsafe.Pointer(next),
			unsafe.Pointer(kval))
		if !more {
			break
		}

		kkey = next
		ret = append(ret, Metric{k: kkey.copy(), v: kval.copy()})
	}

	return ret
}
