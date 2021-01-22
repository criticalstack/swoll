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

func (h *Handler) PruneNamespace(ns int) (int, error) {
	k := &key{}
	v := &val{}
	n := &key{}
	toDelete := make([]*key, 0)

	for {
		more, _ := h.module.LookupNextElement(h.table,
			unsafe.Pointer(k),
			unsafe.Pointer(n),
			unsafe.Pointer(v))
		if !more {
			break
		}

		k = n

		if k.pidNs == uint32(ns) {
			toDelete = append(toDelete, k.copy())
		}

	}

	for _, ent := range toDelete {
		h.module.DeleteElement(h.table, unsafe.Pointer(ent))
	}

	return len(toDelete), nil
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
