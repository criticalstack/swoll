package podmon

import (
	"errors"

	"github.com/criticalstack/swoll/pkg/types"
)

// ResolverContext is used to resolve any type of data that
// can return the pid and mount namespace.
type ResolverContext interface {
	// the pid namespace of this data
	PidNamespace() int
	// the mount namespace of this data
	MntNamespace() int
}

// Resolve attempts to resolve the mapping between th epid/mnt namespaces
// and the underlying container information (including kubernetes info)
func (p *PodMon) Resolve(ctx ResolverContext) (*types.Container, error) {
	if ctx.PidNamespace() == 0 || ctx.MntNamespace() == 0 {
		return nil, errors.New("no namespaces for ctx")
	}

	container, err := p.LookupContainer(ctx.PidNamespace(), ctx.MntNamespace())
	return container, err
}

// Resolve is just a wrapper around podmon.Resolve()
func Resolve(p *PodMon, ctx ResolverContext) (*types.Container, error) {
	return p.Resolve(ctx)
}
