package topology

import (
	"fmt"
	"path"
	"syscall"
)

// getNamespaceIno returns the numerical kernel-namespace for the specified
// namespace-type `t` for the process-id `pid` in the proc-root directory `root`
func getNamespaceIno(root string, pid int, t string) (int, error) {
	var stat syscall.Stat_t

	pfile := path.Join(root, "/proc", fmt.Sprintf("%d", pid), "ns", t)

	if err := syscall.Stat(pfile, &stat); err != nil {
		return -1, err
	}

	return int(stat.Ino), nil
}

// getPidNamespace is a wrapper around getNamespaceIno to fetch a tasks kernel
// pid-namespace.
func getPidNamespace(root string, pid int) (int, error) {
	return getNamespaceIno(root, pid, "pid_for_children")
}
