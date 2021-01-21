package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/criticalstack/swoll/pkg/kernel"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type kernelSyms map[string]string

// parseKernelSyms reads in a `/proc/kallsyms` formatted symtab and merges the
// info into a map.
func parseKernelSyms(r io.Reader) kernelSyms {
	ret := make(map[string]string)
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		tokens := strings.Fields(scanner.Text())
		switch tokens[1] {
		case "t", "T":
			break
		default:
			continue
		}

		// symname = kernel address
		ret[tokens[2]] = tokens[0]
	}

	return ret
}

func parseKallsyms() kernelSyms {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		log.Infof("Failed to open /proc/kallsyms: %s", err.Error())
		return nil
	}
	defer f.Close()

	return parseKernelSyms(f)
}

func objdumpAddress(addr, corefile string) ([]byte, error) {
	r, err := strconv.ParseUint(addr, 16, 64)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(corefile); os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "could not open %s, set offsets manually", corefile)
	}

	if _, err := exec.LookPath("objdump"); err != nil {
		return nil, errors.Wrapf(err, "could not find `objdump`: please install binutils")
	}

	return exec.Command("objdump", corefile,
		"--disassemble",
		"--disassembler-options", "intel",
		"--start-address", fmt.Sprintf("0x%08x", r),
		"--stop-address", fmt.Sprintf("0x%08x", r+(8*32))).Output()
}

const (
	stateRLock = iota
	stateRMov
)

var movre *regexp.Regexp = regexp.MustCompile(`mov\s+\w+,QWORD PTR \[\w+\+(0x\w+?)\]`)
var leare *regexp.Regexp = regexp.MustCompile(`lea\s+\w+,\[\w+[+-](0x\w+?)\]`)

// The purpose of this little nugget is to find the offset of the currently
// running kernel's task_struct->nsproxy variable. We use this offset to
// find the current tasks's pid and mnt namespaces. This (currently) only works
// on x86_64 as we are looking for x86 specific operations.
//
// It works by scanning `/proc/kallsyms` for specific functions we are
// interested in, in our case:
//  - `_raw_spin_lock` (more on this later)
//  - `ipcns_get`
//  - `utsns_get`
//  - `mntns_get`
//  - `cgroupns_get`
//
// With the exception of `_raw_spin_lock`, these kernel functions are small
// helper functions which can be found in all modern linux installs. We target
// these because they:
//    a) are very small in size and pose little risk of changing
//    b) are very similar in operation
//    c) lock the task_struct at a very early stage
//    d) assign a local variable the value of `task_struct->nsproxy`
//
// Take the following function as an example:
//         static struct ns_common *mntns_get(struct task_struct *task)
//        {
//            struct ns_common *ns = NULL;
//            struct nsproxy *nsproxy;
//            task_lock(task); // push %dsi
//                             // call _raw_spin_lock
//            nsproxy = task->nsproxy; // mov reg,dsi+0x... == offset of task->nsproxy
//            if (nsproxy != NULL) {   // test reg,reg
//
// The resulting assembly will have the following characteristics:
//   push  %dsi                      // or wherever arg[0] resides.
//   call _raw_spin_lock             // task_lock(task)
//   mov   %r8,QWORD PTR [%dsi+XXXX] // nsproxy = task->nsproxy (XXXX == offset)
//   test  %r8,%r8                   // if (nsproxy != NULL)
//
// We fetch the addresses of these symbols from /proc/kallsyms, then read
// /proc/kcore and disassemble the first few instructions and attempt to find
// the above pattern.
//
// This is a hack, but it's a working hack.
func nsproxyOffsetSearch(objdump io.Reader) string {
	lockaddr := parseKallsyms()["_raw_spin_lock"]
	scanner := bufio.NewScanner(objdump)
	state := stateRLock

	for scanner.Scan() {
		if !strings.HasPrefix(scanner.Text(), "ffffffff") {
			// skip lines that aren't specifically code segments.
			continue
		}

		switch state {
		case stateRLock:
			// read until we see a call to _raw_spin_lock
			if strings.Contains(scanner.Text(), lockaddr) {
				// found a call to _raw_spin_lock, set the next thing
				// to search for.
				state = stateRMov
			}
		case stateRMov:
			// read instructions until we find a local mov from dsi+offset
			if found := movre.FindStringSubmatch(scanner.Text()); len(found) > 0 {
				// this is a potential match.
				return found[1]
			}

		}
	}

	return ""
}

// pidnscommonOffsetSearch is simple in comparison to nsproxyOffsetSearch. Here
// we are trying to get the offset to the `struct ns_common` member `ns` from
// `struct pid_namespace`. There are several functions in the kernel that do
// something like the following: `return ns ? &(struct ns_common *)ns->ns :
// NULL;`, or `if (ns != NULL) return &ns->ns; else return NULL;`
//
// Returning a pointer to a constant or stack will result in a "load effective
// address" (`lea`), and these functions are small enough where we can just
// count the number of `lea`'s to get a good idea of where this member sits.
func pidnscommonOffsetSearch(objdump io.Reader) []string {
	scanner := bufio.NewScanner(objdump)
	ret := make([]string, 0)

	for scanner.Scan() {
		if found := leare.FindStringSubmatch(scanner.Text()); len(found) > 0 {
			ret = append(ret, found[1])
		}
	}

	return ret
}

func maxCandidates(candidates map[string]int) (string, int) {
	var mn int
	var ms string

	for k, v := range candidates {
		if v == mn {
			log.Infof("warning: same size candidates (%v=%v == %v=%v)\n", k, v, ms, mn)
		}

		if v > mn {
			ms = k
			mn = v
		}
	}

	return ms, mn
}

func pidnsCommonLikelyOffset(symfile, corefile string, functions []string) string {
	symbols := parseKallsyms()
	candidates := make(map[string]int)

	for _, fn := range functions {
		addr, ok := symbols[fn]
		if !ok {
			log.Infof("warning: couldnt find address for sym %s", fn)
		}

		code, err := objdumpAddress(addr, corefile)
		if err != nil {
			log.Warnf("warning: %s", err.Error())
			continue
		}

		if offs := pidnscommonOffsetSearch(bytes.NewReader(code)); len(offs) > 0 {
			for _, off := range offs {
				candidates[off]++
			}
		}
	}

	addr, count := maxCandidates(candidates)
	log.Infof("info: pidns->ns_common likelyOffset addr=%v, count=%v\n", addr, count)
	return addr

}

func nsproxyLikelyOffset(symfile, corefile string, functions []string) string {
	symbols := parseKallsyms()
	candidates := make(map[string]int)

	for _, fn := range functions {
		addr, ok := symbols[fn]
		if !ok {
			log.Warnf("warning: couldn't find address for sym %s", fn)
			continue
		}

		code, err := objdumpAddress(addr, corefile)
		if err != nil {
			log.Warnf("%s", err.Error())
			continue
		}

		if offs := nsproxyOffsetSearch(bytes.NewReader(code)); offs != "" {
			candidates[offs]++
		}
	}

	addr, count := maxCandidates(candidates)
	log.Infof("info: likelyOffset addr=%v, count=%v\n", addr, count)

	return addr
}

func SetOffsetsFromArgs(probe *kernel.Probe, cmd *cobra.Command, args []string) error {
	nodetect, err := cmd.Flags().GetBool("no-detect-offsets")
	if err != nil {
		return err
	}

	var nsproxyOffset string
	var pnsCommOffset string

	if !nodetect {
		nsproxyOffset = nsproxyLikelyOffset("/proc/kallsyms", "/proc/kcore",
			[]string{
				"ipcns_get",
				"mntns_get",
				"cgroupns_get",
				"netns_get",
				"get_proc_task_net",
				"switch_task_namespaces",
				"mounts_open_common",
			})

		pnsCommOffset = pidnsCommonLikelyOffset("/proc/kallsyms", "/proc/kcore",
			[]string{
				"pidns_for_children_get",
				"pidns_put",
				"pidns_get",
			})

	} else {
		offstr, err := cmd.Flags().GetString("nsproxy-offset")
		if err != nil {
			return err
		}

		nsproxyOffset = offstr

		offstr, err = cmd.Flags().GetString("pidns-offset")
		if err != nil {
			return err
		}

		pnsCommOffset = offstr
	}

	if nsproxyOffset != "" {
		nsproxyOffset = strings.TrimPrefix(nsproxyOffset, "0x")
		offset, err := strconv.ParseInt(nsproxyOffset, 16, 64)
		if err != nil {
			return err
		}

		setter, err := kernel.NewOffsetter(probe.Module())
		if err != nil {
			log.Fatal(err)
		}

		log.Infof("Setting task_struct->nsproxy offset to: %x\n", offset)

		if err := setter.Set("nsproxy", kernel.OffsetValue(offset)); err != nil {
			return err
		}
	}

	if pnsCommOffset != "" {
		pnsCommOffset = strings.TrimPrefix(pnsCommOffset, "0x")
		offset, err := strconv.ParseInt(pnsCommOffset, 16, 64)
		if err != nil {
			return err
		}

		setter, err := kernel.NewOffsetter(probe.Module())
		if err != nil {
			log.Fatal(err)
		}

		log.Infof("Setting pid_namespace->ns offset to: %x\n", offset)

		if err := setter.Set("pid_ns_common", kernel.OffsetValue(offset)); err != nil {
			return err
		}

	}

	return nil

}
