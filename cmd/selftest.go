package cmd

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"syscall"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/syndtr/gocapability/capability"
)

func checkCapabilities() error {
	if caps, err := capability.NewPid(0); err != nil {
		return errors.Wrapf(err, "Failed to get capabilities")
	} else {
		if !caps.Get(capability.EFFECTIVE, capability.CAP_SYS_ADMIN) {
			return errors.Errorf("Need CAP_SYS_ADMIN rights (re-run with sudo?)")
		}
	}

	return nil
}

func checkMounts() error {
	if _, err := os.Stat("/sys/kernel/debug/tracing"); os.IsNotExist(err) {
		return errors.Wrapf(err, "Tracefs must be mounted (mount -t debugfs none /sys/kernel/debug")
	}

	return nil
}

func fixMounts() error {
	return syscall.Mount("none", "/sys/kernel/debug", "debugfs", 0, "")
}

func getBootConfigFile() (string, error) {
	slc2str := func(buf []int8) string {
		ret := make([]byte, 0)
		for _, val := range buf {
			if val == 0x0 {
				break
			}
			ret = append(ret, byte(val))
		}

		return string(ret)
	}

	var un syscall.Utsname
	if err := syscall.Uname(&un); err != nil {
		return "", err
	}

	cfg := fmt.Sprintf("/boot/config-%s", slc2str(un.Release[:]))
	if _, err := os.Stat(cfg); err != nil {
		return "", err
	}

	return cfg, nil
}

func parseBootConfig() (map[string]bool, error) {
	cfgfile, err := getBootConfigFile()
	if err != nil {
		return nil, err
	}

	f, err := os.Open(cfgfile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	re := regexp.MustCompile(`^(\w+)\=[ym]$`)
	ret := make(map[string]bool)
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		if found := re.FindStringSubmatch(scanner.Text()); len(found) > 0 {
			ret[found[1]] = true
		}
	}

	return ret, nil

}

func checkFeatures() error {
	bconfig, err := parseBootConfig()
	if err != nil {
		return err
	}

	checks := []string{
		"CONFIG_BPF",
		"CONFIG_BPF_JIT",
		"CONFIG_FTRACE_SYSCALLS", // for syscall tracepoints
	}

	for _, check := range checks {
		if ok := bconfig[check]; !ok {
			return fmt.Errorf("kernel feature '%s' not found", check)
		}
	}

	return nil
}

func runSelfTest(fix bool) error {
	log.Println("checking capabilities")
	if err := checkCapabilities(); err != nil {
		return err
	}

	log.Println("checking for proper mounts")
	if err := checkMounts(); err != nil {
		if fix {
			if err := fixMounts(); err != nil {
				return errors.Wrap(err, "Couldn't fix mounts")
			}

			if err := checkMounts(); err != nil {
				return errors.Wrap(err, "Couldn't check mounts")
			}
		} else {
			return err
		}
	}

	log.Println("checking kernel-config (if available)")
	if err := checkFeatures(); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	}

	return nil
}

var cmdSelfTest = &cobra.Command{
	Use:   "selftest",
	Short: "Run a self-test to verify your installation",
	Run: func(cmd *cobra.Command, args []string) {
		fix, err := cmd.Flags().GetBool("fix")
		if err != nil {
			log.Fatal(err)
		}

		if err := runSelfTest(fix); err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(cmdSelfTest)
	cmdSelfTest.Flags().BoolP("fix", "f", false, "Attempt to fix problems if possible")
}
