package cmd

import (
	"io/ioutil"
	"os"

	"github.com/criticalstack/swoll/pkg/kernel/assets"
	"github.com/spf13/cobra"
)

// loadBPFargs will attempt to find the BPF object file via the commandline,
// If the argument is empty (default), we check the local environment, and if
// that fails, we attempt to load the go-bindata generated asset.
func loadBPFargs(cmd *cobra.Command, args []string) ([]byte, error) {
	var (
		bpf []byte
		err error
	)

	// first check to see if the bpf object was defined at the commandline
	bpfFile, err = cmd.Flags().GetString("bpf")
	if err != nil {
		return nil, err
	}

	if bpfFile == "" {
		// not found on the command-line, now try environment
		bpfFile = os.Getenv("SWOLL_BPFOBJECT")
	}

	if bpfFile != "" {
		// attempt to read the bpf object file if defined
		bpf, err = ioutil.ReadFile(bpfFile)
		if err != nil && !os.IsNotExist(err) {
			// only error if the error is *NOT* of type "file not found"
			return nil, err
		}
	}

	if len(bpf) == 0 {
		// we've tried all sorts of ways to load this file, by default
		// it attempts to use the go-bindata generated asset resource.
		bpf = assets.LoadBPF()
	}

	return bpf, err
}
