package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/criticalstack/swoll/pkg/kernel/ross"
	"github.com/spf13/cobra"
)

var (
	gitCommit string
	buildTime string
)

var (
	bpfFile string

	rootCmd = &cobra.Command{
		Use:   "swoll",
		Short: "The kubernetes-aware eBPF tracing and metrics thingy.",
		Long: ` _     _ || :) 
_>\/\/(_)|| critical-stack(c)
` + ross.Paint(),
		Run: func(cmd *cobra.Command, args []string) {
			ver, err := cmd.Flags().GetBool("version")
			if err != nil {
				log.Fatal(err)
			}

			if ver {
				log.Printf("Version: %s (compiled on: %s)\n", gitCommit, buildTime)
			}
		},
	}
)

// Execute ...
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	rootCmd.PersistentFlags().StringP("cri", "r", "", "path to the local CRI unix socket")
	rootCmd.PersistentFlags().StringP("kubeconfig", "k", "", "path to the local k8s config instance (defaults to incluster config)")
	rootCmd.PersistentFlags().StringP("altroot", "A", "", "alternate root CWD")
	rootCmd.PersistentFlags().StringP("bpf", "b", "", "alternative external bpf object")
	rootCmd.PersistentFlags().BoolP("version", "V", false, "show version information")
	rootCmd.PersistentFlags().String("nsproxy-offset", "", "Offset (in hex) of task_struct->nsproxy")
	rootCmd.PersistentFlags().String("pidns-offset", "", "Offset (in hex) of pid_namespace->ns")
	rootCmd.PersistentFlags().Bool("detect-offsets", false, "Automatically determine task_struct member offsets")
}
