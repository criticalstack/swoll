package cmd

import (
	"fmt"
	"os"
	"runtime"

	log "github.com/sirupsen/logrus"

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
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			log.SetOutput(os.Stderr)

			logcall, _ := cmd.Flags().GetBool("log-callers")
			if logcall {
				log.SetReportCaller(logcall)

			}
			log.SetFormatter(&log.TextFormatter{
				ForceColors:   true,
				FullTimestamp: true,
				PadLevelText:  true,
				CallerPrettyfier: func(f *runtime.Frame) (string, string) {
					return f.Function + ": ", fmt.Sprintf("%s:%d", f.File, f.Line)
				},
			})

			switch cmd.Flag("log").Value.String() {
			case "debug":
				log.SetLevel(log.DebugLevel)
			case "trace":
				log.SetLevel(log.TraceLevel)
			case "info":
				log.SetLevel(log.InfoLevel)
			case "warn":
				log.SetLevel(log.WarnLevel)
			case "error":
				log.SetLevel(log.ErrorLevel)
			case "fatal":
				log.SetLevel(log.FatalLevel)
			case "panic":
				log.SetLevel(log.PanicLevel)
			default:
				return fmt.Errorf("unrecognized log output level")
			}

			return nil
		},
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

	rootCmd.PersistentFlags().StringP("cri", "r", "", "path to the local CRI unix socket")
	rootCmd.PersistentFlags().StringP("kubeconfig", "k", "", "path to the local k8s config instance (defaults to incluster config)")
	rootCmd.PersistentFlags().StringP("altroot", "A", "", "alternate root CWD")
	rootCmd.PersistentFlags().StringP("bpf", "b", "", "alternative external bpf object")
	rootCmd.PersistentFlags().BoolP("version", "V", false, "show version information")
	rootCmd.PersistentFlags().String("nsproxy-offset", "", "Offset (in hex) of task_struct->nsproxy")
	rootCmd.PersistentFlags().String("pidns-offset", "", "Offset (in hex) of pid_namespace->ns")
	rootCmd.PersistentFlags().Bool("no-detect-offsets", false, "Do not automatically determine task_struct member offsets (uses default offsets)")
	rootCmd.PersistentFlags().String("log", "info", "log level")
	rootCmd.PersistentFlags().Bool("log-callers", false, "log callers")
}
