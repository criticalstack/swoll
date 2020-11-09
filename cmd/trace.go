package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/criticalstack/swoll/api/v1alpha1"
	"github.com/criticalstack/swoll/internal/pkg/assets"
	"github.com/criticalstack/swoll/internal/pkg/hub"
	"github.com/criticalstack/swoll/pkg/event"
	"github.com/criticalstack/swoll/pkg/event/call"
	"github.com/criticalstack/swoll/pkg/event/reader"
	"github.com/criticalstack/swoll/pkg/kernel"
	"github.com/criticalstack/swoll/pkg/kernel/filter"
	"github.com/criticalstack/swoll/pkg/topology"
	color "github.com/fatih/color"
	uuid "github.com/google/uuid"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
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
		bpf, err = assets.Asset("internal/bpf/probe.o")
		if err != nil {
			return nil, err
		}
	}

	return bpf, err
}

var cmdTrace = &cobra.Command{
	Use:   "trace",
	Short: "Kubernetes-Aware strace(1)",
	Run: func(cmd *cobra.Command, args []string) {
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

		log.Println("Checking install...")
		if err := runSelfTest(true); err != nil {
			log.Fatal(err)
		}

		namespace, _ := cmd.Flags().GetString("namespace")
		crisock, _ := cmd.Flags().GetString("cri")
		if crisock == "" {
			crisock = os.Getenv("SWOLL_CRISOCKET")
		}

		kconfig, _ := cmd.Flags().GetString("kubeconfig")
		if kconfig == "" {
			kconfig = os.Getenv("SWOLL_KUBECONFIG")
		}

		altroot, _ := cmd.Flags().GetString("altroot")
		if altroot == "" {
			altroot = os.Getenv("SWOLL_ALTROOT")
		}

		out, _ := cmd.Flags().GetString("output")

		scalls, _ := cmd.Flags().GetStringSlice("syscalls")
		if len(scalls) == 0 {
			scalls = []string{"execve"}
		}

		set, err := labels.ConvertSelectorToLabelsMap(strings.Join(args, " "))
		if err != nil {
			log.Fatal(err)
		}

		noContainers, err := cmd.Flags().GetBool("no-containers")
		if err != nil {
			log.Fatal(err)
		}

		fieldSelector, err := cmd.Flags().GetString("field-selector")
		if err != nil {
			log.Fatal(err)
		}

		var fields labels.Set

		if fieldSelector != "" {
			fields, err = labels.ConvertSelectorToLabelsMap(fieldSelector)
			if err != nil {
				log.Fatal(err)
			}
		}

		trace := &v1alpha1.Trace{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
			},
			Spec: v1alpha1.TraceSpec{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: set,
				},
				FieldSelector: metav1.LabelSelector{
					MatchLabels: fields,
				},
				Syscalls: scalls,
			},
			Status: v1alpha1.TraceStatus{
				JobID: uuid.New().String()[:8],
			},
		}

		bpf, err := loadBPFargs(cmd, args)
		if err != nil {
			log.Fatal(err)
		}

		showMsg := func(name string, ev *event.TraceEvent) {
			switch out {
			case "cli":
				green := color.New(color.FgGreen).SprintFunc()
				red := color.New(color.FgRed).SprintFunc()
				cyan := color.New(color.FgCyan).SprintFunc()
				bold := color.New(color.Bold).SprintFunc()
				bgblack := color.New(color.BgBlack).SprintFunc()
				white := color.New(color.FgWhite).SprintFunc()

				fn := ev.Argv.(call.Function)
				args := fn.Arguments()

				var errno string

				if ev.Error == 0 {
					errno = green("OK")
				} else {
					errno = red(ev.Error.String())
				}

				if !noContainers {
					fmt.Printf("%35s: [%9s] (%11s) %s(", bold(green(ev.Container.FQDN())), ev.Comm, errno, bold(cyan(fn.CallName())))
				} else {
					fmt.Printf("[%15s/%-8v] (%11s) %s(", ev.Comm, bold(ev.Pid), errno, bold(cyan(fn.CallName())))
				}

				for x, arg := range args {
					fmt.Printf("(%s)%s=%v", arg.Type, bold(arg.Name), bgblack(white(arg.Value)))

					if x < len(args)-1 {
						fmt.Print(", ")
					}
				}

				fmt.Println(")")
			case "json":
				j, _ := json.MarshalIndent(ev, "", " ")

				fmt.Println(string(j))
			}
		}

		if !noContainers {
			// process with k8s support using a Kubernetes Observer for the
			// Topology API:
			topo, err := topology.NewKubernetes(
				topology.WithKubernetesCRI(crisock),
				topology.WithKubernetesConfig(kconfig),
				topology.WithKubernetesNamespace(namespace),
				// we use an empty label match here since we pretty dumb and only
				// use this as our resolver context for incoming messages
				topology.WithKubernetesLabelSelector("swoll!=false"),
				topology.WithKubernetesProcRoot(altroot))
			if err != nil {
				log.Fatal(err)
			}

			hub, err := hub.NewHub(&hub.Config{
				AltRoot:      altroot,
				BPFObject:    bpf,
				CRIEndpoint:  crisock,
				K8SEndpoint:  kconfig,
				K8SNamespace: namespace}, topo)
			if err != nil {
				log.Fatal(err)
			}

			if err := SetOffsetsFromArgs(hub.Probe(), cmd, args); err != nil {
				log.Fatal(err)
			}

			go func() {
				if err := hub.Run(context.Background()); err != nil {
					log.Fatal(err)
				}
			}()

			go func() {
				if err := hub.RunTrace(trace); err != nil {
					log.Fatal(err)
				}
			}()

			hub.AttachTrace(trace, showMsg)
		} else {
			// run "raw" (without k8s support)
			probe, err := kernel.NewProbe(bytes.NewReader(bpf), nil)
			if err != nil {
				log.Fatal(err)
			}

			if err := probe.InitProbe(); err != nil {
				log.Fatal(err)
			}

			if err := SetOffsetsFromArgs(probe, cmd, args); err != nil {
				log.Fatal(err)
			}

			fltr, err := filter.NewFilter(probe.Module())
			if err != nil {
				log.Fatal(err)
			}

			if err := fltr.FilterSelf(); err != nil {
				log.Fatal(err)
			}

			for _, scall := range scalls {
				if err := fltr.AddSyscall(scall, -1); err != nil {
					log.Fatal(err)
				}
			}

			evreader := reader.NewEventReader(probe)

			go func() {
				if err := evreader.Run(context.Background()); err != nil {
					log.Fatal(err)
				}
			}()

			go func() {
				for {
					msg := <-evreader.Read()
					ev := new(event.TraceEvent)

					if _, err := ev.Ingest(msg); err != nil {
						log.Fatal(err)
					}

					showMsg("", ev)
				}
			}()

		}

		select {}
	},
}

func init() {
	rootCmd.AddCommand(cmdTrace)
	cmdTrace.Flags().StringSliceP("syscalls", "s", nil, "comma-separated list of syscalls to trace")
	cmdTrace.Flags().StringP("namespace", "n", "", "namespace to read from")
	cmdTrace.Flags().StringP("output", "o", "cli", "output format")
	cmdTrace.Flags().StringP("field-selector", "f", "", "field selector")
	cmdTrace.Flags().Bool("no-containers", false, "disable container/k8s processing")
}
