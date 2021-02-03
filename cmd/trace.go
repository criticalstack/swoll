package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/criticalstack/swoll/api/v1alpha1"
	"github.com/criticalstack/swoll/pkg/event"
	"github.com/criticalstack/swoll/pkg/event/reader"
	"github.com/criticalstack/swoll/pkg/kernel"
	"github.com/criticalstack/swoll/pkg/topology"
	color "github.com/fatih/color"
	uuid "github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

var cmdTrace = &cobra.Command{
	Use:   "trace",
	Short: "Kubernetes-Aware strace(1)",
	Run: func(cmd *cobra.Command, args []string) {
		log.Info("Checking install...")
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
				bgblack := color.New(color.BgBlack).SprintFunc()
				white := color.New(color.FgWhite).SprintFunc()

				fn := ev.Argv
				args := fn.Arguments()

				var errno string

				if ev.Error == 0 {
					errno = green("OK")
				} else {
					errno = red(ev.Error.String())
				}

				if !noContainers {
					fmt.Printf("%35s: [%9s] (%11s) %s(", green(ev.Container.FQDN()), ev.Comm, errno, cyan(fn.CallName()))
				} else {
					fmt.Printf("[%15s/%-8v] (%11s) %s(", ev.Comm, ev.Pid, errno, cyan(fn.CallName()))
				}

				for x, arg := range args {
					fmt.Printf("(%s)%s=%v", arg.Type, arg.Name, bgblack(white(arg.Value)))

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

			hub, err := topology.NewHub(bytes.NewReader(bpf), topo)
			if err != nil {
				log.Fatal(err)
			}

			if err := SetOffsetsFromArgs(hub.Probe(), cmd, args); err != nil {
				log.Fatal(err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go func() {
				if err := hub.Run(ctx); err != nil {
					log.Fatal(err)
				}
			}()

			go func() {
				if err := hub.RunTrace(ctx, trace); err != nil {
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

			nfilter := kernel.NewFilter(probe.Module())

			for _, scall := range scalls {
				if err := nfilter.AddRule(
					kernel.NewFilterRuleN(
						kernel.FilterRuleSetModeSyscall(),
						kernel.FilterRuleSetSyscall(scall),
						kernel.FilterRuleSetActionAllow())); err != nil {
					log.Fatal(err)
				}
			}

			if err := nfilter.Enable(); err != nil {
				log.Fatal(err)
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
