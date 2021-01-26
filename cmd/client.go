package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/criticalstack/swoll/api/v1alpha1"
	"github.com/criticalstack/swoll/pkg/client"
	color "github.com/fatih/color"
	uuid "github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/yaml"
)

var cmdClient = &cobra.Command{
	Use:   "client",
	Short: "swoll c&c client operations",
}

var cmdQuery = &cobra.Command{
	Use:   "query",
	Short: "query operations",
}

var cmdClientQueryCompleted = &cobra.Command{
	Use:   "completed",
	Short: "Get list of completed jobs on probes.",
	Run: func(cmd *cobra.Command, args []string) {
		runQuery(cmd, args, true)
	},
}

var cmdClientQueryRun = &cobra.Command{
	Use:   "running",
	Short: "Get list of currently running jobs on probes.",
	Run: func(cmd *cobra.Command, args []string) {
		runQuery(cmd, args, false)
	},
}

var cmdClientDelete = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a job from running probes",
	Run: func(cmd *cobra.Command, args []string) {
		endpoints, err := parseStaticEndpointsArg(cmd, args)
		if err != nil {
			log.Fatal(err)
		}

		jobid := args[0]
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		for _, ep := range endpoints {
			fmt.Printf("Deleting %s from %v... ", jobid, ep)

			if err := ep.DeleteTraceJob(ctx, jobid); err != nil {
				fmt.Printf("FAIL! %s\n", err.Error())
				os.Exit(1)
			}

			fmt.Println("Success!")
		}
	},
}

var cmdClientWatch = &cobra.Command{
	Use: "watch <id>",
	Run: func(cmd *cobra.Command, args []string) {
		endpoints, err := parseStaticEndpointsArg(cmd, args)
		if err != nil {
			log.Fatal(err)
		}

		jobid := args[0]
		if jobid == "" {
			log.Fatal("nil jobid")
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigChan := make(chan os.Signal)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		defer func() {
			close(sigChan)
		}()

		go watchJob(ctx, endpoints, jobid)

	Loop:
		for {
			<-sigChan
			break Loop
		}
	},
}

func watchJob(ctx context.Context, endpoints []*client.Endpoint, id string) {
	outChan := make(chan *client.StreamMessage)
	defer close(outChan)
	wg := sync.WaitGroup{}

	for _, ep := range endpoints {
		wg.Add(1)
		go func(ep *client.Endpoint) {
			defer wg.Done()

			if err := ep.ReadTraceJob(ctx, id, outChan); err != nil {
				log.Warn("Error reading: ", err)
			}

			<-ctx.Done()
		}(ep)
	}

Loop:
	for {
		select {
		case ev := <-outChan:
			fmt.Fprintf(os.Stdout, "%s", ev.Data.ColorString())
		case <-ctx.Done():
			break Loop
		}
	}

	wg.Wait()

}

var cmdClientCreate = &cobra.Command{
	Use: "create",
	Run: func(cmd *cobra.Command, args []string) {
		endpoints, err := parseStaticEndpointsArg(cmd, args)
		if err != nil {
			log.Fatal(err)
		}

		cfile, err := cmd.Flags().GetString("file")
		if err != nil {
			log.Fatal(err)
		}

		ns, err := cmd.Flags().GetString("namespace")
		if err != nil {
			log.Fatal(err)
		}

		if ns == "" {
			log.Fatal("no namespace specified")
		}

		scs, err := cmd.Flags().GetStringSlice("syscalls")
		if err != nil {
			log.Fatal(err)
		}

		labelset, err := cmd.Flags().GetString("label-selector")
		if err != nil {
			log.Fatal(err)
		}

		fieldset, err := cmd.Flags().GetString("field-selector")
		if err != nil {
			log.Fatal(err)
		}

		oneshot, err := cmd.Flags().GetBool("oneshot")
		if err != nil {
			log.Fatal(err)
		}

		jobid, err := cmd.Flags().GetString("jobid")
		if err != nil {
			log.Fatal(err)
		}

		matchhosts, err := cmd.Flags().GetStringSlice("match-hosts")
		if err != nil {
			log.Fatal(err)
		}

		out, err := cmd.Flags().GetString("output")
		if err != nil {
			log.Fatal(err)
		}

		traceSpec := v1alpha1.TraceSpec{}

		if cfile != "" {
			jsFile, err := ioutil.ReadFile(cfile)
			if err != nil {
				log.Fatal(err)
			}

			if err = yaml.Unmarshal(jsFile, &traceSpec); err != nil {
				log.Fatalf("failed to read trace specification: %v", err)
			}
		}

		if len(scs) > 0 {
			traceSpec.Syscalls = scs
		}

		if labelset != "" {
			tmpset, err := labels.ConvertSelectorToLabelsMap(labelset)
			if err != nil {
				log.Fatal(err)
			}

			traceSpec.LabelSelector.MatchLabels = tmpset
		}

		if fieldset != "" {
			tmpset, err := labels.ConvertSelectorToLabelsMap(fieldset)
			if err != nil {
				log.Fatal(err)
			}

			traceSpec.FieldSelector.MatchLabels = tmpset
		}

		if len(matchhosts) > 0 {
			traceSpec.HostSelector = matchhosts
		}

		if jobid == "" {
			// generate a unique ID which we can use to query all our running probes
			// with.
			jobid = uuid.New().String()
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		outChan := make(chan *client.StreamMessage)
		sigChan := make(chan os.Signal, 1)

		defer close(outChan)

		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		go func() {
			defer close(sigChan)
			<-sigChan
			cancel()
		}()

		var wg sync.WaitGroup

		for _, ep := range endpoints {
			trace, err := ep.CreateTrace(ctx, jobid, ns, &traceSpec)
			if err != nil {
				log.Fatal(err)
			}

			log.Debugf("Endpoint %s:%d created %s\n", ep.Hostname, ep.Port, trace.Status.JobID)

			// if oneshot is enabled we also start reading from the job, and
			// delete it once we are done.
			if oneshot {
				wg.Add(1)
				go func() {
					if err := ep.ReadTraceJob(ctx, trace.Status.JobID, outChan); err != nil {
						log.Warn("Error reading", err)
					}

					if err := ep.DeleteTraceJob(ctx, trace.Status.JobID); err != nil {
						log.Warn("Error deleting", err)
					}

					wg.Done()
				}()
			}
		}

		if oneshot {
		Loop:
			for {
				select {
				case ev := <-outChan:
					switch out {
					case "cli":
						fn := ev.Data.Argv
						args := fn.Arguments()

						green := color.New(color.FgGreen).SprintFunc()
						red := color.New(color.FgRed).SprintFunc()
						bold := color.New(color.Bold).SprintFunc()
						cyan := color.New(color.FgCyan).SprintFunc()
						bgblack := color.New(color.BgBlack).SprintFunc()
						white := color.New(color.FgWhite).SprintFunc()

						var errno string

						if ev.Data.Error == 0 {
							errno = bold(green("OK"))
						} else {
							errno = red(ev.Data.Error.String())
						}

						fmt.Printf("%35s: [%11s] (%11s) %s(",
							bold(green(ev.Data.Container.FQDN())),
							ev.Data.Comm, errno,
							bold(cyan(fn.CallName())))

						for x, arg := range args {
							fmt.Printf("(%s)%s=%v",
								arg.Type,
								bold(arg.Name),
								bgblack(white(arg.Value)))

							if x < len(args)-1 {
								fmt.Fprintf(os.Stdout, ", ")
							}
						}

						fmt.Printf(")\n")
					case "json":
						j, _ := json.Marshal(ev)
						fmt.Fprintf(os.Stdout, "%s\n", string(j))
					}

				case <-ctx.Done():
					break Loop
				}
			}

		}

		// notify all background tasks to stop and cleanup
		wg.Wait()

	},
}

// runQuery fetches either the list of running jobs, or the list of completed
// jobs from all endpoints
func runQuery(cmd *cobra.Command, args []string, completed bool) {
	endpoints, err := parseStaticEndpointsArg(cmd, args)
	if err != nil {
		log.Fatal(err)
	}

	for _, ep := range endpoints {
		var jobs []*v1alpha1.Trace
		var err error

		if completed {
			jobs, err = ep.CompletedJobs()
		} else {
			jobs, err = ep.RunningJobs()
		}
		if err != nil {
			fmt.Printf("endpoint=%s:%d error=%v", ep.Hostname, ep.Port, err)
			continue
		}

		js, err := json.MarshalIndent(jobs, "", " ")
		if err != nil {
			continue
		}

		log.Infof("endpoint=%s:%d\n%s\n", ep.Hostname, ep.Port, string(js))
	}
}

// parseStaticEndpointsArg attempts to parse the value of the common argument
// "endpoints" into an array of client.Endpoints. Returns nothing if the
// --endpoint flag was not passed.
func parseStaticEndpointsArg(cmd *cobra.Command, args []string) ([]*client.Endpoint, error) {
	staticEndpoints, err := cmd.Flags().GetStringSlice("endpoints")
	if err != nil {
		return nil, err
	}

	useTLS, err := cmd.Flags().GetBool("use-tls")
	if err != nil {
		return nil, err
	}

	ret := make([]*client.Endpoint, 0)

	for _, endpoint := range staticEndpoints {
		// parse host:port format.
		toks := strings.SplitN(endpoint, ":", 2)

		host := toks[0]
		port, err := strconv.Atoi(toks[1])
		if err != nil {
			return nil, err
		}

		ret = append(ret, client.NewEndpoint(host, port, useTLS))
	}

	return ret, nil
}

func init() {
	cmdClient.PersistentFlags().Bool("use-tls", false, "Use TLS")
	cmdClient.PersistentFlags().StringSliceP("endpoints", "e", nil, "Comma-separated list of endpoints")
	cmdClient.PersistentFlags().StringP("output", "o", "json", "output format")
	cmdClient.PersistentFlags().StringP("namespace", "n", "", "kube namespace")

	cmdClientCreate.Flags().StringP("file", "f", "", "filename that contains the configuration to apply")
	cmdClientCreate.Flags().StringP("jobid", "j", "", "give this job a non-random identifier")
	cmdClientCreate.Flags().StringP("label-selector", "l", "", "k8s label-selector for matching pods (will override the label-selector in the trace spec if -f is used)")
	cmdClientCreate.Flags().StringP("field-selector", "F", "", "k8s field-selector for matching pods (will override the field-selector in the trace spec if -f is used) ")
	cmdClientCreate.Flags().StringSliceP("syscalls", "s", nil, "comma-separated list of syscalls to trace (will override the syscalls in the trace spec if -f is used)")
	cmdClientCreate.Flags().BoolP("oneshot", "O", false, "create, watch, and delete the trace-job all in one swoop")
	cmdClientCreate.Flags().StringSliceP("match-hosts", "m", []string{}, "comma-separated list of specific container-names to match against (overrides Hostselector in the trace spec if -f is used)")

	cmdClient.AddCommand(cmdClientWatch, cmdClientDelete, cmdClientCreate, cmdQuery)
	cmdQuery.AddCommand(cmdClientQueryRun, cmdClientQueryCompleted)
	rootCmd.AddCommand(cmdClient)
}
