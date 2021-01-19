package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/criticalstack/swoll/api/v1alpha1"
	"github.com/criticalstack/swoll/internal/pkg/controller"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	kclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	// +kubebuilder:scaffold:imports
)

const (
	defaultImageName = "cinderegg:5000/swoll:latest"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

var cmdController = &cobra.Command{
	Use:   "controller",
	Short: "start the swoll k8s CRD controller",
	Run: func(cmd *cobra.Command, args []string) {
		var config *kclient.Config
		var err error

		kubeconfig, err := cmd.Flags().GetString("kubeconfig")
		if err != nil {
			log.Fatal(err)
		}

		if kubeconfig == "" {
			log.Info("Using in cluster configuration")
			config, err = kclient.InClusterConfig()
		} else {
			log.Info("Using out of cluster configuration")
			config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		}
		if err != nil {
			log.Fatal(err)
		}

		electionOn, err := cmd.Flags().GetBool("enable-leader-election")
		if err != nil {
			log.Fatal(err)
		}

		client, err := kubernetes.NewForConfig(config)
		if err != nil {
			log.Fatal(err)
		}

		metricsAddr, err := cmd.Flags().GetString("metrics-addr")
		if err != nil {
			log.Fatal(err)
		}

		image, err := cmd.Flags().GetString("image")
		if err != nil {
			log.Fatal(err)
		}

		endpoints, err := cmd.Flags().GetStringSlice("endpoints")
		if err != nil {
			log.Fatal(err)
		}

		ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

		mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
			Scheme:             scheme,
			MetricsBindAddress: metricsAddr,
			Port:               9443,
			LeaderElection:     electionOn,
			LeaderElectionID:   "d4e4c6da.swoll.criticalstack.com",
		})
		if err != nil {
			setupLog.Error(err, "unable to start manager")
			os.Exit(1)
		}

		// XXX OK this is stupid until we can find a better way to "discover"
		// what probes are running where. In this case, we just *ASSUME* that
		// the probe is running on each node, and its port is 9095.
		if len(endpoints) == 0 {
			nodes, err := client.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
			if err != nil {
				log.Fatal(err)
			}

			for i := 0; i < len(nodes.Items); i++ {
				nodeip := nodes.Items[i].Status.Addresses
				endpoints = append(endpoints, fmt.Sprintf("%s:9095", nodeip[0].Address))
			}
		}

		if err = (&controller.TraceReconciler{
			Client:    mgr.GetClient(),
			Image:     image,
			Endpoints: endpoints,
			Log:       ctrl.Log.WithName("controllers").WithName("Trace"),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "Trace")
			os.Exit(1)
		}
		// +kubebuilder:scaffold:builder
		setupLog.Info("starting manager")
		if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
			setupLog.Error(err, "problem running manager")
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(cmdController)

	cmdController.Flags().StringP("kubeconfig", "k", os.Getenv("KUBECONFIG"), "kube config file")
	cmdController.Flags().StringP("metrics-addr", "m", ":8080", "The address the metric endpoint binds to.")
	cmdController.Flags().StringP("image", "i", defaultImageName, "swoll docker-image path")
	cmdController.Flags().StringSliceP("endpoints", "e", []string{}, "comma-separated list of probe endpoints")
	cmdController.Flags().Bool("enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")

	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		log.Fatal(err)
	}

	if err := v1alpha1.AddToScheme(scheme); err != nil {
		log.Fatal(err)
	}
	// +kubebuilder:scaffold:scheme

}
