package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/criticalstack/swoll/api/v1alpha1"
	"github.com/go-logr/logr"
	uuid "github.com/satori/go.uuid"
	v1jobs "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// TraceReconciler reconciles a Trace object
type TraceReconciler struct {
	client.Client
	Log       logr.Logger
	Image     string
	Endpoints []string
	scheme    *runtime.Scheme
	evrec     record.EventRecorder
}

// createJobResource creates the kubernetes Job resource which creates
// a container which runs the "syswall-kube-agent". This tiny service will look for
// containers running inside this namespace using a labelselector. When a
// container is found, it uses the swoll.Client api to create a job and
// stream it to stdout.
func (r *TraceReconciler) createJobResource(t *v1alpha1.Trace) (*v1jobs.Job, error) {
	if len(t.Spec.Syscalls) <= 0 {
		t.Spec.Syscalls = append(t.Spec.Syscalls, "sys_execve")
	}

	jobid := fmt.Sprintf("%s-%s", t.Name, uuid.NewV4().String()[:4])

	ret := &v1jobs.Job{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("sw-%s-", t.Name),
			Namespace:    t.Namespace,
		},
		Spec: v1jobs.JobSpec{
			Template: v1.PodTemplateSpec{
				Spec: v1.PodSpec{
					RestartPolicy: v1.RestartPolicyNever,
					Containers: []v1.Container{
						{
							Name:            fmt.Sprintf("sw-%s", t.Name),
							Image:           r.Image,
							ImagePullPolicy: v1.PullAlways,
							Args: []string{
								"client", "create",
								"--endpoints", "\"" + strings.Join(r.Endpoints, ",") + "\"",
								"--syscalls", strings.Join(t.Spec.Syscalls, ","),
								"--match-hosts", "\"" + strings.Join(t.Spec.HostSelector, ",") + "\"",
								"--label-selector", labels.Set(t.Spec.LabelSelector.MatchLabels).String(),
								"--field-selector", labels.Set(t.Spec.FieldSelector.MatchLabels).String(),
								"--namespace", t.Namespace,
								"--jobid", jobid,
								"--oneshot",
							},
						},
					},
				},
			},
		},
	}

	ret.Spec.Template.Labels = make(map[string]string)
	ret.Spec.Template.Labels["sw-job"] = t.Name

	if err := controllerutil.SetControllerReference(t, ret, r.scheme); err != nil {
		return nil, err
	}

	return ret, nil
}

// +kubebuilder:rbac:groups=tools.syswall.criticalstack.com,resources=traces,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=tools.syswall.criticalstack.com,resources=traces/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=batch,resources=jobs/status,verbs=get
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;watch;list

// Reconcile is the main controller loop which deals with messages from kube
// requesting for traces to be done. If everything goes well, when a new trace
// is created, a Kubernetes job is created which in turn runs a special `swoll
// client` command to start getting the actual trace data from the swoll probe
// endpoints.
//
// When a trace is deleted, this function will also make sure all resources that
// were created to facilitate the trace request are garbage collected.

func (r *TraceReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithName(req.NamespacedName.String())

	log.Info("Reconciling " + req.NamespacedName.String())

	t := &v1alpha1.Trace{}
	if err := r.Get(ctx, req.NamespacedName, t); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	finalizerName := "syswall.finalizer"

	if !t.ObjectMeta.DeletionTimestamp.IsZero() {
		if t.Status.JobID != "" {
			// Delete the job and any pods that were created.
			job := &v1jobs.Job{
				ObjectMeta: metav1.ObjectMeta{
					Name:      t.Status.JobID,
					Namespace: t.Namespace,
				},
			}

			log.Info("Deleting", "Job", job)

			err := r.Delete(ctx, job,
				// delete all pods the job created too.
				client.PropagationPolicy(metav1.DeletePropagationBackground))
			if err != nil {
				return ctrl.Result{}, nil
			}
		}

		controllerutil.RemoveFinalizer(t, finalizerName)

		if err := r.Update(ctx, t); err != nil {
			return ctrl.Result{}, err
		}

	}

	// this adds our finalizer if it's not already there.
	controllerutil.AddFinalizer(t, finalizerName)

	switch t.Status.State {
	case v1alpha1.TraceUnknown:
		t.Status.State = v1alpha1.TracePending

		log.Info("Setting", "state", t.Status.State)
		if err := r.Update(ctx, t); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{
			Requeue:      true,
			RequeueAfter: 5 * time.Second,
		}, nil

	case v1alpha1.TracePending:
		st := metav1.Now()

		spec, err := r.createJobResource(t)
		if err != nil {
			return ctrl.Result{}, err
		}

		if err := r.Create(ctx, spec); err != nil {
			return ctrl.Result{}, err
		}

		r.evrec.Eventf(t, v1.EventTypeNormal, "Created", "Created job %s", spec.Name)

		t.Status.State = v1alpha1.TraceRunning
		t.Status.JobID = spec.Name
		t.Status.StartTime = &st

		log.Info("Setting", "state", t.Status.State, "jobid", t.Status.JobID)
		if err := r.Update(ctx, t); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{
			Requeue:      true,
			RequeueAfter: t.Spec.Duration.Duration - 5*time.Second,
		}, nil
	case v1alpha1.TraceRunning:
		if time.Now().Before(t.Status.StartTime.Add(t.Spec.Duration.Duration)) {
			return ctrl.Result{
				Requeue:      true,
				RequeueAfter: 5 * time.Second,
			}, nil
		}

		t.Status.State = v1alpha1.TraceComplete
		et := metav1.Now()
		t.Status.CompletionTime = &et

		log.Info("Setting", "state", t.Status.State)
		if err := r.Update(ctx, t); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	default:
		return ctrl.Result{}, nil

	}

}

// SetupWithManager initializes the controller with the kube manager.
func (r *TraceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).For(&v1alpha1.Trace{}).Complete(r)
	if err != nil {
		return err
	}

	r.evrec = mgr.GetEventRecorderFor("trace-controller")
	r.scheme = mgr.GetScheme()

	return nil
}
