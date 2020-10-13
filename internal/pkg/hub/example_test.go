package hub_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/criticalstack/swoll/api/v1alpha1"
	"github.com/criticalstack/swoll/internal/pkg/hub"
	"github.com/criticalstack/swoll/pkg/event"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ExampleTrace() {
	t1 := &v1alpha1.Trace{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "syswall",
		},
		Spec: v1alpha1.TraceSpec{
			LabelSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "nginx-with-writer"},
			},
			Syscalls: []string{"execve"},
		},
		Status: v1alpha1.TraceStatus{
			JobID: "test-tracer-a",
		},
	}

	t2 := &v1alpha1.Trace{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "syswall",
		},
		Spec: v1alpha1.TraceSpec{
			LabelSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "nginx-with-writer"},
			},
			Syscalls: []string{"openat", "execve"},
		},
		Status: v1alpha1.TraceStatus{
			JobID: "test-tracer-b",
		},
	}

	t3 := &v1alpha1.Trace{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "syswall",
		},
		Spec: v1alpha1.TraceSpec{
			LabelSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"component": "grafana"},
			},
			Syscalls: []string{"stat", "access", "accept", "accept4", "listen", "socket"},
		},
		Status: v1alpha1.TraceStatus{
			JobID: "test-tracer-c",
		},
	}

	printEvent := func(name string, ev *event.TraceEvent) {
		fmt.Printf("<%s> \033[1m%s:\033[0m [\033[4m%s\033[0m] %s err=%s ses=%v\n", name,
			ev.Container.FQDN(), ev.Comm, ev.Argv, ev.Error.ColorString(), ev.Sid)
	}

	hub, err := hub.NewHub(&hub.Config{
		AltRoot:     os.Getenv("ALT_ROOT"),
		BPFObject:   []byte(os.Getenv("BPF_OBJECT")),
		CRIEndpoint: os.Getenv("CRI_ENDPOINT"),
		K8SEndpoint: os.Getenv("K8S_ENDPOINT"),
	})
	if err != nil {
		log.Fatal(err)
	}

	//nolint:errcheck
	go hub.Run(context.TODO())
	//nolint:errcheck
	go hub.RunTrace(t1)
	//nolint:errcheck
	go hub.RunTrace(t2)
	//nolint:errcheck
	go hub.RunTrace(t3)

	hub.AttachTrace(t1, printEvent)
	hub.AttachTrace(t2, printEvent)
	hub.AttachTrace(t3, printEvent)

	i := 0
	for {
		time.Sleep(time.Second * 1)
		if i++; i > 3 {
			break
		}
	}

	//nolint:errcheck
	hub.DeleteTrace(t1)
	//nolint:errcheck
	hub.DeleteTrace(t2)
	//nolint:errcheck
	hub.DeleteTrace(t3)
}
