/*
Copyright 2020 Critical Stack.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type TraceState string

const (
	TraceUnknown  TraceState = ""
	TracePending  TraceState = "Pending"
	TraceRunning  TraceState = "Running"
	TraceComplete TraceState = "Complete"
	TraceFailed   TraceState = "Failed"
)

// TraceSpec defines the desired state of Trace
type TraceSpec struct {
	LabelSelector metav1.LabelSelector `json:"labelSelector,omitempty" yaml:"labelSelector,omitempty"`
	FieldSelector metav1.LabelSelector `json:"fieldSelector,omitempty" yaml:"fieldSelector,omitempty"`
	HostSelector  []string             `json:"hostSelector,omitempty" yaml:"hostSelector,omitempty"`
	Syscalls      []string             `json:"syscalls,omitempty" yaml:"syscalls,omitempty"`
	Duration      metav1.Duration      `json:"duration,omitempty" yaml:"duration,omitempty"`
	SampleRate    int                  `json:"sampleRate,omitempty" yaml:"sampleRate,omitempty"`
}

// TraceStatus defines the observed state of Trace
type TraceStatus struct {
	State          TraceState   `json:"state,omitempty" yaml:"state,omitempty"`
	StartTime      *metav1.Time `json:"startTime,omitempty" yaml:"startTime,omitempty"`
	CompletionTime *metav1.Time `json:"completionTime,omitempty" yaml:"completeTime,omitempty"`
	JobID          string       `json:"job,omitempty" yaml:"job,omitempty"`
}

// +kubebuilder:object:root=true

// Trace is the Schema for the traces API
// +kubebuilder:printcolumn:name="Name",type=string,JSONPath=`.metadata.name`
// +kubebuilder:printcolumn:name="Job",type=string,JSONPath=`.status.job`
// +kubebuilder:printcolumn:name="Syscalls",type=string,JSONPath=`.spec.syscalls`
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`
type Trace struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TraceSpec   `json:"spec,omitempty"`
	Status TraceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TraceList contains a list of Trace
type TraceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Trace `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Trace{}, &TraceList{})
}
