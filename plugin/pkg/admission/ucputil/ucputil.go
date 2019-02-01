package ucputil

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/kubernetes/pkg/apis/apps"
	"k8s.io/kubernetes/pkg/apis/batch"
	api "k8s.io/kubernetes/pkg/apis/core"
)

// GetPodSpecFromObject returns a pointer to the PodSpec in an object that
// contains one or nil.
func GetPodSpecFromObject(runtimeObject runtime.Object) *api.PodSpec {
	switch object := runtimeObject.(type) {
	case *api.Pod:
		return &object.Spec
	case *api.PodTemplate:
		return &object.Template.Spec
	case *api.ReplicationController:
		return &object.Spec.Template.Spec
	case *apps.StatefulSet:
		return &object.Spec.Template.Spec
	case *batch.CronJob:
		return &object.Spec.JobTemplate.Spec.Template.Spec
	case *batch.Job:
		return &object.Spec.Template.Spec
	case *apps.DaemonSet:
		return &object.Spec.Template.Spec
	case *apps.Deployment:
		return &object.Spec.Template.Spec
	case *apps.ReplicaSet:
		return &object.Spec.Template.Spec
	default:
		return nil
	}
}
