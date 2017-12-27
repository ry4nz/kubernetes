package ucputil

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/apps"
	"k8s.io/kubernetes/pkg/apis/batch"
	"k8s.io/kubernetes/pkg/apis/extensions"
)

// TestGetPodSpecFromObject ensures that GetPodSpecFromObject returns non-nil
// for objects that contain a PodSpec.
func TestGetPodSpecFromObject(t *testing.T) {
	objects := []runtime.Object{
		&api.Pod{},
		&api.PodTemplate{},
		&api.ReplicationController{Spec: api.ReplicationControllerSpec{Template: &api.PodTemplateSpec{}}},
		&apps.StatefulSet{},
		&batch.CronJob{},
		&batch.Job{},
		&extensions.DaemonSet{},
		&extensions.Deployment{},
		&extensions.ReplicaSet{},
	}
	for _, o := range objects {
		assert.NotNil(t, GetPodSpecFromObject(o), "Object type: %T\n", o)
	}
}
