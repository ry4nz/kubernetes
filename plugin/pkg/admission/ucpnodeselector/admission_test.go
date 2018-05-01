package ucpnodeselector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/kubernetes/pkg/apis/apps"
	"k8s.io/kubernetes/pkg/apis/batch"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/plugin/pkg/admission/ucputil"
)

// TestAdmissionKubernetesTolerations verifies all create and update requests
// make appropriate changes to PodSpec tolerations.
func TestAdmissionKubernetesTolerations(t *testing.T) {
	require := require.New(t)

	ts := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			switch req.URL.Query().Get("user") {
			case "":
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("no user query var"))
			case "allow-schedule":
				w.WriteHeader(200)
				w.Write([]byte("true"))
			default:
				w.WriteHeader(200)
				w.Write([]byte("false"))
			}
		}))

	handler := &ucpNodeSelector{
		Handler:      admission.NewHandler(admission.Create, admission.Update),
		ucpLocation:  ts.URL,
		systemPrefix: "systemprefix:",
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:     nil,
				MaxIdleConnsPerHost: 5,
			},
		},
	}

	sameKeyAsOrchestratorToleration := api.Toleration{
		Key: orchestratorToleration.Key,
	}
	sameKeyAsSystemToleration := api.Toleration{
		Key: systemToleration.Key,
	}
	userToleration := api.Toleration{
		Key: "foo",
	}

	cases := []struct {
		namespace           string
		user                string
		initialTolerations  []api.Toleration
		expectedTolerations []api.Toleration
	}{
		{"kube-system", "system", []api.Toleration{orchestratorToleration, sameKeyAsOrchestratorToleration, userToleration}, []api.Toleration{orchestratorToleration, systemToleration, userToleration}},
		{"kube-system", "system", []api.Toleration{orchestratorToleration}, []api.Toleration{orchestratorToleration, systemToleration}},
		{"kube-system", "system", []api.Toleration{sameKeyAsSystemToleration, userToleration}, []api.Toleration{orchestratorToleration, systemToleration, userToleration}},
		{"other-namespace", "allow-schedule", []api.Toleration{orchestratorToleration, sameKeyAsOrchestratorToleration, userToleration}, []api.Toleration{userToleration, systemToleration}},
		{"other-namespace", "disallow-schedule", []api.Toleration{orchestratorToleration, sameKeyAsOrchestratorToleration, userToleration}, []api.Toleration{userToleration}},
	}

	for _, c := range cases {
		podSpec := api.PodSpec{Tolerations: c.initialTolerations}
		podTemplateSpec := api.PodTemplateSpec{Spec: podSpec}
		jobSpec := batch.JobSpec{Template: podTemplateSpec}

		objects := []runtime.Object{
			&api.Pod{Spec: podSpec},
			&api.PodTemplate{Template: podTemplateSpec},
			&api.ReplicationController{Spec: api.ReplicationControllerSpec{Template: &podTemplateSpec}},
			&apps.StatefulSet{Spec: apps.StatefulSetSpec{Template: podTemplateSpec}},
			&batch.CronJob{Spec: batch.CronJobSpec{JobTemplate: batch.JobTemplateSpec{Spec: jobSpec}}},
			&batch.Job{Spec: jobSpec},
			&extensions.DaemonSet{Spec: extensions.DaemonSetSpec{Template: podTemplateSpec}},
			&extensions.Deployment{Spec: extensions.DeploymentSpec{Template: podTemplateSpec}},
			&extensions.ReplicaSet{Spec: extensions.ReplicaSetSpec{Template: podTemplateSpec}},
		}
		for _, operation := range []admission.Operation{admission.Create, admission.Update} {
			for _, object := range objects {
				o := object.DeepCopyObject()
				kind := schema.GroupVersionKind{}
				resource := schema.GroupVersionResource{}
				user := &user.DefaultInfo{Name: c.user}
				err := handler.Admit(admission.NewAttributesRecord(o, nil, kind, c.namespace, "name", resource, "", operation, user))
				require.NoError(err, "Object type: %T\n", o)

				expected := c.expectedTolerations
				if _, ok := o.(*batch.Job); ok && operation == admission.Update {
					expected = c.initialTolerations
				}
				actual := ucputil.GetPodSpecFromObject(o).Tolerations
				require.Subset(expected, actual, "Namespace %s, operation %s, object %T", c.namespace, operation, object)
				require.Subset(actual, expected, "Namespace %s, operation %s, object %T", c.namespace, operation, object)
			}
		}
	}
}
