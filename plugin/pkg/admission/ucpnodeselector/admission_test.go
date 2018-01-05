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
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/apps"
	"k8s.io/kubernetes/pkg/apis/batch"
	"k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/plugin/pkg/admission/ucputil"
)

// TestAdmissionKubernetesTolerations verifies all create and update requests
// make appropriate changes to PodSpec tolerations.
func TestAdmissionKubernetesTolerations(t *testing.T) {
	require := require.New(t)

	ts := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Query().Get("user") == "" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("no user query var"))
			}
			w.WriteHeader(200)
			w.Write([]byte("true"))
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

	systemToleration := api.Toleration{
		Key:      "com.docker.ucp.orchestrator.kubernetes",
		Operator: api.TolerationOpExists,
	}
	sameKeyAsSystemToleration := api.Toleration{
		Key: "com.docker.ucp.orchestrator.kubernetes",
	}
	userToleration := api.Toleration{
		Key: "foo",
	}

	initialTolerations := []api.Toleration{systemToleration, sameKeyAsSystemToleration, userToleration}
	expectedTolerations := map[string][]api.Toleration{
		"kube-system":     {userToleration, systemToleration},
		"other-namespace": {userToleration},
	}

	podSpec := api.PodSpec{Tolerations: initialTolerations}
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

	for _, namespace := range []string{"kube-system", "other-namespace"} {
		for _, operation := range []admission.Operation{admission.Create, admission.Update} {
			for _, object := range objects {
				o := object.DeepCopyObject()
				kind := schema.GroupVersionKind{}
				resource := schema.GroupVersionResource{}
				user := &user.DefaultInfo{Name: "testuser"}
				err := handler.Admit(admission.NewAttributesRecord(o, nil, kind, namespace, "name", resource, "", operation, user))
				require.NoError(err, "Object type: %T\n", o)

				expected := expectedTolerations[namespace]
				if _, ok := o.(*batch.Job); ok && operation == admission.Update {
					expected = initialTolerations
				}
				actual := ucputil.GetPodSpecFromObject(o).Tolerations
				require.Subset(expected, actual, "Namespace %s, operation %s, object %T", namespace, operation, object)
				require.Subset(actual, expected, "Namespace %s, operation %s, object %T", namespace, operation, object)
			}
		}
	}
}

// TestAdmissionManagerScheduling verifies that we add node affinity
// requirements when users cannot schedule on manager nodes.
func TestAdmissionManagerScheduling(t *testing.T) {
	require := require.New(t)

	var statusCode int
	var output string

	ts := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Query().Get("user") == "" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("no user query var"))
			}
			w.WriteHeader(statusCode)
			w.Write([]byte(output))
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

	// If the managerscheduling endpoint returns true, we should not add
	// a node affinity.
	pod := api.Pod{
		Spec: api.PodSpec{
			Containers: []api.Container{{
				Image: "busybox",
			}},
		},
	}
	namespace := "testnamespace"
	statusCode = 200
	output = "true"
	err := handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "testuser"}))
	require.NoError(err)
	require.Nil(pod.Spec.Affinity)

	// If the managerscheduling endpoint returns false, we should add
	// an anti-manager node affinity.
	pod = api.Pod{
		Spec: api.PodSpec{
			Containers: []api.Container{{
				Image: "busybox",
			}},
		},
	}
	namespace = "testnamespace"
	statusCode = 200
	output = "false"
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "testuser"}))
	require.NoError(err)
	matchExpression := pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchExpressions[0]
	require.Equal("com.docker.ucp.collection.system", matchExpression.Key)
	require.Equal(api.NodeSelectorOpNotIn, matchExpression.Operator)
	require.Equal("true", matchExpression.Values[0])

	// If the managerscheduling endpoint returns an error, we should return
	// an error.
	pod = api.Pod{
		Spec: api.PodSpec{
			Containers: []api.Container{{
				Image: "busybox",
			}},
		},
	}
	namespace = "testnamespace"
	statusCode = 500
	output = "some error"
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "testuser"}))
	require.Error(err)
	require.Contains(err.Error(), "unable to lookup manager scheduling settings")
	require.Contains(err.Error(), "some error")
}

// TestAdmissionManagerSchedulingForDeployment verifies that we add node
// affinity requirements on deployments.
func TestAdmissionManagerSchedulingForDeployment(t *testing.T) {
	require := require.New(t)

	var statusCode int
	var output string

	ts := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Query().Get("user") == "" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("no user query var"))
			}
			w.WriteHeader(statusCode)
			w.Write([]byte(output))
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

	deployment := extensions.Deployment{
		Spec: extensions.DeploymentSpec{
			Template: api.PodTemplateSpec{
				Spec: api.PodSpec{
					Containers: []api.Container{{
						Image: "busybox",
					}},
				},
			},
		},
	}
	namespace := "testnamespace"
	statusCode = 200
	output = "false"
	err := handler.Admit(admission.NewAttributesRecord(&deployment, nil, api.Kind("Deployment").WithVersion("version"), namespace, "testpod", api.Resource("deployments").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "testuser"}))
	require.NoError(err)
	matchExpression := deployment.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchExpressions[0]
	require.Equal("com.docker.ucp.collection.system", matchExpression.Key)
	require.Equal(api.NodeSelectorOpNotIn, matchExpression.Operator)
	require.Equal("true", matchExpression.Values[0])

	// Deployments should get updated in Update calls, unlike pods.
	deployment = extensions.Deployment{
		Spec: extensions.DeploymentSpec{
			Template: api.PodTemplateSpec{
				Spec: api.PodSpec{
					Containers: []api.Container{{
						Image: "busybox",
					}},
				},
			},
		},
	}
	namespace = "testnamespace"
	statusCode = 200
	output = "false"
	err = handler.Admit(admission.NewAttributesRecord(&deployment, nil, api.Kind("Deployment").WithVersion("version"), namespace, "testpod", api.Resource("deployments").WithVersion("version"), "", admission.Update, &user.DefaultInfo{Name: "testuser"}))
	require.NoError(err)
	matchExpression = deployment.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchExpressions[0]
	require.Equal("com.docker.ucp.collection.system", matchExpression.Key)
	require.Equal(api.NodeSelectorOpNotIn, matchExpression.Operator)
	require.Equal("true", matchExpression.Values[0])

}
