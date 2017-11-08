package ucpnodeselector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
)

type response struct {
	statuscode int
	image      string
}

// TestAdmissionKubernetesSelector verifies all create requests for pods get a
// kubernetes=true node selector
func TestAdmissionKubernetesSelector(t *testing.T) {
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

	// Regular pods should get the kubernetes=true node selector added.
	pod := api.Pod{
		Spec: api.PodSpec{
			NodeSelector: map[string]string{
				"foo": "bar",
			},
			Containers: []api.Container{{
				Image: "busybox",
			}},
		},
	}
	namespace := "testnamespace"
	err := handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "testuser"}))
	require.NoError(err)
	require.Equal("bar", pod.Spec.NodeSelector["foo"])
	require.Equal("true", pod.Spec.NodeSelector["com.docker.ucp.orchestrator.kubernetes"])

	// If a pod already has a kubernetes= node selector, it should get
	// overridden.
	pod = api.Pod{
		Spec: api.PodSpec{
			NodeSelector: map[string]string{
				"foo": "bar",
				"com.docker.ucp.orchestrator.kubernetes": "baz",
			},
			Containers: []api.Container{{
				Image: "busybox",
			}},
		},
	}
	namespace = "testnamespace"
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "testuser"}))
	require.NoError(err)
	require.Equal("bar", pod.Spec.NodeSelector["foo"])
	require.Equal("true", pod.Spec.NodeSelector["com.docker.ucp.orchestrator.kubernetes"])

	// Pods in the kube-system namespace should not have their node
	// selectors modified.
	pod = api.Pod{
		Spec: api.PodSpec{
			NodeSelector: map[string]string{
				"foo": "bar",
			},
			Containers: []api.Container{{
				Image: "busybox",
			}},
		},
	}
	namespace = "kube-system"
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "testuser"}))
	require.NoError(err)
	require.Equal("bar", pod.Spec.NodeSelector["foo"])
	require.NotContains(pod.Spec.NodeSelector, "com.docker.ucp.orchestrator.kubernetes")
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
}
