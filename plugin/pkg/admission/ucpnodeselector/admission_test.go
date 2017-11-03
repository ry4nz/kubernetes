package ucpnodeselector

import (
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/kubernetes/pkg/api"
)

// TestAdmission verifies all create requests for pods get a
// kubernetes=true node selector
func TestAdmission(t *testing.T) {
	require := require.New(t)
	handler := &ucpNodeSelector{
		Handler: admission.NewHandler(admission.Create, admission.Update),
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
