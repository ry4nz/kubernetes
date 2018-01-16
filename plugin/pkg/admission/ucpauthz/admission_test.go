package ucpauthz

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/kubernetes/pkg/api"
)

// TestAdmission verifies all create requests for pods result in every container's image pull policy
// set to Always
type response struct {
	statuscode int
	body       string
}

func TestStackAnnotation(t *testing.T) {
	require := require.New(t)

	handler := &ucpAuthz{
		Handler: admission.NewHandler(admission.Create, admission.Update),
	}

	// Test 1: attempt to pre-annotate a stack
	stack := &unstructured.Unstructured{}
	stack.SetName("somestack")
	stack.SetNamespace("default")
	stack.SetAnnotations(map[string]string{
		userAnnotationKey: "otheruser",
	})

	err := handler.Admit(admission.NewAttributesRecord(stack, nil, api.Kind("Stack").WithVersion("version"), stack.GetNamespace(), stack.GetName(), api.Resource("stacks").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "testuser"}))
	require.NoError(err)
	require.Equal(stack.GetAnnotations()[userAnnotationKey], "testuser")

	// Test 2: A stack with no annotations is annotated as the user
	stack = &unstructured.Unstructured{}
	stack.SetName("somestack")
	stack.SetNamespace("default")
	stack.SetAnnotations(make(map[string]string))

	err = handler.Admit(admission.NewAttributesRecord(stack, nil, api.Kind("Stack").WithVersion("version"), stack.GetNamespace(), stack.GetName(), api.Resource("stacks").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "testuser"}))
	require.NoError(err)
	require.Equal(stack.GetAnnotations()[userAnnotationKey], "testuser")

	// Test 3: Stack annotations are not changed if edited by the compose fry
	stack = &unstructured.Unstructured{}
	stack.SetName("somestack")
	stack.SetNamespace("default")
	stack.SetAnnotations(map[string]string{
		userAnnotationKey: "testuser",
	})

	err = handler.Admit(admission.NewAttributesRecord(stack, nil, api.Kind("Stack").WithVersion("version"), stack.GetNamespace(), stack.GetName(), api.Resource("stacks").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: composeUser}))
	require.NoError(err)
	require.Equal(stack.GetAnnotations()[userAnnotationKey], "testuser")
}

func TestAdmission(t *testing.T) {
	require := require.New(t)
	namespace := "test"
	nsResponses := []response{
		{200, "true"},
		{200, "false"},
		{500, "unable to lookup user adminuser: some unexpected error"},
		{200, "false"},

		// Params requests
		{200, "true"},
		{200, "false"},
	}
	paramsResponses := []response{
		{200, "true"},
		{200, "false"},
	}
	nsIdx := 0
	paramsIdx := 0
	ts := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			switch req.URL.Path {
			case isAdminPath:
				if req.URL.Query().Get("user") == "" {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte("no user query var"))
					return
				}
				w.WriteHeader(nsResponses[nsIdx].statuscode)
				w.Write([]byte(nsResponses[nsIdx].body))
				nsIdx++
			case parametersPath:
				if req.URL.Query().Get("user") == "" {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte("no user query var"))
					return
				}
				if req.URL.Query().Get("params") == "" {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte("no user query var"))
					return
				}
				w.WriteHeader(paramsResponses[paramsIdx].statuscode)
				w.Write([]byte(paramsResponses[paramsIdx].body))
				paramsIdx++
			}
		}))

	pod := api.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "123", Namespace: namespace},
		Spec: api.PodSpec{
			Containers:         []api.Container{},
			ServiceAccountName: "serviceaccount",
		},
	}

	handler := &ucpAuthz{
		Handler:      admission.NewHandler(admission.Create, admission.Update),
		ucpLocation:  ts.URL,
		systemPrefix: "systemprefix:",
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: nil,
				// The default is 2 which is too small. We may need to
				// adjust this value as we get results from load/stress
				// tests.
				MaxIdleConnsPerHost: 5,
			},
		},
	}
	// Test1: user is admin, service account is used
	err := handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "adminuser"}))
	require.NoError(err)

	// Test 2: user is not admin, service account is used
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "notadmin"}))
	require.NoError(err)

	// Test 3: user is a system component, service account is used
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "systemprefix:controllermanager"}))
	require.NoError(err)

	// Test 4: user is a system component with the wrong prefix, service
	// account is used.
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "other:systemprefix:controllermanager"}))
	require.NoError(err)

	// Test 6: user is not an admin, no service account is used
	pod = api.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "123", Namespace: namespace},
		Spec: api.PodSpec{
			Containers: []api.Container{},
		},
	}
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "notadmin"}))
	require.NoError(err)

	// Test 7: non-admin user has privileged permissions, no service account is
	// used, pod uses privileged mode.
	privileged := true
	pod.Spec = api.PodSpec{
		Containers: []api.Container{
			{
				Name: "emptycontainer",
			},
			{
				Name: "pwntainer",
				SecurityContext: &api.SecurityContext{
					Privileged: &privileged,
				},
			},
		},
	}
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "candoprivileged"}))
	require.NoError(err)

	// Test 8: non-admin user does not have privileged permissions, no service
	// account is used, pod uses privileged mode.
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "cannotdoprivileged"}))
	require.Error(err)
	require.Contains(err.Error(), "does not have permissions to use")
}

// TestParameterString tests the String() serialization method of
// authzParameters.
func TestParameterString(t *testing.T) {
	require := require.New(t)
	noParams := authzParameters{}
	require.Equal(noParams.String(), "")

	allParams := authzParameters{
		hostBindMounts: true,
		privileged:     true,
		extraCaps:      true,
		hostNetwork:    true,
		hostIPC:        true,
		hostPID:        true,
	}
	require.Equal(allParams.String(), "host bind mounts, privileged mode, extra kernel capabilities, host networking, host IPC mode, host PID mode")

	someParams := authzParameters{
		privileged: true,
		hostIPC:    true,
	}
	require.Equal(someParams.String(), "privileged mode, host IPC mode")
}

// TestParameterHasRestrictedParameters tests the HasRestrictedParameters()
// method of authzParameters.
func TestParameterHasRestrictedParameters(t *testing.T) {
	require := require.New(t)
	require.False((&authzParameters{}).HasRestrictedParameters())
	require.True((&authzParameters{false, false, true, false, false, false}).HasRestrictedParameters())
	require.True((&authzParameters{true, true, true, true, true, true}).HasRestrictedParameters())
}

// TestParamsFromPodSpec tests the ParamsFromPodSpec constructor
func TestParamsFromPodSpec(t *testing.T) {
	require := require.New(t)
	require.Nil(ParamsFromPodSpec(nil))

	// Test a "clean" container with a nil SecurityContext
	podSpecEmpty := &api.PodSpec{
		Containers: []api.Container{
			{
				Name: "emptycontainer",
			},
		},
	}
	require.False(ParamsFromPodSpec(podSpecEmpty).HasRestrictedParameters())

	// Test a "clean" container with an empty SecurityContext
	podSpecEmpty.Containers[0].SecurityContext = &api.SecurityContext{}
	require.False(ParamsFromPodSpec(podSpecEmpty).HasRestrictedParameters())

	// Test HostPID mode
	podSpecHostPID := &api.PodSpec{
		SecurityContext: &api.PodSecurityContext{
			HostPID: true,
		},
	}
	require.Equal(*ParamsFromPodSpec(podSpecHostPID), authzParameters{
		hostPID: true,
	})

	// Test HostIPC mode
	podSpecHostIPC := &api.PodSpec{
		SecurityContext: &api.PodSecurityContext{
			HostIPC: true,
		},
	}
	require.Equal(*ParamsFromPodSpec(podSpecHostIPC), authzParameters{
		hostIPC: true,
	})

	// Test HostNetwork mode
	podSpecHostNetwork := &api.PodSpec{
		SecurityContext: &api.PodSecurityContext{
			HostNetwork: true,
		},
	}
	require.Equal(*ParamsFromPodSpec(podSpecHostNetwork), authzParameters{
		hostNetwork: true,
	})

	// Negative Test hostBindMounts
	podSpecNoHostMount := &api.PodSpec{
		Volumes: []api.Volume{
			{
				Name: "flockerVolume",
				VolumeSource: api.VolumeSource{
					Flocker: &api.FlockerVolumeSource{},
				},
			},
		},
	}
	require.Equal(*ParamsFromPodSpec(podSpecNoHostMount), authzParameters{})

	// Test hostBindMounts
	podSpecHostMount := &api.PodSpec{
		Volumes: []api.Volume{
			{
				Name: "bindmount",
				VolumeSource: api.VolumeSource{
					HostPath: &api.HostPathVolumeSource{
						Path: "/etc/passwd",
					},
				},
			},
		},
	}
	require.Equal(*ParamsFromPodSpec(podSpecHostMount), authzParameters{
		hostBindMounts: true,
	})

	// Test Privileged
	privileged := true
	podSpecPrivileged := &api.PodSpec{
		Containers: []api.Container{
			{
				Name: "emptycontainer",
			},
			{
				Name: "pwntainer",
				SecurityContext: &api.SecurityContext{
					Privileged: &privileged,
				},
			},
		},
	}
	require.Equal(*ParamsFromPodSpec(podSpecPrivileged), authzParameters{
		privileged: true,
	})
	podSpecAllowEscalation := &api.PodSpec{
		Containers: []api.Container{
			{
				Name: "pwntainer",
				SecurityContext: &api.SecurityContext{
					AllowPrivilegeEscalation: &privileged,
				},
			},
		},
	}
	require.Equal(*ParamsFromPodSpec(podSpecAllowEscalation), authzParameters{
		privileged: true,
	})

	// Test Extra capabilities
	podSpecCapAdd := &api.PodSpec{
		Containers: []api.Container{
			{
				Name: "pwntainer",
				SecurityContext: &api.SecurityContext{
					Capabilities: &api.Capabilities{
						Add: []api.Capability{
							"CAP_SYS_ADMIN",
						},
					},
				},
			},
		},
	}
	require.Equal(*ParamsFromPodSpec(podSpecCapAdd), authzParameters{
		extraCaps: true,
	})

	// Test Multiple parameters at the same time
	podSpecMulti := &api.PodSpec{
		Containers: []api.Container{
			{
				Name: "pwntainer",
				SecurityContext: &api.SecurityContext{
					Privileged: &privileged,
					Capabilities: &api.Capabilities{
						Add: []api.Capability{
							"CAP_SYS_ADMIN",
						},
					},
				},
			},
		},
		Volumes: []api.Volume{
			{
				Name: "bindmount",
				VolumeSource: api.VolumeSource{
					HostPath: &api.HostPathVolumeSource{
						Path: "/etc/passwd",
					},
				},
			},
		},
		SecurityContext: &api.PodSecurityContext{
			HostPID: true,
		},
	}
	require.Equal(*ParamsFromPodSpec(podSpecMulti), authzParameters{
		privileged:     true,
		extraCaps:      true,
		hostBindMounts: true,
		hostPID:        true,
	})
}

func TestAdmissionWithFlexVolumes(t *testing.T) {
	require := require.New(t)
	namespace := "test"
	volumeAccessResponses := []response{
		{200, `{"volumes": {"testvol1": {"allowed":true,"reason":""}}}`},
		{200, `{"volumes": {"testvol1": {"allowed":false,"reason":"testreason"}}}`},
		{200, `invalid response`},
		{500, `error response`},
		{200, `{"volumes": {}}`},
	}
	volumeAccessIdx := 0
	ts := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			switch req.URL.Path {
			case isAdminPath:
				w.WriteHeader(200)
				w.Write([]byte("false"))
			case parametersPath:
				w.WriteHeader(200)
				w.Write([]byte("true"))
			case volumeAccessPath:
				if req.URL.Query().Get("user") == "" {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte("no user query var"))
					return
				}
				w.WriteHeader(volumeAccessResponses[volumeAccessIdx].statuscode)
				w.Write([]byte(volumeAccessResponses[volumeAccessIdx].body))
				volumeAccessIdx++
			}
		}))

	pod := api.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "123", Namespace: namespace},
		Spec: api.PodSpec{
			Containers: []api.Container{},
			Volumes: []api.Volume{
				{
					Name: "testvol1",
					VolumeSource: api.VolumeSource{
						FlexVolume: &api.FlexVolumeSource{
							Driver: "docker-plugin/local",
						},
					},
				},
			},
		},
	}

	handler := &ucpAuthz{
		Handler:      admission.NewHandler(admission.Create, admission.Update),
		ucpLocation:  ts.URL,
		systemPrefix: "systemprefix:",
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: nil,
				// The default is 2 which is too small. We may need to
				// adjust this value as we get results from load/stress
				// tests.
				MaxIdleConnsPerHost: 5,
			},
		},
	}
	err := handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "adminuser"}))
	require.NoError(err)

	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "adminuser"}))
	require.Error(err)
	require.Contains(err.Error(), "does not have access to volume testvol1: testreason")

	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "adminuser"}))
	require.Error(err)
	require.Contains(err.Error(), "unable to unmarshal response")

	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "adminuser"}))
	require.Error(err)
	require.Contains(err.Error(), "received status code 500: error response")

	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "adminuser"}))
	require.Error(err)
	require.Contains(err.Error(), "volume testvol1 was not in the volume access API response")
}

func TestAdmissionServiceAccountDeletion(t *testing.T) {
	require := require.New(t)
	responses := []response{
		{204, ``},
		{500, `some error`},
		{500, `some other error`},
	}
	i := 0
	ts := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(responses[i].statuscode)
			w.Write([]byte(responses[i].body))
			i++
		}))

	handler := &ucpAuthz{
		Handler:      admission.NewHandler(admission.Create, admission.Update),
		ucpLocation:  ts.URL,
		systemPrefix: "systemprefix:",
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: nil,
				// The default is 2 which is too small. We may need to
				// adjust this value as we get results from load/stress
				// tests.
				MaxIdleConnsPerHost: 5,
			},
		},
	}

	sa := api.ServiceAccount{}
	// Delete a service account and get a 204 from the service agent deletion.
	err := handler.Admit(admission.NewAttributesRecord(&sa, nil, api.Kind("ServiceAccount").WithVersion("version"), "default", "superservice", api.Resource("serviceaccounts").WithVersion("version"), "", admission.Delete, &user.DefaultInfo{Name: "adminuser"}))
	require.NoError(err)

	// Delete a service account and get a 500 from the service agent deletion.
	err = handler.Admit(admission.NewAttributesRecord(&sa, nil, api.Kind("ServiceAccount").WithVersion("version"), "default", "superservice", api.Resource("serviceaccounts").WithVersion("version"), "", admission.Delete, &user.DefaultInfo{Name: "adminuser"}))
	require.Error(err)
	require.Equal(err.Error(), "failed to delete agent: server responded with status 500: some error")

	// Update a service account and don't expect to hit the service agent
	// deletion backend.
	err = handler.Admit(admission.NewAttributesRecord(&sa, nil, api.Kind("ServiceAccount").WithVersion("version"), "default", "superservice", api.Resource("serviceaccounts").WithVersion("version"), "", admission.Update, &user.DefaultInfo{Name: "adminuser"}))
	require.NoError(err)
}
