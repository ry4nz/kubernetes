package ucpauthz

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	// Test1: user is admin, service account is used
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
	err := handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "adminuser"}))
	require.NoError(err)

	// Test 2: user is not admin, service account is used
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "notadmin"}))
	require.Error(err)
	require.Contains(err.Error(), "only docker EE admin users are permitted to use service accounts")

	// Test 3: user is an admin, service account is used, ucp controller webhook fails
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "adminuser"}))
	require.Error(err)
	require.Contains(err.Error(), "unable to lookup user adminuser: some unexpected error")

	// Test 4: user is a system component, service account is used
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "systemprefix:controllermanager"}))
	require.NoError(err)

	// Test 5: user is a system component with the wrong prefix, service
	// account is used.
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "other:systemprefix:controllermanager"}))
	require.Error(err)
	require.Contains(err.Error(), "only docker EE admin users are permitted to use service accounts")

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
