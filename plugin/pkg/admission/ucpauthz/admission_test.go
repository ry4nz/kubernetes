package ucpauthz

import (
	"fmt"
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
	image      string
}

func TestAdmission(t *testing.T) {
	require := require.New(t)
	namespace := "test"
	responses := []response{
		response{200, "true"},
		response{200, "false"},
		response{500, "unable to lookup user adminuser: some unexpected error"},
		response{200, "false"},
	}
	i := 0
	ts := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Query().Get("user") == "" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("no user query var"))
			}
			fmt.Print(responses[1].image)
			w.WriteHeader(responses[i].statuscode)
			w.Write([]byte(responses[i].image))
			i++
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
}
