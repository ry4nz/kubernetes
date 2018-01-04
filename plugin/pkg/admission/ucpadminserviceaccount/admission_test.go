package ucpadminserviceaccount

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/fake"
)

type response struct {
	statuscode int
	body       string
}

// TestAdmission verifies that only admins have the `default` service
// account injected in their podspecs
func TestAdmission(t *testing.T) {
	require := require.New(t)
	namespace := "test"
	nsResponses := []response{
		{200, "true"},
		{200, "false"},
		{500, "unable to lookup user adminuser: some unexpected error"},
		{200, "true"},
		{200, "false"},
		{200, "true"},
	}
	nsIdx := 0
	ts := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Query().Get("user") == "" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("no user query var"))
				return
			}
			w.WriteHeader(nsResponses[nsIdx].statuscode)
			w.Write([]byte(nsResponses[nsIdx].body))
			nsIdx++
		}))

	// Test1: user is admin, no service account is used with a plain "Pod"
	pod := api.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "123", Namespace: namespace},
		Spec: api.PodSpec{
			Containers: []api.Container{},
		},
	}

	handler := &ucpAdminServiceAccount{
		Handler:     admission.NewHandler(admission.Create, admission.Update),
		ucpLocation: ts.URL,
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

	client := fake.NewSimpleClientset()
	handler.SetInternalKubeClientSet(client)

	err := handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "adminuser"}))
	require.NoError(err)
	require.Equal(defaultServiceAccountName, pod.Spec.ServiceAccountName)

	// Test 2: user is not admin, nonadmindefault account is used
	pod.Spec.ServiceAccountName = ""
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "notadmin"}))
	require.NoError(err)
	require.Equal(nonAdminDefaultServiceAccountName, pod.Spec.ServiceAccountName)

	// Test 3: no service account is used, ucp controller webhook fails
	pod.Spec.ServiceAccountName = ""
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{Name: "adminuser"}))
	require.Error(err)
	require.Contains(err.Error(), "unable to lookup user adminuser: some unexpected error")

	// Test 4: update a deployment as an admin user
	deployment := extensions.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "123", Namespace: namespace},
		Spec: extensions.DeploymentSpec{
			Template: api.PodTemplateSpec{
				Spec: api.PodSpec{
					ServiceAccountName: "",
				},
			},
		},
	}
	err = handler.Admit(admission.NewAttributesRecord(&deployment, nil, api.Kind("Deployment").WithVersion("version"), deployment.Namespace, deployment.Name, api.Resource("deployments").WithVersion("version"), "", admission.Update, &user.DefaultInfo{Name: "adminuser"}))
	require.NoError(err)
	require.Equal(defaultServiceAccountName, deployment.Spec.Template.Spec.ServiceAccountName)

	// Test 5: update a deployment with no service account as a non-admin user
	deployment.Spec.Template.Spec.ServiceAccountName = ""
	err = handler.Admit(admission.NewAttributesRecord(&deployment, nil, api.Kind("Deployment").WithVersion("version"), deployment.Namespace, deployment.Name, api.Resource("deployments").WithVersion("version"), "", admission.Update, &user.DefaultInfo{Name: "notadmin"}))
	require.NoError(err)
	require.Equal(nonAdminDefaultServiceAccountName, deployment.Spec.Template.Spec.ServiceAccountName)

	// Test 6: update a deployment with a service account as an admin user
	deployment.Spec.Template.Spec.ServiceAccountName = "foobar"
	err = handler.Admit(admission.NewAttributesRecord(&deployment, nil, api.Kind("Deployment").WithVersion("version"), deployment.Namespace, deployment.Name, api.Resource("deployments").WithVersion("version"), "", admission.Update, &user.DefaultInfo{Name: "adminuser"}))
	require.NoError(err)
	require.Equal("foobar", deployment.Spec.Template.Spec.ServiceAccountName)
}
