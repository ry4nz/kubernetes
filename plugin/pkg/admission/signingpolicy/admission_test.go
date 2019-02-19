package signingpolicy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	api "k8s.io/kubernetes/pkg/apis/core"
)

// TestAdmission verifies all create requests for pods result in every container's image pull policy
// set to Always
type response struct {
	statuscode  int
	rawResponse string
}

func TestAdmission(t *testing.T) {
	namespace := "test"
	responses := []response{
		response{200, `{"resolvedImages":{"signed":"signed@sha256:b507b3e73a633c62f72a0daf0cbf49bb2632e7bbae0926eb26c9006ba982fcd5"}}`},
		response{200, `{"errorMessages":["error fixture"]}`},
		response{200, `{"resolvedImages":{"signed":"signed@sha256:b507b3e73a633c62f72a0daf0cbf49bb2632e7bbae0926eb26c9006ba982fcd5"}}`},
		response{200, `{"errorMessages":["error fixture"]}`},
	}
	i := 0
	ts := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(responses[i].statuscode)
			w.Write([]byte(responses[i].rawResponse))
			i++
		}))
	fmt.Printf("UCP mock sever URL: %s", ts.URL)
	os.Setenv("UCP_URL", ts.URL)

	pod := api.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "123", Namespace: namespace},
		Spec: api.PodSpec{
			InitContainers: []api.Container{
				{Name: "init1", Image: "signed"},
			},
		},
	}
	handler := &signingPolicy{
		Handler:       admission.NewHandler(admission.Create, admission.Update),
		ucpWebHookURL: os.Getenv("UCP_URL"),
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
	err := handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, false, &user.DefaultInfo{Name: "alice"}))
	assert.NoError(t, err)
	assert.Equal(t, "signed@sha256:b507b3e73a633c62f72a0daf0cbf49bb2632e7bbae0926eb26c9006ba982fcd5", pod.Spec.InitContainers[0].Image)

	pod = api.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "123", Namespace: namespace},
		Spec: api.PodSpec{
			InitContainers: []api.Container{
				{Name: "init2", Image: "unsigned"},
			},
		},
	}
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, false, &user.DefaultInfo{Name: "alice"}))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error fixture")

	pod = api.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "123", Namespace: namespace},
		Spec: api.PodSpec{
			Containers: []api.Container{
				{Name: "ctr1", Image: "signed"},
			},
		},
	}
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, false, &user.DefaultInfo{Name: "alice"}))
	assert.NoError(t, err)
	assert.Equal(t, "signed@sha256:b507b3e73a633c62f72a0daf0cbf49bb2632e7bbae0926eb26c9006ba982fcd5", pod.Spec.Containers[0].Image)

	pod = api.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "123", Namespace: namespace},
		Spec: api.PodSpec{
			Containers: []api.Container{
				{Name: "ctr2", Image: "unsigned"},
			},
		},
	}
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, false, &user.DefaultInfo{Name: "alice"}))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error fixture")
}
