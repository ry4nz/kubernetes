/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package signingpolicy

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/admission"
	"github.com/stretchr/testify/assert"
	"k8s.io/kubernetes/pkg/api"
	"net/http"
	"net/http/httptest"
	"os"
)

// TestAdmission verifies all create requests for pods result in every container's image pull policy
// set to Always
type response struct {
	statuscode int
	image      string
}

func TestAdmission(t *testing.T) {
	namespace := "test"
	handler := &signingPolicy{}
	responses := []response{
		response{200, "signed@sha256:b507b3e73a633c62f72a0daf0cbf49bb2632e7bbae0926eb26c9006ba982fcd5"},
		response{403, ""},
		response{200, "signed@sha256:b507b3e73a633c62f72a0daf0cbf49bb2632e7bbae0926eb26c9006ba982fcd5"},
		response{403, ""},
	}
	i := 0
	ts := httptest.NewServer(http.Handler(
		func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(responses[i].statuscode)
			w.Write([]byte(responses[i].image))
			i++
		}))
	os.Setenv("UCP_LOCATION", ts.URL)

	pod := api.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "123", Namespace: namespace},
		Spec: api.PodSpec{
			InitContainers: []api.Container{
				{Name: "init1", Image: "signed"},
			},
		},
	}
	err := handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, nil))
	if err != nil {
		t.Errorf("Unexpected error returned from admission handler")
	}
	if pod.Spec.Containers[0].Image != "signed@sha256:b507b3e73a633c62f72a0daf0cbf49bb2632e7bbae0926eb26c9006ba982fcd5" {
		t.Errorf("Container %v: expected signed@sha256:b507b3e73a633c62f72a0daf0cbf49bb2632e7bbae0926eb26c9006ba982fcd5, got %v", pod.Spec.Containers[0], pod.Spec.Containers[0].Image)
	}

	pod = api.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "123", Namespace: namespace},
		Spec: api.PodSpec{
			InitContainers: []api.Container{
				{Name: "init2", Image: "unsigned"},
			},
		},
	}
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, nil))
	assert.EqualError(t, err, "unsigned is not signed")

	pod = api.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "123", Namespace: namespace},
		Spec: api.PodSpec{
			Containers: []api.Container{
				{Name: "ctr1", Image: "signed"},
			},
		},
	}
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, nil))
	if err != nil {
		t.Errorf("Unexpected error returned from admission handler")
	}
	if pod.Spec.Containers[0].Image != "signed@sha256:b507b3e73a633c62f72a0daf0cbf49bb2632e7bbae0926eb26c9006ba982fcd5" {
		t.Errorf("Container %v: expected signed@sha256:b507b3e73a633c62f72a0daf0cbf49bb2632e7bbae0926eb26c9006ba982fcd5, got %v", pod.Spec.Containers[0], pod.Spec.Containers[0].Image)
	}

	pod = api.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "123", Namespace: namespace},
		Spec: api.PodSpec{
			Containers: []api.Container{
				{Name: "ctr2", Image: "unsigned"},
			},
		},
	}
	err = handler.Admit(admission.NewAttributesRecord(&pod, nil, api.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, nil))
	assert.EqualError(t, err, "unsigned is not signed")
}
