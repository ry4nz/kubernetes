package ucpnodeselector

import (
	"io"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
)

// The UCPNodeSelector admission controller adds a
// com.docker.ucp.orchestrator.kubernetes=true node selector to all pods not
// in the kube-system namespace. This ensures that user workloads always run
// on UCP nodes marked for Kubernetes.

const (
	kubeSystemNamespace   = "kube-system"
	kubeNodeSelectorLabel = "com.docker.ucp.orchestrator.kubernetes"
	kubeNodeSelectorValue = "true"
)

const (
	PluginName = "UCPNodeSelector"
)

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(config io.Reader) (admission.Interface, error) {
		return NewUCPNodeSelector(), nil
	})
}

type ucpNodeSelector struct {
	*admission.Handler
}

// Admit handles resources that are passed through this admission controller
func (a *ucpNodeSelector) Admit(attributes admission.Attributes) (err error) {
	// Ignore all calls to subresources or resources other than pods.
	if len(attributes.GetSubresource()) != 0 || attributes.GetResource().GroupResource() != api.Resource("pods") {
		return nil
	}
	pod, ok := attributes.GetObject().(*api.Pod)
	if !ok {
		return apierrors.NewBadRequest("resource was marked with kind Pod but was unable to be converted")
	}

	namespace := attributes.GetNamespace()
	if namespace == kubeSystemNamespace {
		// Don't do anything for system pods
		return nil
	}
	pod.Spec.NodeSelector[kubeNodeSelectorLabel] = kubeNodeSelectorValue
	return nil
}

// NewUCPNodeSelector returns a UCP node selector admission controller
func NewUCPNodeSelector() admission.Interface {
	return &ucpNodeSelector{
		Handler: admission.NewHandler(admission.Create, admission.Update),
	}
}
