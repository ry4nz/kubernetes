package ucputil

import (
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	authUser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/kubernetes/pkg/apis/apps"
	"k8s.io/kubernetes/pkg/apis/batch"
	api "k8s.io/kubernetes/pkg/apis/core"
)

// GetPodSpecFromObject returns a pointer to the PodSpec in an object that
// contains one or nil.
func GetPodSpecFromObject(runtimeObject runtime.Object) *api.PodSpec {
	switch object := runtimeObject.(type) {
	case *api.Pod:
		return &object.Spec
	case *api.PodTemplate:
		return &object.Template.Spec
	case *api.ReplicationController:
		return &object.Spec.Template.Spec
	case *apps.StatefulSet:
		return &object.Spec.Template.Spec
	case *batch.CronJob:
		return &object.Spec.JobTemplate.Spec.Template.Spec
	case *batch.Job:
		return &object.Spec.Template.Spec
	case *apps.DaemonSet:
		return &object.Spec.Template.Spec
	case *apps.Deployment:
		return &object.Spec.Template.Spec
	case *apps.ReplicaSet:
		return &object.Spec.Template.Spec
	default:
		return nil
	}
}

var systemUsers = []string{
	authUser.APIServerUser,
	authUser.KubeProxy,
	authUser.KubeControllerManager,
	authUser.KubeScheduler,
}

// IsSystemUser returns true if the given username represents a Kube system
// component (e.g. the Kube controller manager). For these users, we generally
// don't want to modify or validate their requests; we should only perform our
// checks on requests initiated by users.
func IsSystemUser(user string) bool {
	for _, systemUser := range systemUsers {
		if user == systemUser {
			return true
		}
	}
	// We also want to special-case service accounts with a name like
	// system:serviceaccount:kube-system:deployment-controller.
	// These are service accounts that the Kube controller manager uses
	// when --use-service-account-credentials is specified. See
	// https://github.com/kubernetes/kubernetes/blob/master/cmd/kube-controller-manager/app/apps.go
	// for the source of these service accounts.
	// Since these service accounts are in the protected kube-system
	// namespace, there should be no danger of non-admin users creating
	// fake versions of these accounts.
	return strings.HasPrefix(user, "system:serviceaccount:kube-system") && strings.HasSuffix(user, "-controller")
}
