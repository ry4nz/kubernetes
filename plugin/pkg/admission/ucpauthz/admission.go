package ucpauthz

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/docker/go-connections/tlsconfig"
	log "github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/apis/rbac"
	"k8s.io/kubernetes/plugin/pkg/admission/ucputil"
)

// The UCPAuthorization admission controller rejects requests based on the
// contents of a podspec.

const (
	key                 = "key.pem"
	cert                = "cert.pem"
	rootCA              = "ca.pem"
	isFullControlPath   = "/api/authz/isfullcontrol"
	parametersPath      = "/api/authz/parameters"
	volumeAccessPath    = "/api/authz/volumeaccess"
	agentPathTemplate   = "/api/agent/%s"
	resolveSubjectsPath = "/api/authz/resolve-rbac-subjects"
	queryKey            = "user"
	userAnnotationKey   = "com.docker.compose.user"
	composeUser         = "system:serviceaccount:kube-system:compose"
)

// These structs are used in the /api/authz/volumeaccess endpoint in UCP.
type kubeVolumeAccessRequest struct {
	Volumes []string `json:"volumes"`
}

type volumeAccessInfo struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

type kubeVolumeAccessResponse struct {
	Volumes map[string]volumeAccessInfo `json:"volumes"`
}

const (
	PluginName = "UCPAuthorization"
)

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(config io.Reader) (admission.Interface, error) {
		var tlsConfig *tls.Config
		var err error
		certDir := os.Getenv("CERT_DIR")
		if certDir != "" {
			tlsOptions := tlsconfig.Options{
				CAFile:   filepath.Join(certDir, rootCA),
				CertFile: filepath.Join(certDir, cert),
				KeyFile:  filepath.Join(certDir, key),
			}
			tlsConfig, err = tlsconfig.Client(tlsOptions)
			if err != nil {
				return nil, err
			}
		}
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
				// The default is 2 which is too small. We may need to
				// adjust this value as we get results from load/stress
				// tests.
				MaxIdleConnsPerHost: 5,
			},
		}

		return NewUCPAuthz(httpClient), nil
	})
}

type ucpAuthz struct {
	*admission.Handler
	ucpLocation  string
	httpClient   *http.Client
	systemPrefix string
}

type authzParameters struct {
	hostBindMounts bool // true if the pod has a hostPath volume defined
	privileged     bool // true if any container's SecurityContext or the PodSecurityPolicy has `privileged` or has allowPrivilegedEscalation
	extraCaps      bool // true if any container's SecurityContext or the PodSecurityPolicy has `capabilities`
	hostNetwork    bool // true if the Pod has hostNetwork set
	hostIPC        bool // trie if the Pod has hostIPC set
	hostPID        bool // trie if the Pod has hostPID
}

// String serializes only the true parameters into a string.
func (p *authzParameters) String() string {
	acc := []string{}
	for _, v := range []struct {
		param     string
		requested bool
	}{
		{"host bind mounts", p.hostBindMounts},
		{"privileged mode", p.privileged},
		{"extra kernel capabilities", p.extraCaps},
		{"host networking", p.hostNetwork},
		{"host IPC mode", p.hostIPC},
		{"host PID mode", p.hostPID},
	} {
		if !v.requested {
			continue
		}
		acc = append(acc, v.param)
	}
	return strings.Join(acc, ", ")
}

// HasRestrictedParameters returns true if any of the parameters are true
func (p *authzParameters) HasRestrictedParameters() bool {
	return p.hostBindMounts ||
		p.privileged ||
		p.extraCaps ||
		p.hostNetwork ||
		p.hostIPC ||
		p.hostPID
}

// ParamsFromPodSpec parses a PodSpec and calculates the requested authzParameters
func ParamsFromPodSpec(podSpec *api.PodSpec) *authzParameters {
	if podSpec == nil {
		return nil
	}
	resp := &authzParameters{}

	// First parse the SecurityContext of the PodSpec
	if podSpec.SecurityContext != nil {
		resp.hostPID = podSpec.SecurityContext.HostPID
		resp.hostIPC = podSpec.SecurityContext.HostIPC
		resp.hostNetwork = podSpec.SecurityContext.HostNetwork
	}

	// If the PodSpec is defining any HostPath-source volumes, mark the
	// hostBindMounts parameter.
	for _, volume := range podSpec.Volumes {
		if volume.HostPath != nil && volume.HostPath.Path != "" {
			resp.hostBindMounts = true
			break
		}
	}

	// For each container, parse their individual SecurityContext
	for _, container := range append(podSpec.Containers, podSpec.InitContainers...) {
		if container.SecurityContext != nil {
			if container.SecurityContext.Privileged != nil {
				resp.privileged = resp.privileged || *container.SecurityContext.Privileged
			}
			if container.SecurityContext.AllowPrivilegeEscalation != nil {
				resp.privileged = resp.privileged || *container.SecurityContext.AllowPrivilegeEscalation
			}
			if container.SecurityContext.Capabilities != nil {
				if len(container.SecurityContext.Capabilities.Add) > 0 {
					resp.extraCaps = true
				}
			}
		}
	}

	return resp
}

func (a *ucpAuthz) Admit(attributes admission.Attributes) (err error) {
	user := attributes.GetUserInfo().GetName()
	namespace := attributes.GetNamespace()
	log.Debugf("the user is: %s", user)

	nameAttr := attributes.GetName()
	kindAttr := attributes.GetKind()
	operationAttr := attributes.GetOperation()

	// For stacks, annotate the object with the user that issued this request
	// to let authorization happen via impersonation.
	if kindAttr.Kind == "Stack" && operationAttr != admission.Delete {
		stack, ok := attributes.GetObject().(*unstructured.Unstructured)
		if !ok {
			return fmt.Errorf("detected object of kind \"Stack\" and type %s but was expecting *unstructured.Unstructured", reflect.TypeOf(attributes.GetObject()).String())
		}

		annotations := stack.GetAnnotations()
		if annotations == nil {
			annotations = make(map[string]string)
		}

		// Overwrite any user-specified annotations, except if the stack is
		// being modified by the compose adaptor itself.
		if user != composeUser {
			annotations[userAnnotationKey] = user
		}
		stack.SetAnnotations(annotations)
		return nil
	}

	// If a service account is being deleted, also delete the corresponding enzi agent.
	if kindAttr.Kind == "ServiceAccount" && attributes.GetOperation() == admission.Delete {
		return a.deleteAgent(namespace, nameAttr)
	}

	// Always admit requests from system components
	if a.systemPrefix != "" && strings.HasPrefix(user, a.systemPrefix) {
		return nil
	}

	if isCreateOrUpdateRBACBinding(attributes) {
		return a.resolveRBACBindingSubjects(attributes)
	}

	if isDeleteClusterAdminClusterRoleOrBinding(attributes) {
		return admission.NewForbidden(attributes, fmt.Errorf("you may not delete the cluster-admin ClusterRole or ClusterRoleBinding"))
	}

	if kindAttr.Kind == "PersistentVolume" && (attributes.GetOperation() == admission.Create || attributes.GetOperation() == admission.Update) {
		return a.checkPersistentVolumeCreateOrUpdate(user, namespace, attributes.GetObject())
	}

	podSpec := ucputil.GetPodSpecFromObject(attributes.GetObject())
	if podSpec == nil {
		// The resource is not a known object type which contains a PodSpec
		return nil
	}

	if attributes.GetOperation() == admission.Delete {
		return nil
	}

	// Inspect the podSpec for low-level request parameters
	params := ParamsFromPodSpec(podSpec)
	if params.HasRestrictedParameters() {
		allowed, err := a.isFullControl(user, namespace)
		//allowed, err := a.userHasPermissions(user, params)
		if err != nil {
			return apierrors.NewInternalError(fmt.Errorf("unable to determine if user \"%s\" has fine-grained permissions \"%s\" for resource %s: %s", user, params.String(), nameAttr, err))
		}

		if !allowed {
			return admission.NewForbidden(attributes, fmt.Errorf("user \"%s\" is not an admin and does not have permissions to use %s for resource %s", user, params.String(), nameAttr))
		}
	}

	return nil
}

var (
	clusterRoleGroupKind = schema.GroupKind{
		Group: "rbac.authorization.k8s.io",
		Kind:  "ClusterRole",
	}
	clusterRoleBindingGroupKind = schema.GroupKind{
		Group: "rbac.authorization.k8s.io",
		Kind:  "ClusterRoleBinding",
	}
	roleBindingGroupKind = schema.GroupKind{
		Group: "rbac.authorization.k8s.io",
		Kind:  "RoleBinding",
	}
)

// isDeleteClusterAdminClusterRoleOrBinding returns whether the given
// attributes are for a delete operation on a ClusterRole or ClusterRoleBinding
// object named "cluster-admin".
func isDeleteClusterAdminClusterRoleOrBinding(attributes admission.Attributes) bool {
	nameAttr := attributes.GetName()
	groupKind := attributes.GetKind().GroupKind()
	opAttr := attributes.GetOperation()

	return opAttr == admission.Delete && nameAttr == "cluster-admin" && (groupKind == clusterRoleGroupKind || groupKind == clusterRoleBindingGroupKind)
}

// isCreateOrUpdateRBACBinding returns whether the given attributes are for a
// create or update operation on a RoleBinding or ClusterRoleBinding object.
func isCreateOrUpdateRBACBinding(attributes admission.Attributes) bool {
	groupKind := attributes.GetKind().GroupKind()
	opAttr := attributes.GetOperation()
	return (opAttr == admission.Create || opAttr == admission.Update) && (groupKind == clusterRoleBindingGroupKind || groupKind == roleBindingGroupKind)
}

func (a *ucpAuthz) resolveRBACBindingSubjects(attributes admission.Attributes) error {
	var subjects *[]rbac.Subject
	switch object := attributes.GetObject().(type) {
	case *rbac.RoleBinding:
		subjects = &object.Subjects
	case *rbac.ClusterRoleBinding:
		subjects = &object.Subjects
	default:
		return fmt.Errorf("object %T is not a RoleBinding or ClusterRoleBinding", object)
	}

	u, err := url.Parse(a.ucpLocation)
	if err != nil {
		return fmt.Errorf("unable to parse UCP location \"%s\": %s", a.ucpLocation, err)
	}
	u.Path = resolveSubjectsPath

	payload, err := json.Marshal(*subjects)
	if err != nil {
		return fmt.Errorf("unable to encode subject review payload to JSON: %s", err)
	}

	req, err := http.NewRequest("POST", u.String(), bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("unable to create delete agent request against %s: %s", u.String(), err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("unable to perform request at %s: %s", u.String(), err)
	}
	defer resp.Body.Close()

	responseBuf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to resolve subjects: server responded with status %d", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unable to resolve subjects: server responded with status %d: %s", resp.StatusCode, string(responseBuf))
	}

	var resolvedResponse kubeResolevRBACSubjectsResponse
	if err := json.Unmarshal(responseBuf, &resolvedResponse); err != nil {
		return fmt.Errorf("unable to decode resolved subjects response: %s --- response body: %s", err, string(responseBuf))
	}

	if len(resolvedResponse.Errors) != 0 {
		return fmt.Errorf("unable to resolve %d subjects: %q", len(resolvedResponse.Errors), resolvedResponse.Errors)
	}

	*subjects = resolvedResponse.Subjects

	return nil
}

// kubeResolevRBACSubjectsResponse is used as the response type in the
// resolveRBACBindingSubjects API call.
type kubeResolevRBACSubjectsResponse struct {
	Subjects []rbac.Subject `json:"subjects"`
	Errors   []string       `json:"errors"`
}

// deleteAgent removes an enzi agent when the corresponding kubernetes service
// account is being deleted.
func (a *ucpAuthz) deleteAgent(namespace, name string) error {
	u, err := url.Parse(a.ucpLocation)
	if err != nil {
		return fmt.Errorf("unable to parse UCP location \"%s\": %s", a.ucpLocation, err)
	}
	serviceAccountID := fmt.Sprintf("system:serviceaccount:%s:%s", namespace, name)
	u.Path = fmt.Sprintf(agentPathTemplate, serviceAccountID)

	req, err := http.NewRequest("DELETE", u.String(), nil)
	if err != nil {
		return fmt.Errorf("unable to create delete agent request against %s: %s", u.String(), err)
	}
	resp, err := a.httpClient.Do(req)
	defer resp.Body.Close()
	if err != nil {
		return fmt.Errorf("request at %s failed: %s", u.String(), err)
	}

	if resp.StatusCode != http.StatusNoContent {
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to delete agent: server responded with status %d", resp.StatusCode)
		}
		return fmt.Errorf("failed to delete agent: server responded with status %d: %s", resp.StatusCode, string(b))
	}

	return nil
}

func (a *ucpAuthz) userHasPermissions(username string, params *authzParameters) (bool, error) {
	u, err := url.Parse(a.ucpLocation)
	if err != nil {
		return false, fmt.Errorf("unable to parse UCP location \"%s\": %s", a.ucpLocation, err)
	}
	u.Path = parametersPath

	// Serialize the parameters
	m, err := json.Marshal(params)
	if err != nil {
		return false, fmt.Errorf("unable to marshal parameters request: %s", err)
	}

	q := u.Query()
	q.Set("user", username)
	q.Set("params", string(m))
	u.RawQuery = q.Encode()

	resp, err := a.httpClient.Get(u.String())
	if err != nil {
		return false, fmt.Errorf("request at %s failed: %s", u.String(), err)
	}

	defer resp.Body.Close()
	msg, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("received status code %d from %s but unable to read response message: %s", resp.StatusCode, u.String(), err)
	}
	msgStr := strings.TrimSpace(string(msg))

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("received status code %d from %s: %s", resp.StatusCode, u.String(), msgStr)
	}

	switch msgStr {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("unknown response \"%s\" while requesting parameter permissions for user %s", msgStr, username)
	}
}

func (a *ucpAuthz) isFullControl(username, namespace string) (bool, error) {
	u, err := url.Parse(a.ucpLocation)
	if err != nil {
		return false, fmt.Errorf("unable to parse UCP location \"%s\": %s", a.ucpLocation, err)
	}
	u.Path = isFullControlPath
	q := u.Query()
	q.Set("user", username)
	q.Set("namespace", namespace)
	u.RawQuery = q.Encode()

	resp, err := a.httpClient.Get(u.String())
	if err != nil {
		return false, fmt.Errorf("unable to lookup user \"%s\" at %s: %s", username, u.String(), err)
	}

	defer resp.Body.Close()
	msg, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("unable to verify if user %s has full control privileges at %s: received status code %d but unable to read response message: %s", username, u.String(), resp.StatusCode, err)
	}
	msgStr := strings.TrimSpace(string(msg))

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unable to verify if user %s has full control privileges at %s: received status code %d: %s", username, u.String(), resp.StatusCode, msgStr)
	}

	switch msgStr {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("unknown response \"%s\" while verifying if user %s is an admin", msgStr, username)
	}
}

func (a *ucpAuthz) checkPersistentVolumeCreateOrUpdate(username, namespace string, obj runtime.Object) error {
	pv, ok := obj.(*api.PersistentVolume)
	if !ok {
		return fmt.Errorf("detected object of kind \"PersistentVolume\" and type %s but was expecting *api.PersistentVolume", reflect.TypeOf(obj).String())
	}
	// Only full control users may create local or hostpath PVs to prevent
	// users from bind mounting UCP data.
	if pv.Spec.Local != nil || pv.Spec.HostPath != nil {
		allowed, err := a.isFullControl(username, namespace)
		//allowed, err := a.userHasPermissions(user, params)
		if err != nil {
			return apierrors.NewInternalError(fmt.Errorf("unable to determine if user \"%s\" has permissions to create local PersistentVolumes: %s", username, err))
		}

		if !allowed {
			return apierrors.NewInternalError(fmt.Errorf("user \"%s\" is not an admin and does not have permissions to create local PersistentVolumes", username))
		}
	}
	return nil
}

// NewUCPAuthz returns a signing policy handler
func NewUCPAuthz(httpClient *http.Client) admission.Interface {
	return &ucpAuthz{
		Handler:      admission.NewHandler(admission.Create, admission.Update, admission.Delete),
		ucpLocation:  os.Getenv("UCP_URL"),
		httpClient:   httpClient,
		systemPrefix: os.Getenv("SYSTEM_PREFIX"),
	}
}
