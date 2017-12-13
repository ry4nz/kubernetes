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
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/apps"
	"k8s.io/kubernetes/pkg/apis/batch"
	"k8s.io/kubernetes/pkg/apis/extensions"
)

// The UCPAuthorization admission controller rejects requests based on the
// contents of a podspec. Specifically:
// 1. Requests using a ServiceAccount will be rejected if the user is not an
// admin.

const (
	key               = "key.pem"
	cert              = "cert.pem"
	rootCA            = "ca.pem"
	isAdminPath       = "/api/authz/isadmin"
	parametersPath    = "/api/authz/parameters"
	volumeAccessPath  = "/api/authz/volumeaccess"
	queryKey          = "user"
	userAnnotationKey = "com.docker.compose.user"
	composeUser       = "system:serviceaccount:kube-system:compose"
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
	log.Debugf("the user is: %s", user)

	// For stacks, annotate the object with the user that issued this request
	// to let authorization happen via impersonation.
	if attributes.GetKind().Kind == "Stack" {
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

	// Always admit requests from system components
	if a.systemPrefix != "" && strings.HasPrefix(user, a.systemPrefix) {
		return nil
	}

	podSpec := getPodSpecFromObject(attributes.GetObject())
	if podSpec == nil {
		// The resource is not a known object type which contains a PodSpec
		return nil
	}

	// Only UCP admins are allowed to use service accounts. However, the
	// `default` service account of each namespace is permitted because it is
	// automatically added to pods during the ServiceAccount admission
	// controller and its actions will be blocked during authorization.
	if podSpec.ServiceAccountName != "" && podSpec.ServiceAccountName != "default" {
		isAdmin, err := a.isAdmin(user)
		if err != nil {
			return apierrors.NewInternalError(err)
		}
		if !isAdmin {
			return admission.NewForbidden(attributes, fmt.Errorf("only docker EE admin users are permitted to use service accounts other than `default`"))
		}
	}

	// Inspect the podSpec for low-level request parameters
	params := ParamsFromPodSpec(podSpec)
	if params.HasRestrictedParameters() {
		allowed, err := a.isAdmin(user)
		//allowed, err := a.userHasPermissions(user, params)
		if err != nil {
			return apierrors.NewInternalError(fmt.Errorf("unable to determine if user \"%s\" has fine-grained permissions \"%s\" for resource %s: %s", user, params.String(), attributes.GetName(), err))
		}

		if !allowed {
			return admission.NewForbidden(attributes, fmt.Errorf("user \"%s\" is not an admin and does not have permissions to use %s for resource %s", user, params.String(), attributes.GetName()))
		}
	}

	hasVolumeAccess, msg, err := a.hasVolumeAccess(user, podSpec)
	if err != nil {
		return apierrors.NewInternalError(fmt.Errorf("unable to determine if user \"%s\" has volume access for resource %s: %s", user, attributes.GetName(), err))
	}
	if !hasVolumeAccess {
		return admission.NewForbidden(attributes, fmt.Errorf(msg))
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

func (a *ucpAuthz) isAdmin(username string) (bool, error) {
	u, err := url.Parse(a.ucpLocation)
	if err != nil {
		return false, fmt.Errorf("unable to parse UCP location \"%s\": %s", a.ucpLocation, err)
	}
	u.Path = isAdminPath
	q := u.Query()
	q.Set("user", username)
	u.RawQuery = q.Encode()

	resp, err := a.httpClient.Get(u.String())
	if err != nil {
		return false, fmt.Errorf("unable to lookup user \"%s\" at %s: %s", username, u.String(), err)
	}

	defer resp.Body.Close()
	msg, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("unable to verify if user %s is an admin at %s: received status code %d but unable to read response message: %s", username, u.String(), resp.StatusCode, err)
	}
	msgStr := strings.TrimSpace(string(msg))

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unable to verify if user %s is an admin at %s: received status code %d: %s", username, u.String(), resp.StatusCode, msgStr)
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

func (a *ucpAuthz) hasVolumeAccess(username string, podSpec *api.PodSpec) (bool, string, error) {
	volumes := []string{}
	for _, v := range podSpec.Volumes {
		if v.VolumeSource.FlexVolume != nil && v.VolumeSource.FlexVolume.Driver == "docker-plugin/local" {
			volumes = append(volumes, v.Name)
		}
	}
	if len(volumes) == 0 {
		return true, "", nil
	}

	req := kubeVolumeAccessRequest{Volumes: volumes}
	u, err := url.Parse(a.ucpLocation)
	if err != nil {
		return false, "", fmt.Errorf("unable to parse UCP location \"%s\": %s", a.ucpLocation, err)
	}
	u.Path = volumeAccessPath
	q := u.Query()
	q.Set("user", username)
	u.RawQuery = q.Encode()

	jsonReq, err := json.Marshal(req)
	if err != nil {
		return false, "", fmt.Errorf("unable to marshal volume access request: %s", err)
	}
	resp, err := a.httpClient.Post(u.String(), "application/json", bytes.NewBuffer(jsonReq))
	if err != nil {
		return false, "", fmt.Errorf("unable to get volume access for user \"%s\" at %s: %s", username, u.String(), err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, "", fmt.Errorf("unable to get volume access for user \"%s\" at %s: received status code %d but unable to read response message: %s", username, u.String(), resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("unable to get volume access for user \"%s\" at %s: received status code %d: %s", username, u.String(), resp.StatusCode, string(body))
	}

	var volumeAccessResponse kubeVolumeAccessResponse
	err = json.Unmarshal(body, &volumeAccessResponse)
	if err != nil {
		return false, "", fmt.Errorf("unable to get volume access for user \"%s\" at %s: unable to unmarshal response: %s", username, u.String(), resp.StatusCode, string(body))
	}

	for _, v := range volumes {
		respVolume, ok := volumeAccessResponse.Volumes[v]
		if !ok {
			return false, "", fmt.Errorf("volume %s was not in the volume access API response", v)
		}
		if !respVolume.Allowed {
			return false, fmt.Sprintf("user \"%s\" does not have access to volume %s: %s", username, v, respVolume.Reason), nil
		}
	}
	return true, "", nil
}

// TODO(alexmavr): DRY across other admission controllers
func getPodSpecFromObject(runtimeObject runtime.Object) *api.PodSpec {
	switch object := runtimeObject.(type) {
	case *api.Pod:
		return &object.Spec
	case *api.PodTemplate:
		return &object.Template.Spec
	case *api.ReplicationController:
		return &object.Spec.Template.Spec
	case *apps.StatefulSet:
		return &object.Spec.Template.Spec
	case *extensions.DaemonSet:
		return &object.Spec.Template.Spec
	case *extensions.Deployment:
		return &object.Spec.Template.Spec
	case *extensions.ReplicaSet:
		return &object.Spec.Template.Spec
	case *batch.Job:
		return &object.Spec.Template.Spec
	case *batch.CronJob:
		return &object.Spec.JobTemplate.Spec.Template.Spec
	default:
		// Ignore all calls for objects that do not contain a Pod Spec.
		return nil
	}
}

// NewUCPAuthz returns a signing policy handler
func NewUCPAuthz(httpClient *http.Client) admission.Interface {
	return &ucpAuthz{
		Handler:      admission.NewHandler(admission.Create, admission.Update),
		ucpLocation:  os.Getenv("UCP_URL"),
		httpClient:   httpClient,
		systemPrefix: os.Getenv("SYSTEM_PREFIX"),
	}
}
