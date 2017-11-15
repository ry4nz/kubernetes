package ucpnodeselector

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/go-connections/tlsconfig"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
	authUser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/apps"
	"k8s.io/kubernetes/pkg/apis/batch"
	"k8s.io/kubernetes/pkg/apis/extensions"
)

// The UCPNodeSelector admission controller adds a
// com.docker.ucp.orchestrator.kubernetes=true node selector to all pods not
// in the kube-system namespace. This ensures that user workloads always run
// on UCP nodes marked for Kubernetes. It also adds a node affinity to prevent
// pods from running on manager nodes depending on UCP's settings (as gathered
// from the /api/authz/managerscheduling UCP endpoint).

const (
	key      = "key.pem"
	cert     = "cert.pem"
	rootCA   = "ca.pem"
	apiPath  = "/api/authz/managerscheduling"
	queryKey = "user"

	kubeSystemNamespace   = "kube-system"
	kubeNodeSelectorLabel = "com.docker.ucp.orchestrator.kubernetes"
	kubeNodeSelectorValue = "true"

	ucpSystemCollectionLabel = "com.docker.ucp.collection.system"
	ucpCollectionLabelValue  = "true"
)

var systemUsers = []string{
	authUser.APIServerUser,
	authUser.KubeProxy,
	authUser.KubeControllerManager,
	authUser.KubeScheduler,
}

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register("UCPNodeSelector", func(config io.Reader) (admission.Interface, error) {
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

		return NewUCPNodeSelector(httpClient), nil
	})
}

type ucpNodeSelector struct {
	*admission.Handler
	ucpLocation  string
	httpClient   *http.Client
	systemPrefix string
}

// Admit handles resources that are passed through this admission controller
func (a *ucpNodeSelector) Admit(attributes admission.Attributes) (err error) {
	if !objectHasPodSpec(attributes.GetObject()) {
		return nil
	}
	if attributes.GetOperation() == admission.Update && !objectSupportsNodeSelectorUpdates(attributes.GetObject()) {
		return nil
	}
	namespace := attributes.GetNamespace()
	nodeSelector := map[string]string{}
	nodeAffinityRequirements := []api.NodeSelectorTerm{}
	// Don't do anything for system pods
	if namespace != kubeSystemNamespace {
		nodeSelector[kubeNodeSelectorLabel] = kubeNodeSelectorValue
	}

	user := attributes.GetUserInfo().GetName()
	hasSystemPrefix := a.systemPrefix != "" && strings.HasPrefix(user, a.systemPrefix)
	isSystemUser := false
	for _, systemUser := range systemUsers {
		if user == systemUser {
			isSystemUser = true
			break
		}
	}
	if !(isSystemUser || hasSystemPrefix) {
		allowsManagerScheduling, err := a.allowsManagerScheduling(user)
		if err != nil {
			return apierrors.NewInternalError(err)
		}
		if !allowsManagerScheduling {
			matchExpressions := []api.NodeSelectorRequirement{{
				Key:      ucpSystemCollectionLabel,
				Operator: api.NodeSelectorOpNotIn,
				Values:   []string{ucpCollectionLabelValue},
			}}
			nodeAffinityRequirements = append(nodeAffinityRequirements, api.NodeSelectorTerm{
				MatchExpressions: matchExpressions,
			})
		}
	}
	updatePodSpecForObject(attributes.GetObject(), nodeSelector, nodeAffinityRequirements)

	return nil
}

// NewUCPNodeSelector returns a UCP node selector admission controller
func NewUCPNodeSelector(httpClient *http.Client) admission.Interface {
	return &ucpNodeSelector{
		Handler:      admission.NewHandler(admission.Create, admission.Update),
		ucpLocation:  os.Getenv("UCP_URL"),
		httpClient:   httpClient,
		systemPrefix: os.Getenv("SYSTEM_PREFIX"),
	}
}

func (a *ucpNodeSelector) allowsManagerScheduling(username string) (bool, error) {
	u, err := url.Parse(a.ucpLocation)
	if err != nil {
		return false, fmt.Errorf("unable to parse UCP location \"%s\": %s", a.ucpLocation, err)
	}
	u.Path = apiPath
	q := u.Query()
	q.Set("user", username)
	u.RawQuery = q.Encode()

	resp, err := a.httpClient.Get(u.String())
	if err != nil {
		return false, fmt.Errorf("unable to lookup manager scheduling settings for user \"%s\" at %s: %s", username, u.String(), err)
	}

	defer resp.Body.Close()
	msg, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("unable to lookup manager scheduling settings for user \"%s\": received status code %d but unable to read response message: %s", username, resp.StatusCode, err)
	}
	msgStr := strings.TrimSpace(string(msg))

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unable to lookup manager scheduling settings for user \"%s\": received status code %d: %s", username, resp.StatusCode, msgStr)
	}

	switch msgStr {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("unknown response \"%s\" while looking manager scheduling settings for user \"%s\"", msgStr, username)
	}
}

func objectHasPodSpec(runtimeObject runtime.Object) bool {
	switch runtimeObject.(type) {
	case *api.Pod, *api.PodTemplate, *api.ReplicationController, *apps.StatefulSet, *extensions.DaemonSet, *extensions.Deployment, *extensions.ReplicaSet, *batch.Job, *batch.CronJob:
		return true
	default:
		return false
	}
}

func objectSupportsNodeSelectorUpdates(runtimeObject runtime.Object) bool {
	// Pods and jobs cannot have their node selectors updated except at
	// creation
	switch runtimeObject.(type) {
	case *api.Pod, *batch.Job:
		return false
	default:
		return true
	}
}

func updatePodSpecForObject(runtimeObject runtime.Object, nodeSelector map[string]string, nodeAffinityRequirements []api.NodeSelectorTerm) {
	switch object := runtimeObject.(type) {
	case *api.Pod:
		mergePodSpec(&object.Spec, nodeSelector, nodeAffinityRequirements)
	case *api.PodTemplate:
		mergePodSpec(&object.Template.Spec, nodeSelector, nodeAffinityRequirements)
	case *api.ReplicationController:
		mergePodSpec(&object.Spec.Template.Spec, nodeSelector, nodeAffinityRequirements)
	case *apps.StatefulSet:
		mergePodSpec(&object.Spec.Template.Spec, nodeSelector, nodeAffinityRequirements)
	case *extensions.DaemonSet:
		mergePodSpec(&object.Spec.Template.Spec, nodeSelector, nodeAffinityRequirements)
	case *extensions.Deployment:
		mergePodSpec(&object.Spec.Template.Spec, nodeSelector, nodeAffinityRequirements)
	case *extensions.ReplicaSet:
		mergePodSpec(&object.Spec.Template.Spec, nodeSelector, nodeAffinityRequirements)
	case *batch.Job:
		mergePodSpec(&object.Spec.Template.Spec, nodeSelector, nodeAffinityRequirements)
	case *batch.CronJob:
		mergePodSpec(&object.Spec.JobTemplate.Spec.Template.Spec, nodeSelector, nodeAffinityRequirements)
	default:
		// Ignore all calls for objects that do not contain a Pod Spec.
	}
}

func mergePodSpec(podSpec *api.PodSpec, nodeSelector map[string]string, nodeAffinityRequirements []api.NodeSelectorTerm) {
	if len(nodeSelector) > 0 {
		if podSpec.NodeSelector == nil {
			podSpec.NodeSelector = map[string]string{}
		}
		for k, v := range nodeSelector {
			podSpec.NodeSelector[k] = v
		}
	}
	if len(nodeAffinityRequirements) > 0 {
		if podSpec.Affinity == nil {
			podSpec.Affinity = &api.Affinity{}
		}
		if podSpec.Affinity.NodeAffinity == nil {
			podSpec.Affinity.NodeAffinity = &api.NodeAffinity{}
		}
		if podSpec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
			podSpec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution = &api.NodeSelector{}
		}
		podSpec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms = append(podSpec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms, nodeAffinityRequirements...)
	}
}
