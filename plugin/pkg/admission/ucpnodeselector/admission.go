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
	"k8s.io/apiserver/pkg/admission"
	authUser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/plugin/pkg/admission/ucputil"
)

// The UCPNodeSelector admission controller adds a
// com.docker.ucp.orchestrator.kubernetes:* toleration to pods in the
// kube-system namespace and removes com.docker.ucp.orchestrator.kubernetes
// tolerations from pods in other namespaces.  This ensures that user workloads
// do not run on swarm-only nodes, which UCP taints with
// com.docker.ucp.orchestrator.kubernetes:NoExecute.
//
// It also adds a node affinity to prevent pods from running on manager nodes
// depending on UCP's settings (as gathered from the
// /api/authz/managerscheduling UCP endpoint).

const (
	key      = "key.pem"
	cert     = "cert.pem"
	rootCA   = "ca.pem"
	apiPath  = "/api/authz/managerscheduling"
	queryKey = "user"

	kubeSystemNamespace = "kube-system"

	tolerationKey = "com.docker.ucp.orchestrator.kubernetes"

	ucpSystemCollectionLabel = "com.docker.ucp.collection.system"
	ucpCollectionLabelValue  = "true"
)

const (
	PluginName = "UCPNodeSelector"
)

var systemUsers = []string{
	authUser.APIServerUser,
	authUser.KubeProxy,
	authUser.KubeControllerManager,
	authUser.KubeScheduler,
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
	// Jobs don't support PodTemplateSpec updates.
	if attributes.GetOperation() == admission.Update && attributes.GetKind().GroupKind() == api.Kind("Job") {
		return nil
	}

	podSpec := ucputil.GetPodSpecFromObject(attributes.GetObject())
	if podSpec == nil {
		return nil
	}

	// UCP adds a tolerationKey:NoExecute taint to swarm-only nodes to keep user pods off.
	// First, remove any toleration with that key.
	var tolerations []api.Toleration
	for _, t := range podSpec.Tolerations {
		if t.Key != tolerationKey {
			tolerations = append(tolerations, t)
		}
	}
	// Second, add a tolerationKey:* toleration to kube-system pods so they can run on swarm-only nodes.
	if attributes.GetNamespace() == kubeSystemNamespace {
		tolerations = append(tolerations, api.Toleration{
			Key:      tolerationKey,
			Operator: api.TolerationOpExists,
			// Zero value for Effect matches all taint effects.
		})
	}
	podSpec.Tolerations = tolerations

	// Pods don't support node affinity updates.
	if attributes.GetOperation() == admission.Update && attributes.GetKind().GroupKind() == api.Kind("Pod") {
		return nil
	}

	nodeAffinityRequirements := []api.NodeSelectorTerm{}
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
	addNodeAffinityRequirementsToPodSpec(podSpec, nodeAffinityRequirements)

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

func addNodeAffinityRequirementsToPodSpec(podSpec *api.PodSpec, nodeAffinityRequirements []api.NodeSelectorTerm) {
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
