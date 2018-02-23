package ucpnodeselector

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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
	"k8s.io/kubernetes/pkg/apis/batch"
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
)

var (
	orchestratorToleration = api.Toleration{
		Key:      "com.docker.ucp.orchestrator.kubernetes",
		Operator: api.TolerationOpExists,
		// Zero value for Effect matches all taint effects.
	}

	systemToleration = api.Toleration{
		Key:      "com.docker.ucp.manager",
		Operator: api.TolerationOpExists,
		// Zero value for Effect matches all taint effects.
	}
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
func (a *ucpNodeSelector) Admit(attributes admission.Attributes) error {
	object := attributes.GetObject()

	// Jobs don't support PodTemplateSpec updates.
	if _, ok := object.(*batch.Job); ok && attributes.GetOperation() == admission.Update {
		return nil
	}

	podSpec := ucputil.GetPodSpecFromObject(object)
	if podSpec == nil {
		return nil
	}

	var tolerations []api.Toleration
	// UCP adds an orchestratorToleration.Key:NoExecute taint to swarm-only
	// nodes and adds a systemToleration.Key:NoSchedule taint to manager/DTR
	// nodes. Remove tolerations with these keys from the pod if they are present.
	for _, t := range podSpec.Tolerations {
		if t.Key != orchestratorToleration.Key && t.Key != systemToleration.Key {
			tolerations = append(tolerations, t)
		}
	}

	if attributes.GetNamespace() == kubeSystemNamespace {
		// Check if the kube-system pod has the orchestrator and system tolerations
		// already.
		var hasOrchestratorToleration, hasSystemToleration bool
		// Note: We check the actual pod tolerations here.
		for _, t := range podSpec.Tolerations {
			if t == orchestratorToleration {
				hasOrchestratorToleration = true
			} else if t == systemToleration {
				hasSystemToleration = true
			}
		}
		if hasOrchestratorToleration && hasSystemToleration {
			// If these tolerations are already present, we have nothing to do.
			return nil
		}
		// Add an orchestratorToleration and a systemToleration to kube-system pods
		// so they can run on swarm-only, UCP manager, and DTR nodes.
		// Note: We add both these tolerations to the `tolerations` list, not to the
		// actual pod tolerations.
		tolerations = append(tolerations, orchestratorToleration)
		tolerations = append(tolerations, systemToleration)
	} else {
		user := attributes.GetUserInfo().GetName()
		hasSystemPrefix := a.systemPrefix != "" && strings.HasPrefix(user, a.systemPrefix)
		isSystemUser := false
		for _, systemUser := range systemUsers {
			if user == systemUser {
				isSystemUser = true
				break
			}
		}

		if hasSystemPrefix || isSystemUser {
			// If this is a system pod, do not modify it.
			return nil
		}

		allowsManagerScheduling, err := a.allowsManagerScheduling(user)
		if err != nil {
			return apierrors.NewInternalError(err)
		}
		if allowsManagerScheduling {
			// Add a systemToleration to pods run by users who are allowed to schedule
			// on manager/DTR nodes.
			tolerations = append(tolerations, systemToleration)
		}
	}

	podSpec.Tolerations = tolerations

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

// allowsManagerScheduling takes a username and returns if the user is allowed
// to schedule pods on a manager/DTR node.
func (a *ucpNodeSelector) allowsManagerScheduling(username string) (bool, error) {
	u, err := url.Parse(a.ucpLocation)
	if err != nil {
		return false, fmt.Errorf("unable to parse UCP location %q: %s", a.ucpLocation, err)
	}
	u.Path = apiPath
	q := u.Query()
	q.Set("user", username)
	u.RawQuery = q.Encode()

	resp, err := a.httpClient.Get(u.String())
	if err != nil {
		return false, fmt.Errorf("unable to perform request for user %q at %s: %s", username, u.String(), err)
	}
	defer resp.Body.Close()

	res := false
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return false, fmt.Errorf("unable to unmarshal response: %s", err)
	}
	return res, nil
}
