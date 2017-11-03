package ucpauthz

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
	log "github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	key      = "key.pem"
	cert     = "cert.pem"
	rootCA   = "ca.pem"
	apiPath  = "/api/authz/isadmin"
	queryKey = "user"
)

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

func (a *ucpAuthz) Admit(attributes admission.Attributes) (err error) {
	user := attributes.GetUserInfo().GetName()
	log.Debugf("the user is: %s", user)

	// Always admit requests from system components
	if a.systemPrefix != "" && strings.HasPrefix(user, a.systemPrefix) {
		return nil
	}

	podSpec := getPodSpecFromObject(attributes.GetObject())
	if podSpec == nil {
		// The resource is not a known object type which contains a PodSpec
		return nil
	}

	// The `default` service account of each namespace is permitted because its
	// permissions are blocked via authorization.
	if podSpec.ServiceAccountName != "" && podSpec.ServiceAccountName != "default" {
		isAdmin, err := a.isAdmin(user)
		if err != nil {
			return apierrors.NewInternalError(err)
		}
		if !isAdmin {
			return admission.NewForbidden(attributes, fmt.Errorf("only docker EE admin users are permitted to use service accounts other than `default`"))
		}
	}

	return nil
}

func (a *ucpAuthz) isAdmin(username string) (bool, error) {
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
