package ucpadminserviceaccount

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	kubeapiserveradmission "k8s.io/kubernetes/pkg/kubeapiserver/admission"
	"k8s.io/kubernetes/plugin/pkg/admission/ucputil"
)

// The UCPAdminServiceAccount admission controller injects the
// `default` service account to all PodSpecs created by an admin-level user
// and the `nonadmindefault` service account to all PodSpecs created by a
// non-admin user.
// It is intended to be chained before the ServiceAccount admission controller

const (
	key                               = "key.pem"
	cert                              = "cert.pem"
	rootCA                            = "ca.pem"
	isAdminPath                       = "/api/authz/isadmin"
	defaultServiceAccountName         = "default"
	nonAdminDefaultServiceAccountName = "nonadmindefault"
)

const (
	PluginName = "UCPAdminServiceAccount"
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

		return NewUCPAdminServiceAccount(httpClient), nil
	})
}

type ucpAdminServiceAccount struct {
	*admission.Handler
	ucpLocation string
	httpClient  *http.Client

	client internalclientset.Interface
}

var _ = kubeapiserveradmission.WantsInternalKubeClientSet(&ucpAdminServiceAccount{})

// Validate ensures the client is set
func (a *ucpAdminServiceAccount) Validate() error {
	if a.client == nil {
		return fmt.Errorf("missing client")
	}

	return nil
}

func (a *ucpAdminServiceAccount) SetInternalKubeClientSet(cl internalclientset.Interface) {
	a.client = cl
}

func (a *ucpAdminServiceAccount) Admit(attributes admission.Attributes) (err error) {
	user := attributes.GetUserInfo().GetName()
	log.Debugf("the user is: %s", user)

	podSpec := ucputil.GetPodSpecFromObject(attributes.GetObject())
	if podSpec == nil {
		// The resource is not a known object type which contains a PodSpec
		return nil
	}

	if podSpec.ServiceAccountName == "" {
		isAdmin, err := a.isAdmin(user)
		if err != nil {
			return apierrors.NewInternalError(err)
		}
		if isAdmin {
			podSpec.ServiceAccountName = defaultServiceAccountName
		} else {
			podSpec.ServiceAccountName = nonAdminDefaultServiceAccountName
			// Attempt to create the service account and fail silently
			_, err := a.client.Core().ServiceAccounts(attributes.GetNamespace()).Create(&api.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name: nonAdminDefaultServiceAccountName,
				},
			})
			if err != nil && !apierrors.IsAlreadyExists(err) {
				return apierrors.NewInternalError(err)
			}
		}
	}
	return nil
}

// TODO(alexmavr): DRY across other admission controllers
func (a *ucpAdminServiceAccount) isAdmin(username string) (bool, error) {
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

// NewUCPAdminServiceAccount returns a new admission controller
func NewUCPAdminServiceAccount(httpClient *http.Client) admission.Interface {
	return &ucpAdminServiceAccount{
		Handler:     admission.NewHandler(admission.Create, admission.Update),
		ucpLocation: os.Getenv("UCP_URL"),
		httpClient:  httpClient,
	}
}
