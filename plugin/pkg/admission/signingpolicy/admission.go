package signingpolicy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/docker/go-connections/tlsconfig"
	log "github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
)

const (
	key     = "key.pem"
	cert    = "cert.pem"
	rootCA  = "ca.pem"
	apiPath = "/api/dct/resolveimage/"
)

const (
	PluginName = "CheckImageSigning"
)

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register("CheckImageSigning", func(config io.Reader) (admission.Interface, error) {
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

		return NewSignedImage(httpClient), nil
	})
}

type signingPolicy struct {
	*admission.Handler
	ucpLocation string
	httpClient  *http.Client
}

func (a *signingPolicy) Admit(attributes admission.Attributes) (err error) {
	// Ignore all calls to subresources or resources other than pods.
	if len(attributes.GetSubresource()) != 0 || attributes.GetResource().GroupResource() != api.Resource("pods") {
		return nil
	}
	user := attributes.GetUserInfo().GetName()
	log.Debugf("the user is: %s", user)
	pod, ok := attributes.GetObject().(*api.Pod)
	if !ok {
		return apierrors.NewBadRequest("Resource was marked with kind Pod but was unable to be converted")
	}

	for i, container := range pod.Spec.InitContainers {
		image := container.Image
		resolved, err := a.resolve(image, user)
		if err != nil {
			log.Infof("Reject image %s", image)
			return err
		}
		log.Infof("Accept image %s, using now %s", image, resolved)
		pod.Spec.InitContainers[i].Image = resolved
	}

	for i, container := range pod.Spec.Containers {
		image := container.Image
		resolved, err := a.resolve(image, user)
		if err != nil {
			log.Infof("Reject image %s", image)
			return err
		}
		log.Infof("Accept image %s, using now %s", image, resolved)
		pod.Spec.Containers[i].Image = resolved
	}
	return nil
}

//NewSignedImage returns a signing policy handler
func NewSignedImage(httpClient *http.Client) admission.Interface {
	return &signingPolicy{
		Handler:     admission.NewHandler(admission.Create, admission.Update),
		ucpLocation: os.Getenv("UCP_URL"),
		httpClient:  httpClient,
	}
}

func (a *signingPolicy) resolve(image, user string) (string, error) {
	if a.ucpLocation == "" {
		return "", errors.New("unable to resolve image: UCP controller location not configured")
	}
	img, err := a.checkUCPSigningPolicy(image, user)
	if err != nil {
		return "", err
	}
	if img == "" {
		return "", fmt.Errorf("%s is not signed", image)
	}
	return img, nil
}

func (a *signingPolicy) checkUCPSigningPolicy(image, user string) (string, error) {

	apiArgs := url.Values{}
	apiArgs.Set("image", image)
	apiArgs.Set("user", user)
	resp, err := a.httpClient.PostForm(a.ucpLocation+apiPath, apiArgs)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	//check status code
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden {
			return "", nil

		}
		errMsg, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("UCP returned http statuscode %s", resp.StatusCode)
		}
		return "", fmt.Errorf("UCP returned http statuscode %s: %s", resp.StatusCode, errMsg)
	}
	img, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(img), nil
}
