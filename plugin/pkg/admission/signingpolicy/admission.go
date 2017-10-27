package signingpolicy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"io/ioutil"
	"os"

	"github.com/docker/go-connections/tlsconfig"
	log "github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
)

const (
	key    = "key.pem"
	cert   = "cert.pem"
	rootCA = "ca.pem"
	apiUrl = "/api/dct/resolveimage/"
)

const (
	PluginName = "CheckImageSigning"
)

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(config io.Reader) (admission.Interface, error) {
		return NewSignedImage(), nil
	})
}

type signingPolicy struct {
	*admission.Handler
}

func (a *signingPolicy) Admit(attributes admission.Attributes) (err error) {
	// Ignore all calls to subresources or resources other than pods.
	if len(attributes.GetSubresource()) != 0 || attributes.GetResource().GroupResource() != api.Resource("pods") {
		return nil
	}
	user := attributes.GetUserInfo().GetName()
	pod, ok := attributes.GetObject().(*api.Pod)
	if !ok {
		return apierrors.NewBadRequest("Resource was marked with kind Pod but was unable to be converted")
	}

	for _, container := range pod.Spec.InitContainers {
		image := container.Image
		resolved, err := resolve(image, user)
		if err != nil {
			log.Infof("Reject image %s", image)
			return err
		}
		log.Infof("Accept image %s, using now %s", image, resolved)
		container.Image = resolved
	}

	for _, container := range pod.Spec.Containers {
		image := container.Image
		resolved, err := resolve(image, user)
		if err != nil {
			log.Infof("Reject image %s", image)
			return err
		}
		log.Infof("Accept image %s, using now %s", image, resolved)
		container.Image = resolved
	}
	return nil
}

func NewSignedImage() admission.Interface {
	return &signingPolicy{
		Handler: admission.NewHandler(admission.Create, admission.Update),
	}
}

func resolve(image, user string) (string, error) {
	ucpLocation := os.Getenv("UCP_URL")
	if ucpLocation == "" {
		return "", errors.New("UCP is not configured")
	}
	img, err := checkUCPSigningPolicy(image, ucpLocation, user)
	if err != nil {
		return "", err
	}
	if img == "" {
		return "", errors.New(image + " is not signed")
	}
	//format image
	return img, nil
}

func checkUCPSigningPolicy(image, ucpLocation, user string) (string, error) {
	certDir := os.Getenv("CERT_DIR")
	tlsOptions := tlsconfig.Options{
		CAFile:   certDir + rootCA,
		CertFile: certDir + cert,
		KeyFile:  certDir + key,
	}
	tlsConfig, err := tlsconfig.Client(tlsOptions)
	if err != nil {
		return "", err
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
	apiArgs := url.Values{}
	apiArgs.Set("image", image)
	apiArgs.Set("user", user)
	req, err := httpClient.PostForm(ucpLocation+apiUrl, apiArgs)
	if err != nil {
		return "", err
	}
	defer req.Body.Close()
	//check status code
	if req.StatusCode != http.StatusOK {
		if req.StatusCode == http.StatusForbidden {
			return "", nil

		}
		return "", fmt.Errorf("UCP returned http statuscode %s", req.StatusCode)
	}
	img, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return "", err
	}
	return string(img), nil
}
