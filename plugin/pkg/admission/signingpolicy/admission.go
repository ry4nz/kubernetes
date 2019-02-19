package signingpolicy

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/plugin/pkg/admission/ucputil"
)

const (
	key     = "key.pem"
	cert    = "cert.pem"
	rootCA  = "ca.pem"
	apiPath = "/api/dct/resolveimage"
)

const (
	PluginName = "CheckImageSigning"
)

type dctResolveImageResponse struct {
	ResolvedImages map[string]string `json:"resolvedImages"`
	ErrorMessages  []string          `json:"errorMessages"`
}

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(config io.Reader) (admission.Interface, error) {
		var tlsConfig *tls.Config
		var err error

		ucpURL := os.Getenv("UCP_URL")
		if ucpURL == "" {
			return nil, fmt.Errorf("UCP controller location not configured")
		}
		if !strings.HasPrefix(strings.ToLower(ucpURL), "https://") {
			return nil, fmt.Errorf("UCP conroller location must use HTTPS")
		}

		certDir := os.Getenv("CERT_DIR")
		if certDir == "" {
			return nil, fmt.Errorf("certificate directory not specified: image signing policy webhook MUST use mutual TLS authentication")
		}

		tlsConfig, err = tlsconfig.Client(tlsconfig.Options{
			CAFile:   filepath.Join(certDir, rootCA),
			CertFile: filepath.Join(certDir, cert),
			KeyFile:  filepath.Join(certDir, key),
		})
		if err != nil {
			return nil, fmt.Errorf("unable to configure TLS client: %s", err)
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

		return NewSignedImage(httpClient, ucpURL), nil
	})
}

type signingPolicy struct {
	*admission.Handler
	ucpWebHookURL      string
	httpClient         *http.Client
	internalKubeClient kubernetes.Interface
	systemUserPrefix   string
}

//NewSignedImage returns a signing policy handler
func NewSignedImage(httpClient *http.Client, ucpURL string) admission.Interface {
	return &signingPolicy{
		Handler:          admission.NewHandler(admission.Create, admission.Update),
		ucpWebHookURL:    ucpURL + apiPath,
		httpClient:       httpClient,
		systemUserPrefix: os.Getenv("SYSTEM_PREFIX"),
	}
}

// SetExternalKubeClientSet implements the WantsInternalKubeClientSet interface.
func (p *signingPolicy) SetExternalKubeClientSet(client kubernetes.Interface) {
	p.internalKubeClient = client
}

func (a *signingPolicy) ValidateInitialization() error {
	if a.internalKubeClient == nil {
		return fmt.Errorf("missing internal kube client")
	}
	return nil
}

func getOldImageSet(oldObject runtime.Object) map[string]struct{} {
	oldPodSpec := ucputil.GetPodSpecFromObject(oldObject)
	if oldPodSpec == nil {
		return nil
	}

	oldImageSet := map[string]struct{}{}
	for _, container := range oldPodSpec.InitContainers {
		oldImageSet[container.Image] = struct{}{}
	}
	for _, container := range oldPodSpec.Containers {
		oldImageSet[container.Image] = struct{}{}
	}

	return oldImageSet
}

func (a *signingPolicy) Admit(attributes admission.Attributes) (err error) {
	defer func() {
		if err != nil {
			log.Errorf("[DCT Signing Policy] error: %s", err)
		}
	}()

	if a.systemUserPrefix != "" && strings.HasPrefix(attributes.GetUserInfo().GetName(), a.systemUserPrefix) {
		// Give system components a free pass. These are usually requests from
		// a system component (like the kube controller manager) which is
		// creating or updating a sub-object for which there would be a PodSpec
		// which has already gone through admission control (e.g., when a
		// Deployment was created).
		return nil
	}

	podSpec := ucputil.GetPodSpecFromObject(attributes.GetObject())
	if podSpec == nil {
		return nil // The object does not contain a Pod Spec.
	}

	log.WithFields(log.Fields{
		"op":            attributes.GetOperation(),
		"kind":          attributes.GetKind(),
		"groupResource": attributes.GetResource().GroupResource(),
		"namespace":     attributes.GetNamespace(),
		"name":          attributes.GetName(),
	}).Infof("DCT Image Signing Policy Check")

	// Images from private registries or repositories require the user to
	// specify image pull secrets so that the kubelet can have access to pull
	// the images. The same credentials are also necessary when looking up a
	// Notary repository.
	imagePullSecretsData := make([]string, len(podSpec.ImagePullSecrets))
	for i, secretRef := range podSpec.ImagePullSecrets {
		secret, err := a.internalKubeClient.Core().Secrets(attributes.GetNamespace()).Get(secretRef.Name, metav1.GetOptions{})
		if err != nil {
			return admission.NewForbidden(attributes, fmt.Errorf("unable to lookup image pull secret %q from namespace %q: %s", secretRef.Name, attributes.GetNamespace(), err))
		}

		// The data is a JSON object. Something like:
		//   {"registry.example.com":{"authCreds":"secretcredentialvalue"}}
		if cfgData, ok := secret.Data[".dockercfg"]; ok {
			imagePullSecretsData[i] = base64.URLEncoding.EncodeToString(cfgData)
		}
	}

	// Put the container image names into a set to de-duplicate the values.
	containerImageSet := map[string]struct{}{}
	for _, container := range podSpec.InitContainers {
		containerImageSet[container.Image] = struct{}{}
	}
	for _, container := range podSpec.Containers {
		containerImageSet[container.Image] = struct{}{}
	}

	var oldImageSet map[string]struct{}
	if attributes.GetOperation() == admission.Update {
		oldImageSet = getOldImageSet(attributes.GetOldObject())
	}

	// Convert the set back into a list; filter out images from the old spec if
	// this is an update.
	containerImages := make([]string, 0, len(containerImageSet))
	for containerImage := range containerImageSet {
		if _, inOldSpec := oldImageSet[containerImage]; !inOldSpec {
			containerImages = append(containerImages, containerImage)
		}
	}

	if len(containerImages) == 0 {
		// There are no images to check; the update does not modify the images.
		return nil
	}

	response, err := a.resolveImages(containerImages, imagePullSecretsData)
	if err != nil {
		return apierrors.NewInternalError(err)
	}

	log.Infof("[DCT Signing Policy] Resolved Images: %s", response.ResolvedImages)
	log.Infof("[DCT Signing Policy] Error Messages: %s", response.ErrorMessages)

	// If there were any error messages about images which violated the policy,
	// return an error which notifies about the bad images.
	if len(response.ErrorMessages) > 0 {
		return admission.NewForbidden(attributes, fmt.Errorf("one or more container images do not meet the required signing policy: %s", response.ErrorMessages))
	}

	// Update the pod spec with the resolved images.
	for i, container := range podSpec.InitContainers {
		if resolvedImage, ok := response.ResolvedImages[container.Image]; ok {
			podSpec.InitContainers[i].Image = resolvedImage
		}
	}
	for i, container := range podSpec.Containers {
		if resolvedImage, ok := response.ResolvedImages[container.Image]; ok {
			podSpec.Containers[i].Image = resolvedImage
		}
	}

	return nil
}

func (a *signingPolicy) resolveImages(containerImages, imagePullSecrets []string) (*dctResolveImageResponse, error) {
	apiArgs := url.Values{
		"containerImage":  containerImages,
		"imagePullSecret": imagePullSecrets,
	}

	resp, err := a.httpClient.PostForm(a.ucpWebHookURL, apiArgs)
	if err != nil {
		return nil, fmt.Errorf("unable to perform UCP DCT image resolve request: %s", err)
	}
	defer resp.Body.Close()

	//check status code
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("UCP DCT image resolve request returned status %d", resp.StatusCode)
		if bodyContent, err := ioutil.ReadAll(resp.Body); err == nil {
			err = fmt.Errorf("%s: %s", err, bodyContent)
		}
		return nil, err
	}

	var response dctResolveImageResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("could not parse UCP DCT image resolve response as JSON: %s", err)
	}

	return &response, nil
}
