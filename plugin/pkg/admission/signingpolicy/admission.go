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
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/apps"
	"k8s.io/kubernetes/pkg/apis/batch"
	"k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	kubeapiserveradmission "k8s.io/kubernetes/pkg/kubeapiserver/admission"
)

const (
	key     = "key.pem"
	cert    = "cert.pem"
	rootCA  = "ca.pem"
	apiPath = "/api/dct/resolveimage"
)

type dctResolveImageResponse struct {
	ResolvedImages map[string]string `json:"resolvedImages"`
	ErrorMessages  []string          `json:"errorMessages"`
}

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register("CheckImageSigning", func(config io.Reader) (admission.Interface, error) {
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
	internalKubeClient internalclientset.Interface
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

var _ = kubeapiserveradmission.WantsInternalKubeClientSet(&signingPolicy{})

func (a *signingPolicy) SetInternalKubeClientSet(internalKubeClient internalclientset.Interface) {
	a.internalKubeClient = internalKubeClient
}

func (a *signingPolicy) Validate() error {
	if a.internalKubeClient == nil {
		return fmt.Errorf("missing internal kube client")
	}
	return nil
}

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

func (a *signingPolicy) Admit(attributes admission.Attributes) (err error) {
	defer func() {
		if err != nil {
			log.Errorf("[DCT Signing Policy]: %s", err)
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

	podSpec := getPodSpecFromObject(attributes.GetObject())
	if podSpec == nil {
		return nil // The object does not contain a Pod Spec.
	}

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

	// Convert the set back into a list.
	containerImages := make([]string, 0, len(containerImageSet))
	for containerImage := range containerImageSet {
		containerImages = append(containerImages, containerImage)
	}

	response, err := a.resolveImages(containerImages, imagePullSecretsData)
	if err != nil {
		return apierrors.NewInternalError(err)
	}

	log.Infof("[DCT Signing Policy] Resolved Images: %s", response.ResolvedImages)
	log.Infof("[DCT Signing Policy] Error Messages: %s", response.ErrorMessages)

	// Update the pod spec with the resolved images. If an image in not in
	// the resolved mapping then it does not meet the signing requirements.
	policyViolatingImageSet := map[string]struct{}{}

	for i, container := range podSpec.InitContainers {
		if resolvedImage, ok := response.ResolvedImages[container.Image]; ok {
			podSpec.InitContainers[i].Image = resolvedImage
		} else {
			policyViolatingImageSet[container.Image] = struct{}{}
		}
	}
	for i, container := range podSpec.Containers {
		if resolvedImage, ok := response.ResolvedImages[container.Image]; ok {
			podSpec.Containers[i].Image = resolvedImage
		} else {
			policyViolatingImageSet[container.Image] = struct{}{}
		}
	}

	// If there were any images which violated the policy, return an error
	// which also notifies about the bad images.
	if len(policyViolatingImageSet) > 0 || len(response.ErrorMessages) > 0 {
		policyViolatingImages := make([]string, 0, len(policyViolatingImageSet))
		for image := range policyViolatingImageSet {
			policyViolatingImages = append(policyViolatingImages, image)
		}
		return admission.NewForbidden(attributes, fmt.Errorf("one or more images do not meet the required signing policy: %s; additional error messages: %s", policyViolatingImages, response.ErrorMessages))
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
