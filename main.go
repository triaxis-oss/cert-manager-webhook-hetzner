package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

type Record struct {
	Type    string `json:"type"`
	ID      int64  `json:"id,omitempty"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int64  `json:"ttl,omitempty"`
	Note    string `json:"note,omitempty"`
}

type Records struct {
	Items []Record
}

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&websupportDNSProviderSolver{},
	)
}

// websupportDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type websupportDNSProviderSolver struct {
	client *kubernetes.Clientset
}

// websupportDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type websupportDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	APIRoot         string
	APIKeySecretRef cmmeta.SecretKeySelector `json:"apiKeySecretRef"`
	APIKey          string                   `json:"apiKey"`
	APISecretRef    cmmeta.SecretKeySelector `json:"apiSecretRef"`
	APISecret       string                   `json:"apiSecret"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *websupportDNSProviderSolver) Name() string {
	return "websupport"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *websupportDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(c, ch)
	if err != nil {
		return err
	}

	zone := ch.ResolvedZone
	name := ch.ResolvedFQDN
	if strings.HasSuffix(name, "."+zone) {
		name = name[:len(name)-len(zone)-1]
	}
	zone = strings.TrimRight(zone, ".")

	data, err := json.Marshal(Record{
		Type:    "TXT",
		Name:    name,
		Content: ch.Key,
		TTL:     10,
	})
	if err != nil {
		return err
	}

	_, err = c.WSAPI(ch, &cfg, "POST", "/v1/user/self/zone/"+zone+"/record", bytes.NewBuffer(data))
	return err
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *websupportDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(c, ch)
	if err != nil {
		return err
	}

	zone := ch.ResolvedZone
	name := ch.ResolvedFQDN
	if strings.HasSuffix(name, "."+zone) {
		name = name[:len(name)-len(zone)-1]
	}
	zone = strings.TrimRight(zone, ".")

	var records Records

	recordData, err := c.WSAPI(ch, &cfg, "GET", "/v1/user/self/zone/"+zone+"/record", nil)
	if err == nil {
		err = json.Unmarshal(recordData, &records)
	}
	if err != nil {
		return err
	}

	var found *Record = nil

	for _, record := range records.Items {
		if record.Type == "TXT" && record.Name == name && record.Content == ch.Key {
			found = &record
			log.Printf("Deleting record ID %d", record.ID)
			_, err = c.WSAPI(ch, &cfg, "DELETE", fmt.Sprintf("/v1/user/self/zone/%s/record/%d", zone, record.ID), nil)
			if err != nil {
				return err
			}
		}
	}

	if found == nil {
		log.Printf("Record %s for domain %s not found", ch.Key, ch.ResolvedFQDN)
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *websupportDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(c *websupportDNSProviderSolver, ch *v1alpha1.ChallengeRequest) (websupportDNSProviderConfig, error) {
	cfg := websupportDNSProviderConfig{}
	cfgJSON := ch.Config

	// default values
	cfg.APIRoot = "https://rest.websupport.sk"

	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}

	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *websupportDNSProviderSolver) parseSecret(namespace string, value string, ref *cmmeta.SecretKeySelector) (string, error) {
	if value == "" && ref.Name != "" && ref.Key != "" {
		secret, err := c.client.CoreV1().Secrets(namespace).Get(ref.Name, metav1.GetOptions{})
		if err != nil {
			return value, err
		}
		value = string(secret.Data[ref.Key])
		log.Printf("Resolved secret %s:%s:%s: %s", namespace, ref.Name, ref.Key, value)
	} else {
		log.Println("Not resolving secret, value found:", value)
	}
	
	return value, nil
}

func (c *websupportDNSProviderSolver) WSAPI(ch *v1alpha1.ChallengeRequest, cfg *websupportDNSProviderConfig, method string, url string, body io.Reader) ([]byte, error) {
	now := time.Now().UTC()

	secret, err := c.parseSecret(ch.ResourceNamespace, cfg.APISecret, &cfg.APISecretRef)
	if err != nil {
		return nil, err
	}

	hash := hmac.New(sha1.New, []byte(secret))
	canonical := fmt.Sprintf("%s %s %d", method, url, now.Unix())
	log.Println("WSAPI >>", canonical, secret)
	hash.Write([]byte(canonical))
	sig := hex.EncodeToString(hash.Sum(nil))

	client := &http.Client{}
	req, err := http.NewRequest(method, cfg.APIRoot+url, body)
	if err != nil {
		return nil, err
	}

	key, err := c.parseSecret(ch.ResourceNamespace, cfg.APIKey, &cfg.APIKeySecretRef)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(key, sig)
	log.Println("Auth:", key, sig)
	req.Header.Set("Date", now.Format(time.RFC3339))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode/100 != 2 {
		err = fmt.Errorf("WSAPI !! %d %s", resp.StatusCode, resp.Status)
		log.Println(err)
		return nil, err
	}

	log.Printf("Response: %v", string(data))

	return data, nil
}
