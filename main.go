package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

type zoneResponseMessage struct {
	Zones []zoneResponse `json:"zones"`
}

type zoneResponse struct {
	ID string `json:"id"`
}

type record struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name"`
	TTL    uint64 `json:"ttl"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	ZoneID string `json:"zone_id"`
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
		&hetznerDNSProviderSolver{},
	)
}

// hetznerDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type hetznerDNSProviderSolver struct {
	client *kubernetes.Clientset
}

// hetznerDNSProviderConfig is a structure that is used to decode into when
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
type hetznerDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	APIRoot         string
	APIKeySecretRef cmmeta.SecretKeySelector `json:"apiKeySecretRef"`
	APIKey          string                   `json:"apiKey"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *hetznerDNSProviderSolver) Name() string {
	return "hetzner"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *hetznerDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(c, ch)
	if err != nil {
		return err
	}

	zoneID, name, err := c.getZoneID(ch, &cfg)
	if err != nil {
		return err
	}

	record := record{
		ZoneID: zoneID,
		Name:   name,
		TTL:    10,
		Type:   "TXT",
		Value:  ch.Key,
	}

	err = c.callAPI(ch, &cfg, "POST", "/records", record, nil)
	return err
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *hetznerDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(c, ch)
	if err != nil {
		return err
	}

	zoneID, name, err := c.getZoneID(ch, &cfg)
	if err != nil {
		return err
	}

	var recordData struct {
		Records []record `json:"records"`
	}

	err = c.callAPI(ch, &cfg, "GET", "/records?zone_id="+zoneID, nil, &recordData)
	if err != nil {
		return err
	}

	var found *record = nil

	for _, record := range recordData.Records {
		if record.Type == "TXT" && record.Name == name && record.Value == ch.Key {
			found = &record
			log.Printf("Deleting record ID %s", record.ID)
			err = c.callAPI(ch, &cfg, "DELETE", "/records/"+record.ID, nil, nil)
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
func (c *hetznerDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(c *hetznerDNSProviderSolver, ch *v1alpha1.ChallengeRequest) (hetznerDNSProviderConfig, error) {
	cfg := hetznerDNSProviderConfig{}
	cfgJSON := ch.Config

	// default values
	cfg.APIRoot = "https://dns.hetzner.com/api/v1"

	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}

	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *hetznerDNSProviderSolver) parseSecret(namespace string, value string, ref *cmmeta.SecretKeySelector) (string, error) {
	if value == "" && ref.Name != "" && ref.Key != "" {
		secret, err := c.client.CoreV1().Secrets(namespace).Get(ref.Name, metav1.GetOptions{})
		if err != nil {
			return value, err
		}
		value = string(secret.Data[ref.Key])
		log.Printf("Resolved secret %s:%s:%s", namespace, ref.Name, ref.Key)
	} else {
		log.Println("Not resolving secret, using provided value")
	}

	return value, nil
}

func (c *hetznerDNSProviderSolver) getZoneID(ch *v1alpha1.ChallengeRequest, cfg *hetznerDNSProviderConfig) (string, string, error) {
	zone := ch.ResolvedZone
	name := ch.ResolvedFQDN
	if strings.HasSuffix(name, "."+zone) {
		name = name[:len(name)-len(zone)-1]
	}
	zone = strings.TrimRight(zone, ".")

	if zone == "" {
		return zone, name, fmt.Errorf("No zone provided in challenge")
	}

	var msg zoneResponseMessage
	var zoneID string

	err := c.callAPI(ch, cfg, "GET", "/zones?name="+zone, nil, &msg)
	if err == nil {
		if len(msg.Zones) == 1 {
			zoneID = msg.Zones[0].ID
			log.Printf("Zone %s ID: %s", zone, zoneID)
		} else {
			err = fmt.Errorf("Zone not found: %s", zone)
		}
	}

	return zoneID, name, err
}

func (c *hetznerDNSProviderSolver) callAPI(ch *v1alpha1.ChallengeRequest, cfg *hetznerDNSProviderConfig, method string, url string, request interface{}, resp interface{}) error {
	var body []byte = nil
	var err error

	if request != nil {
		body, err = json.Marshal(request)
		if err != nil {
			return err
		}
		log.Println("API >>", method, url, string(body))
	} else {
		log.Println("API >>", method, url)
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, cfg.APIRoot+url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	key, err := c.parseSecret(ch.ResourceNamespace, cfg.APIKey, &cfg.APIKeySecretRef)
	if err != nil {
		return err
	}

	req.Header.Set("Auth-API-Token", key)

	respData, err := client.Do(req)
	if err != nil {
		return err
	}

	defer respData.Body.Close()

	data, err := ioutil.ReadAll(respData.Body)
	if err != nil {
		return err
	}

	if respData.StatusCode/100 != 2 {
		err = fmt.Errorf("API !! %d %s", respData.StatusCode, respData.Status)
		log.Println(err)
		return err
	}

	log.Printf("API << %v", string(data))

	if resp != nil {
		err = json.Unmarshal(data, resp)
		if err != nil {
			return err
		}
	}

	return nil
}
