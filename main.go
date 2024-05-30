package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	whois "github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"gopkg.in/yaml.v2"
)

// Config struct for the YAML configuration
type Config struct {
	Interval int       `yaml:"interval"`
	Domains  []Domain  `yaml:"domains"`
	Webhooks []Webhook `yaml:"webhooks"`
}

// Domain struct for domain configuration
type Domain struct {
	Name     string    `yaml:"name"`
	Webhooks []Webhook `yaml:"webhooks"`
}

// Webhook struct for webhook configuration
type Webhook struct {
	Type string `yaml:"type"`
	URL  string `yaml:"url"`
}

// DomainInfo struct to hold WHOIS information and DNS resolution
type DomainInfo struct {
	Domain       string
	RegistrarTag string
	NameServers  []string
	CreationDate time.Time
	ExpiryDate   time.Time
	UpdatedDate  time.Time
	IPAddress    string
}

// LoadConfig loads the configuration from a YAML file
func LoadConfig(filePath string) (*Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config Config
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}

	if config.Interval < 5 {
		config.Interval = 5
	}

	return &config, nil
}

// ParseWHOIS parses the WHOIS response to extract relevant information
func ParseWHOIS(domain string, response string) (*DomainInfo, error) {
	domainInfo := &DomainInfo{Domain: domain}

	// Parse the WHOIS response using whois-parser
	result, err := whoisparser.Parse(response)
	if err != nil {
		return nil, err
	}

	if result.Registrar.Name != "" {
		domainInfo.RegistrarTag = result.Registrar.Name
	}

	if result.Domain.NameServers != nil {
		domainInfo.NameServers = result.Domain.NameServers
	}

	if result.Domain.CreatedDate != "" {
		domainInfo.CreationDate = parseDate(result.Domain.CreatedDate)
	}

	if result.Domain.ExpirationDate != "" {
		domainInfo.ExpiryDate = parseDate(result.Domain.ExpirationDate)
	}

	if result.Domain.UpdatedDate != "" {
		domainInfo.UpdatedDate = parseDate(result.Domain.UpdatedDate)
	}

	return domainInfo, nil
}

// ResolveIP resolves the IP address for the APEX of the domain
func ResolveIP(domain string) (string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for domain %s", domain)
	}
	return ips[0].String(), nil
}

// parseDate attempts to parse a date string using multiple formats
func parseDate(dateStr string) time.Time {
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",     // Example: 2006-01-02T15:04:05Z
		"2006-01-02 15:04:05",      // Example: 2006-01-02 15:04:05
		"2006-01-02",               // Example: 2006-01-02
		"02-Jan-2006",              // Example: 02-Jan-2006
		"02-Jan-2006 15:04:05 MST", // Example: 02-Jan-2006 15:04:05 MST
	}

	var parsedDate time.Time
	var err error
	for _, format := range formats {
		parsedDate, err = time.Parse(format, dateStr)
		if err == nil {
			return parsedDate
		}
	}

	// If no format matched, return the zero time
	return time.Time{}
}

// HashDomainInfo computes a hash for the DomainInfo struct to detect changes
func HashDomainInfo(info *DomainInfo) string {
	data := fmt.Sprintf("%v", *info)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
}

// SendWebhook sends a notification to the specified webhook URL
func SendWebhook(webhook Webhook, message string, domainInfo *DomainInfo) error {
	var payload []byte
	var err error

	switch webhook.Type {
	case "pagerduty":
		payload, err = json.Marshal(map[string]interface{}{
			"payload": map[string]string{
				"summary":  message,
				"severity": "info",
				"source":   "domain-monitor",
			},
			"routing_key":  webhook.URL, // Assuming the URL here is the routing key for PagerDuty
			"event_action": "trigger",
		})
	case "teams":
		payload, err = json.Marshal(map[string]string{"text": message})
	case "discord":
		embed := map[string]interface{}{
			"title":       message,
			"description": fmt.Sprintf("Details: \n- Domain: %s\n- Registrar: %s\n- Name Servers: %v\n- Creation Date: %s\n- Expiry Date: %s\n- Updated Date: %s\n- IP Address: %s", domainInfo.Domain, domainInfo.RegistrarTag, domainInfo.NameServers, domainInfo.CreationDate, domainInfo.ExpiryDate, domainInfo.UpdatedDate, domainInfo.IPAddress),
			"color":       3447003, // Blue color
		}
		payload, err = json.Marshal(map[string]interface{}{
			"embeds": []map[string]interface{}{embed},
		})
	default:
		return fmt.Errorf("unsupported webhook type: %s", webhook.Type)
	}

	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", webhook.URL, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("received non-2xx response status: %d", resp.StatusCode)
	}

	return nil
}

// MonitorDomains monitors the domains based on the configuration and sends notifications on changes
func MonitorDomains(config *Config, previousStates map[string]string) map[string]string {
	currentStates := make(map[string]string)

	for _, domain := range config.Domains {
		response, err := whois.Whois(domain.Name)
		if err != nil {
			fmt.Printf("Error fetching WHOIS information for %s: %s\n", domain.Name, err)
			continue
		}

		domainInfo, err := ParseWHOIS(domain.Name, response)
		if err != nil {
			fmt.Printf("Error parsing WHOIS information for %s: %s\n", domain.Name, err)
			continue
		}

		ip, err := ResolveIP(domain.Name)
		if err != nil {
			fmt.Printf("Error resolving IP address for %s: %s\n", domain.Name, err)
			continue
		}
		domainInfo.IPAddress = ip

		hash := HashDomainInfo(domainInfo)
		currentStates[domain.Name] = hash

		if previousHash, found := previousStates[domain.Name]; !found {
			message := fmt.Sprintf("Monitoring enabled for domain: %s", domain.Name)
			for _, webhook := range domain.Webhooks {
				if err := SendWebhook(webhook, message, domainInfo); err != nil {
					fmt.Printf("Error sending webhook for %s: %s\n", domain.Name, err)
				}
			}
			for _, webhook := range config.Webhooks {
				if err := SendWebhook(webhook, message, domainInfo); err != nil {
					fmt.Printf("Error sending webhook for %s: %s\n", domain.Name, err)
				}
			}
		} else if previousHash != hash {
			message := fmt.Sprintf("Domain information changed for: %s", domain.Name)
			for _, webhook := range domain.Webhooks {
				if err := SendWebhook(webhook, message, domainInfo); err != nil {
					fmt.Printf("Error sending webhook for %s: %s\n", domain.Name, err)
				}
			}
			for _, webhook := range config.Webhooks {
				if err := SendWebhook(webhook, message, domainInfo); err != nil {
					fmt.Printf("Error sending webhook for %s: %s\n", domain.Name, err)
				}
			}
		}
	}

	for domainName := range previousStates {
		if _, found := currentStates[domainName]; !found {
			message := fmt.Sprintf("Monitoring finished for domain: %s", domainName)
			for _, domain := range config.Domains {
				if domain.Name == domainName {
					for _, webhook := range domain.Webhooks {
						if err := SendWebhook(webhook, message, nil); err != nil {
							fmt.Printf("Error sending webhook for %s: %s\n", domainName, err)
						}
					}
				}
			}
			for _, webhook := range config.Webhooks {
				if err := SendWebhook(webhook, message, nil); err != nil {
					fmt.Printf("Error sending webhook for %s: %s\n", domainName, err)
				}
			}
		}
	}

	return currentStates
}

func main() {
	configPath := "config.yaml"
	previousStates := make(map[string]string)

	for {
		config, err := LoadConfig(configPath)
		if err != nil {
			fmt.Printf("Error loading config: %s\n", err)
			return
		}

		previousStates = MonitorDomains(config, previousStates)

		time.Sleep(time.Duration(config.Interval) * time.Minute)
	}
}
