package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	EnrichedSubject  = "certs.enriched"
	NotifierGroup    = "notifier-group"
	AlertThreshold   = 60 // Minimum risk score to dispatch immediate alerts
)

// SlackWebhookPayload formats payload for Slack / Discord webhooks
type SlackWebhookPayload struct {
	Text        string       `json:"text,omitempty"`
	Attachments []Attachment `json:"attachments,omitempty"`
}

type Attachment struct {
	Color     string  `json:"color"`
	Title     string  `json:"title"`
	TitleLink string  `json:"title_link,omitempty"`
	Fields    []Field `json:"fields"`
	Footer    string  `json:"footer"`
	Ts        int64   `json:"ts"`
}

type Field struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

func main() {
	webhookURL := os.Getenv("ALERT_WEBHOOK_URL")
	if webhookURL == "" {
		log.Println("[!] ALERT_WEBHOOK_URL not set. Running in stdout-only alert mode.")
	}

	nc, err := nats.Connect(nats.DefaultURL)
	if err != nil {
		log.Fatalf("NATS connect error: %v", err)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		log.Fatalf("JetStream error: %v", err)
	}

	log.Println("[*] Alerting & SIEM Export Service Started.")

	sub, err := js.QueueSubscribe(EnrichedSubject, NotifierGroup, func(m *nats.Msg) {
		var event EnrichedEvent
		if err := json.Unmarshal(m.Data, &event); err != nil {
			m.Ack()
			return
		}

		// Filter for high-severity threats
		if event.RiskScore >= AlertThreshold {
			// 1. Send SIEM JSON Event to stdout/file for log shippers (Filebeat, Logstash, FluentBit)
			exportToSIEM(event)

			// 2. Dispatch Chat/Webhook Alert
			if webhookURL != "" {
				if err := sendWebhookAlert(webhookURL, event); err != nil {
					log.Printf("[-] Webhook dispatch error: %v", err)
				}
			}
		}

		m.Ack()
	}, nats.Durable("notifier-durable"), nats.ManualAck())

	if err != nil {
		log.Fatalf("Subscribe error: %v", err)
	}
	defer sub.Unsubscribe()

	runtime.Goexit()
}

func exportToSIEM(event EnrichedEvent) {
	siemLog := map[string]interface{}{
		"@timestamp":  event.ProbedAt.Format(time.RFC3339),
		"event_type":  "adversary_infrastructure_early_warning",
		"domain":      event.Domain,
		"risk_score":  event.RiskScore,
		"reasons":     event.Reasons,
		"entropy":     event.Entropy,
		"target_brand": event.MatchedBrand,
		"ip_addresses": event.IPs,
		"mx_records":  event.MX,
		"ns_records":  event.NS,
		"jarm_hash":   event.JARM,
	}

	siemJSON, _ := json.Marshal(siemLog)
	// Output formatted single-line JSON log for SIEM forwarders
	fmt.Printf("[SIEM-LOG] %s\n", string(siemJSON))
}

func sendWebhookAlert(webhookURL string, event EnrichedEvent) error {
	color := "#ff9900" // Orange for high
	if event.RiskScore >= 80 {
		color = "#ff0000" // Red for critical
	}

	payload := SlackWebhookPayload{
		Attachments: []Attachment{
			{
				Color:     color,
				Title:     fmt.Sprintf("🚨 Critical Threat Domain Detected: %s", event.Domain),
				Fields: []Field{
					{Title: "Risk Score", Value: fmt.Sprintf("%d / 100", event.RiskScore), Short: true},
					{Title: "Entropy", Value: fmt.Sprintf("%.2f", event.Entropy), Short: true},
					{Title: "Targeted Brand", Value: event.MatchedBrand, Short: true},
					{Title: "JARM Fingerprint", Value: event.JARM, Short: true},
					{Title: "Resolved IPs", Value: strings.Join(event.IPs, ", "), Short: false},
					{Title: "Detection Reasons", Value: strings.Join(event.Reasons, " | "), Short: false},
				},
				Footer: "CertIntel Early-Warning Engine",
				Ts:     time.Now().Unix(),
			},
		},
	}

	jsonBytes, _ := json.Marshal(payload)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook responded with HTTP %d", resp.StatusCode)
	}

	log.Printf("[ALERT SENT] Dispatched webhook alert for domain: %s", event.Domain)
	return nil
}