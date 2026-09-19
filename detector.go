package main

import (
	"encoding/json"
	"fmt"
	"log"
	"runtime"

	"github.com/nats-io/nats.go"
)

const (
	IngestSubject = "certs.ingested"
	FlaggedSubject = "certs.flagged"
)

func main() {
	nc, err := nats.Connect(nats.DefaultURL)
	if err != nil {
		log.Fatalf("Failed to connect to NATS: %v", err)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		log.Fatalf("Failed to create JetStream context: %v", err)
	}

	log.Println("[*] Detector Microservice Started. Listening for events...")

	// Durable Queue Consumer
	sub, err := js.QueueSubscribe(IngestSubject, "detector-group", func(m *nats.Msg) {
		var event DomainEvent
		if err := json.Unmarshal(m.Data, &event); err != nil {
			m.Ack()
			return
		}

		domains := append(event.SANs, event.CommonName)
		for _, domain := range domains {
			if domain == "" || domain == "N/A" {
				continue
			}

			analysis := AnalyzeDomain(domain)
			
			// If Risk Score >= 40, flag the domain
			if analysis.RiskScore >= 40 {
				payload, _ := json.Marshal(analysis)
				js.Publish(FlaggedSubject, payload)

				fmt.Printf("\n[ALERT] High Risk Domain Flagged!\n")
				fmt.Printf(" Domain:     %s\n", analysis.Domain)
				fmt.Printf(" Risk Score: %d/100\n", analysis.RiskScore)
				fmt.Printf(" Reasons:    %v\n", analysis.Reasons)
				fmt.Printf(" Entropy:    %.2f\n", analysis.Entropy)
			}
		}

		m.Ack()
	}, nats.Durable("detector-durable"), nats.ManualAck())

	if err != nil {
		log.Fatalf("Queue subscribe failed: %v", err)
	}
	defer sub.Unsubscribe()

	runtime.Goexit()
}