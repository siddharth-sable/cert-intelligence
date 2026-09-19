package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	CTLogURL = "https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1"
	Subject  = "certs.ingested"
)

type STHResponse struct {
	TreeSize int64 `json:"tree_size"`
}

type Entry struct {
	LeafInput string `json:"leaf_input"`
}

type EntriesResponse struct {
	Entries []Entry `json:"entries"`
}

func main() {
	// 1. Connect to NATS
	nc, err := nats.Connect(nats.DefaultURL)
	if err != nil {
		log.Fatalf("Failed to connect to NATS: %v", err)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		log.Fatalf("Failed to create JetStream context: %v", err)
	}

	// Create JetStream Stream if it doesn't exist
	_, err = js.AddStream(&nats.StreamConfig{
		Name:     "CERTS",
		Subjects: []string{Subject},
	})
	if err != nil {
		log.Printf("Stream init note: %v", err)
	}

	log.Println("[*] Connected to NATS JetStream")

	// 2. Fetch initial Tree Size
	treeSize, err := getTreeSize()
	if err != nil {
		log.Fatalf("Error fetching STH: %v", err)
	}

	currentIndex := treeSize - 2000 // Start 20 entries back
	log.Printf("[*] Starting CT Ingestion at Index: %d\n", currentIndex)

	client := &http.Client{Timeout: 10 * time.Second}
	batchSize := int64(32)

	// 3. Continuous Ingestion Loop
	for {
		latestSize, err := getTreeSize()
		if err != nil {
			log.Printf("[-] STH fetch error: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		if latestSize > currentIndex {
			endIndex := currentIndex + batchSize - 1
			if endIndex >= latestSize {
				endIndex = latestSize - 1
			}

			entries, err := fetchEntries(client, currentIndex, endIndex)
			if err != nil {
				log.Printf("[-] Entry fetch error: %v", err)
				time.Sleep(1 * time.Second)
				continue
			}

			for i, entry := range entries {
				idx := currentIndex + int64(i)
				cn, sans, err := parseLeafInput(entry.LeafInput)
				if err == nil && (cn != "" || len(sans) > 0) {
					event := DomainEvent{
						Index:      idx,
						CommonName: cn,
						SANs:       sans,
						Timestamp:  time.Now(),
					}

					payload, _ := json.Marshal(event)
					_, err := js.Publish(Subject, payload)
					if err != nil {
						log.Printf("[-] Failed to publish event %d: %v", idx, err)
					} else {
						fmt.Printf("[+] Published Entry #%d | CN: %s | SANs: %v\n", idx, cn, sans)
					}
				}
			}

			currentIndex = endIndex + 1
		} else {
			time.Sleep(1500 * time.Millisecond)
		}
	}
}

func getTreeSize() (int64, error) {
	resp, err := http.Get(CTLogURL + "/get-sth")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var sth STHResponse
	if err := json.Unmarshal(body, &sth); err != nil {
		return 0, err
	}
	return sth.TreeSize, nil
}

func fetchEntries(client *http.Client, start, end int64) ([]Entry, error) {
	url := fmt.Sprintf("%s/get-entries?start=%d&end=%d", CTLogURL, start, end)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var er EntriesResponse
	if err := json.Unmarshal(body, &er); err != nil {
		return nil, err
	}
	return er.Entries, nil
}

func parseLeafInput(leafInputB64 string) (string, []string, error) {
	data, err := base64.StdEncoding.DecodeString(leafInputB64)
	if err != nil || len(data) < 15 {
		return "", nil, fmt.Errorf("invalid leaf input length")
	}

	// RFC 6962: entry_type is at offset 10..11
	entryType := binary.BigEndian.Uint16(data[10:12])
	if entryType != 0 { // 0 = X509Entry
		return "", nil, fmt.Errorf("not an x509 entry")
	}

	certLen := int(data[12])<<16 | int(data[13])<<8 | int(data[14])
	if len(data) < 15+certLen {
		return "", nil, fmt.Errorf("truncated certificate payload")
	}

	certBytes := data[15 : 15+certLen]
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return "", nil, err
	}

	return cert.Subject.CommonName, cert.DNSNames, nil
}