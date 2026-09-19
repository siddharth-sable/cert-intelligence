package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/hdm/jarm-go"
	"github.com/nats-io/nats.go"
)

const (
	FlaggedSubject  = "certs.flagged"
	EnrichedSubject = "certs.enriched"
)

// EnrichedEvent holds the full intelligence report for a threat domain
type EnrichedEvent struct {
	AnalysisResult
	IPs       []string  `json:"ips"`
	MX        []string  `json:"mx_records"`
	NS        []string  `json:"ns_records"`
	JARM      string    `json:"jarm_hash"`
	ProbedAt  time.Time `json:"probed_at"`
}

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

	log.Println("[*] Active Infrastructure Prober Started. Listening for flagged domains...")

	// Queue subscriber to distribute network probes across workers
	sub, err := js.QueueSubscribe(FlaggedSubject, "prober-group", func(m *nats.Msg) {
		var analysis AnalysisResult
		if err := json.Unmarshal(m.Data, &analysis); err != nil {
			m.Ack()
			return
		}

		cleanDomain := strings.TrimPrefix(analysis.Domain, "*.")
		fmt.Printf("\n[PROBING] Starting active reconnaissance on: %s\n", cleanDomain)

		// 1. Resolve DNS Infrastructure
		ips, mx, ns := resolveDNS(cleanDomain)
		
		// 2. Compute JARM Fingerprint against primary IP
		jarmHash := ""
		if len(ips) > 0 {
			jarmHash = computeJARM(ips[0], 443)
		}

		// 3. Build Enriched Threat Profile
		enriched := EnrichedEvent{
			AnalysisResult: analysis,
			IPs:            ips,
			MX:             mx,
			NS:             ns,
			JARM:           jarmHash,
			ProbedAt:       time.Now(),
		}

		// 4. Publish to `certs.enriched`
		payload, _ := json.Marshal(enriched)
		js.Publish(EnrichedSubject, payload)

		fmt.Printf("[+] Enriched Threat Profile Created!\n")
		fmt.Printf("    Domain: %s | Risk Score: %d\n", enriched.Domain, enriched.RiskScore)
		fmt.Printf("    IPs:    %v\n", enriched.IPs)
		fmt.Printf("    NS:     %v\n", enriched.NS)
		fmt.Printf("    JARM:   %s\n", enriched.JARM)

		m.Ack()
	}, nats.Durable("prober-durable"), nats.ManualAck())

	if err != nil {
		log.Fatalf("Prober subscribe failed: %v", err)
	}
	defer sub.Unsubscribe()

	runtime.Goexit()
}

// resolveDNS queries A, MX, and NS records for a domain
func resolveDNS(domain string) ([]string, []string, []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var ips []string
	var mxRecords []string
	var nsRecords []string

	r := net.Resolver{}

	// Resolve IPv4 Addresses (A Records)
	addrs, err := r.LookupHost(ctx, domain)
	if err == nil {
		ips = addrs
	}

	// Resolve Mail Servers (MX Records)
	mxList, err := r.LookupMX(ctx, domain)
	if err == nil {
		for _, mx := range mxList {
			mxRecords = append(mxRecords, mx.Host)
		}
	}

	// Resolve Name Servers (NS Records)
	nsList, err := r.LookupNS(ctx, domain)
	if err == nil {
		for _, ns := range nsList {
			nsRecords = append(nsRecords, ns.Host)
		}
	}

	return ips, mxRecords, nsRecords
}

// computeJARM sends 10 custom TLS client hellos to extract a JARM fingerprint
func computeJARM(host string, port int) string {
	timeout := 2 * time.Second
	results := make([]string, 0, 10)

	targets := jarm.GenerateProbeTargets(host, port)
	for _, target := range targets {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port)), timeout)
		if err != nil {
			results = append(results, "")
			continue
		}

		conn.SetDeadline(time.Now().Add(timeout))
		probe := jarm.BuildProbe(target)
		_, err = conn.Write(probe)
		if err != nil {
			conn.Close()
			results = append(results, "")
			continue
		}

		buff := make([]byte, 1484)
		n, _ := conn.Read(buff)
		conn.Close()

		ans, _ := jarm.ParseServerHello(buff[:n], target)
		results = append(results, ans)
	}

	return jarm.ParseJARM(results)
}