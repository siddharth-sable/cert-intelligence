package main

import "time"

// DomainEvent represents a parsed certificate event sent to NATS
type DomainEvent struct {
	Index      int64     `json:"index"`
	CommonName string    `json:"common_name"`
	SANs       []string  `json:"sans"`
	Timestamp  time.Time `json:"timestamp"`
}