package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"time"

	"github.com/lib/pq"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
)

const (
	EnrichedSubject = "certs.enriched"
	RedisKeyPrefix  = "seen_domain:"
)

type StorageWorker struct {
	db  *sql.DB
	rdb *redis.Client
	ctx context.Context
}

func NewStorageWorker(pgConnStr string, redisAddr string) (*StorageWorker, error) {
	db, err := sql.Open("postgres", pgConnStr)
	if err != nil {
		return nil, fmt.Errorf("postgres conn err: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("postgres ping err: %w", err)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})

	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping err: %w", err)
	}

	return &StorageWorker{db: db, rdb: rdb, ctx: ctx}, nil
}

func (sw *StorageWorker) SaveThreat(event EnrichedEvent) error {
	// 1. Redis Deduplication Check (TTL set to 24 hours)
	redisKey := RedisKeyPrefix + event.Domain
	set, err := sw.rdb.SetNX(sw.ctx, redisKey, "1", 24*time.Hour).Result()
	if err != nil {
		log.Printf("[-] Redis check error: %v", err)
	} else if !set {
		log.Printf("[~] Duplicate domain skipped (Redis): %s", event.Domain)
		return nil
	}

	// 2. Insert into PostgreSQL
	query := `
		INSERT INTO flagged_domains (
			domain, risk_score, reasons, entropy, matched_brand, ips, mx_records, ns_records, jarm_hash, probed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (domain) DO UPDATE SET
			risk_score = EXCLUDED.risk_score,
			reasons = EXCLUDED.reasons,
			jarm_hash = EXCLUDED.jarm_hash,
			probed_at = EXCLUDED.probed_at;
	`

	_, err = sw.db.Exec(
		query,
		event.Domain,
		event.RiskScore,
		pq.Array(event.Reasons),
		event.Entropy,
		event.MatchedBrand,
		pq.Array(event.IPs),
		pq.Array(event.MX),
		pq.Array(event.NS),
		event.JARM,
		event.ProbedAt,
	)

	if err != nil {
		return fmt.Errorf("postgres insert error: %w", err)
	}

	log.Printf("[DB SUCCESS] Persisted threat profile for: %s", event.Domain)
	return nil
}

func main() {
	pgConn := "host=localhost port=5432 user=postgres password=postgres dbname=threat_intel sslmode=disable"
	redisAddr := "localhost:6379"

	worker, err := NewStorageWorker(pgConn, redisAddr)
	if err != nil {
		log.Fatalf("Worker init failed: %v", err)
	}
	defer worker.db.Close()

	nc, err := nats.Connect(nats.DefaultURL)
	if err != nil {
		log.Fatalf("NATS connect error: %v", err)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		log.Fatalf("JetStream error: %v", err)
	}

	log.Println("[*] Storage & Persistence Service Started.")

	sub, err := js.QueueSubscribe(EnrichedSubject, "storage-group", func(m *nats.Msg) {
		var event EnrichedEvent
		if err := json.Unmarshal(m.Data, &event); err != nil {
			m.Ack()
			return
		}

		if err := worker.SaveThreat(event); err != nil {
			log.Printf("[-] Failed to persist record: %v", err)
		}

		m.Ack()
	}, nats.Durable("storage-durable"), nats.ManualAck())

	if err != nil {
		log.Fatalf("Subscribe error: %v", err)
	}
	defer sub.Unsubscribe()

	runtime.Goexit()
}