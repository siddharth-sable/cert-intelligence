CREATE TABLE IF NOT EXISTS flagged_domains (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    risk_score INT NOT NULL,
    reasons TEXT[],
    entropy DOUBLE PRECISION,
    matched_brand VARCHAR(100),
    ips TEXT[],
    mx_records TEXT[],
    ns_records TEXT[],
    jarm_hash VARCHAR(100),
    probed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_risk_score ON flagged_domains(risk_score);
CREATE INDEX IF NOT EXISTS idx_jarm_hash ON flagged_domains(jarm_hash);