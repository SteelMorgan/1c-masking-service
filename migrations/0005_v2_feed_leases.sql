--++agent TASK-221 [23.09.2026 21:09:00]
CREATE TABLE IF NOT EXISTS v2_feed_leases (
    job_id TEXT PRIMARY KEY REFERENCES feed_jobs(id) ON DELETE CASCADE,
    lease_id TEXT NOT NULL UNIQUE,
    service_epoch TEXT NOT NULL,
    database_id TEXT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    base_policy_digest TEXT NOT NULL,
    candidate_policy_digest TEXT NOT NULL,
    candidate_generation TEXT NOT NULL,
    target_version INTEGER NOT NULL,
    issued_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL
);
--++agent TASK-221
