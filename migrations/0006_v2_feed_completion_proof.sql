--++agent TASK-221 [23.09.2026 21:40:00]
ALTER TABLE v2_feed_leases ADD COLUMN completed_mode TEXT;
ALTER TABLE v2_feed_leases ADD COLUMN completed_filter_free INTEGER NOT NULL DEFAULT 0;
--++agent TASK-221
