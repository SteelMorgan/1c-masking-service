--++agent TASK-222 [05.10.2026 00:00:00]
-- Откат транспорта v2 и feed receiver: lease-протокол, чанковая загрузка и
-- активируемые через HTTP снапшоты заменены pull-моделью через manager UDS.
-- v2_feed_leases ссылается на feed_jobs, поэтому удаляется первой.
DROP TABLE IF EXISTS v2_feed_leases;
DROP TABLE IF EXISTS feed_jobs;
DROP TABLE IF EXISTS v2_call_receipts;
DROP TABLE IF EXISTS v2_active_snapshots;
--++agent TASK-222
