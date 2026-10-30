-- Migration 0071: news/decree edit time. Runs automatically on boot via
-- migrations/list/0071_news_edited_at.js; this is the same change by hand.
SET SESSION system_versioning_alter_history = KEEP;
ALTER TABLE news_entries ADD COLUMN edited_at DATETIME NULL DEFAULT NULL;
