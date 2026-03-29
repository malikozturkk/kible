-- Enable pg_trgm extension for trigram-based fuzzy search
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- GIN index on username for fast trigram similarity lookups
CREATE INDEX idx_users_username_trgm ON users USING GIN (username gin_trgm_ops);
