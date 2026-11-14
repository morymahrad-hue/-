-- EdgePanel Cloudflare D1 (SQLite) Schema
-- Note: src/index.ts also auto-runs CREATE TABLE IF NOT EXISTS on first request.

CREATE TABLE IF NOT EXISTS inbounds (
  id TEXT PRIMARY KEY,
  tag TEXT NOT NULL,
  remark TEXT NOT NULL DEFAULT '',
  protocol TEXT NOT NULL,
  listen_host TEXT NOT NULL DEFAULT '0.0.0.0',
  server_address TEXT NOT NULL DEFAULT '',
  port INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  network TEXT NOT NULL DEFAULT 'tcp',
  security TEXT NOT NULL DEFAULT 'none',
  sni TEXT NOT NULL DEFAULT '',
  fingerprint TEXT NOT NULL DEFAULT 'chrome',
  alpn TEXT NOT NULL DEFAULT 'h2,http/1.1',
  flow TEXT NOT NULL DEFAULT '',
  ws_path TEXT NOT NULL DEFAULT '/',
  ws_host TEXT NOT NULL DEFAULT '',
  grpc_service_name TEXT NOT NULL DEFAULT 'grpc',
  reality_private_key TEXT NOT NULL DEFAULT '',
  reality_public_key TEXT NOT NULL DEFAULT '',
  reality_short_id TEXT NOT NULL DEFAULT '',
  reality_dest TEXT NOT NULL DEFAULT '',
  ss_method TEXT NOT NULL DEFAULT 'aes-256-gcm',
  tuic_congestion TEXT NOT NULL DEFAULT 'bbr',
  tuic_udp_relay TEXT NOT NULL DEFAULT 'native',
  hy2_obfs TEXT NOT NULL DEFAULT 'none',
  hy2_obfs_password TEXT NOT NULL DEFAULT '',
  hy2_up_mbps INTEGER NOT NULL DEFAULT 100,
  hy2_down_mbps INTEGER NOT NULL DEFAULT 200,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY,
  inbound_id TEXT NOT NULL,
  email TEXT NOT NULL,
  credential TEXT NOT NULL,
  secondary_password TEXT NOT NULL DEFAULT '',
  sub_id TEXT NOT NULL,
  total_gb REAL NOT NULL DEFAULT 0,
  up_bytes INTEGER NOT NULL DEFAULT 0,
  down_bytes INTEGER NOT NULL DEFAULT 0,
  expiry_time INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  alter_id INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS clean_endpoints (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  address TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 443,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS access_logs (
  id TEXT PRIMARY KEY,
  sub_id TEXT NOT NULL,
  client_email TEXT NOT NULL DEFAULT '',
  format TEXT NOT NULL DEFAULT 'base64',
  user_agent TEXT NOT NULL DEFAULT '',
  country TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  status INTEGER NOT NULL DEFAULT 200,
  timestamp INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS panel_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_clients_inbound_id ON clients(inbound_id);
CREATE INDEX IF NOT EXISTS idx_clients_sub_id ON clients(sub_id);
CREATE INDEX IF NOT EXISTS idx_access_logs_ts ON access_logs(timestamp DESC);
