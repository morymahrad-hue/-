# EdgePanel — Serverless Proxy Configuration & Edge Relay Panel (Cloudflare Workers)

EdgePanel is an open-source, zero-VPS alternative to Sanaei/X-UI panels built specifically for **Cloudflare Workers**. It runs natively on Cloudflare's global edge using ES Modules, Fetch API handlers, Web Crypto (`X25519` + `HMAC-SHA256`), `cloudflare:sockets`, and **Cloudflare D1 / KV** storage.

---

## Key Capabilities

- **100% Serverless Edge Runtime**: Zero VPS required. Includes an optional **Built-in VLESS-over-WebSocket Edge Relay** (`cloudflare:sockets`) with client UUID validation, expiry/quota enforcement, ProxyIP fallback, and traffic accounting.
- **Dual Storage Adapter (D1 + KV)**: Automatically uses Cloudflare **D1 (SQLite)** when `DB` is bound (with automatic table initialization on first request), or falls back seamlessly to **Workers KV** (`PANEL_KV`).
- **6 Modern Protocols**:
  - **VLESS** (`Reality` with RFC 7748 X25519 keypair generator, `WebSocket`, `gRPC`, `TLS`)
  - **VMess** (`WS`, `gRPC`, `TCP`, `TLS`)
  - **Trojan** (`TLS`, `Reality`, `WS`, `gRPC`)
  - **Shadowsocks** (`2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`)
  - **TUIC v5** (`bbr`/`cubic`, `h3` ALPN, `native`/`quic` UDP relay)
  - **Hysteria2** (`Salamander` obfuscation, bandwidth shaping, `h3` ALPN)
- **Clean IP Pool + TLS Fragment + Mux + Geo-Routing**:
  - Manage Clean Cloudflare IPs/Endpoints to automatically expand CDN WebSocket nodes.
  - Configure TLS Fragment (`packets`, `length`, `interval`), Mux concurrency, AdBlock, and GeoIP/GeoSite bypass (`IR`, `CN`, `RU`).
- **Universal Subscription Exports (`/sub/:subId`)**:
  - Smart User-Agent auto-detection + explicit `?format=base64|clash|singbox|xray|raw`.
  - Standard **`Subscription-Userinfo`** headers for **v2rayNG**, **Clash Meta (Mihomo)**, **Sing-box**, **Xray**, **NekoBox**, and **Shadowrocket**.
- **Batch Generator, Backup/Restore & Access Logs**:
  - Generate up to 50 clients in one batch, export/import full JSON backups, and inspect edge subscription request logs.

---

## Option A: One-Command Automated Setup (`deploy.sh`)

```bash
chmod +x deploy.sh
./deploy.sh
```

`deploy.sh` automatically authenticates Wrangler, creates the D1 database, patches `wrangler.toml`, sets your encrypted secrets, deploys the Worker, and prints your live `https://...workers.dev` panel URL.

---

## Option B: GitHub + Git-to-Workers Automatic Deployment

1. Push the contents of `cloudflare-worker/` to your GitHub repository (`main` branch).
2. In **GitHub -> Settings -> Secrets and variables -> Actions**, add:
   - `CLOUDFLARE_API_TOKEN` (Workers + D1 Edit permission)
   - `CLOUDFLARE_ACCOUNT_ID`
   - `ADMIN_USERNAME`
   - `ADMIN_PASSWORD`
   - `SESSION_SECRET` (random 32+ char string)
3. Update `database_id` in `wrangler.toml` with your D1 ID from `npx wrangler d1 create edgepanel-db` (or use Cloudflare Workers native Git Integration).
4. Every push to `main` automatically typechecks and deploys via `.github/workflows/deploy.yml`!

---

## REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/auth/login` | Admin login with HttpOnly HMAC-SHA256 cookie |
| `POST` | `/api/auth/logout` | Clear admin session |
| `GET` | `/api/auth/session` | Inspect session and storage backend (`d1` / `kv`) |
| `GET` | `/api/overview` | Aggregate inbound, client, traffic, and endpoint stats |
| `GET/POST` | `/api/inbounds` | List or create inbound configurations |
| `PUT/DELETE` | `/api/inbounds/:id` | Update or remove an inbound |
| `POST` | `/api/clients` | Create a single client |
| `POST` | `/api/clients/batch` | Batch-generate multiple clients with shared prefix, quota, and expiry |
| `PUT/DELETE` | `/api/clients/:id` | Update or remove a client |
| `POST` | `/api/clients/:id/reset-traffic` | Reset client upload/download bytes |
| `GET/POST/DELETE` | `/api/endpoints` | Manage Clean Cloudflare IPs / edge endpoints |
| `GET/POST` | `/api/backup` | Export or restore complete JSON snapshot |
| `GET` | `/api/logs` | View recent subscription & edge access logs |
| `GET` | `/api/tools/keygen` | Generate UUIDv4, X25519 Reality keypair, ShortID, SS2022 keys |
| `GET/PUT` | `/api/settings` | Manage panel, relay, fragment, mux, DNS, and routing settings |
| `GET` | `/sub/:subId` | Public subscription endpoint (`?format=base64|clash|singbox|xray|raw`) |
