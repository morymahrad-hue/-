import { connect } from 'cloudflare:sockets';

export interface Env {
  DB?: D1Database;
  PANEL_KV?: KVNamespace;
  ADMIN_USERNAME?: string;
  ADMIN_PASSWORD?: string;
  SESSION_SECRET?: string;
  PANEL_TITLE?: string;
  SUB_PATH?: string;
  DEFAULT_SNI?: string;
}

export type ProtocolType = 'vless' | 'vmess' | 'trojan' | 'shadowsocks' | 'tuic' | 'hysteria2';
export type NetworkType = 'tcp' | 'ws' | 'grpc' | 'quic';
export type SecurityType = 'none' | 'tls' | 'reality';
export type BypassCountry = 'none' | 'ir' | 'cn' | 'ru';

export interface InboundConfig {
  id: string;
  tag: string;
  remark: string;
  protocol: ProtocolType;
  listenHost: string;
  serverAddress: string;
  port: number;
  enabled: boolean;
  network: NetworkType;
  security: SecurityType;
  sni: string;
  fingerprint: string;
  alpn: string;
  flow: string;
  wsPath: string;
  wsHost: string;
  grpcServiceName: string;
  realityPrivateKey: string;
  realityPublicKey: string;
  realityShortId: string;
  realityDest: string;
  ssMethod: string;
  tuicCongestion: string;
  tuicUdpRelay: string;
  hy2Obfs: string;
  hy2ObfsPassword: string;
  hy2UpMbps: number;
  hy2DownMbps: number;
  createdAt: number;
  updatedAt: number;
}

export interface ClientConfig {
  id: string;
  inboundId: string;
  email: string;
  credential: string;
  secondaryPassword?: string;
  subId: string;
  totalGb: number;
  upBytes: number;
  downBytes: number;
  expiryTime: number;
  enabled: boolean;
  alterId?: number;
  createdAt: number;
  updatedAt: number;
}

export interface CleanEndpoint {
  id: string;
  label: string;
  address: string;
  port: number;
  enabled: boolean;
  createdAt: number;
}

export interface AccessLogEntry {
  id: string;
  subId: string;
  clientEmail: string;
  format: string;
  userAgent: string;
  country: string;
  ip: string;
  status: number;
  timestamp: number;
}

export interface PanelSettings {
  panelTitle: string;
  edgeDomain: string;
  subPath: string;
  defaultSni: string;
  defaultFingerprint: string;
  allowInsecureTls: boolean;
  clashMixedPort: number;
  workerRelayEnabled: boolean;
  workerRelayPath: string;
  workerProxyIp: string;
  fragmentEnabled: boolean;
  fragmentPackets: string;
  fragmentLength: string;
  fragmentInterval: string;
  muxEnabled: boolean;
  muxConcurrency: number;
  bypassCountry: BypassCountry;
  blockAds: boolean;
  dnsServer: string;
}

interface KvState {
  inbounds: InboundConfig[];
  clients: ClientConfig[];
  endpoints: CleanEndpoint[];
  logs: AccessLogEntry[];
  settings: PanelSettings;
}

// ---------------------------------------------------------------------------
// RFC 7748 Curve25519 Keypair & Crypto Helpers
// ---------------------------------------------------------------------------
const P25519 = (1n << 255n) - 19n;

function modP(n: bigint): bigint {
  const r = n % P25519;
  return r >= 0n ? r : r + P25519;
}

function powP(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = modP(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = modP(result * b);
    b = modP(b * b);
    e >>= 1n;
  }
  return result;
}

function invP(n: bigint): bigint {
  return powP(n, P25519 - 2n);
}

function cswap(swap: bigint, x2: bigint, x3: bigint): [bigint, bigint] {
  return swap === 1n ? [x3, x2] : [x2, x3];
}

function decodeLE(bytes: Uint8Array): bigint {
  let res = 0n;
  for (let i = 0; i < 32; i++) res += BigInt(bytes[i]) << (8n * BigInt(i));
  return res;
}

function encodeLE(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = modP(n);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function clampScalar(bytes: Uint8Array): Uint8Array {
  const clamped = new Uint8Array(bytes);
  clamped[0] &= 248;
  clamped[31] &= 127;
  clamped[31] |= 64;
  return clamped;
}

function x25519ScalarMult(scalarBytes: Uint8Array, uBytes: Uint8Array): Uint8Array {
  const k = decodeLE(clampScalar(scalarBytes));
  const uMasked = new Uint8Array(uBytes);
  uMasked[31] &= 127;
  const u = modP(decodeLE(uMasked));
  let x1 = u;
  let x2 = 1n;
  let z2 = 0n;
  let x3 = u;
  let z3 = 1n;
  let swap = 0n;
  const a24 = 121665n;

  for (let t = 254; t >= 0; t--) {
    const kt = (k >> BigInt(t)) & 1n;
    swap ^= kt;
    [x2, x3] = cswap(swap, x2, x3);
    [z2, z3] = cswap(swap, z2, z3);
    swap = kt;
    const A = modP(x2 + z2);
    const AA = modP(A * A);
    const B = modP(x2 - z2);
    const BB = modP(B * B);
    const E = modP(AA - BB);
    const C = modP(x3 + z3);
    const D = modP(x3 - z3);
    const DA = modP(D * A);
    const CB = modP(C * B);
    x3 = modP(modP(DA + CB) * modP(DA + CB));
    z3 = modP(x1 * modP(modP(DA - CB) * modP(DA - CB)));
    x2 = modP(AA * BB);
    z2 = modP(E * modP(AA + modP(a24 * E)));
  }

  [x2, x3] = cswap(swap, x2, x3);
  [z2, z3] = cswap(swap, z2, z3);
  return encodeLE(modP(x2 * invP(z2)));
}

function toBase64Url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(str: string): Uint8Array {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function toBase64Std(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  crypto.getRandomValues(buf);
  return buf;
}

function generateRealityKeypair(): { privateKey: string; publicKey: string } {
  const priv = clampScalar(randomBytes(32));
  const base = new Uint8Array(32);
  base[0] = 9;
  const pub = x25519ScalarMult(priv, base);
  return { privateKey: toBase64Url(priv), publicKey: toBase64Url(pub) };
}

function generateShortId(byteLen = 8): string {
  return Array.from(randomBytes(byteLen))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function generateSubId(): string {
  return toBase64Url(randomBytes(12));
}

function generateSs2022Key(bits: 128 | 256): string {
  const bytes = randomBytes(bits === 128 ? 16 : 32);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// ---------------------------------------------------------------------------
// Authentication Middleware (Web Crypto HMAC-SHA256 Signed HttpOnly Cookie)
// ---------------------------------------------------------------------------
const SESSION_COOKIE = 'edgepanel_session';

async function sha256ArrayBuffer(input: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
}

async function constantTimeEqual(a: string, b: string): Promise<boolean> {
  const [haBuf, hbBuf] = await Promise.all([sha256ArrayBuffer(a), sha256ArrayBuffer(b)]);
  const ha = new Uint8Array(haBuf);
  const hb = new Uint8Array(hbBuf);
  let diff = 0;
  for (let i = 0; i < ha.length; i++) diff |= ha[i] ^ hb[i];
  return diff === 0;
}

function getSessionSecret(env: Env): string {
  if (env.SESSION_SECRET && env.SESSION_SECRET.length >= 16) return env.SESSION_SECRET;
  return `${env.ADMIN_USERNAME || 'admin'}:${env.ADMIN_PASSWORD || 'change-me'}:edgepanel`;
}

async function importHmacKey(secret: string): Promise<CryptoKey> {
  const raw = await sha256ArrayBuffer(secret);
  return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function signSessionToken(username: string, env: Env): Promise<string> {
  const payload = JSON.stringify({ sub: username, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 });
  const encoded = toBase64Url(new TextEncoder().encode(payload));
  const key = await importHmacKey(getSessionSecret(env));
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(encoded));
  return `${encoded}.${toBase64Url(new Uint8Array(sig))}`;
}

async function verifySessionToken(token: string | null, env: Env): Promise<{ username: string } | null> {
  if (!token || !token.includes('.')) return null;
  const [encoded, sigB64] = token.split('.');
  if (!encoded || !sigB64) return null;
  try {
    const key = await importHmacKey(getSessionSecret(env));
    const sigBytes = fromBase64Url(sigB64);
    const sigBuf = sigBytes.buffer.slice(sigBytes.byteOffset, sigBytes.byteOffset + sigBytes.byteLength) as ArrayBuffer;
    const valid = await crypto.subtle.verify('HMAC', key, sigBuf, new TextEncoder().encode(encoded));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(fromBase64Url(encoded))) as {
      sub: string;
      exp: number;
    };
    if (!payload.sub || !payload.exp || Date.now() > payload.exp) return null;
    return { username: payload.sub };
  } catch {
    return null;
  }
}

function getCookie(request: Request, name: string): string | null {
  const header = request.headers.get('Cookie');
  if (!header) return null;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k === name) return decodeURIComponent(v);
  }
  return null;
}

// ---------------------------------------------------------------------------
// Storage Abstraction (Cloudflare D1 primary, KV seamless fallback)
// ---------------------------------------------------------------------------
function defaultSettings(env: Env, originHost: string): PanelSettings {
  return {
    panelTitle: env.PANEL_TITLE || 'EdgePanel',
    edgeDomain: originHost,
    subPath: env.SUB_PATH || '/sub',
    defaultSni: env.DEFAULT_SNI || 'www.cloudflare.com',
    defaultFingerprint: 'chrome',
    allowInsecureTls: false,
    clashMixedPort: 7890,
    workerRelayEnabled: true,
    workerRelayPath: '/edge-ws',
    workerProxyIp: '',
    fragmentEnabled: true,
    fragmentPackets: 'tlshello',
    fragmentLength: '100-200',
    fragmentInterval: '10-20',
    muxEnabled: false,
    muxConcurrency: 4,
    bypassCountry: 'none',
    blockAds: true,
    dnsServer: 'https://1.1.1.1/dns-query',
  };
}

let d1Initialized = false;

async function ensureD1Schema(db: D1Database): Promise<void> {
  if (d1Initialized) return;
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS inbounds (
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
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS clients (
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
      updated_at INTEGER NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS clean_endpoints (
      id TEXT PRIMARY KEY,
      label TEXT NOT NULL,
      address TEXT NOT NULL,
      port INTEGER NOT NULL DEFAULT 443,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS access_logs (
      id TEXT PRIMARY KEY,
      sub_id TEXT NOT NULL,
      client_email TEXT NOT NULL DEFAULT '',
      format TEXT NOT NULL DEFAULT 'base64',
      user_agent TEXT NOT NULL DEFAULT '',
      country TEXT NOT NULL DEFAULT '',
      ip TEXT NOT NULL DEFAULT '',
      status INTEGER NOT NULL DEFAULT 200,
      timestamp INTEGER NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS panel_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    )`),
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_clients_inbound_id ON clients(inbound_id)`),
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_clients_sub_id ON clients(sub_id)`),
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_access_logs_ts ON access_logs(timestamp DESC)`),
  ]);
  d1Initialized = true;
}

function mapD1Inbound(row: Record<string, unknown>): InboundConfig {
  return {
    id: String(row.id),
    tag: String(row.tag),
    remark: String(row.remark || ''),
    protocol: String(row.protocol) as ProtocolType,
    listenHost: String(row.listen_host || '0.0.0.0'),
    serverAddress: String(row.server_address || ''),
    port: Number(row.port),
    enabled: Number(row.enabled) === 1,
    network: String(row.network || 'tcp') as NetworkType,
    security: String(row.security || 'none') as SecurityType,
    sni: String(row.sni || ''),
    fingerprint: String(row.fingerprint || 'chrome'),
    alpn: String(row.alpn || 'h2,http/1.1'),
    flow: String(row.flow || ''),
    wsPath: String(row.ws_path || '/'),
    wsHost: String(row.ws_host || ''),
    grpcServiceName: String(row.grpc_service_name || 'grpc'),
    realityPrivateKey: String(row.reality_private_key || ''),
    realityPublicKey: String(row.reality_public_key || ''),
    realityShortId: String(row.reality_short_id || ''),
    realityDest: String(row.reality_dest || ''),
    ssMethod: String(row.ss_method || 'aes-256-gcm'),
    tuicCongestion: String(row.tuic_congestion || 'bbr'),
    tuicUdpRelay: String(row.tuic_udp_relay || 'native'),
    hy2Obfs: String(row.hy2_obfs || 'none'),
    hy2ObfsPassword: String(row.hy2_obfs_password || ''),
    hy2UpMbps: Number(row.hy2_up_mbps || 100),
    hy2DownMbps: Number(row.hy2_down_mbps || 200),
    createdAt: Number(row.created_at),
    updatedAt: Number(row.updated_at),
  };
}

function mapD1Client(row: Record<string, unknown>): ClientConfig {
  return {
    id: String(row.id),
    inboundId: String(row.inbound_id),
    email: String(row.email),
    credential: String(row.credential),
    secondaryPassword: String(row.secondary_password || ''),
    subId: String(row.sub_id),
    totalGb: Number(row.total_gb || 0),
    upBytes: Number(row.up_bytes || 0),
    downBytes: Number(row.down_bytes || 0),
    expiryTime: Number(row.expiry_time || 0),
    enabled: Number(row.enabled) === 1,
    alterId: Number(row.alter_id || 0),
    createdAt: Number(row.created_at),
    updatedAt: Number(row.updated_at),
  };
}

function mapD1Endpoint(row: Record<string, unknown>): CleanEndpoint {
  return {
    id: String(row.id),
    label: String(row.label),
    address: String(row.address),
    port: Number(row.port || 443),
    enabled: Number(row.enabled) === 1,
    createdAt: Number(row.created_at),
  };
}

function mapD1Log(row: Record<string, unknown>): AccessLogEntry {
  return {
    id: String(row.id),
    subId: String(row.sub_id),
    clientEmail: String(row.client_email || ''),
    format: String(row.format || 'base64'),
    userAgent: String(row.user_agent || ''),
    country: String(row.country || ''),
    ip: String(row.ip || ''),
    status: Number(row.status || 200),
    timestamp: Number(row.timestamp),
  };
}

const KV_KEY = 'edgepanel:state:v2';

async function loadState(env: Env, originHost: string): Promise<{
  backend: 'd1' | 'kv';
  inbounds: InboundConfig[];
  clients: ClientConfig[];
  endpoints: CleanEndpoint[];
  logs: AccessLogEntry[];
  settings: PanelSettings;
}> {
  if (env.DB) {
    await ensureD1Schema(env.DB);
    const [inbRes, cliRes, epRes, logRes, setRes] = await Promise.all([
      env.DB.prepare('SELECT * FROM inbounds ORDER BY created_at DESC').all(),
      env.DB.prepare('SELECT * FROM clients ORDER BY created_at DESC').all(),
      env.DB.prepare('SELECT * FROM clean_endpoints ORDER BY created_at DESC').all(),
      env.DB.prepare('SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT 100').all(),
      env.DB.prepare("SELECT value FROM panel_settings WHERE key = 'global'").first<{ value: string }>(),
    ]);
    const settings = setRes?.value
      ? { ...defaultSettings(env, originHost), ...JSON.parse(setRes.value) }
      : defaultSettings(env, originHost);
    return {
      backend: 'd1',
      inbounds: (inbRes.results || []).map((r: Record<string, unknown>) => mapD1Inbound(r)),
      clients: (cliRes.results || []).map((r: Record<string, unknown>) => mapD1Client(r)),
      endpoints: (epRes.results || []).map((r: Record<string, unknown>) => mapD1Endpoint(r)),
      logs: (logRes.results || []).map((r: Record<string, unknown>) => mapD1Log(r)),
      settings,
    };
  }

  if (env.PANEL_KV) {
    const raw = await env.PANEL_KV.get<KvState>(KV_KEY, 'json');
    if (raw) {
      return {
        backend: 'kv',
        inbounds: raw.inbounds || [],
        clients: raw.clients || [],
        endpoints: raw.endpoints || [],
        logs: raw.logs || [],
        settings: { ...defaultSettings(env, originHost), ...(raw.settings || {}) },
      };
    }
    return {
      backend: 'kv',
      inbounds: [],
      clients: [],
      endpoints: [],
      logs: [],
      settings: defaultSettings(env, originHost),
    };
  }

  throw new Error('No Cloudflare D1 (DB) or KV (PANEL_KV) binding configured in wrangler.toml');
}

async function saveKvState(env: Env, state: KvState): Promise<void> {
  if (!env.PANEL_KV) throw new Error('PANEL_KV binding not configured');
  await env.PANEL_KV.put(KV_KEY, JSON.stringify(state));
}

async function recordAccessLog(env: Env, originHost: string, entry: AccessLogEntry): Promise<void> {
  if (env.DB) {
    await ensureD1Schema(env.DB);
    await env.DB.prepare(
      `INSERT INTO access_logs (id, sub_id, client_email, format, user_agent, country, ip, status, timestamp)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(entry.id, entry.subId, entry.clientEmail, entry.format, entry.userAgent, entry.country, entry.ip, entry.status, entry.timestamp)
      .run();
    return;
  }
  const st = await loadState(env, originHost);
  await saveKvState(env, {
    inbounds: st.inbounds,
    clients: st.clients,
    endpoints: st.endpoints,
    logs: [entry, ...st.logs].slice(0, 100),
    settings: st.settings,
  });
}

async function incrementClientTraffic(
  env: Env,
  originHost: string,
  clientId: string,
  upDelta: number,
  downDelta: number
): Promise<void> {
  if (upDelta <= 0 && downDelta <= 0) return;
  const now = Date.now();
  if (env.DB) {
    await env.DB.prepare(
      'UPDATE clients SET up_bytes = up_bytes + ?, down_bytes = down_bytes + ?, updated_at = ? WHERE id = ?'
    )
      .bind(upDelta, downDelta, now, clientId)
      .run();
    return;
  }
  const st = await loadState(env, originHost);
  await saveKvState(env, {
    ...st,
    clients: st.clients.map((c) =>
      c.id === clientId
        ? { ...c, upBytes: c.upBytes + upDelta, downBytes: c.downBytes + downDelta, updatedAt: now }
        : c
    ),
  });
}

// ---------------------------------------------------------------------------
// Built-in Serverless VLESS-over-WebSocket Edge Relay (cloudflare:sockets)
// ---------------------------------------------------------------------------
function formatUuidBytes(bytes: Uint8Array): string {
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function parseVlessHeader(buffer: Uint8Array): {
  error?: string;
  version: number;
  uuid: string;
  isUdp: boolean;
  hostname: string;
  port: number;
  rawDataIndex: number;
} | null {
  if (buffer.byteLength < 24) return null;
  const version = buffer[0];
  const uuid = formatUuidBytes(buffer.slice(1, 17));
  const optLength = buffer[17];
  const cmdIndex = 18 + optLength;
  if (buffer.byteLength < cmdIndex + 4) return null;
  const command = buffer[cmdIndex];
  if (command !== 1 && command !== 2) {
    return { error: `Unsupported VLESS command: ${command}`, version, uuid, isUdp: false, hostname: '', port: 0, rawDataIndex: 0 };
  }
  const portIndex = cmdIndex + 1;
  const port = (buffer[portIndex] << 8) | buffer[portIndex + 1];
  const addrType = buffer[portIndex + 2];
  let addrIndex = portIndex + 3;
  let hostname = '';

  if (addrType === 1) {
    if (buffer.byteLength < addrIndex + 4) return null;
    hostname = `${buffer[addrIndex]}.${buffer[addrIndex + 1]}.${buffer[addrIndex + 2]}.${buffer[addrIndex + 3]}`;
    addrIndex += 4;
  } else if (addrType === 2) {
    const len = buffer[addrIndex];
    addrIndex += 1;
    if (buffer.byteLength < addrIndex + len) return null;
    hostname = new TextDecoder().decode(buffer.slice(addrIndex, addrIndex + len));
    addrIndex += len;
  } else if (addrType === 3) {
    if (buffer.byteLength < addrIndex + 16) return null;
    const parts: string[] = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(((buffer[addrIndex + i] << 8) | buffer[addrIndex + i + 1]).toString(16));
    }
    hostname = parts.join(':');
    addrIndex += 16;
  } else {
    return { error: `Unsupported address type: ${addrType}`, version, uuid, isUdp: false, hostname: '', port: 0, rawDataIndex: 0 };
  }

  return {
    version,
    uuid,
    isUdp: command === 2,
    hostname,
    port,
    rawDataIndex: addrIndex,
  };
}

async function handleVlessWebSocket(
  request: Request,
  env: Env,
  originHost: string,
  state: Awaited<ReturnType<typeof loadState>>,
  ctx: ExecutionContext
): Promise<Response> {
  const pair = new WebSocketPair();
  const [clientWs, serverWs] = Object.values(pair);
  serverWs.accept();

  let remoteSocket: ReturnType<typeof connect> | null = null;
  let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  let activeClientId: string | null = null;
  let upBytesCount = 0;
  let downBytesCount = 0;
  let headerProcessed = false;

  const flushTraffic = () => {
    if (activeClientId && (upBytesCount > 0 || downBytesCount > 0)) {
      const up = upBytesCount;
      const down = downBytesCount;
      const cid = activeClientId;
      upBytesCount = 0;
      downBytesCount = 0;
      ctx.waitUntil(incrementClientTraffic(env, originHost, cid, up, down));
    }
  };

  serverWs.addEventListener('message', async (event) => {
    try {
      const chunk =
        event.data instanceof ArrayBuffer
          ? new Uint8Array(event.data)
          : new TextEncoder().encode(String(event.data));

      if (headerProcessed && writer) {
        upBytesCount += chunk.byteLength;
        await writer.write(chunk);
        return;
      }

      const parsed = parseVlessHeader(chunk);
      if (!parsed || parsed.error) {
        serverWs.close(1002, parsed?.error || 'Invalid VLESS header');
        return;
      }

      const matchedClient = state.clients.find(
        (c) => c.credential.toLowerCase() === parsed.uuid.toLowerCase() && c.enabled
      );
      if (!matchedClient) {
        serverWs.close(1008, 'Unknown or disabled UUID');
        return;
      }
      if (matchedClient.expiryTime > 0 && matchedClient.expiryTime < Date.now()) {
        serverWs.close(1008, 'Client expired');
        return;
      }
      if (
        matchedClient.totalGb > 0 &&
        matchedClient.upBytes + matchedClient.downBytes >= matchedClient.totalGb * 1024 ** 3
      ) {
        serverWs.close(1008, 'Quota exceeded');
        return;
      }

      activeClientId = matchedClient.id;
      headerProcessed = true;

      if (parsed.isUdp && parsed.port !== 53) {
        serverWs.close(1002, 'Only DNS UDP/53 is supported on edge relay');
        return;
      }

      const openSocket = async (host: string, port: number) => {
        const sock = connect({ hostname: host, port });
        await sock.opened;
        return sock;
      };

      try {
        remoteSocket = await openSocket(parsed.hostname, parsed.port);
      } catch {
        const proxyIp = state.settings.workerProxyIp.trim();
        if (!proxyIp) throw new Error('Direct connect failed and no ProxyIP configured');
        const [pHost, pPort] = proxyIp.includes(':') ? proxyIp.split(':') : [proxyIp, String(parsed.port)];
        remoteSocket = await openSocket(pHost, Number(pPort) || parsed.port);
      }

      writer = remoteSocket.writable.getWriter();
      const payload = chunk.slice(parsed.rawDataIndex);
      if (payload.byteLength > 0) {
        upBytesCount += payload.byteLength;
        await writer.write(payload);
      }

      let sentResponseHeader = false;
      const vlessRespHeader = new Uint8Array([parsed.version, 0]);

      remoteSocket.readable
        .pipeTo(
          new WritableStream({
            write(data) {
              downBytesCount += data.byteLength;
              if (!sentResponseHeader) {
                sentResponseHeader = true;
                const combined = new Uint8Array(vlessRespHeader.length + data.byteLength);
                combined.set(vlessRespHeader, 0);
                combined.set(data, vlessRespHeader.length);
                serverWs.send(combined);
              } else {
                serverWs.send(data);
              }
            },
            close() {
              flushTraffic();
              try {
                serverWs.close(1000);
              } catch {
                // ignore
              }
            },
            abort() {
              flushTraffic();
            },
          })
        )
        .catch(() => flushTraffic());
    } catch {
      flushTraffic();
      try {
        serverWs.close(1011, 'Relay error');
      } catch {
        // ignore
      }
    }
  });

  serverWs.addEventListener('close', () => {
    flushTraffic();
    try {
      remoteSocket?.close();
    } catch {
      // ignore
    }
  });

  return new Response(null, { status: 101, webSocket: clientWs });
}

// ---------------------------------------------------------------------------
// Protocol URI, Clash Meta YAML, Sing-box JSON & Xray JSON Generators
// ---------------------------------------------------------------------------
interface NodeTarget {
  inbound: InboundConfig;
  client: ClientConfig;
  overrideHost?: string;
  overridePort?: number;
  labelSuffix?: string;
}

function expandWithEndpoints(
  pairs: Array<{ inbound: InboundConfig; client: ClientConfig }>,
  endpoints: CleanEndpoint[]
): NodeTarget[] {
  const active = endpoints.filter((e) => e.enabled);
  const out: NodeTarget[] = [];
  for (const p of pairs) {
    if (p.inbound.network === 'ws' && active.length > 0) {
      for (const ep of active) {
        out.push({ ...p, overrideHost: ep.address, overridePort: ep.port || p.inbound.port, labelSuffix: ep.label });
      }
    } else {
      out.push(p);
    }
  }
  return out;
}

function buildClientUri(
  inbound: InboundConfig,
  client: ClientConfig,
  fallbackHost: string,
  overrideHost?: string,
  overridePort?: number,
  labelSuffix?: string
): string {
  const host = overrideHost || inbound.serverAddress || fallbackHost;
  const port = overridePort || inbound.port;
  const rawLabel = `${inbound.remark || inbound.tag}${labelSuffix ? ` (${labelSuffix})` : ''} - ${client.email}`;
  const label = encodeURIComponent(rawLabel);

  if (inbound.protocol === 'vless') {
    const p = new URLSearchParams();
    p.set('encryption', 'none');
    p.set('type', inbound.network);
    p.set('security', inbound.security);
    if (inbound.security === 'reality') {
      if (inbound.sni) p.set('sni', inbound.sni);
      p.set('fp', inbound.fingerprint || 'chrome');
      if (inbound.realityPublicKey) p.set('pbk', inbound.realityPublicKey);
      if (inbound.realityShortId) p.set('sid', inbound.realityShortId);
      p.set('spx', '/');
      if (inbound.network === 'tcp' && inbound.flow) p.set('flow', inbound.flow);
    } else if (inbound.security === 'tls') {
      if (inbound.sni) p.set('sni', inbound.sni);
      if (inbound.fingerprint) p.set('fp', inbound.fingerprint);
      if (inbound.alpn) p.set('alpn', inbound.alpn);
      if (inbound.network === 'tcp' && inbound.flow) p.set('flow', inbound.flow);
    }
    if (inbound.network === 'ws') {
      p.set('path', inbound.wsPath || '/');
      if (inbound.wsHost || inbound.sni) p.set('host', inbound.wsHost || inbound.sni);
    } else if (inbound.network === 'grpc') {
      p.set('serviceName', inbound.grpcServiceName || 'grpc');
      p.set('mode', 'gun');
    }
    return `vless://${client.credential}@${host}:${port}?${p.toString()}#${label}`;
  }

  if (inbound.protocol === 'vmess') {
    const payload = {
      v: '2',
      ps: rawLabel,
      add: host,
      port: String(port),
      id: client.credential,
      aid: String(client.alterId ?? 0),
      scy: 'auto',
      net: inbound.network,
      type: 'none',
      host: inbound.network === 'ws' ? inbound.wsHost || inbound.sni || host : '',
      path: inbound.network === 'ws' ? inbound.wsPath || '/' : inbound.network === 'grpc' ? inbound.grpcServiceName || 'grpc' : '',
      tls: inbound.security === 'tls' ? 'tls' : '',
      sni: inbound.security === 'tls' ? inbound.sni || host : '',
      alpn: inbound.security === 'tls' ? inbound.alpn || 'h2,http/1.1' : '',
      fp: inbound.security === 'tls' ? inbound.fingerprint || 'chrome' : '',
    };
    return `vmess://${toBase64Std(JSON.stringify(payload))}`;
  }

  if (inbound.protocol === 'trojan') {
    const p = new URLSearchParams();
    p.set('security', inbound.security === 'none' ? 'tls' : inbound.security);
    p.set('type', inbound.network);
    if (inbound.sni) p.set('sni', inbound.sni);
    if (inbound.fingerprint) p.set('fp', inbound.fingerprint);
    if (inbound.security === 'reality') {
      if (inbound.realityPublicKey) p.set('pbk', inbound.realityPublicKey);
      if (inbound.realityShortId) p.set('sid', inbound.realityShortId);
    } else if (inbound.alpn) {
      p.set('alpn', inbound.alpn);
    }
    if (inbound.network === 'ws') {
      p.set('path', inbound.wsPath || '/');
      if (inbound.wsHost || inbound.sni) p.set('host', inbound.wsHost || inbound.sni);
    } else if (inbound.network === 'grpc') {
      p.set('serviceName', inbound.grpcServiceName || 'grpc');
    }
    return `trojan://${encodeURIComponent(client.credential)}@${host}:${port}?${p.toString()}#${label}`;
  }

  if (inbound.protocol === 'shadowsocks') {
    const userInfo = toBase64Std(`${inbound.ssMethod || 'aes-256-gcm'}:${client.credential}`);
    return `ss://${userInfo}@${host}:${port}#${label}`;
  }

  if (inbound.protocol === 'tuic') {
    const p = new URLSearchParams();
    p.set('congestion_control', inbound.tuicCongestion || 'bbr');
    p.set('alpn', inbound.alpn || 'h3');
    p.set('udp_relay_mode', inbound.tuicUdpRelay || 'native');
    if (inbound.sni) p.set('sni', inbound.sni);
    p.set('allow_insecure', '0');
    const pass = encodeURIComponent(client.secondaryPassword || client.credential);
    return `tuic://${client.credential}:${pass}@${host}:${port}?${p.toString()}#${label}`;
  }

  const p = new URLSearchParams();
  if (inbound.sni) p.set('sni', inbound.sni);
  p.set('alpn', inbound.alpn || 'h3');
  if (inbound.hy2Obfs === 'salamander' && inbound.hy2ObfsPassword) {
    p.set('obfs', 'salamander');
    p.set('obfs-password', inbound.hy2ObfsPassword);
  }
  p.set('insecure', '0');
  return `hysteria2://${encodeURIComponent(client.credential)}@${host}:${port}?${p.toString()}#${label}`;
}

function buildClashYaml(
  pairs: Array<{ inbound: InboundConfig; client: ClientConfig }>,
  settings: PanelSettings,
  endpoints: CleanEndpoint[]
): string {
  const targets = expandWithEndpoints(pairs, endpoints);
  const names: string[] = [];
  const blocks: string[] = [];
  for (const { inbound, client, overrideHost, overridePort, labelSuffix } of targets) {
    const host = overrideHost || inbound.serverAddress || settings.edgeDomain;
    const port = overridePort || inbound.port;
    const name = `${inbound.remark || inbound.tag}${labelSuffix ? ` (${labelSuffix})` : ''} - ${client.email}`;
    names.push(name);
    const L: string[] = [`  - name: ${JSON.stringify(name)}`];
    if (inbound.protocol === 'vless') {
      L.push(`    type: vless`, `    server: ${JSON.stringify(host)}`, `    port: ${port}`, `    uuid: ${JSON.stringify(client.credential)}`, `    network: ${inbound.network}`, `    udp: true`);
      if (inbound.network === 'tcp' && inbound.flow) L.push(`    flow: ${JSON.stringify(inbound.flow)}`);
      if (inbound.security !== 'none') {
        L.push(`    tls: true`);
        if (inbound.sni) L.push(`    servername: ${JSON.stringify(inbound.sni)}`);
        if (inbound.fingerprint) L.push(`    client-fingerprint: ${JSON.stringify(inbound.fingerprint)}`);
      }
      if (inbound.security === 'reality') {
        L.push(`    reality-opts:`, `      public-key: ${JSON.stringify(inbound.realityPublicKey)}`);
        if (inbound.realityShortId) L.push(`      short-id: ${JSON.stringify(inbound.realityShortId)}`);
      }
      if (inbound.network === 'ws') {
        L.push(`    ws-opts:`, `      path: ${JSON.stringify(inbound.wsPath || '/')}`);
        if (inbound.wsHost || inbound.sni) L.push(`      headers:`, `        Host: ${JSON.stringify(inbound.wsHost || inbound.sni)}`);
      } else if (inbound.network === 'grpc') {
        L.push(`    grpc-opts:`, `      grpc-service-name: ${JSON.stringify(inbound.grpcServiceName || 'grpc')}`);
      }
    } else if (inbound.protocol === 'vmess') {
      L.push(`    type: vmess`, `    server: ${JSON.stringify(host)}`, `    port: ${port}`, `    uuid: ${JSON.stringify(client.credential)}`, `    alterId: ${client.alterId ?? 0}`, `    cipher: auto`, `    udp: true`, `    network: ${inbound.network}`);
      if (inbound.security === 'tls') {
        L.push(`    tls: true`);
        if (inbound.sni) L.push(`    servername: ${JSON.stringify(inbound.sni)}`);
        if (inbound.fingerprint) L.push(`    client-fingerprint: ${JSON.stringify(inbound.fingerprint)}`);
      }
      if (inbound.network === 'ws') {
        L.push(`    ws-opts:`, `      path: ${JSON.stringify(inbound.wsPath || '/')}`);
        if (inbound.wsHost || inbound.sni) L.push(`      headers:`, `        Host: ${JSON.stringify(inbound.wsHost || inbound.sni)}`);
      } else if (inbound.network === 'grpc') {
        L.push(`    grpc-opts:`, `      grpc-service-name: ${JSON.stringify(inbound.grpcServiceName || 'grpc')}`);
      }
    } else if (inbound.protocol === 'trojan') {
      L.push(`    type: trojan`, `    server: ${JSON.stringify(host)}`, `    port: ${port}`, `    password: ${JSON.stringify(client.credential)}`, `    udp: true`);
      if (inbound.sni) L.push(`    sni: ${JSON.stringify(inbound.sni)}`);
      if (inbound.fingerprint) L.push(`    client-fingerprint: ${JSON.stringify(inbound.fingerprint)}`);
      if (inbound.network !== 'tcp') L.push(`    network: ${inbound.network}`);
      if (inbound.network === 'ws') {
        L.push(`    ws-opts:`, `      path: ${JSON.stringify(inbound.wsPath || '/')}`);
        if (inbound.wsHost || inbound.sni) L.push(`      headers:`, `        Host: ${JSON.stringify(inbound.wsHost || inbound.sni)}`);
      } else if (inbound.network === 'grpc') {
        L.push(`    grpc-opts:`, `      grpc-service-name: ${JSON.stringify(inbound.grpcServiceName || 'grpc')}`);
      }
    } else if (inbound.protocol === 'shadowsocks') {
      L.push(`    type: ss`, `    server: ${JSON.stringify(host)}`, `    port: ${port}`, `    cipher: ${JSON.stringify(inbound.ssMethod || 'aes-256-gcm')}`, `    password: ${JSON.stringify(client.credential)}`, `    udp: true`);
    } else if (inbound.protocol === 'tuic') {
      L.push(`    type: tuic`, `    server: ${JSON.stringify(host)}`, `    port: ${port}`, `    uuid: ${JSON.stringify(client.credential)}`, `    password: ${JSON.stringify(client.secondaryPassword || client.credential)}`, `    congestion-controller: ${inbound.tuicCongestion || 'bbr'}`, `    udp-relay-mode: ${inbound.tuicUdpRelay || 'native'}`);
      if (inbound.sni) L.push(`    sni: ${JSON.stringify(inbound.sni)}`);
      L.push(`    alpn:`, `      - ${inbound.alpn || 'h3'}`);
    } else {
      L.push(`    type: hysteria2`, `    server: ${JSON.stringify(host)}`, `    port: ${port}`, `    password: ${JSON.stringify(client.credential)}`);
      if (inbound.sni) L.push(`    sni: ${JSON.stringify(inbound.sni)}`);
      if (inbound.hy2UpMbps) L.push(`    up: "${inbound.hy2UpMbps} Mbps"`);
      if (inbound.hy2DownMbps) L.push(`    down: "${inbound.hy2DownMbps} Mbps"`);
      if (inbound.hy2Obfs === 'salamander' && inbound.hy2ObfsPassword) {
        L.push(`    obfs: salamander`, `    obfs-password: ${JSON.stringify(inbound.hy2ObfsPassword)}`);
      }
    }
    blocks.push(L.join('\n'));
  }

  const list = names.map((n) => `      - ${JSON.stringify(n)}`).join('\n') || '      - DIRECT';
  const rules = [`  - IP-CIDR,127.0.0.0/8,DIRECT`, `  - IP-CIDR,192.168.0.0/16,DIRECT`];
  if (settings.blockAds) rules.push(`  - GEOSITE,category-ads-all,REJECT`);
  if (settings.bypassCountry && settings.bypassCountry !== 'none') {
    rules.push(`  - GEOSITE,${settings.bypassCountry},DIRECT`);
    rules.push(`  - GEOIP,${settings.bypassCountry.toUpperCase()},DIRECT`);
  }
  rules.push(`  - MATCH,EdgeProxy`);

  return [
    `mixed-port: ${settings.clashMixedPort || 7890}`,
    `allow-lan: false`,
    `mode: rule`,
    `log-level: info`,
    `unified-delay: true`,
    `dns:`,
    `  enable: true`,
    `  enhanced-mode: fake-ip`,
    `  nameserver:`,
    `    - ${settings.dnsServer || 'https://1.1.1.1/dns-query'}`,
    `proxies:`,
    blocks.length ? blocks.join('\n') : '  []',
    `proxy-groups:`,
    `  - name: "EdgeProxy"`,
    `    type: select`,
    `    proxies:`,
    `      - "Auto Select"`,
    list,
    `  - name: "Auto Select"`,
    `    type: url-test`,
    `    url: "https://www.gstatic.com/generate_204"`,
    `    interval: 300`,
    `    proxies:`,
    list,
    `rules:`,
    ...rules,
  ].join('\n');
}

function buildSingboxJson(
  pairs: Array<{ inbound: InboundConfig; client: ClientConfig }>,
  settings: PanelSettings,
  endpoints: CleanEndpoint[]
): string {
  const targets = expandWithEndpoints(pairs, endpoints);
  const outbounds: Array<Record<string, unknown>> = [];
  const tags: string[] = [];

  for (const { inbound, client, overrideHost, overridePort, labelSuffix } of targets) {
    const host = overrideHost || inbound.serverAddress || settings.edgeDomain;
    const port = overridePort || inbound.port;
    const tag = `${inbound.remark || inbound.tag}${labelSuffix ? ` (${labelSuffix})` : ''} - ${client.email}`;
    tags.push(tag);

    const tls =
      inbound.security === 'none'
        ? undefined
        : {
            enabled: true,
            server_name: inbound.sni || host,
            utls: { enabled: true, fingerprint: inbound.fingerprint || 'chrome' },
            ...(inbound.security === 'tls' && inbound.alpn
              ? { alpn: inbound.alpn.split(',').map((s) => s.trim()).filter(Boolean) }
              : {}),
            ...(inbound.security === 'reality'
              ? { reality: { enabled: true, public_key: inbound.realityPublicKey, short_id: inbound.realityShortId || '' } }
              : {}),
            ...(settings.fragmentEnabled && inbound.security === 'tls' ? { fragment: true } : {}),
          };

    const transport =
      inbound.network === 'ws'
        ? {
            type: 'ws',
            path: inbound.wsPath || '/',
            ...(inbound.wsHost || inbound.sni ? { headers: { Host: inbound.wsHost || inbound.sni } } : {}),
          }
        : inbound.network === 'grpc'
        ? { type: 'grpc', service_name: inbound.grpcServiceName || 'grpc' }
        : undefined;

    if (inbound.protocol === 'vless') {
      outbounds.push({
        type: 'vless',
        tag,
        server: host,
        server_port: port,
        uuid: client.credential,
        ...(inbound.network === 'tcp' && inbound.flow ? { flow: inbound.flow } : {}),
        ...(tls ? { tls } : {}),
        ...(transport ? { transport } : {}),
      });
    } else if (inbound.protocol === 'vmess') {
      outbounds.push({
        type: 'vmess',
        tag,
        server: host,
        server_port: port,
        uuid: client.credential,
        security: 'auto',
        alter_id: client.alterId ?? 0,
        ...(tls ? { tls } : {}),
        ...(transport ? { transport } : {}),
      });
    } else if (inbound.protocol === 'trojan') {
      outbounds.push({
        type: 'trojan',
        tag,
        server: host,
        server_port: port,
        password: client.credential,
        ...(tls ? { tls } : {}),
        ...(transport ? { transport } : {}),
      });
    } else if (inbound.protocol === 'shadowsocks') {
      outbounds.push({
        type: 'shadowsocks',
        tag,
        server: host,
        server_port: port,
        method: inbound.ssMethod || 'aes-256-gcm',
        password: client.credential,
      });
    } else if (inbound.protocol === 'tuic') {
      outbounds.push({
        type: 'tuic',
        tag,
        server: host,
        server_port: port,
        uuid: client.credential,
        password: client.secondaryPassword || client.credential,
        congestion_control: inbound.tuicCongestion || 'bbr',
        udp_relay_mode: inbound.tuicUdpRelay || 'native',
        tls: { enabled: true, server_name: inbound.sni || host, alpn: [inbound.alpn || 'h3'] },
      });
    } else {
      outbounds.push({
        type: 'hysteria2',
        tag,
        server: host,
        server_port: port,
        password: client.credential,
        up_mbps: inbound.hy2UpMbps || 100,
        down_mbps: inbound.hy2DownMbps || 200,
        tls: { enabled: true, server_name: inbound.sni || host, alpn: [inbound.alpn || 'h3'] },
        ...(inbound.hy2Obfs === 'salamander' && inbound.hy2ObfsPassword
          ? { obfs: { type: 'salamander', password: inbound.hy2ObfsPassword } }
          : {}),
      });
    }
  }

  return JSON.stringify(
    {
      log: { level: 'info', timestamp: true },
      inbounds: [{ type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 }],
      outbounds: [
        { type: 'selector', tag: 'proxy', outbounds: ['auto', ...tags, 'direct'], default: tags[0] || 'direct' },
        { type: 'urltest', tag: 'auto', outbounds: tags.length ? tags : ['direct'], url: 'https://www.gstatic.com/generate_204', interval: '3m' },
        ...outbounds,
        { type: 'direct', tag: 'direct' },
        { type: 'block', tag: 'block' },
      ],
      route: { rules: [{ ip_is_private: true, outbound: 'direct' }], final: 'proxy' },
    },
    null,
    2
  );
}

function buildXrayJson(
  pairs: Array<{ inbound: InboundConfig; client: ClientConfig }>,
  settings: PanelSettings,
  endpoints: CleanEndpoint[]
): string {
  const targets = expandWithEndpoints(pairs, endpoints);
  const outbounds: Array<Record<string, unknown>> = [];

  for (const [idx, { inbound, client, overrideHost, overridePort, labelSuffix }] of targets.entries()) {
    const host = overrideHost || inbound.serverAddress || settings.edgeDomain;
    const port = overridePort || inbound.port;
    const tag = idx === 0 ? 'proxy' : `proxy-${idx + 1}`;
    const remark = `${inbound.remark || inbound.tag}${labelSuffix ? ` (${labelSuffix})` : ''} - ${client.email}`;
    const streamSettings: Record<string, unknown> = {
      network: inbound.network === 'quic' ? 'tcp' : inbound.network,
      security: inbound.security,
    };
    if (inbound.security === 'tls') {
      streamSettings.tlsSettings = {
        serverName: inbound.sni || host,
        fingerprint: inbound.fingerprint || 'chrome',
        alpn: inbound.alpn ? inbound.alpn.split(',').map((s) => s.trim()) : ['h2', 'http/1.1'],
      };
      if (settings.fragmentEnabled) streamSettings.sockopt = { dialerProxy: 'fragment', tcpFastOpen: true };
    } else if (inbound.security === 'reality') {
      streamSettings.realitySettings = {
        serverName: inbound.sni || 'www.cloudflare.com',
        fingerprint: inbound.fingerprint || 'chrome',
        publicKey: inbound.realityPublicKey,
        shortId: inbound.realityShortId || '',
        spiderX: '/',
      };
    }
    if (inbound.network === 'ws') {
      streamSettings.wsSettings = {
        path: inbound.wsPath || '/',
        headers: inbound.wsHost || inbound.sni ? { Host: inbound.wsHost || inbound.sni } : undefined,
      };
    } else if (inbound.network === 'grpc') {
      streamSettings.grpcSettings = { serviceName: inbound.grpcServiceName || 'grpc' };
    }

    const mux = settings.muxEnabled ? { enabled: true, concurrency: settings.muxConcurrency || 8 } : { enabled: false };
    if (inbound.protocol === 'vless') {
      outbounds.push({
        tag,
        remark,
        protocol: 'vless',
        settings: { vnext: [{ address: host, port, users: [{ id: client.credential, encryption: 'none', flow: inbound.network === 'tcp' ? inbound.flow || '' : '' }] }] },
        streamSettings,
        mux,
      });
    } else if (inbound.protocol === 'vmess') {
      outbounds.push({
        tag,
        remark,
        protocol: 'vmess',
        settings: { vnext: [{ address: host, port, users: [{ id: client.credential, alterId: client.alterId ?? 0, security: 'auto' }] }] },
        streamSettings,
        mux,
      });
    } else if (inbound.protocol === 'trojan') {
      outbounds.push({
        tag,
        remark,
        protocol: 'trojan',
        settings: { servers: [{ address: host, port, password: client.credential }] },
        streamSettings,
        mux,
      });
    }
  }

  if (settings.fragmentEnabled) {
    outbounds.push({
      tag: 'fragment',
      protocol: 'freedom',
      settings: {
        fragment: {
          packets: settings.fragmentPackets || 'tlshello',
          length: settings.fragmentLength || '100-200',
          interval: settings.fragmentInterval || '10-20',
        },
      },
    });
  }
  outbounds.push({ tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' });

  const rules: Array<Record<string, unknown>> = [{ type: 'field', ip: ['geoip:private'], outboundTag: 'direct' }];
  if (settings.blockAds) rules.push({ type: 'field', domain: ['geosite:category-ads-all'], outboundTag: 'block' });
  if (settings.bypassCountry && settings.bypassCountry !== 'none') {
    rules.push({ type: 'field', domain: [`geosite:${settings.bypassCountry}`], outboundTag: 'direct' });
    rules.push({ type: 'field', ip: [`geoip:${settings.bypassCountry}`], outboundTag: 'direct' });
  }

  return JSON.stringify(
    {
      log: { loglevel: 'warning' },
      dns: { servers: [settings.dnsServer || '1.1.1.1', '8.8.8.8', 'localhost'] },
      inbounds: [{ tag: 'socks-in', port: 10808, listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: true } }],
      outbounds,
      routing: { domainStrategy: 'IPIfNonMatch', rules },
    },
    null,
    2
  );
}

// ---------------------------------------------------------------------------
// Response Helpers
// ---------------------------------------------------------------------------
function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers },
  });
}

function escapeServerHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] || c));
}

// ---------------------------------------------------------------------------
// Embedded Tailwind CDN Web UI HTML Renderer
// ---------------------------------------------------------------------------
function renderHtml(panelTitle: string): string {
  const safeTitle = escapeServerHtml(panelTitle);
  return `<!doctype html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${safeTitle} — Cloudflare Workers Proxy &amp; Relay Panel</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Plus+Jakarta+Sans:wght@500;600;700&family=Public+Sans:wght@400;500;600&display=swap" rel="stylesheet" />
  <style>
    body { font-family: 'Public Sans', system-ui, sans-serif; }
    h1, h2, h3, .font-display { font-family: 'Plus Jakarta Sans', system-ui, sans-serif; }
    code, pre, .font-mono { font-family: 'JetBrains Mono', monospace; font-variant-numeric: tabular-nums; }
    .tabular-nums { font-variant-numeric: tabular-nums; }
  </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen antialiased">
  <div id="app"></div>
  <script>
    const state = {
      authenticated: false,
      username: '',
      backend: 'd1',
      tab: 'inbounds',
      inbounds: [],
      endpoints: [],
      logs: [],
      settings: {},
      filter: 'all',
      search: '',
      modal: null,
      qrData: null,
      toast: null
    };

    const api = async (path, opts = {}) => {
      const res = await fetch(path, {
        headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
        ...opts
      });
      if (res.status === 401 && !path.includes('/auth/')) {
        state.authenticated = false;
        render();
        throw new Error('Unauthorized');
      }
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || 'Request failed');
      return data;
    };

    const showToast = (msg) => {
      state.toast = msg;
      render();
      setTimeout(() => { state.toast = null; render(); }, 2600);
    };

    const fmtBytes = (b) => {
      if (!b || b <= 0) return '0 B';
      const u = ['B', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), u.length - 1);
      return (b / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 2) + ' ' + u[i];
    };

    const escapeHtml = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

    async function loadDashboard() {
      const session = await api('/api/auth/session');
      if (!session.authenticated) {
        state.authenticated = false;
        render();
        return;
      }
      state.authenticated = true;
      state.username = session.username;
      state.backend = session.backend;
      const [inb, ep, lg, cfg] = await Promise.all([
        api('/api/inbounds'),
        api('/api/endpoints'),
        api('/api/logs'),
        api('/api/settings')
      ]);
      state.inbounds = inb.inbounds || [];
      state.endpoints = ep.endpoints || [];
      state.logs = lg.logs || [];
      state.settings = cfg.settings || {};
      render();
    }

    async function handleLogin(e) {
      e.preventDefault();
      const form = new FormData(e.target);
      try {
        await api('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify({ username: form.get('username'), password: form.get('password') })
        });
        await loadDashboard();
      } catch (err) {
        showToast(err.message);
      }
    }

    async function handleLogout() {
      await api('/api/auth/logout', { method: 'POST' });
      state.authenticated = false;
      render();
    }

    async function createInbound(e) {
      e.preventDefault();
      const f = new FormData(e.target);
      const protocol = f.get('protocol');
      await api('/api/inbounds', {
        method: 'POST',
        body: JSON.stringify({
          remark: f.get('remark'),
          tag: f.get('tag') || (protocol + '-' + f.get('port')),
          protocol,
          serverAddress: f.get('serverAddress'),
          port: Number(f.get('port')),
          network: f.get('network'),
          security: f.get('security'),
          sni: f.get('sni'),
          wsPath: f.get('wsPath') || '/edge-ws',
          realityPublicKey: f.get('realityPublicKey') || '',
          realityPrivateKey: f.get('realityPrivateKey') || '',
          realityShortId: f.get('realityShortId') || ''
        })
      });
      state.modal = null;
      showToast('Inbound created');
      await loadDashboard();
    }

    async function createClient(e) {
      e.preventDefault();
      const f = new FormData(e.target);
      const days = Number(f.get('expiryDays') || 0);
      await api('/api/clients', {
        method: 'POST',
        body: JSON.stringify({
          inboundId: f.get('inboundId'),
          email: f.get('email'),
          totalGb: Number(f.get('totalGb') || 0),
          expiryTime: days > 0 ? Date.now() + days * 86400000 : 0
        })
      });
      state.modal = null;
      showToast('Client added');
      await loadDashboard();
    }

    async function batchCreateClients(e) {
      e.preventDefault();
      const f = new FormData(e.target);
      const days = Number(f.get('expiryDays') || 0);
      await api('/api/clients/batch', {
        method: 'POST',
        body: JSON.stringify({
          inboundId: f.get('inboundId'),
          prefix: f.get('prefix'),
          count: Number(f.get('count') || 5),
          totalGb: Number(f.get('totalGb') || 0),
          expiryTime: days > 0 ? Date.now() + days * 86400000 : 0
        })
      });
      state.modal = null;
      showToast('Batch clients provisioned');
      await loadDashboard();
    }

    async function addEndpoint(e) {
      e.preventDefault();
      const f = new FormData(e.target);
      await api('/api/endpoints', {
        method: 'POST',
        body: JSON.stringify({ label: f.get('label'), address: f.get('address'), port: Number(f.get('port') || 443) })
      });
      showToast('Clean IP added');
      await loadDashboard();
    }

    async function deleteEndpoint(id) {
      await api('/api/endpoints/' + id, { method: 'DELETE' });
      await loadDashboard();
    }

    async function saveRelaySettings(e) {
      e.preventDefault();
      const f = new FormData(e.target);
      await api('/api/settings', {
        method: 'PUT',
        body: JSON.stringify({
          workerRelayEnabled: f.get('workerRelayEnabled') === 'on',
          workerRelayPath: f.get('workerRelayPath') || '/edge-ws',
          workerProxyIp: f.get('workerProxyIp') || '',
          fragmentEnabled: f.get('fragmentEnabled') === 'on',
          bypassCountry: f.get('bypassCountry') || 'none',
          blockAds: f.get('blockAds') === 'on'
        })
      });
      showToast('Relay & routing settings saved');
      await loadDashboard();
    }

    async function downloadBackup() {
      const data = await api('/api/backup');
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'edgepanel-backup.json';
      a.click();
    }

    async function toggleInbound(id, enabled) {
      await api('/api/inbounds/' + id, { method: 'PUT', body: JSON.stringify({ enabled: !enabled }) });
      await loadDashboard();
    }

    async function deleteInbound(id) {
      await api('/api/inbounds/' + id, { method: 'DELETE' });
      showToast('Inbound deleted');
      await loadDashboard();
    }

    async function deleteClient(id) {
      await api('/api/clients/' + id, { method: 'DELETE' });
      showToast('Client removed');
      await loadDashboard();
    }

    async function resetTraffic(id) {
      await api('/api/clients/' + id + '/reset-traffic', { method: 'POST' });
      showToast('Traffic counters reset');
      await loadDashboard();
    }

    async function fillKeygen() {
      const keys = await api('/api/tools/keygen');
      const pubEl = document.querySelector('[name="realityPublicKey"]');
      const privEl = document.querySelector('[name="realityPrivateKey"]');
      const sidEl = document.querySelector('[name="realityShortId"]');
      if (pubEl) pubEl.value = keys.reality.publicKey;
      if (privEl) privEl.value = keys.reality.privateKey;
      if (sidEl) sidEl.value = keys.shortId;
    }

    function openQr(title, text) {
      state.qrData = { title, text };
      render();
      setTimeout(() => {
        const canvas = document.getElementById('qr-canvas');
        if (canvas && window.QRCode) window.QRCode.toCanvas(canvas, text, { width: 220, margin: 1 });
      }, 20);
    }

    function copyText(text) {
      navigator.clipboard.writeText(text);
      showToast('Copied to clipboard');
    }

    function render() {
      const root = document.getElementById('app');
      if (!state.authenticated) {
        root.innerHTML = \`
          <div class="min-h-screen flex items-center justify-center p-6 bg-slate-950">
            <form onsubmit="handleLogin(event)" class="w-full max-w-sm border border-slate-800 bg-slate-900 rounded-xl p-6 space-y-5">
              <div>
                <h1 class="text-xl font-semibold text-white tracking-tight">${safeTitle}</h1>
                <p class="text-sm text-slate-400 mt-1">Sign in with your Cloudflare Worker admin secrets.</p>
              </div>
              <div class="space-y-3">
                <div>
                  <label class="block text-xs font-medium text-slate-300 mb-1.5">Username</label>
                  <input name="username" required class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white focus:outline-none focus:border-orange-500" placeholder="admin" />
                </div>
                <div>
                  <label class="block text-xs font-medium text-slate-300 mb-1.5">Password</label>
                  <input name="password" type="password" required class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white focus:outline-none focus:border-orange-500" placeholder="••••••••••••" />
                </div>
              </div>
              <button type="submit" class="w-full py-2.5 px-4 bg-orange-600 hover:bg-orange-500 text-white text-sm font-medium rounded-lg transition-colors">Sign In</button>
            </form>
          </div>\`;
        return;
      }

      const allClients = state.inbounds.flatMap(i => i.clients || []);
      const totalTraffic = allClients.reduce((acc, c) => acc + (c.upBytes || 0) + (c.downBytes || 0), 0);
      const filtered = state.inbounds.filter(i => {
        if (state.filter !== 'all' && i.protocol !== state.filter) return false;
        if (state.search) {
          const q = state.search.toLowerCase();
          return (i.remark + ' ' + i.tag + ' ' + i.protocol).toLowerCase().includes(q) ||
            (i.clients || []).some(c => c.email.toLowerCase().includes(q));
        }
        return true;
      });

      root.innerHTML = \`
        <div class="min-h-screen flex flex-col">
          <header class="border-b border-slate-800 bg-slate-900/60 px-6 py-3.5 flex items-center justify-between gap-8">
            <div class="text-base font-semibold text-white whitespace-nowrap shrink-0">${safeTitle}</div>
            <nav class="flex items-center gap-4 text-xs font-medium overflow-x-auto">
              <button onclick="state.tab='inbounds'; render()" class="\${state.tab==='inbounds'?'text-orange-400':'text-slate-400 hover:text-white'} whitespace-nowrap">Inbounds</button>
              <button onclick="state.tab='relay'; render()" class="\${state.tab==='relay'?'text-orange-400':'text-slate-400 hover:text-white'} whitespace-nowrap">Relay &amp; Clean IPs</button>
              <button onclick="state.tab='logs'; render()" class="\${state.tab==='logs'?'text-orange-400':'text-slate-400 hover:text-white'} whitespace-nowrap">Access Logs</button>
            </nav>
            <div class="flex items-center gap-2 shrink-0">
              <button onclick="downloadBackup()" class="px-3 py-2 border border-slate-700 hover:border-slate-600 text-slate-300 text-xs rounded-lg whitespace-nowrap">Backup</button>
              <button onclick="state.modal='inbound'; render()" class="px-3.5 py-2 bg-orange-600 hover:bg-orange-500 text-white text-xs font-medium rounded-lg whitespace-nowrap">Add Inbound</button>
              <button onclick="handleLogout()" class="px-3 py-2 border border-slate-700 hover:border-slate-600 text-slate-300 text-xs rounded-lg whitespace-nowrap">Sign Out</button>
            </div>
          </header>

          <main class="max-w-7xl w-full mx-auto px-6 py-6 space-y-6 flex-1">
            <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <div class="border border-slate-800 bg-slate-900 rounded-xl p-4">
                <div class="text-xs text-slate-400">Active Inbounds</div>
                <div class="text-2xl font-semibold text-white mt-1 tabular-nums">\${state.inbounds.filter(i => i.enabled).length} / \${state.inbounds.length}</div>
              </div>
              <div class="border border-slate-800 bg-slate-900 rounded-xl p-4">
                <div class="text-xs text-slate-400">Total Clients</div>
                <div class="text-2xl font-semibold text-white mt-1 tabular-nums">\${allClients.length}</div>
              </div>
              <div class="border border-slate-800 bg-slate-900 rounded-xl p-4">
                <div class="text-xs text-slate-400">Aggregate Traffic</div>
                <div class="text-2xl font-semibold text-white mt-1 tabular-nums">\${fmtBytes(totalTraffic)}</div>
              </div>
              <div class="border border-slate-800 bg-slate-900 rounded-xl p-4">
                <div class="text-xs text-slate-400">Clean IPs &amp; Storage</div>
                <div class="text-sm font-mono text-slate-200 mt-2">\${state.endpoints.length} IPs · \${escapeHtml(state.backend.toUpperCase())}</div>
              </div>
            </div>

            \${state.tab === 'inbounds' ? \`
              <div class="flex flex-wrap items-center justify-between gap-4">
                <div class="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg overflow-x-auto">
                  \${['all','vless','vmess','trojan','shadowsocks','tuic','hysteria2'].map(p => \`
                    <button onclick="state.filter='\${p}'; render()" class="px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap \${state.filter === p ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'}">\${p === 'all' ? 'All' : p.toUpperCase()}</button>
                  \`).join('')}
                </div>
                <input value="\${escapeHtml(state.search)}" oninput="state.search=this.value; render()" placeholder="Filter inbounds or clients..." class="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 w-64 focus:outline-none focus:border-orange-500" />
              </div>

              <div class="space-y-4">
                \${filtered.length === 0 ? \`
                  <div class="border border-slate-800 bg-slate-900 rounded-xl p-10 text-center">
                    <div class="text-sm font-medium text-slate-200">No inbound configurations found</div>
                    <button onclick="state.modal='inbound'; render()" class="mt-4 px-4 py-2 bg-orange-600 hover:bg-orange-500 text-white text-xs font-medium rounded-lg">Create First Inbound</button>
                  </div>
                \` : filtered.map(inb => \`
                  <div class="border border-slate-800 bg-slate-900 rounded-xl overflow-hidden">
                    <div class="px-5 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4">
                      <div>
                        <div class="flex items-center gap-2.5">
                          <span class="text-sm font-semibold text-white">\${escapeHtml(inb.remark || inb.tag)}</span>
                          <span class="text-xs \${inb.enabled ? 'text-emerald-400' : 'text-rose-400'}">\${inb.enabled ? 'Active' : 'Disabled'}</span>
                        </div>
                        <div class="text-xs text-slate-400 font-mono mt-0.5">\${inb.protocol.toUpperCase()} · \${inb.network.toUpperCase()} · \${inb.security.toUpperCase()} · \${escapeHtml(inb.serverAddress || location.hostname)}:\${inb.port}</div>
                      </div>
                      <div class="flex items-center gap-2">
                        <button onclick="state.modal='client:' + '\${inb.id}'; render()" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-lg">Add Client</button>
                        <button onclick="state.modal='batch:' + '\${inb.id}'; render()" class="px-3 py-1.5 border border-slate-700 hover:border-slate-600 text-slate-200 text-xs rounded-lg">Batch</button>
                        <button onclick="toggleInbound('\${inb.id}', \${inb.enabled})" class="px-3 py-1.5 border border-slate-700 text-slate-300 text-xs rounded-lg">\${inb.enabled ? 'Disable' : 'Enable'}</button>
                        <button onclick="deleteInbound('\${inb.id}')" class="px-3 py-1.5 border border-rose-900/60 text-rose-400 text-xs rounded-lg">Delete</button>
                      </div>
                    </div>
                    <div class="overflow-x-auto">
                      <table class="w-full text-left text-xs">
                        <thead class="bg-slate-950/60 text-slate-400 border-b border-slate-800">
                          <tr>
                            <th class="px-5 py-2.5 font-medium">Client</th>
                            <th class="px-5 py-2.5 font-medium">Traffic</th>
                            <th class="px-5 py-2.5 font-medium">Expiry</th>
                            <th class="px-5 py-2.5 font-medium text-right">Actions</th>
                          </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-800/70">
                          \${(inb.clients || []).map(c => {
                            const subUrl = location.origin + '/sub/' + c.subId;
                            return \`
                              <tr class="hover:bg-slate-800/30">
                                <td class="px-5 py-3 font-medium text-slate-200">\${escapeHtml(c.email)}</td>
                                <td class="px-5 py-3 font-mono tabular-nums text-slate-300">\${fmtBytes((c.upBytes||0)+(c.downBytes||0))} / \${c.totalGb ? c.totalGb + ' GB' : 'Unlimited'}</td>
                                <td class="px-5 py-3 font-mono tabular-nums text-slate-400">\${c.expiryTime ? new Date(c.expiryTime).toISOString().slice(0,10) : 'Never'}</td>
                                <td class="px-5 py-3 text-right space-x-2 whitespace-nowrap">
                                  <button onclick="copyText('\${subUrl}')" class="text-orange-400 hover:text-orange-300">Sub</button>
                                  <button onclick="copyText('\${subUrl}?format=clash')" class="text-slate-300 hover:text-white">Clash</button>
                                  <button onclick="copyText('\${subUrl}?format=singbox')" class="text-slate-300 hover:text-white">Sing-box</button>
                                  <button onclick="copyText('\${subUrl}?format=xray')" class="text-slate-300 hover:text-white">Xray</button>
                                  <button onclick="openQr('\${escapeHtml(c.email)} Subscription', '\${subUrl}')" class="text-slate-300 hover:text-white">QR</button>
                                  <button onclick="resetTraffic('\${c.id}')" class="text-slate-400 hover:text-slate-200">Reset</button>
                                  <button onclick="deleteClient('\${c.id}')" class="text-rose-400 hover:text-rose-300">Remove</button>
                                </td>
                              </tr>\`;
                          }).join('')}
                        </tbody>
                      </table>
                    </div>
                  </div>
                \`).join('')}
              </div>
            \` : state.tab === 'relay' ? \`
              <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <form onsubmit="saveRelaySettings(event)" class="border border-slate-800 bg-slate-900 rounded-xl p-5 space-y-4 text-xs">
                  <h2 class="text-sm font-semibold text-white">Built-in VLESS-WS Edge Relay &amp; Routing</h2>
                  <label class="flex items-center gap-2 text-slate-200">
                    <input type="checkbox" name="workerRelayEnabled" \${state.settings.workerRelayEnabled ? 'checked' : ''} />
                    Enable Serverless VLESS WebSocket Relay inside this Worker
                  </label>
                  <div class="grid grid-cols-2 gap-3">
                    <div>
                      <label class="block text-slate-400 mb-1">Relay WS Path</label>
                      <input name="workerRelayPath" value="\${escapeHtml(state.settings.workerRelayPath || '/edge-ws')}" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg font-mono text-white" />
                    </div>
                    <div>
                      <label class="block text-slate-400 mb-1">Fallback ProxyIP</label>
                      <input name="workerProxyIp" value="\${escapeHtml(state.settings.workerProxyIp || '')}" placeholder="cdn.example.com:443" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg font-mono text-white" />
                    </div>
                    <div>
                      <label class="block text-slate-400 mb-1">Geo-Bypass Country</label>
                      <select name="bypassCountry" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white">
                        <option value="none" \${state.settings.bypassCountry==='none'?'selected':''}>None</option>
                        <option value="ir" \${state.settings.bypassCountry==='ir'?'selected':''}>Iran (IR)</option>
                        <option value="cn" \${state.settings.bypassCountry==='cn'?'selected':''}>China (CN)</option>
                        <option value="ru" \${state.settings.bypassCountry==='ru'?'selected':''}>Russia (RU)</option>
                      </select>
                    </div>
                    <div class="flex flex-col justify-end gap-2">
                      <label class="flex items-center gap-2 text-slate-200"><input type="checkbox" name="fragmentEnabled" \${state.settings.fragmentEnabled ? 'checked' : ''} /> TLS Fragment</label>
                      <label class="flex items-center gap-2 text-slate-200"><input type="checkbox" name="blockAds" \${state.settings.blockAds ? 'checked' : ''} /> Block Ads</label>
                    </div>
                  </div>
                  <button type="submit" class="px-4 py-2 bg-orange-600 hover:bg-orange-500 text-white rounded-lg font-medium">Save Relay Settings</button>
                </form>

                <div class="border border-slate-800 bg-slate-900 rounded-xl p-5 space-y-4 text-xs">
                  <h2 class="text-sm font-semibold text-white">Clean Cloudflare IP Pool</h2>
                  <form onsubmit="addEndpoint(event)" class="grid grid-cols-3 gap-2">
                    <input name="label" required placeholder="CF-Clean-1" class="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white" />
                    <input name="address" required placeholder="104.16.132.229" class="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg font-mono text-white" />
                    <div class="flex gap-2">
                      <input name="port" type="number" value="443" class="w-20 px-2 py-2 bg-slate-950 border border-slate-800 rounded-lg font-mono text-white" />
                      <button type="submit" class="px-3 py-2 bg-orange-600 text-white rounded-lg font-medium">Add</button>
                    </div>
                  </form>
                  <div class="divide-y divide-slate-800">
                    \${state.endpoints.map(ep => \`
                      <div class="py-2.5 flex items-center justify-between">
                        <span class="font-mono text-slate-200">\${escapeHtml(ep.label)} · \${escapeHtml(ep.address)}:\${ep.port}</span>
                        <button onclick="deleteEndpoint('\${ep.id}')" class="text-rose-400">Remove</button>
                      </div>
                    \`).join('') || '<div class="text-slate-500 py-2">No clean endpoints added yet.</div>'}
                  </div>
                </div>
              </div>
            \` : \`
              <div class="border border-slate-800 bg-slate-900 rounded-xl overflow-hidden">
                <table class="w-full text-left text-xs">
                  <thead class="bg-slate-950/60 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th class="px-4 py-2.5">Time</th>
                      <th class="px-4 py-2.5">Client</th>
                      <th class="px-4 py-2.5">Format</th>
                      <th class="px-4 py-2.5">Country / IP</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-slate-800">
                    \${state.logs.map(l => \`
                      <tr>
                        <td class="px-4 py-2.5 font-mono text-slate-400">\${new Date(l.timestamp).toISOString().slice(0,19).replace('T',' ')}</td>
                        <td class="px-4 py-2.5 text-slate-200">\${escapeHtml(l.clientEmail || l.subId)}</td>
                        <td class="px-4 py-2.5 font-mono text-orange-400">\${escapeHtml(l.format)}</td>
                        <td class="px-4 py-2.5 font-mono text-slate-300">\${escapeHtml(l.country || '—')} · \${escapeHtml(l.ip)}</td>
                      </tr>
                    \`).join('') || '<tr><td colspan="4" class="px-4 py-6 text-center text-slate-500">No subscription access logs recorded yet.</td></tr>'}
                  </tbody>
                </table>
              </div>
            \`}
          </main>
        </div>

        \${state.modal === 'inbound' ? \`
          <div class="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
            <form onsubmit="createInbound(event)" class="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-lg p-6 space-y-4">
              <div class="flex items-center justify-between"><h2 class="text-base font-semibold text-white">Create Inbound</h2><button type="button" onclick="state.modal=null; render()" class="text-slate-400 text-sm">Close</button></div>
              <div class="grid grid-cols-2 gap-3 text-xs">
                <div class="col-span-2"><label class="block text-slate-400 mb-1">Remark</label><input name="remark" required placeholder="CF Edge VLESS WS" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white" /></div>
                <div><label class="block text-slate-400 mb-1">Protocol</label><select name="protocol" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white"><option value="vless">VLESS</option><option value="vmess">VMess</option><option value="trojan">Trojan</option><option value="shadowsocks">Shadowsocks</option><option value="tuic">TUIC v5</option><option value="hysteria2">Hysteria2</option></select></div>
                <div><label class="block text-slate-400 mb-1">Port</label><input name="port" type="number" value="443" required class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono" /></div>
                <div><label class="block text-slate-400 mb-1">Server / Worker Host</label><input name="serverAddress" value="\${escapeHtml(location.hostname)}" required class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono" /></div>
                <div><label class="block text-slate-400 mb-1">Transport</label><select name="network" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white"><option value="ws">WebSocket</option><option value="tcp">TCP</option><option value="grpc">gRPC</option><option value="quic">QUIC</option></select></div>
                <div><label class="block text-slate-400 mb-1">Security</label><select name="security" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white"><option value="tls">TLS</option><option value="reality">Reality</option><option value="none">None</option></select></div>
                <div><label class="block text-slate-400 mb-1">SNI / WS Path</label><input name="sni" value="\${escapeHtml(location.hostname)}" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono" /></div>
                <div class="col-span-2 flex justify-between pt-1"><span class="text-slate-400">Reality Keys</span><button type="button" onclick="fillKeygen()" class="text-orange-400">Generate X25519 Keypair</button></div>
                <div><input name="realityPublicKey" placeholder="Public Key (pbk)" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono" /></div>
                <div><input name="realityShortId" placeholder="Short ID (sid)" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono" /></div>
                <input type="hidden" name="realityPrivateKey" />
              </div>
              <div class="flex justify-end gap-2"><button type="button" onclick="state.modal=null; render()" class="px-4 py-2 border border-slate-700 text-slate-300 text-xs rounded-lg">Cancel</button><button type="submit" class="px-4 py-2 bg-orange-600 text-white text-xs rounded-lg">Save</button></div>
            </form>
          </div>
        \` : ''}

        \${state.modal && (state.modal.startsWith('client:') || state.modal.startsWith('batch:')) ? \`
          <div class="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
            <form onsubmit="\${state.modal.startsWith('batch:') ? 'batchCreateClients(event)' : 'createClient(event)'}" class="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-md p-6 space-y-4 text-xs">
              <div class="flex items-center justify-between"><h2 class="text-base font-semibold text-white">\${state.modal.startsWith('batch:') ? 'Batch Generate Clients' : 'Add Client'}</h2><button type="button" onclick="state.modal=null; render()" class="text-slate-400 text-sm">Close</button></div>
              <input type="hidden" name="inboundId" value="\${escapeHtml(state.modal.split(':')[1])}" />
              \${state.modal.startsWith('batch:') ? \`
                <div class="grid grid-cols-2 gap-3">
                  <div><label class="block text-slate-400 mb-1">Prefix</label><input name="prefix" required value="vip-user" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white" /></div>
                  <div><label class="block text-slate-400 mb-1">Count</label><input name="count" type="number" min="1" max="50" value="5" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono" /></div>
                </div>
              \` : \`
                <div><label class="block text-slate-400 mb-1">Client Email</label><input name="email" required placeholder="user@edgepanel" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white" /></div>
              \`}
              <div class="grid grid-cols-2 gap-3">
                <div><label class="block text-slate-400 mb-1">Quota (GB)</label><input name="totalGb" type="number" value="100" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono" /></div>
                <div><label class="block text-slate-400 mb-1">Expiry (Days)</label><input name="expiryDays" type="number" value="30" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono" /></div>
              </div>
              <div class="flex justify-end gap-2"><button type="button" onclick="state.modal=null; render()" class="px-4 py-2 border border-slate-700 text-slate-300 rounded-lg">Cancel</button><button type="submit" class="px-4 py-2 bg-orange-600 text-white rounded-lg">Create</button></div>
            </form>
          </div>
        \` : ''}

        \${state.qrData ? \`
          <div class="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-sm w-full text-center space-y-4">
              <div class="text-sm font-semibold text-white">\${escapeHtml(state.qrData.title)}</div>
              <div class="bg-white p-3 rounded-lg inline-block"><canvas id="qr-canvas"></canvas></div>
              <button onclick="state.qrData=null; render()" class="w-full py-2 bg-slate-800 text-white text-xs rounded-lg">Close</button>
            </div>
          </div>
        \` : ''}

        \${state.toast ? \`<div class="fixed bottom-5 right-5 bg-slate-800 border border-slate-700 text-white text-xs px-4 py-2.5 rounded-lg">\${escapeHtml(state.toast)}</div>\` : ''}
      \`;
    }

    loadDashboard();
  </script>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Main Cloudflare Worker Fetch Handler & Router
// ---------------------------------------------------------------------------
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    try {
      // 0. Built-in Serverless VLESS-over-WebSocket Relay (Upgrade: websocket)
      if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
        const state = await loadState(env, url.hostname);
        const relayPath = state.settings.workerRelayPath || '/edge-ws';
        if (state.settings.workerRelayEnabled && (path === relayPath || path.startsWith(relayPath + '/'))) {
          return handleVlessWebSocket(request, env, url.hostname, state, ctx);
        }
        return new Response('WebSocket relay disabled or invalid path', { status: 403 });
      }

      // 1. Public Subscription Endpoint: GET /sub/:subId
      const subPrefix = (env.SUB_PATH || '/sub').replace(/\/+$/, '');
      if (method === 'GET' && path.startsWith(subPrefix + '/')) {
        const subId = decodeURIComponent(path.slice(subPrefix.length + 1)).split('/')[0];
        if (!subId) return new Response('Missing subscription ID', { status: 400 });

        const state = await loadState(env, url.hostname);
        const matchedClients = state.clients.filter((c) => c.subId === subId && c.enabled);
        if (matchedClients.length === 0) {
          return new Response('Subscription not found or disabled', { status: 404 });
        }

        const now = Date.now();
        const activePairs: Array<{ inbound: InboundConfig; client: ClientConfig }> = [];
        for (const client of matchedClients) {
          if (client.expiryTime > 0 && client.expiryTime < now) continue;
          if (client.totalGb > 0 && client.upBytes + client.downBytes >= client.totalGb * 1024 ** 3) continue;
          const inbound = state.inbounds.find((i) => i.id === client.inboundId && i.enabled);
          if (inbound) activePairs.push({ inbound, client });
        }

        if (activePairs.length === 0) {
          return new Response('Subscription expired or quota exceeded', { status: 403 });
        }

        const primary = matchedClients[0];
        const totalBytes = primary.totalGb > 0 ? Math.round(primary.totalGb * 1024 ** 3) : 0;
        const expireSec = primary.expiryTime > 0 ? Math.floor(primary.expiryTime / 1000) : 0;
        const userInfo = `upload=${primary.upBytes}; download=${primary.downBytes}; total=${totalBytes}; expire=${expireSec}`;

        const formatParam = url.searchParams.get('format')?.toLowerCase();
        const ua = (request.headers.get('User-Agent') || '').toLowerCase();
        const format =
          formatParam ||
          (ua.includes('clash') || ua.includes('mihomo') || ua.includes('stash')
            ? 'clash'
            : ua.includes('sing-box') || ua.includes('sfa') || ua.includes('sfi')
            ? 'singbox'
            : 'base64');

        ctx.waitUntil(
          recordAccessLog(env, url.hostname, {
            id: crypto.randomUUID(),
            subId,
            clientEmail: primary.email,
            format,
            userAgent: (request.headers.get('User-Agent') || '').slice(0, 120),
            country: String((request as Request & { cf?: { country?: string } }).cf?.country || ''),
            ip: request.headers.get('CF-Connecting-IP') || '',
            status: 200,
            timestamp: Date.now(),
          })
        );

        if (format === 'clash') {
          return new Response(buildClashYaml(activePairs, state.settings, state.endpoints), {
            headers: {
              'Content-Type': 'text/yaml; charset=utf-8',
              'Subscription-Userinfo': userInfo,
              'Content-Disposition': `attachment; filename="${primary.email || 'edgepanel'}.yaml"`,
            },
          });
        }

        if (format === 'singbox') {
          return new Response(buildSingboxJson(activePairs, state.settings, state.endpoints), {
            headers: { 'Content-Type': 'application/json; charset=utf-8', 'Subscription-Userinfo': userInfo },
          });
        }

        if (format === 'xray') {
          return new Response(buildXrayJson(activePairs, state.settings, state.endpoints), {
            headers: { 'Content-Type': 'application/json; charset=utf-8', 'Subscription-Userinfo': userInfo },
          });
        }

        const targets = expandWithEndpoints(activePairs, state.endpoints);
        const uris = targets.map(({ inbound, client, overrideHost, overridePort, labelSuffix }) =>
          buildClientUri(inbound, client, state.settings.edgeDomain || url.hostname, overrideHost, overridePort, labelSuffix)
        );
        const body = format === 'raw' ? uris.join('\n') : toBase64Std(uris.join('\n'));
        return new Response(body, {
          headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Subscription-Userinfo': userInfo,
            'Profile-Update-Interval': '12',
          },
        });
      }

      // 2. Authentication Routes
      if (path === '/api/auth/login' && method === 'POST') {
        const body = (await request.json().catch(() => ({}))) as { username?: string; password?: string };
        const expectedUser = env.ADMIN_USERNAME || 'admin';
        const expectedPass = env.ADMIN_PASSWORD;
        if (!expectedPass) return json({ error: 'ADMIN_PASSWORD secret is not configured' }, 500);
        const [uOk, pOk] = await Promise.all([
          constantTimeEqual(body.username || '', expectedUser),
          constantTimeEqual(body.password || '', expectedPass),
        ]);
        if (!uOk || !pOk) return json({ error: 'Invalid credentials' }, 401);
        const token = await signSessionToken(expectedUser, env);
        const secureFlag = url.protocol === 'https:' ? 'Secure; ' : '';
        return json(
          { ok: true, username: expectedUser },
          200,
          { 'Set-Cookie': `${SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly; ${secureFlag}SameSite=Lax; Path=/; Max-Age=604800` }
        );
      }

      if (path === '/api/auth/logout' && method === 'POST') {
        return json({ ok: true }, 200, { 'Set-Cookie': `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0` });
      }

      if (path === '/api/auth/session' && method === 'GET') {
        const session = await verifySessionToken(getCookie(request, SESSION_COOKIE), env);
        return json({
          authenticated: Boolean(session),
          username: session?.username || null,
          backend: env.DB ? 'd1' : env.PANEL_KV ? 'kv' : 'unconfigured',
        });
      }

      // 3. Authenticated REST API Middleware
      if (path.startsWith('/api/')) {
        const session = await verifySessionToken(getCookie(request, SESSION_COOKIE), env);
        if (!session) return json({ error: 'Unauthorized' }, 401);

        if (path === '/api/tools/keygen' && method === 'GET') {
          return json({
            uuid: crypto.randomUUID(),
            reality: generateRealityKeypair(),
            shortId: generateShortId(8),
            ss2022_128: generateSs2022Key(128),
            ss2022_256: generateSs2022Key(256),
          });
        }

        const state = await loadState(env, url.hostname);

        if (path === '/api/overview' && method === 'GET') {
          const now = Date.now();
          const fiveDays = 5 * 86400000;
          return json({
            activeInbounds: state.inbounds.filter((i) => i.enabled).length,
            totalInbounds: state.inbounds.length,
            activeClients: state.clients.filter((c) => c.enabled).length,
            totalClients: state.clients.length,
            totalUpBytes: state.clients.reduce((s, c) => s + c.upBytes, 0),
            totalDownBytes: state.clients.reduce((s, c) => s + c.downBytes, 0),
            expiringSoonCount: state.clients.filter((c) => c.expiryTime > now && c.expiryTime - now <= fiveDays).length,
            cleanEndpointsCount: state.endpoints.filter((e) => e.enabled).length,
            storageBackend: state.backend,
          });
        }

        if (path === '/api/inbounds' && method === 'GET') {
          return json({
            inbounds: state.inbounds.map((inb) => ({
              ...inb,
              clients: state.clients.filter((c) => c.inboundId === inb.id),
            })),
            backend: state.backend,
          });
        }

        if (path === '/api/inbounds' && method === 'POST') {
          const body = (await request.json()) as Partial<InboundConfig>;
          const now = Date.now();
          const protocol = (body.protocol || 'vless') as ProtocolType;
          const security = (body.security || (protocol === 'vless' ? 'reality' : 'tls')) as SecurityType;
          const realityKeys =
            security === 'reality' && (!body.realityPrivateKey || !body.realityPublicKey)
              ? generateRealityKeypair()
              : { privateKey: body.realityPrivateKey || '', publicKey: body.realityPublicKey || '' };

          const inbound: InboundConfig = {
            id: crypto.randomUUID(),
            tag: body.tag || `${protocol}-${body.port || 443}`,
            remark: body.remark || `${protocol.toUpperCase()} Edge Node`,
            protocol,
            listenHost: body.listenHost || '0.0.0.0',
            serverAddress: body.serverAddress || state.settings.edgeDomain || url.hostname,
            port: Number(body.port || 443),
            enabled: body.enabled !== false,
            network: (body.network || 'tcp') as NetworkType,
            security,
            sni: body.sni ?? state.settings.defaultSni,
            fingerprint: body.fingerprint || 'chrome',
            alpn: body.alpn || 'h2,http/1.1',
            flow: body.flow ?? (protocol === 'vless' && (body.network || 'tcp') === 'tcp' ? 'xtls-rprx-vision' : ''),
            wsPath: body.wsPath || '/edge-ws',
            wsHost: body.wsHost || '',
            grpcServiceName: body.grpcServiceName || 'grpc',
            realityPrivateKey: realityKeys.privateKey,
            realityPublicKey: realityKeys.publicKey,
            realityShortId: body.realityShortId || (security === 'reality' ? generateShortId(8) : ''),
            realityDest: body.realityDest || `${body.sni || state.settings.defaultSni}:443`,
            ssMethod: body.ssMethod || 'aes-256-gcm',
            tuicCongestion: body.tuicCongestion || 'bbr',
            tuicUdpRelay: body.tuicUdpRelay || 'native',
            hy2Obfs: body.hy2Obfs || 'none',
            hy2ObfsPassword: body.hy2ObfsPassword || '',
            hy2UpMbps: Number(body.hy2UpMbps || 100),
            hy2DownMbps: Number(body.hy2DownMbps || 200),
            createdAt: now,
            updatedAt: now,
          };

          if (env.DB) {
            await env.DB.prepare(
              `INSERT INTO inbounds (id, tag, remark, protocol, listen_host, server_address, port, enabled, network, security, sni, fingerprint, alpn, flow, ws_path, ws_host, grpc_service_name, reality_private_key, reality_public_key, reality_short_id, reality_dest, ss_method, tuic_congestion, tuic_udp_relay, hy2_obfs, hy2_obfs_password, hy2_up_mbps, hy2_down_mbps, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
            )
              .bind(
                inbound.id, inbound.tag, inbound.remark, inbound.protocol, inbound.listenHost, inbound.serverAddress,
                inbound.port, inbound.enabled ? 1 : 0, inbound.network, inbound.security, inbound.sni,
                inbound.fingerprint, inbound.alpn, inbound.flow, inbound.wsPath, inbound.wsHost, inbound.grpcServiceName,
                inbound.realityPrivateKey, inbound.realityPublicKey, inbound.realityShortId, inbound.realityDest,
                inbound.ssMethod, inbound.tuicCongestion, inbound.tuicUdpRelay, inbound.hy2Obfs, inbound.hy2ObfsPassword,
                inbound.hy2UpMbps, inbound.hy2DownMbps, inbound.createdAt, inbound.updatedAt
              )
              .run();
          } else {
            await saveKvState(env, { ...state, inbounds: [inbound, ...state.inbounds] });
          }
          return json({ inbound }, 201);
        }

        if (path.startsWith('/api/inbounds/') && method === 'PUT') {
          const id = path.slice('/api/inbounds/'.length);
          const existing = state.inbounds.find((i) => i.id === id);
          if (!existing) return json({ error: 'Inbound not found' }, 404);
          const patch = (await request.json()) as Partial<InboundConfig>;
          const updated: InboundConfig = { ...existing, ...patch, id, updatedAt: Date.now() };
          if (env.DB) {
            await env.DB.prepare(
              `UPDATE inbounds SET tag=?, remark=?, protocol=?, listen_host=?, server_address=?, port=?, enabled=?, network=?, security=?, sni=?, fingerprint=?, alpn=?, flow=?, ws_path=?, ws_host=?, grpc_service_name=?, reality_private_key=?, reality_public_key=?, reality_short_id=?, reality_dest=?, ss_method=?, tuic_congestion=?, tuic_udp_relay=?, hy2_obfs=?, hy2_obfs_password=?, hy2_up_mbps=?, hy2_down_mbps=?, updated_at=? WHERE id=?`
            )
              .bind(
                updated.tag, updated.remark, updated.protocol, updated.listenHost, updated.serverAddress,
                updated.port, updated.enabled ? 1 : 0, updated.network, updated.security, updated.sni,
                updated.fingerprint, updated.alpn, updated.flow, updated.wsPath, updated.wsHost, updated.grpcServiceName,
                updated.realityPrivateKey, updated.realityPublicKey, updated.realityShortId, updated.realityDest,
                updated.ssMethod, updated.tuicCongestion, updated.tuicUdpRelay, updated.hy2Obfs, updated.hy2ObfsPassword,
                updated.hy2UpMbps, updated.hy2DownMbps, updated.updatedAt, id
              )
              .run();
          } else {
            await saveKvState(env, { ...state, inbounds: state.inbounds.map((i) => (i.id === id ? updated : i)) });
          }
          return json({ inbound: updated });
        }

        if (path.startsWith('/api/inbounds/') && method === 'DELETE') {
          const id = path.slice('/api/inbounds/'.length);
          if (env.DB) {
            await env.DB.batch([
              env.DB.prepare('DELETE FROM clients WHERE inbound_id = ?').bind(id),
              env.DB.prepare('DELETE FROM inbounds WHERE id = ?').bind(id),
            ]);
          } else {
            await saveKvState(env, {
              ...state,
              inbounds: state.inbounds.filter((i) => i.id !== id),
              clients: state.clients.filter((c) => c.inboundId !== id),
            });
          }
          return json({ ok: true });
        }

        if (path === '/api/clients/batch' && method === 'POST') {
          const body = (await request.json()) as {
            inboundId?: string;
            prefix?: string;
            count?: number;
            totalGb?: number;
            expiryTime?: number;
          };
          if (!body.inboundId) return json({ error: 'inboundId required' }, 400);
          const inbound = state.inbounds.find((i) => i.id === body.inboundId);
          if (!inbound) return json({ error: 'Inbound not found' }, 404);
          const count = Math.min(Math.max(Number(body.count || 5), 1), 50);
          const prefix = (body.prefix || 'user').trim();
          const now = Date.now();
          const created: ClientConfig[] = [];

          for (let i = 1; i <= count; i++) {
            let cred: string = crypto.randomUUID();
            if (inbound.protocol === 'shadowsocks') {
              cred = inbound.ssMethod.includes('2022')
                ? generateSs2022Key(inbound.ssMethod.includes('256') ? 256 : 128)
                : generateShortId(12);
            } else if (inbound.protocol === 'trojan' || inbound.protocol === 'hysteria2') {
              cred = generateShortId(12);
            }
            created.push({
              id: crypto.randomUUID(),
              inboundId: inbound.id,
              email: `${prefix}-${String(i).padStart(2, '0')}`,
              credential: cred,
              secondaryPassword: inbound.protocol === 'tuic' ? generateShortId(10) : '',
              subId: generateSubId(),
              totalGb: Number(body.totalGb ?? 100),
              upBytes: 0,
              downBytes: 0,
              expiryTime: Number(body.expiryTime ?? 0),
              enabled: true,
              alterId: 0,
              createdAt: now,
              updatedAt: now,
            });
          }

          if (env.DB) {
            await env.DB.batch(
              created.map((c) =>
                env.DB!.prepare(
                  `INSERT INTO clients (id, inbound_id, email, credential, secondary_password, sub_id, total_gb, up_bytes, down_bytes, expiry_time, enabled, alter_id, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
                ).bind(
                  c.id, c.inboundId, c.email, c.credential, c.secondaryPassword || '', c.subId,
                  c.totalGb, c.upBytes, c.downBytes, c.expiryTime, 1, 0, c.createdAt, c.updatedAt
                )
              )
            );
          } else {
            await saveKvState(env, { ...state, clients: [...created, ...state.clients] });
          }
          return json({ clients: created }, 201);
        }

        if (path === '/api/clients' && method === 'POST') {
          const body = (await request.json()) as Partial<ClientConfig>;
          if (!body.inboundId || !body.email) return json({ error: 'inboundId and email are required' }, 400);
          const inbound = state.inbounds.find((i) => i.id === body.inboundId);
          if (!inbound) return json({ error: 'Parent inbound not found' }, 404);

          const now = Date.now();
          let defaultCred: string = crypto.randomUUID();
          if (inbound.protocol === 'shadowsocks') {
            defaultCred = inbound.ssMethod.includes('2022')
              ? generateSs2022Key(inbound.ssMethod.includes('256') ? 256 : 128)
              : generateShortId(12);
          } else if (inbound.protocol === 'trojan' || inbound.protocol === 'hysteria2') {
            defaultCred = generateShortId(12);
          }

          const client: ClientConfig = {
            id: crypto.randomUUID(),
            inboundId: body.inboundId,
            email: body.email.trim(),
            credential: body.credential || defaultCred,
            secondaryPassword: body.secondaryPassword || (inbound.protocol === 'tuic' ? generateShortId(10) : ''),
            subId: body.subId || generateSubId(),
            totalGb: Number(body.totalGb ?? 0),
            upBytes: Number(body.upBytes ?? 0),
            downBytes: Number(body.downBytes ?? 0),
            expiryTime: Number(body.expiryTime ?? 0),
            enabled: body.enabled !== false,
            alterId: Number(body.alterId ?? 0),
            createdAt: now,
            updatedAt: now,
          };

          if (env.DB) {
            await env.DB.prepare(
              `INSERT INTO clients (id, inbound_id, email, credential, secondary_password, sub_id, total_gb, up_bytes, down_bytes, expiry_time, enabled, alter_id, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
            )
              .bind(
                client.id, client.inboundId, client.email, client.credential, client.secondaryPassword || '',
                client.subId, client.totalGb, client.upBytes, client.downBytes, client.expiryTime,
                client.enabled ? 1 : 0, client.alterId || 0, client.createdAt, client.updatedAt
              )
              .run();
          } else {
            await saveKvState(env, { ...state, clients: [client, ...state.clients] });
          }
          return json({ client }, 201);
        }

        if (path.endsWith('/reset-traffic') && path.startsWith('/api/clients/') && method === 'POST') {
          const id = path.slice('/api/clients/'.length, -'/reset-traffic'.length);
          const now = Date.now();
          if (env.DB) {
            await env.DB.prepare('UPDATE clients SET up_bytes=0, down_bytes=0, updated_at=? WHERE id=?').bind(now, id).run();
          } else {
            await saveKvState(env, {
              ...state,
              clients: state.clients.map((c) => (c.id === id ? { ...c, upBytes: 0, downBytes: 0, updatedAt: now } : c)),
            });
          }
          return json({ ok: true });
        }

        if (path.startsWith('/api/clients/') && method === 'PUT') {
          const id = path.slice('/api/clients/'.length);
          const existing = state.clients.find((c) => c.id === id);
          if (!existing) return json({ error: 'Client not found' }, 404);
          const patch = (await request.json()) as Partial<ClientConfig>;
          const updated: ClientConfig = { ...existing, ...patch, id, updatedAt: Date.now() };
          if (env.DB) {
            await env.DB.prepare(
              `UPDATE clients SET email=?, credential=?, secondary_password=?, sub_id=?, total_gb=?, up_bytes=?, down_bytes=?, expiry_time=?, enabled=?, alter_id=?, updated_at=? WHERE id=?`
            )
              .bind(
                updated.email, updated.credential, updated.secondaryPassword || '', updated.subId, updated.totalGb,
                updated.upBytes, updated.downBytes, updated.expiryTime, updated.enabled ? 1 : 0,
                updated.alterId || 0, updated.updatedAt, id
              )
              .run();
          } else {
            await saveKvState(env, { ...state, clients: state.clients.map((c) => (c.id === id ? updated : c)) });
          }
          return json({ client: updated });
        }

        if (path.startsWith('/api/clients/') && method === 'DELETE') {
          const id = path.slice('/api/clients/'.length);
          if (env.DB) {
            await env.DB.prepare('DELETE FROM clients WHERE id = ?').bind(id).run();
          } else {
            await saveKvState(env, { ...state, clients: state.clients.filter((c) => c.id !== id) });
          }
          return json({ ok: true });
        }

        // Clean Endpoints CRUD
        if (path === '/api/endpoints' && method === 'GET') {
          return json({ endpoints: state.endpoints });
        }

        if (path === '/api/endpoints' && method === 'POST') {
          const body = (await request.json()) as Partial<CleanEndpoint>;
          if (!body.address) return json({ error: 'address is required' }, 400);
          const ep: CleanEndpoint = {
            id: crypto.randomUUID(),
            label: body.label?.trim() || 'Clean Edge',
            address: body.address.trim(),
            port: Number(body.port || 443),
            enabled: body.enabled !== false,
            createdAt: Date.now(),
          };
          if (env.DB) {
            await env.DB.prepare('INSERT INTO clean_endpoints (id, label, address, port, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?)')
              .bind(ep.id, ep.label, ep.address, ep.port, ep.enabled ? 1 : 0, ep.createdAt)
              .run();
          } else {
            await saveKvState(env, { ...state, endpoints: [ep, ...state.endpoints] });
          }
          return json({ endpoint: ep }, 201);
        }

        if (path.startsWith('/api/endpoints/') && method === 'DELETE') {
          const id = path.slice('/api/endpoints/'.length);
          if (env.DB) {
            await env.DB.prepare('DELETE FROM clean_endpoints WHERE id = ?').bind(id).run();
          } else {
            await saveKvState(env, { ...state, endpoints: state.endpoints.filter((e) => e.id !== id) });
          }
          return json({ ok: true });
        }

        // Logs & Backup
        if (path === '/api/logs' && method === 'GET') {
          return json({ logs: state.logs });
        }

        if (path === '/api/backup' && method === 'GET') {
          return json({
            exportedAt: Date.now(),
            inbounds: state.inbounds,
            clients: state.clients,
            endpoints: state.endpoints,
            settings: state.settings,
          });
        }

        if (path === '/api/backup' && method === 'POST') {
          const body = (await request.json()) as Partial<KvState>;
          const nextInbounds = Array.isArray(body.inbounds) ? body.inbounds : state.inbounds;
          const nextClients = Array.isArray(body.clients) ? body.clients : state.clients;
          const nextEndpoints = Array.isArray(body.endpoints) ? body.endpoints : state.endpoints;
          const nextSettings = body.settings ? { ...state.settings, ...body.settings } : state.settings;

          if (env.DB) {
            const stmts: D1PreparedStatement[] = [
              env.DB.prepare('DELETE FROM clients'),
              env.DB.prepare('DELETE FROM inbounds'),
              env.DB.prepare('DELETE FROM clean_endpoints'),
            ];
            for (const inb of nextInbounds) {
              stmts.push(
                env.DB.prepare(
                  `INSERT INTO inbounds (id, tag, remark, protocol, listen_host, server_address, port, enabled, network, security, sni, fingerprint, alpn, flow, ws_path, ws_host, grpc_service_name, reality_private_key, reality_public_key, reality_short_id, reality_dest, ss_method, tuic_congestion, tuic_udp_relay, hy2_obfs, hy2_obfs_password, hy2_up_mbps, hy2_down_mbps, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
                ).bind(
                  inb.id, inb.tag, inb.remark, inb.protocol, inb.listenHost, inb.serverAddress, inb.port,
                  inb.enabled ? 1 : 0, inb.network, inb.security, inb.sni, inb.fingerprint, inb.alpn, inb.flow,
                  inb.wsPath, inb.wsHost, inb.grpcServiceName, inb.realityPrivateKey, inb.realityPublicKey,
                  inb.realityShortId, inb.realityDest, inb.ssMethod, inb.tuicCongestion, inb.tuicUdpRelay,
                  inb.hy2Obfs, inb.hy2ObfsPassword, inb.hy2UpMbps, inb.hy2DownMbps, inb.createdAt, inb.updatedAt
                )
              );
            }
            for (const c of nextClients) {
              stmts.push(
                env.DB.prepare(
                  `INSERT INTO clients (id, inbound_id, email, credential, secondary_password, sub_id, total_gb, up_bytes, down_bytes, expiry_time, enabled, alter_id, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
                ).bind(
                  c.id, c.inboundId, c.email, c.credential, c.secondaryPassword || '', c.subId,
                  c.totalGb, c.upBytes, c.downBytes, c.expiryTime, c.enabled ? 1 : 0, c.alterId || 0, c.createdAt, c.updatedAt
                )
              );
            }
            for (const ep of nextEndpoints) {
              stmts.push(
                env.DB.prepare('INSERT INTO clean_endpoints (id, label, address, port, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?)')
                  .bind(ep.id, ep.label, ep.address, ep.port, ep.enabled ? 1 : 0, ep.createdAt)
              );
            }
            stmts.push(
              env.DB.prepare(
                `INSERT INTO panel_settings (key, value, updated_at) VALUES ('global', ?, ?)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`
              ).bind(JSON.stringify(nextSettings), Date.now())
            );
            await env.DB.batch(stmts);
          } else {
            await saveKvState(env, {
              inbounds: nextInbounds,
              clients: nextClients,
              endpoints: nextEndpoints,
              logs: state.logs,
              settings: nextSettings,
            });
          }
          return json({ ok: true });
        }

        if (path === '/api/settings' && method === 'GET') {
          return json({ settings: state.settings });
        }

        if (path === '/api/settings' && method === 'PUT') {
          const patch = (await request.json()) as Partial<PanelSettings>;
          const updated: PanelSettings = { ...state.settings, ...patch };
          const now = Date.now();
          if (env.DB) {
            await env.DB.prepare(
              `INSERT INTO panel_settings (key, value, updated_at) VALUES ('global', ?, ?)
               ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`
            )
              .bind(JSON.stringify(updated), now)
              .run();
          } else {
            await saveKvState(env, { ...state, settings: updated });
          }
          return json({ settings: updated });
        }

        return json({ error: 'API route not found' }, 404);
      }

      // 4. Web UI Entry Point
      if (method === 'GET' && (path === '/' || path === '/panel')) {
        return new Response(renderHtml(env.PANEL_TITLE || 'EdgePanel'), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        });
      }

      return new Response('Not Found', { status: 404 });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Internal Worker Error';
      return json({ error: message }, 500);
    }
  },
};
