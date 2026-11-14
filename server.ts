import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import express, { type Request, type Response, type NextFunction } from 'express';
import { createServer as createViteServer } from 'vite';
import {
  buildClashMetaYaml,
  buildClientUri,
  buildSingboxJson,
  buildXrayJson,
  expandPairsWithCleanEndpoints,
  generateRealityKeypair,
  generateShortId,
  generateSs2022Key,
  generateSubId,
  generateUuid,
  toBase64Standard,
  type AccessLogEntry,
  type CleanEndpoint,
  type ClientConfig,
  type InboundConfig,
  type NetworkType,
  type PanelSettings,
  type ProtocolType,
  type SecurityType,
} from './src/lib/protocols.ts';

const PORT = 3000;
const DATA_DIR = path.resolve(process.cwd(), '.data');
const DATA_FILE = path.join(DATA_DIR, 'edgepanel.json');
const WORKER_DIR = path.resolve(process.cwd(), 'cloudflare-worker');

const SESSION_COOKIE = 'edgepanel_session';
const LOGGED_OUT_COOKIE = 'edgepanel_logged_out';

interface StoreData {
  inbounds: InboundConfig[];
  clients: ClientConfig[];
  endpoints: CleanEndpoint[];
  logs: AccessLogEntry[];
  settings: PanelSettings;
}

function getCredentials() {
  return {
    username: process.env.ADMIN_USERNAME || 'admin',
    password: process.env.ADMIN_PASSWORD || 'edgepanel-demo-password',
    secret:
      process.env.SESSION_SECRET ||
      `${process.env.ADMIN_USERNAME || 'admin'}:${process.env.ADMIN_PASSWORD || 'edgepanel-demo-password'}:edgepanel-local`,
  };
}

function signSession(username: string): string {
  const { secret } = getCredentials();
  const payload = Buffer.from(
    JSON.stringify({ sub: username, exp: Date.now() + 7 * 86400000 })
  ).toString('base64url');
  const sig = crypto
    .createHmac('sha256', crypto.createHash('sha256').update(secret).digest())
    .update(payload)
    .digest('base64url');
  return `${payload}.${sig}`;
}

function verifySession(token: string | undefined): { username: string } | null {
  if (!token || !token.includes('.')) return null;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return null;
  const { secret } = getCredentials();
  const expectedSig = crypto
    .createHmac('sha256', crypto.createHash('sha256').update(secret).digest())
    .update(payload)
    .digest('base64url');

  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }
  try {
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as {
      sub: string;
      exp: number;
    };
    if (!parsed.sub || !parsed.exp || Date.now() > parsed.exp) return null;
    return { username: parsed.sub };
  } catch {
    return null;
  }
}

function parseCookies(req: Request): Record<string, string> {
  const raw = req.headers.cookie;
  const out: Record<string, string> = {};
  if (!raw) return out;
  for (const part of raw.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  }
  return out;
}

function isPreviewAuthenticated(req: Request): { authenticated: boolean; username: string | null } {
  const cookies = parseCookies(req);
  const tokenSession = verifySession(cookies[SESSION_COOKIE]);
  if (tokenSession) {
    return { authenticated: true, username: tokenSession.username };
  }
  if (cookies[LOGGED_OUT_COOKIE] === '1') {
    return { authenticated: false, username: null };
  }
  return { authenticated: true, username: getCredentials().username };
}

function createInitialSeed(host: string): StoreData {
  const now = Date.now();
  const realityKeys = generateRealityKeypair();
  const realityInboundId = generateUuid();
  const wsInboundId = generateUuid();
  const hy2InboundId = generateUuid();
  const ssInboundId = generateUuid();

  const inbounds: InboundConfig[] = [
    {
      id: realityInboundId,
      tag: 'vless-reality-443',
      remark: 'Edge Reality Vision',
      protocol: 'vless',
      listenHost: '0.0.0.0',
      serverAddress: host,
      port: 443,
      enabled: true,
      network: 'tcp',
      security: 'reality',
      sni: 'www.cloudflare.com',
      fingerprint: 'chrome',
      alpn: 'h2,http/1.1',
      flow: 'xtls-rprx-vision',
      wsPath: '/',
      wsHost: '',
      grpcServiceName: 'grpc',
      realityPrivateKey: realityKeys.privateKey,
      realityPublicKey: realityKeys.publicKey,
      realityShortId: generateShortId(8),
      realityDest: 'www.cloudflare.com:443',
      ssMethod: 'aes-256-gcm',
      tuicCongestion: 'bbr',
      tuicUdpRelay: 'native',
      hy2Obfs: 'none',
      hy2ObfsPassword: '',
      hy2UpMbps: 100,
      hy2DownMbps: 200,
      createdAt: now - 86400000 * 4,
      updatedAt: now - 3600000,
    },
    {
      id: wsInboundId,
      tag: 'vless-ws-cdn-443',
      remark: 'Worker VLESS-WS Relay',
      protocol: 'vless',
      listenHost: '0.0.0.0',
      serverAddress: host,
      port: 443,
      enabled: true,
      network: 'ws',
      security: 'tls',
      sni: host,
      fingerprint: 'chrome',
      alpn: 'h2,http/1.1',
      flow: '',
      wsPath: '/edge-ws',
      wsHost: host,
      grpcServiceName: 'grpc',
      realityPrivateKey: '',
      realityPublicKey: '',
      realityShortId: '',
      realityDest: '',
      ssMethod: 'aes-256-gcm',
      tuicCongestion: 'bbr',
      tuicUdpRelay: 'native',
      hy2Obfs: 'none',
      hy2ObfsPassword: '',
      hy2UpMbps: 100,
      hy2DownMbps: 200,
      createdAt: now - 86400000 * 3,
      updatedAt: now - 7200000,
    },
    {
      id: hy2InboundId,
      tag: 'hy2-quic-2096',
      remark: 'Hysteria2 QUIC Fast',
      protocol: 'hysteria2',
      listenHost: '0.0.0.0',
      serverAddress: host,
      port: 2096,
      enabled: true,
      network: 'quic',
      security: 'tls',
      sni: host,
      fingerprint: 'chrome',
      alpn: 'h3',
      flow: '',
      wsPath: '/',
      wsHost: '',
      grpcServiceName: 'grpc',
      realityPrivateKey: '',
      realityPublicKey: '',
      realityShortId: '',
      realityDest: '',
      ssMethod: 'aes-256-gcm',
      tuicCongestion: 'bbr',
      tuicUdpRelay: 'native',
      hy2Obfs: 'salamander',
      hy2ObfsPassword: generateShortId(10),
      hy2UpMbps: 150,
      hy2DownMbps: 500,
      createdAt: now - 86400000 * 2,
      updatedAt: now - 10800000,
    },
    {
      id: ssInboundId,
      tag: 'ss2022-8388',
      remark: 'Shadowsocks 2022 AEAD',
      protocol: 'shadowsocks',
      listenHost: '0.0.0.0',
      serverAddress: host,
      port: 8388,
      enabled: false,
      network: 'tcp',
      security: 'none',
      sni: '',
      fingerprint: 'chrome',
      alpn: '',
      flow: '',
      wsPath: '/',
      wsHost: '',
      grpcServiceName: 'grpc',
      realityPrivateKey: '',
      realityPublicKey: '',
      realityShortId: '',
      realityDest: '',
      ssMethod: '2022-blake3-aes-128-gcm',
      tuicCongestion: 'bbr',
      tuicUdpRelay: 'native',
      hy2Obfs: 'none',
      hy2ObfsPassword: '',
      hy2UpMbps: 100,
      hy2DownMbps: 200,
      createdAt: now - 86400000,
      updatedAt: now - 86400000,
    },
  ];

  const sharedSubAlice = 'alice-edge-sub';
  const clients: ClientConfig[] = [
    {
      id: generateUuid(),
      inboundId: realityInboundId,
      email: 'alice@ops.dev',
      credential: generateUuid(),
      subId: sharedSubAlice,
      totalGb: 250,
      upBytes: 18_420_000_000,
      downBytes: 74_190_000_000,
      expiryTime: now + 28 * 86400000,
      enabled: true,
      createdAt: now - 86400000 * 4,
      updatedAt: now - 3600000,
    },
    {
      id: generateUuid(),
      inboundId: realityInboundId,
      email: 'marcus@mobile',
      credential: generateUuid(),
      subId: 'marcus-mobile-sub',
      totalGb: 100,
      upBytes: 12_100_000_000,
      downBytes: 68_400_000_000,
      expiryTime: now + 3 * 86400000,
      enabled: true,
      createdAt: now - 86400000 * 3,
      updatedAt: now - 7200000,
    },
    {
      id: generateUuid(),
      inboundId: wsInboundId,
      email: 'alice@ops.dev',
      credential: generateUuid(),
      subId: sharedSubAlice,
      totalGb: 250,
      upBytes: 5_200_000_000,
      downBytes: 21_600_000_000,
      expiryTime: now + 28 * 86400000,
      enabled: true,
      createdAt: now - 86400000 * 3,
      updatedAt: now - 3600000,
    },
    {
      id: generateUuid(),
      inboundId: hy2InboundId,
      email: 'elena@desktop',
      credential: generateShortId(12),
      subId: 'elena-hy2-sub',
      totalGb: 500,
      upBytes: 24_000_000_000,
      downBytes: 142_500_000_000,
      expiryTime: 0,
      enabled: true,
      createdAt: now - 86400000 * 2,
      updatedAt: now - 1800000,
    },
    {
      id: generateUuid(),
      inboundId: ssInboundId,
      email: 'legacy@iot',
      credential: generateSs2022Key(128),
      subId: 'legacy-ss-sub',
      totalGb: 50,
      upBytes: 1_200_000_000,
      downBytes: 4_800_000_000,
      expiryTime: now + 60 * 86400000,
      enabled: true,
      createdAt: now - 86400000,
      updatedAt: now - 86400000,
    },
  ];

  const endpoints: CleanEndpoint[] = [
    {
      id: generateUuid(),
      label: 'CF Anycast Primary',
      address: '104.16.132.229',
      port: 443,
      enabled: true,
      createdAt: now - 86400000 * 2,
    },
    {
      id: generateUuid(),
      label: 'CF Anycast Alt-8443',
      address: '172.67.188.140',
      port: 8443,
      enabled: true,
      createdAt: now - 86400000,
    },
  ];

  const logs: AccessLogEntry[] = [
    {
      id: generateUuid(),
      subId: sharedSubAlice,
      clientEmail: 'alice@ops.dev',
      format: 'clash',
      userAgent: 'clash-verge/v1.7.7 mihomo',
      country: 'DE',
      ip: '198.51.100.42',
      status: 200,
      timestamp: now - 1800000,
    },
    {
      id: generateUuid(),
      subId: 'marcus-mobile-sub',
      clientEmail: 'marcus@mobile',
      format: 'base64',
      userAgent: 'v2rayNG/1.9.10',
      country: 'NL',
      ip: '203.0.113.19',
      status: 200,
      timestamp: now - 5400000,
    },
  ];

  return {
    inbounds,
    clients,
    endpoints,
    logs,
    settings: {
      panelTitle: 'EdgePanel',
      edgeDomain: host,
      subPath: '/sub',
      defaultSni: 'www.cloudflare.com',
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
      bypassCountry: 'ir',
      blockAds: true,
      dnsServer: 'https://1.1.1.1/dns-query',
    },
  };
}

async function readStore(host: string): Promise<StoreData> {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    const raw = await fs.readFile(DATA_FILE, 'utf8');
    const parsed = JSON.parse(raw) as Partial<StoreData>;
    const defaults = createInitialSeed(host);
    return {
      inbounds: parsed.inbounds || defaults.inbounds,
      clients: parsed.clients || defaults.clients,
      endpoints: parsed.endpoints || defaults.endpoints,
      logs: parsed.logs || defaults.logs,
      settings: { ...defaults.settings, ...(parsed.settings || {}) },
    };
  } catch {
    const seeded = createInitialSeed(host);
    await fs.writeFile(DATA_FILE, JSON.stringify(seeded, null, 2), 'utf8');
    return seeded;
  }
}

async function writeStore(data: StoreData): Promise<void> {
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function requireAuth(req: Request, res: Response, next: NextFunction) {
  const session = isPreviewAuthenticated(req);
  if (!session.authenticated) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  next();
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '4mb' }));

  // Public Subscription Endpoint
  app.get('/sub/:subId', async (req, res) => {
    const host = req.hostname || 'edge.example.com';
    const store = await readStore(host);
    const subId = req.params.subId;
    const matchedClients = store.clients.filter((c) => c.subId === subId && c.enabled);

    if (matchedClients.length === 0) {
      res.status(404).send('Subscription not found or disabled');
      return;
    }

    const now = Date.now();
    const activePairs: Array<{ inbound: InboundConfig; client: ClientConfig }> = [];
    for (const client of matchedClients) {
      if (client.expiryTime > 0 && client.expiryTime < now) continue;
      if (client.totalGb > 0 && client.upBytes + client.downBytes >= client.totalGb * 1024 ** 3) continue;
      const inbound = store.inbounds.find((i) => i.id === client.inboundId && i.enabled);
      if (inbound) activePairs.push({ inbound, client });
    }

    if (activePairs.length === 0) {
      res.status(403).send('Subscription expired or quota exceeded');
      return;
    }

    const primary = matchedClients[0];
    const totalBytes = primary.totalGb > 0 ? Math.round(primary.totalGb * 1024 ** 3) : 0;
    const expireSec = primary.expiryTime > 0 ? Math.floor(primary.expiryTime / 1000) : 0;
    const userInfo = `upload=${primary.upBytes}; download=${primary.downBytes}; total=${totalBytes}; expire=${expireSec}`;

    const formatParam = String(req.query.format || '').toLowerCase();
    const ua = String(req.headers['user-agent'] || '').toLowerCase();
    const format =
      formatParam ||
      (ua.includes('clash') || ua.includes('mihomo') || ua.includes('stash')
        ? 'clash'
        : ua.includes('sing-box') || ua.includes('sfa') || ua.includes('sfi')
        ? 'singbox'
        : 'base64');

    store.logs.unshift({
      id: generateUuid(),
      subId,
      clientEmail: primary.email,
      format,
      userAgent: String(req.headers['user-agent'] || '').slice(0, 120),
      country: String(req.headers['cf-ipcountry'] || 'LOCAL'),
      ip: req.ip || '127.0.0.1',
      status: 200,
      timestamp: Date.now(),
    });
    store.logs = store.logs.slice(0, 100);
    await writeStore(store);

    res.setHeader('Subscription-Userinfo', userInfo);
    res.setHeader('Profile-Update-Interval', '12');

    if (format === 'clash') {
      res.setHeader('Content-Type', 'text/yaml; charset=utf-8');
      res.send(buildClashMetaYaml(activePairs, store.settings, store.endpoints));
      return;
    }
    if (format === 'singbox') {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.send(buildSingboxJson(activePairs, store.settings, store.endpoints));
      return;
    }
    if (format === 'xray') {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.send(buildXrayJson(activePairs, store.settings, store.endpoints));
      return;
    }

    const targets = expandPairsWithCleanEndpoints(activePairs, store.endpoints);
    const uris = targets.map(({ inbound, client, overrideHost, overridePort, labelSuffix }) =>
      buildClientUri(
        inbound,
        client,
        store.settings.edgeDomain || host,
        overrideHost,
        overridePort,
        labelSuffix
      )
    );
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(format === 'raw' ? uris.join('\n') : toBase64Standard(uris.join('\n')));
  });

  // Auth Endpoints
  app.post('/api/auth/login', (req, res) => {
    const { username, password } = (req.body || {}) as { username?: string; password?: string };
    const creds = getCredentials();
    const uOk =
      username !== undefined &&
      username.length === creds.username.length &&
      crypto.timingSafeEqual(Buffer.from(username), Buffer.from(creds.username));
    const pOk =
      password !== undefined &&
      password.length === creds.password.length &&
      crypto.timingSafeEqual(Buffer.from(password), Buffer.from(creds.password));

    if (!uOk || !pOk) {
      res.status(401).json({ error: 'Invalid admin username or password' });
      return;
    }

    const token = signSession(creds.username);
    res.cookie(SESSION_COOKIE, token, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 7 * 86400 * 1000,
    });
    res.clearCookie(LOGGED_OUT_COOKIE, { path: '/' });
    res.json({ ok: true, username: creds.username });
  });

  app.post('/api/auth/logout', (_req, res) => {
    res.clearCookie(SESSION_COOKIE, { path: '/' });
    res.cookie(LOGGED_OUT_COOKIE, '1', { httpOnly: true, sameSite: 'lax', path: '/' });
    res.json({ ok: true });
  });

  app.get('/api/auth/session', (req, res) => {
    const session = isPreviewAuthenticated(req);
    const creds = getCredentials();
    res.json({
      authenticated: session.authenticated,
      username: session.username,
      backend: 'local',
      previewHint: { username: creds.username, password: creds.password },
    });
  });

  // Protected API Routes
  app.get('/api/tools/keygen', requireAuth, (_req, res) => {
    res.json({
      uuid: generateUuid(),
      reality: generateRealityKeypair(),
      shortId: generateShortId(8),
      ss2022_128: generateSs2022Key(128),
      ss2022_256: generateSs2022Key(256),
    });
  });

  app.get('/api/overview', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    const now = Date.now();
    const fiveDays = 5 * 86400000;
    res.json({
      activeInbounds: store.inbounds.filter((i) => i.enabled).length,
      totalInbounds: store.inbounds.length,
      activeClients: store.clients.filter((c) => c.enabled).length,
      totalClients: store.clients.length,
      totalUpBytes: store.clients.reduce((s, c) => s + c.upBytes, 0),
      totalDownBytes: store.clients.reduce((s, c) => s + c.downBytes, 0),
      expiringSoonCount: store.clients.filter(
        (c) => c.expiryTime > now && c.expiryTime - now <= fiveDays
      ).length,
      cleanEndpointsCount: store.endpoints.filter((e) => e.enabled).length,
      storageBackend: 'local',
    });
  });

  app.get('/api/inbounds', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    const inbounds = store.inbounds.map((inb) => ({
      ...inb,
      clients: store.clients.filter((c) => c.inboundId === inb.id),
    }));
    res.json({ inbounds, backend: 'local' });
  });

  app.post('/api/inbounds', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    const body = (req.body || {}) as Partial<InboundConfig>;
    const now = Date.now();
    const protocol = (body.protocol || 'vless') as ProtocolType;
    const security = (body.security || (protocol === 'vless' ? 'reality' : 'tls')) as SecurityType;
    const realityKeys =
      security === 'reality' && (!body.realityPrivateKey || !body.realityPublicKey)
        ? generateRealityKeypair()
        : { privateKey: body.realityPrivateKey || '', publicKey: body.realityPublicKey || '' };

    const inbound: InboundConfig = {
      id: generateUuid(),
      tag: body.tag || `${protocol}-${body.port || 443}`,
      remark: body.remark || `${protocol.toUpperCase()} Edge Node`,
      protocol,
      listenHost: body.listenHost || '0.0.0.0',
      serverAddress: body.serverAddress || store.settings.edgeDomain || req.hostname || 'edge.example.com',
      port: Number(body.port || 443),
      enabled: body.enabled !== false,
      network: (body.network || 'tcp') as NetworkType,
      security,
      sni: body.sni ?? store.settings.defaultSni,
      fingerprint: body.fingerprint || 'chrome',
      alpn: body.alpn || 'h2,http/1.1',
      flow: body.flow ?? (protocol === 'vless' && (body.network || 'tcp') === 'tcp' ? 'xtls-rprx-vision' : ''),
      wsPath: body.wsPath || '/edge-ws',
      wsHost: body.wsHost || '',
      grpcServiceName: body.grpcServiceName || 'grpc',
      realityPrivateKey: realityKeys.privateKey,
      realityPublicKey: realityKeys.publicKey,
      realityShortId: body.realityShortId || (security === 'reality' ? generateShortId(8) : ''),
      realityDest: body.realityDest || `${body.sni || store.settings.defaultSni}:443`,
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

    store.inbounds.unshift(inbound);
    await writeStore(store);
    res.status(201).json({ inbound });
  });

  app.put('/api/inbounds/:id', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    const idx = store.inbounds.findIndex((i) => i.id === req.params.id);
    if (idx === -1) {
      res.status(404).json({ error: 'Inbound not found' });
      return;
    }
    const updated: InboundConfig = {
      ...store.inbounds[idx],
      ...(req.body as Partial<InboundConfig>),
      id: req.params.id,
      updatedAt: Date.now(),
    };
    store.inbounds[idx] = updated;
    await writeStore(store);
    res.json({ inbound: updated });
  });

  app.delete('/api/inbounds/:id', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    store.inbounds = store.inbounds.filter((i) => i.id !== req.params.id);
    store.clients = store.clients.filter((c) => c.inboundId !== req.params.id);
    await writeStore(store);
    res.json({ ok: true });
  });

  app.post('/api/clients/batch', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    const body = (req.body || {}) as {
      inboundId?: string;
      prefix?: string;
      count?: number;
      totalGb?: number;
      expiryTime?: number;
    };
    if (!body.inboundId) {
      res.status(400).json({ error: 'inboundId is required' });
      return;
    }
    const inbound = store.inbounds.find((i) => i.id === body.inboundId);
    if (!inbound) {
      res.status(404).json({ error: 'Inbound not found' });
      return;
    }
    const count = Math.min(Math.max(Number(body.count || 5), 1), 50);
    const prefix = (body.prefix || 'user').trim();
    const now = Date.now();
    const created: ClientConfig[] = [];

    for (let i = 1; i <= count; i++) {
      let cred = generateUuid();
      if (inbound.protocol === 'shadowsocks') {
        cred = inbound.ssMethod.includes('2022')
          ? generateSs2022Key(inbound.ssMethod.includes('256') ? 256 : 128)
          : generateShortId(12);
      } else if (inbound.protocol === 'trojan' || inbound.protocol === 'hysteria2') {
        cred = generateShortId(12);
      }
      created.push({
        id: generateUuid(),
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

    store.clients = [...created, ...store.clients];
    await writeStore(store);
    res.status(201).json({ clients: created });
  });

  app.post('/api/clients', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    const body = (req.body || {}) as Partial<ClientConfig>;
    if (!body.inboundId || !body.email) {
      res.status(400).json({ error: 'inboundId and email are required' });
      return;
    }
    const inbound = store.inbounds.find((i) => i.id === body.inboundId);
    if (!inbound) {
      res.status(404).json({ error: 'Inbound not found' });
      return;
    }

    let defaultCred = generateUuid();
    if (inbound.protocol === 'shadowsocks') {
      defaultCred = inbound.ssMethod.includes('2022')
        ? generateSs2022Key(inbound.ssMethod.includes('256') ? 256 : 128)
        : generateShortId(12);
    } else if (inbound.protocol === 'trojan' || inbound.protocol === 'hysteria2') {
      defaultCred = generateShortId(12);
    }

    const now = Date.now();
    const client: ClientConfig = {
      id: generateUuid(),
      inboundId: body.inboundId,
      email: body.email.trim(),
      credential: body.credential || defaultCred,
      secondaryPassword:
        body.secondaryPassword || (inbound.protocol === 'tuic' ? generateShortId(10) : ''),
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

    store.clients.unshift(client);
    await writeStore(store);
    res.status(201).json({ client });
  });

  app.post('/api/clients/:id/reset-traffic', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    const client = store.clients.find((c) => c.id === req.params.id);
    if (!client) {
      res.status(404).json({ error: 'Client not found' });
      return;
    }
    client.upBytes = 0;
    client.downBytes = 0;
    client.updatedAt = Date.now();
    await writeStore(store);
    res.json({ ok: true, client });
  });

  app.put('/api/clients/:id', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    const idx = store.clients.findIndex((c) => c.id === req.params.id);
    if (idx === -1) {
      res.status(404).json({ error: 'Client not found' });
      return;
    }
    const updated: ClientConfig = {
      ...store.clients[idx],
      ...(req.body as Partial<ClientConfig>),
      id: req.params.id,
      updatedAt: Date.now(),
    };
    store.clients[idx] = updated;
    await writeStore(store);
    res.json({ client: updated });
  });

  app.delete('/api/clients/:id', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    store.clients = store.clients.filter((c) => c.id !== req.params.id);
    await writeStore(store);
    res.json({ ok: true });
  });

  // Clean Endpoints
  app.get('/api/endpoints', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    res.json({ endpoints: store.endpoints });
  });

  app.post('/api/endpoints', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    const body = (req.body || {}) as Partial<CleanEndpoint>;
    if (!body.address) {
      res.status(400).json({ error: 'address is required' });
      return;
    }
    const endpoint: CleanEndpoint = {
      id: generateUuid(),
      label: body.label?.trim() || 'Clean Edge',
      address: body.address.trim(),
      port: Number(body.port || 443),
      enabled: body.enabled !== false,
      createdAt: Date.now(),
    };
    store.endpoints.unshift(endpoint);
    await writeStore(store);
    res.status(201).json({ endpoint });
  });

  app.put('/api/endpoints/:id', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    const idx = store.endpoints.findIndex((e) => e.id === req.params.id);
    if (idx === -1) {
      res.status(404).json({ error: 'Endpoint not found' });
      return;
    }
    store.endpoints[idx] = {
      ...store.endpoints[idx],
      ...(req.body as Partial<CleanEndpoint>),
      id: req.params.id,
    };
    await writeStore(store);
    res.json({ endpoint: store.endpoints[idx] });
  });

  app.delete('/api/endpoints/:id', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    store.endpoints = store.endpoints.filter((e) => e.id !== req.params.id);
    await writeStore(store);
    res.json({ ok: true });
  });

  // Logs & Backup
  app.get('/api/logs', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    res.json({ logs: store.logs });
  });

  app.get('/api/backup', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    res.json({
      exportedAt: Date.now(),
      inbounds: store.inbounds,
      clients: store.clients,
      endpoints: store.endpoints,
      settings: store.settings,
    });
  });

  app.post('/api/backup', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    const body = (req.body || {}) as Partial<StoreData>;
    const next: StoreData = {
      inbounds: Array.isArray(body.inbounds) ? body.inbounds : store.inbounds,
      clients: Array.isArray(body.clients) ? body.clients : store.clients,
      endpoints: Array.isArray(body.endpoints) ? body.endpoints : store.endpoints,
      logs: store.logs,
      settings: body.settings ? { ...store.settings, ...body.settings } : store.settings,
    };
    await writeStore(next);
    res.json({ ok: true });
  });

  app.get('/api/settings', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    res.json({ settings: store.settings });
  });

  app.put('/api/settings', requireAuth, async (req, res) => {
    const store = await readStore(req.hostname || 'edge.example.com');
    store.settings = { ...store.settings, ...(req.body as Partial<PanelSettings>) };
    await writeStore(store);
    res.json({ settings: store.settings });
  });

  // Expose the Cloudflare Worker repository deliverable files
  app.get('/api/deliverables', requireAuth, async (_req, res) => {
    const filePaths = [
      'wrangler.toml',
      'deploy.sh',
      '.github/workflows/deploy.yml',
      'package.json',
      'tsconfig.json',
      'schema.sql',
      '.gitignore',
      'src/index.ts',
      'README.md',
    ];
    const files = await Promise.all(
      filePaths.map(async (relPath) => {
        const content = await fs.readFile(path.join(WORKER_DIR, relPath), 'utf8').catch(() => '');
        return { path: relPath, content };
      })
    );
    res.json({ files });
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`EdgePanel server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start EdgePanel server:', err);
  process.exit(1);
});
