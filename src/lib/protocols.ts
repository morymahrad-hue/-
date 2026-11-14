export type ProtocolType =
  | 'vless'
  | 'vmess'
  | 'trojan'
  | 'shadowsocks'
  | 'tuic'
  | 'hysteria2';

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
  // Built-in Worker VLESS-WS Relay & ProxyIP
  workerRelayEnabled: boolean;
  workerRelayPath: string;
  workerProxyIp: string;
  // Fragment & Mux
  fragmentEnabled: boolean;
  fragmentPackets: string;
  fragmentLength: string;
  fragmentInterval: string;
  muxEnabled: boolean;
  muxConcurrency: number;
  // Routing & DNS
  bypassCountry: BypassCountry;
  blockAds: boolean;
  dnsServer: string;
}

export interface InboundWithClients extends InboundConfig {
  clients: ClientConfig[];
}

export interface OverviewStats {
  activeInbounds: number;
  totalInbounds: number;
  activeClients: number;
  totalClients: number;
  totalUpBytes: number;
  totalDownBytes: number;
  expiringSoonCount: number;
  cleanEndpointsCount: number;
  storageBackend: 'd1' | 'kv' | 'local';
}

// RFC 7748 Curve25519 scalar multiplication for Xray/Sing-box Reality X25519 keys
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

function decodeLittleEndian(bytes: Uint8Array): bigint {
  let res = 0n;
  for (let i = 0; i < 32; i++) {
    res += BigInt(bytes[i]) << (8n * BigInt(i));
  }
  return res;
}

function encodeLittleEndian(n: bigint): Uint8Array {
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
  const clamped = clampScalar(scalarBytes);
  const k = decodeLittleEndian(clamped);
  const uMasked = new Uint8Array(uBytes);
  uMasked[31] &= 127;
  const u = modP(decodeLittleEndian(uMasked));

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
    const sumDACB = modP(DA + CB);
    const diffDACB = modP(DA - CB);

    x3 = modP(sumDACB * sumDACB);
    z3 = modP(x1 * modP(diffDACB * diffDACB));
    x2 = modP(AA * BB);
    z2 = modP(E * modP(AA + modP(a24 * E)));
  }

  [x2, x3] = cswap(swap, x2, x3);
  [z2, z3] = cswap(swap, z2, z3);
  return encodeLittleEndian(modP(x2 * invP(z2)));
}

export function toBase64Url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function toBase64Standard(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin);
}

export function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  crypto.getRandomValues(buf);
  return buf;
}

export function generateUuid(): string {
  return crypto.randomUUID();
}

export function generateShortId(byteLen = 8): string {
  const bytes = randomBytes(byteLen);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function generateSubId(): string {
  const bytes = randomBytes(12);
  return toBase64Url(bytes);
}

export function generatePassword(length = 24): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) {
    out += chars[bytes[i] % chars.length];
  }
  return out;
}

export function generateSs2022Key(bits: 128 | 256 = 128): string {
  const bytes = randomBytes(bits === 128 ? 16 : 32);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin);
}

export function generateRealityKeypair(): { privateKey: string; publicKey: string } {
  const priv = clampScalar(randomBytes(32));
  const basePoint = new Uint8Array(32);
  basePoint[0] = 9;
  const pub = x25519ScalarMult(priv, basePoint);
  return {
    privateKey: toBase64Url(priv),
    publicKey: toBase64Url(pub),
  };
}

export interface NodeTarget {
  inbound: InboundConfig;
  client: ClientConfig;
  overrideHost?: string;
  overridePort?: number;
  labelSuffix?: string;
}

export function expandPairsWithCleanEndpoints(
  pairs: Array<{ inbound: InboundConfig; client: ClientConfig }>,
  endpoints: CleanEndpoint[] = []
): NodeTarget[] {
  const activeEps = endpoints.filter((e) => e.enabled);
  const targets: NodeTarget[] = [];

  for (const pair of pairs) {
    // Expand WebSocket/CDN-compatible inbounds across clean endpoints if present
    if (pair.inbound.network === 'ws' && activeEps.length > 0) {
      for (const ep of activeEps) {
        targets.push({
          ...pair,
          overrideHost: ep.address,
          overridePort: ep.port || pair.inbound.port,
          labelSuffix: ep.label,
        });
      }
    } else {
      targets.push(pair);
    }
  }
  return targets;
}

export function buildClientUri(
  inbound: InboundConfig,
  client: ClientConfig,
  fallbackHost?: string,
  overrideHost?: string,
  overridePort?: number,
  labelSuffix?: string
): string {
  const host = overrideHost || inbound.serverAddress || fallbackHost || 'edge.example.com';
  const port = overridePort || inbound.port;
  const rawLabel = `${inbound.remark || inbound.tag}${labelSuffix ? ` (${labelSuffix})` : ''} - ${client.email}`;
  const label = encodeURIComponent(rawLabel);

  if (inbound.protocol === 'vless') {
    const params = new URLSearchParams();
    params.set('encryption', 'none');
    params.set('type', inbound.network);
    params.set('security', inbound.security);

    if (inbound.security === 'reality') {
      if (inbound.sni) params.set('sni', inbound.sni);
      params.set('fp', inbound.fingerprint || 'chrome');
      if (inbound.realityPublicKey) params.set('pbk', inbound.realityPublicKey);
      if (inbound.realityShortId) params.set('sid', inbound.realityShortId);
      params.set('spx', '/');
      if (inbound.network === 'tcp' && inbound.flow) {
        params.set('flow', inbound.flow);
      }
    } else if (inbound.security === 'tls') {
      if (inbound.sni) params.set('sni', inbound.sni);
      if (inbound.fingerprint) params.set('fp', inbound.fingerprint);
      if (inbound.alpn) params.set('alpn', inbound.alpn);
      if (inbound.network === 'tcp' && inbound.flow) {
        params.set('flow', inbound.flow);
      }
    }

    if (inbound.network === 'ws') {
      params.set('path', inbound.wsPath || '/');
      if (inbound.wsHost || inbound.sni) {
        params.set('host', inbound.wsHost || inbound.sni);
      }
    } else if (inbound.network === 'grpc') {
      params.set('serviceName', inbound.grpcServiceName || 'grpc');
      params.set('mode', 'gun');
    }

    return `vless://${client.credential}@${host}:${port}?${params.toString()}#${label}`;
  }

  if (inbound.protocol === 'vmess') {
    const vmessPayload = {
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
      path:
        inbound.network === 'ws'
          ? inbound.wsPath || '/'
          : inbound.network === 'grpc'
          ? inbound.grpcServiceName || 'grpc'
          : '',
      tls: inbound.security === 'tls' ? 'tls' : '',
      sni: inbound.security === 'tls' ? inbound.sni || host : '',
      alpn: inbound.security === 'tls' ? inbound.alpn || 'h2,http/1.1' : '',
      fp: inbound.security === 'tls' ? inbound.fingerprint || 'chrome' : '',
    };
    return `vmess://${toBase64Standard(JSON.stringify(vmessPayload))}`;
  }

  if (inbound.protocol === 'trojan') {
    const params = new URLSearchParams();
    params.set('security', inbound.security === 'none' ? 'tls' : inbound.security);
    params.set('type', inbound.network);
    if (inbound.sni) params.set('sni', inbound.sni);
    if (inbound.fingerprint) params.set('fp', inbound.fingerprint);
    if (inbound.security === 'reality') {
      if (inbound.realityPublicKey) params.set('pbk', inbound.realityPublicKey);
      if (inbound.realityShortId) params.set('sid', inbound.realityShortId);
    } else if (inbound.alpn) {
      params.set('alpn', inbound.alpn);
    }
    if (inbound.network === 'ws') {
      params.set('path', inbound.wsPath || '/');
      if (inbound.wsHost || inbound.sni) params.set('host', inbound.wsHost || inbound.sni);
    } else if (inbound.network === 'grpc') {
      params.set('serviceName', inbound.grpcServiceName || 'grpc');
    }
    return `trojan://${encodeURIComponent(client.credential)}@${host}:${port}?${params.toString()}#${label}`;
  }

  if (inbound.protocol === 'shadowsocks') {
    const method = inbound.ssMethod || 'aes-256-gcm';
    const userInfo = toBase64Standard(`${method}:${client.credential}`);
    return `ss://${userInfo}@${host}:${port}#${label}`;
  }

  if (inbound.protocol === 'tuic') {
    const params = new URLSearchParams();
    params.set('congestion_control', inbound.tuicCongestion || 'bbr');
    params.set('alpn', inbound.alpn || 'h3');
    params.set('udp_relay_mode', inbound.tuicUdpRelay || 'native');
    if (inbound.sni) params.set('sni', inbound.sni);
    params.set('allow_insecure', '0');
    const pass = encodeURIComponent(client.secondaryPassword || client.credential);
    return `tuic://${client.credential}:${pass}@${host}:${port}?${params.toString()}#${label}`;
  }

  const params = new URLSearchParams();
  if (inbound.sni) params.set('sni', inbound.sni);
  params.set('alpn', inbound.alpn || 'h3');
  if (inbound.hy2Obfs === 'salamander' && inbound.hy2ObfsPassword) {
    params.set('obfs', 'salamander');
    params.set('obfs-password', inbound.hy2ObfsPassword);
  }
  params.set('insecure', '0');
  return `hysteria2://${encodeURIComponent(client.credential)}@${host}:${port}?${params.toString()}#${label}`;
}

function yamlStr(value: string): string {
  return JSON.stringify(value);
}

export function buildClashMetaYaml(
  pairs: Array<{ inbound: InboundConfig; client: ClientConfig }>,
  settings?: Partial<PanelSettings>,
  endpoints: CleanEndpoint[] = []
): string {
  const targets = expandPairsWithCleanEndpoints(pairs, endpoints);
  const mixedPort = settings?.clashMixedPort || 7890;
  const dnsServer = settings?.dnsServer || 'https://1.1.1.1/dns-query';
  const proxyNames: string[] = [];
  const proxyBlocks: string[] = [];

  for (const { inbound, client, overrideHost, overridePort, labelSuffix } of targets) {
    const host = overrideHost || inbound.serverAddress || settings?.edgeDomain || 'edge.example.com';
    const port = overridePort || inbound.port;
    const name = `${inbound.remark || inbound.tag}${labelSuffix ? ` (${labelSuffix})` : ''} - ${client.email}`;
    proxyNames.push(name);

    const lines: string[] = [`  - name: ${yamlStr(name)}`];

    if (inbound.protocol === 'vless') {
      lines.push(`    type: vless`, `    server: ${yamlStr(host)}`, `    port: ${port}`, `    uuid: ${yamlStr(client.credential)}`, `    network: ${inbound.network}`, `    udp: true`);
      if (inbound.network === 'tcp' && inbound.flow) lines.push(`    flow: ${yamlStr(inbound.flow)}`);
      if (inbound.security === 'tls' || inbound.security === 'reality') {
        lines.push(`    tls: true`);
        if (inbound.sni) lines.push(`    servername: ${yamlStr(inbound.sni)}`);
        if (inbound.fingerprint) lines.push(`    client-fingerprint: ${yamlStr(inbound.fingerprint)}`);
      }
      if (inbound.security === 'reality') {
        lines.push(`    reality-opts:`, `      public-key: ${yamlStr(inbound.realityPublicKey)}`);
        if (inbound.realityShortId) lines.push(`      short-id: ${yamlStr(inbound.realityShortId)}`);
      }
      if (inbound.network === 'ws') {
        lines.push(`    ws-opts:`, `      path: ${yamlStr(inbound.wsPath || '/')}`);
        if (inbound.wsHost || inbound.sni) {
          lines.push(`      headers:`, `        Host: ${yamlStr(inbound.wsHost || inbound.sni)}`);
        }
      } else if (inbound.network === 'grpc') {
        lines.push(`    grpc-opts:`, `      grpc-service-name: ${yamlStr(inbound.grpcServiceName || 'grpc')}`);
      }
    } else if (inbound.protocol === 'vmess') {
      lines.push(`    type: vmess`, `    server: ${yamlStr(host)}`, `    port: ${port}`, `    uuid: ${yamlStr(client.credential)}`, `    alterId: ${client.alterId ?? 0}`, `    cipher: auto`, `    udp: true`, `    network: ${inbound.network}`);
      if (inbound.security === 'tls') {
        lines.push(`    tls: true`);
        if (inbound.sni) lines.push(`    servername: ${yamlStr(inbound.sni)}`);
        if (inbound.fingerprint) lines.push(`    client-fingerprint: ${yamlStr(inbound.fingerprint)}`);
      }
      if (inbound.network === 'ws') {
        lines.push(`    ws-opts:`, `      path: ${yamlStr(inbound.wsPath || '/')}`);
        if (inbound.wsHost || inbound.sni) {
          lines.push(`      headers:`, `        Host: ${yamlStr(inbound.wsHost || inbound.sni)}`);
        }
      } else if (inbound.network === 'grpc') {
        lines.push(`    grpc-opts:`, `      grpc-service-name: ${yamlStr(inbound.grpcServiceName || 'grpc')}`);
      }
    } else if (inbound.protocol === 'trojan') {
      lines.push(`    type: trojan`, `    server: ${yamlStr(host)}`, `    port: ${port}`, `    password: ${yamlStr(client.credential)}`, `    udp: true`);
      if (inbound.sni) lines.push(`    sni: ${yamlStr(inbound.sni)}`);
      if (inbound.fingerprint) lines.push(`    client-fingerprint: ${yamlStr(inbound.fingerprint)}`);
      if (inbound.network !== 'tcp') lines.push(`    network: ${inbound.network}`);
      if (inbound.network === 'ws') {
        lines.push(`    ws-opts:`, `      path: ${yamlStr(inbound.wsPath || '/')}`);
        if (inbound.wsHost || inbound.sni) {
          lines.push(`      headers:`, `        Host: ${yamlStr(inbound.wsHost || inbound.sni)}`);
        }
      } else if (inbound.network === 'grpc') {
        lines.push(`    grpc-opts:`, `      grpc-service-name: ${yamlStr(inbound.grpcServiceName || 'grpc')}`);
      }
    } else if (inbound.protocol === 'shadowsocks') {
      lines.push(`    type: ss`, `    server: ${yamlStr(host)}`, `    port: ${port}`, `    cipher: ${yamlStr(inbound.ssMethod || 'aes-256-gcm')}`, `    password: ${yamlStr(client.credential)}`, `    udp: true`);
    } else if (inbound.protocol === 'tuic') {
      lines.push(`    type: tuic`, `    server: ${yamlStr(host)}`, `    port: ${port}`, `    uuid: ${yamlStr(client.credential)}`, `    password: ${yamlStr(client.secondaryPassword || client.credential)}`, `    congestion-controller: ${inbound.tuicCongestion || 'bbr'}`, `    udp-relay-mode: ${inbound.tuicUdpRelay || 'native'}`);
      if (inbound.sni) lines.push(`    sni: ${yamlStr(inbound.sni)}`);
      lines.push(`    alpn:`, `      - ${inbound.alpn || 'h3'}`);
    } else {
      lines.push(`    type: hysteria2`, `    server: ${yamlStr(host)}`, `    port: ${port}`, `    password: ${yamlStr(client.credential)}`);
      if (inbound.sni) lines.push(`    sni: ${yamlStr(inbound.sni)}`);
      if (inbound.hy2UpMbps) lines.push(`    up: "${inbound.hy2UpMbps} Mbps"`);
      if (inbound.hy2DownMbps) lines.push(`    down: "${inbound.hy2DownMbps} Mbps"`);
      if (inbound.hy2Obfs === 'salamander' && inbound.hy2ObfsPassword) {
        lines.push(`    obfs: salamander`, `    obfs-password: ${yamlStr(inbound.hy2ObfsPassword)}`);
      }
    }

    proxyBlocks.push(lines.join('\n'));
  }

  const indentedNames = proxyNames.map((n) => `      - ${yamlStr(n)}`).join('\n');
  const rules: string[] = [
    `  - IP-CIDR,127.0.0.0/8,DIRECT`,
    `  - IP-CIDR,10.0.0.0/8,DIRECT`,
    `  - IP-CIDR,172.16.0.0/12,DIRECT`,
    `  - IP-CIDR,192.168.0.0/16,DIRECT`,
  ];
  if (settings?.blockAds) {
    rules.push(`  - GEOSITE,category-ads-all,REJECT`);
  }
  if (settings?.bypassCountry && settings.bypassCountry !== 'none') {
    const cc = settings.bypassCountry.toUpperCase();
    rules.push(`  - GEOSITE,${settings.bypassCountry},DIRECT`);
    rules.push(`  - GEOIP,${cc},DIRECT`);
  }
  rules.push(`  - MATCH,EdgeProxy`);

  return [
    `mixed-port: ${mixedPort}`,
    `allow-lan: false`,
    `mode: rule`,
    `log-level: info`,
    `unified-delay: true`,
    `tcp-concurrent: true`,
    `dns:`,
    `  enable: true`,
    `  enhanced-mode: fake-ip`,
    `  nameserver:`,
    `    - ${dnsServer}`,
    `    - https://8.8.8.8/dns-query`,
    `proxies:`,
    proxyBlocks.length ? proxyBlocks.join('\n') : '  []',
    `proxy-groups:`,
    `  - name: "EdgeProxy"`,
    `    type: select`,
    `    proxies:`,
    `      - "Auto Select"`,
    indentedNames || '      - DIRECT',
    `  - name: "Auto Select"`,
    `    type: url-test`,
    `    url: "https://www.gstatic.com/generate_204"`,
    `    interval: 300`,
    `    proxies:`,
    indentedNames || '      - DIRECT',
    `rules:`,
    ...rules,
  ].join('\n');
}

export function buildSingboxJson(
  pairs: Array<{ inbound: InboundConfig; client: ClientConfig }>,
  settings?: Partial<PanelSettings>,
  endpoints: CleanEndpoint[] = []
): string {
  const targets = expandPairsWithCleanEndpoints(pairs, endpoints);
  const outbounds: Array<Record<string, unknown>> = [];
  const tags: string[] = [];

  for (const { inbound, client, overrideHost, overridePort, labelSuffix } of targets) {
    const host = overrideHost || inbound.serverAddress || settings?.edgeDomain || 'edge.example.com';
    const port = overridePort || inbound.port;
    const tag = `${inbound.remark || inbound.tag}${labelSuffix ? ` (${labelSuffix})` : ''} - ${client.email}`;
    tags.push(tag);

    const buildTls = () => {
      if (inbound.security === 'none') return undefined;
      const tlsObj: Record<string, unknown> = {
        enabled: true,
        server_name: inbound.sni || host,
        utls: {
          enabled: true,
          fingerprint: inbound.fingerprint || 'chrome',
        },
      };
      if (inbound.alpn && inbound.security === 'tls') {
        tlsObj.alpn = inbound.alpn.split(',').map((s) => s.trim()).filter(Boolean);
      }
      if (inbound.security === 'reality') {
        tlsObj.reality = {
          enabled: true,
          public_key: inbound.realityPublicKey,
          short_id: inbound.realityShortId || '',
        };
      }
      if (settings?.fragmentEnabled && inbound.security === 'tls') {
        tlsObj.fragment = true;
      }
      return tlsObj;
    };

    const buildTransport = () => {
      if (inbound.network === 'ws') {
        return {
          type: 'ws',
          path: inbound.wsPath || '/',
          headers: inbound.wsHost || inbound.sni ? { Host: inbound.wsHost || inbound.sni } : undefined,
        };
      }
      if (inbound.network === 'grpc') {
        return {
          type: 'grpc',
          service_name: inbound.grpcServiceName || 'grpc',
        };
      }
      return undefined;
    };

    const muxObj =
      settings?.muxEnabled && (inbound.protocol === 'vless' || inbound.protocol === 'vmess' || inbound.protocol === 'trojan')
        ? { enabled: true, protocol: 'h2mux', max_connections: settings.muxConcurrency || 4 }
        : undefined;

    if (inbound.protocol === 'vless') {
      const node: Record<string, unknown> = {
        type: 'vless',
        tag,
        server: host,
        server_port: port,
        uuid: client.credential,
      };
      if (inbound.network === 'tcp' && inbound.flow) node.flow = inbound.flow;
      const tls = buildTls();
      if (tls) node.tls = tls;
      const transport = buildTransport();
      if (transport) node.transport = transport;
      if (muxObj && !node.flow) node.multiplex = muxObj;
      outbounds.push(node);
    } else if (inbound.protocol === 'vmess') {
      const node: Record<string, unknown> = {
        type: 'vmess',
        tag,
        server: host,
        server_port: port,
        uuid: client.credential,
        security: 'auto',
        alter_id: client.alterId ?? 0,
      };
      const tls = buildTls();
      if (tls) node.tls = tls;
      const transport = buildTransport();
      if (transport) node.transport = transport;
      if (muxObj) node.multiplex = muxObj;
      outbounds.push(node);
    } else if (inbound.protocol === 'trojan') {
      const node: Record<string, unknown> = {
        type: 'trojan',
        tag,
        server: host,
        server_port: port,
        password: client.credential,
      };
      const tls = buildTls();
      if (tls) node.tls = tls;
      const transport = buildTransport();
      if (transport) node.transport = transport;
      if (muxObj) node.multiplex = muxObj;
      outbounds.push(node);
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
        tls: {
          enabled: true,
          server_name: inbound.sni || host,
          alpn: [inbound.alpn || 'h3'],
        },
      });
    } else {
      const node: Record<string, unknown> = {
        type: 'hysteria2',
        tag,
        server: host,
        server_port: port,
        password: client.credential,
        up_mbps: inbound.hy2UpMbps || 100,
        down_mbps: inbound.hy2DownMbps || 200,
        tls: {
          enabled: true,
          server_name: inbound.sni || host,
          alpn: [inbound.alpn || 'h3'],
        },
      };
      if (inbound.hy2Obfs === 'salamander' && inbound.hy2ObfsPassword) {
        node.obfs = { type: 'salamander', password: inbound.hy2ObfsPassword };
      }
      outbounds.push(node);
    }
  }

  const routeRules: Array<Record<string, unknown>> = [{ ip_is_private: true, outbound: 'direct' }];
  if (settings?.blockAds) {
    routeRules.push({ protocol: 'dns', outbound: 'dns-out' });
  }
  if (settings?.bypassCountry && settings.bypassCountry !== 'none') {
    routeRules.push({ rule_set: [`geoip-${settings.bypassCountry}`], outbound: 'direct' });
  }

  const config = {
    log: { level: 'info', timestamp: true },
    dns: {
      servers: [
        { tag: 'cf-dns', address: settings?.dnsServer || 'https://1.1.1.1/dns-query', detour: 'proxy' },
        { tag: 'local-dns', address: 'local', detour: 'direct' },
      ],
      rules: [{ outbound: 'any', server: 'local-dns' }],
    },
    inbounds: [
      {
        type: 'mixed',
        tag: 'mixed-in',
        listen: '127.0.0.1',
        listen_port: settings?.clashMixedPort || 2080,
      },
    ],
    outbounds: [
      {
        type: 'selector',
        tag: 'proxy',
        outbounds: ['auto', ...tags, 'direct'],
        default: tags[0] || 'direct',
      },
      {
        type: 'urltest',
        tag: 'auto',
        outbounds: tags.length ? tags : ['direct'],
        url: 'https://www.gstatic.com/generate_204',
        interval: '3m',
      },
      ...outbounds,
      { type: 'direct', tag: 'direct' },
      { type: 'block', tag: 'block' },
      { type: 'dns', tag: 'dns-out' },
    ],
    route: {
      rules: routeRules,
      final: 'proxy',
    },
  };

  return JSON.stringify(config, null, 2);
}

export function buildXrayJson(
  pairs: Array<{ inbound: InboundConfig; client: ClientConfig }>,
  settings?: Partial<PanelSettings>,
  endpoints: CleanEndpoint[] = []
): string {
  const targets = expandPairsWithCleanEndpoints(pairs, endpoints);
  const outbounds: Array<Record<string, unknown>> = [];

  for (const [idx, { inbound, client, overrideHost, overridePort, labelSuffix }] of targets.entries()) {
    const host = overrideHost || inbound.serverAddress || settings?.edgeDomain || 'edge.example.com';
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
      if (settings?.fragmentEnabled) {
        streamSettings.sockopt = {
          dialerProxy: 'fragment',
          tcpFastOpen: true,
        };
      }
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
      streamSettings.grpcSettings = {
        serviceName: inbound.grpcServiceName || 'grpc',
      };
    }

    const mux = settings?.muxEnabled
      ? { enabled: true, concurrency: settings.muxConcurrency || 8 }
      : { enabled: false };

    if (inbound.protocol === 'vless') {
      outbounds.push({
        tag,
        remark,
        protocol: 'vless',
        settings: {
          vnext: [
            {
              address: host,
              port,
              users: [
                {
                  id: client.credential,
                  encryption: 'none',
                  flow: inbound.network === 'tcp' ? inbound.flow || '' : '',
                },
              ],
            },
          ],
        },
        streamSettings,
        mux,
      });
    } else if (inbound.protocol === 'vmess') {
      outbounds.push({
        tag,
        remark,
        protocol: 'vmess',
        settings: {
          vnext: [
            {
              address: host,
              port,
              users: [{ id: client.credential, alterId: client.alterId ?? 0, security: 'auto' }],
            },
          ],
        },
        streamSettings,
        mux,
      });
    } else if (inbound.protocol === 'trojan') {
      outbounds.push({
        tag,
        remark,
        protocol: 'trojan',
        settings: {
          servers: [{ address: host, port, password: client.credential }],
        },
        streamSettings,
        mux,
      });
    } else if (inbound.protocol === 'shadowsocks') {
      outbounds.push({
        tag,
        remark,
        protocol: 'shadowsocks',
        settings: {
          servers: [
            {
              address: host,
              port,
              method: inbound.ssMethod || 'aes-256-gcm',
              password: client.credential,
            },
          ],
        },
      });
    }
  }

  if (settings?.fragmentEnabled) {
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

  outbounds.push({ tag: 'direct', protocol: 'freedom' });
  outbounds.push({ tag: 'block', protocol: 'blackhole' });

  const routingRules: Array<Record<string, unknown>> = [
    { type: 'field', ip: ['geoip:private'], outboundTag: 'direct' },
  ];
  if (settings?.blockAds) {
    routingRules.push({ type: 'field', domain: ['geosite:category-ads-all'], outboundTag: 'block' });
  }
  if (settings?.bypassCountry && settings.bypassCountry !== 'none') {
    routingRules.push({
      type: 'field',
      domain: [`geosite:${settings.bypassCountry}`],
      outboundTag: 'direct',
    });
    routingRules.push({
      type: 'field',
      ip: [`geoip:${settings.bypassCountry}`],
      outboundTag: 'direct',
    });
  }

  return JSON.stringify(
    {
      log: { loglevel: 'warning' },
      dns: {
        servers: [settings?.dnsServer || '1.1.1.1', '8.8.8.8', 'localhost'],
      },
      inbounds: [
        {
          tag: 'socks-in',
          port: 10808,
          listen: '127.0.0.1',
          protocol: 'socks',
          settings: { auth: 'noauth', udp: true },
        },
        {
          tag: 'http-in',
          port: 10809,
          listen: '127.0.0.1',
          protocol: 'http',
        },
      ],
      outbounds,
      routing: {
        domainStrategy: 'IPIfNonMatch',
        rules: routingRules,
      },
    },
    null,
    2
  );
}

export function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const idx = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const val = bytes / Math.pow(1024, idx);
  return `${val.toFixed(idx === 0 ? 0 : 2)} ${units[idx]}`;
}

export function formatExpiry(expiryTime: number): {
  label: string;
  state: 'never' | 'active' | 'expiring' | 'expired';
} {
  if (!expiryTime || expiryTime === 0) {
    return { label: 'Never', state: 'never' };
  }
  const now = Date.now();
  const diff = expiryTime - now;
  if (diff <= 0) {
    return { label: 'Expired', state: 'expired' };
  }
  const days = Math.ceil(diff / (1000 * 60 * 60 * 24));
  const dateStr = new Date(expiryTime).toISOString().slice(0, 10);
  if (days <= 5) {
    return { label: `${days}d left (${dateStr})`, state: 'expiring' };
  }
  return { label: `${days}d (${dateStr})`, state: 'active' };
}
