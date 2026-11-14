import { useState, type FormEvent } from 'react';
import { KeyRound, RefreshCw, X } from 'lucide-react';
import type {
  InboundConfig,
  NetworkType,
  ProtocolType,
  SecurityType,
} from '../lib/protocols';

interface InboundModalProps {
  initial?: InboundConfig | null;
  defaultHost: string;
  defaultSni: string;
  onClose: () => void;
  onSave: (payload: Partial<InboundConfig>, existingId?: string) => Promise<void>;
}

const PROTOCOLS: Array<{ id: ProtocolType; label: string }> = [
  { id: 'vless', label: 'VLESS' },
  { id: 'vmess', label: 'VMess' },
  { id: 'trojan', label: 'Trojan' },
  { id: 'shadowsocks', label: 'Shadowsocks' },
  { id: 'tuic', label: 'TUIC v5' },
  { id: 'hysteria2', label: 'Hysteria2' },
];

export function InboundModal({
  initial,
  defaultHost,
  defaultSni,
  onClose,
  onSave,
}: InboundModalProps) {
  const [protocol, setProtocol] = useState<ProtocolType>(initial?.protocol || 'vless');
  const [remark, setRemark] = useState(initial?.remark || '');
  const [tag, setTag] = useState(initial?.tag || '');
  const [serverAddress, setServerAddress] = useState(initial?.serverAddress || defaultHost);
  const [port, setPort] = useState(String(initial?.port || 443));
  const [network, setNetwork] = useState<NetworkType>(initial?.network || 'tcp');
  const [security, setSecurity] = useState<SecurityType>(initial?.security || 'reality');
  const [sni, setSni] = useState(initial?.sni || defaultSni || 'www.cloudflare.com');
  const [fingerprint, setFingerprint] = useState(initial?.fingerprint || 'chrome');
  const [alpn, setAlpn] = useState(initial?.alpn || 'h2,http/1.1');
  const [flow, setFlow] = useState(initial?.flow ?? 'xtls-rprx-vision');
  const [wsPath, setWsPath] = useState(initial?.wsPath || '/edge-ws');
  const [wsHost, setWsHost] = useState(initial?.wsHost || '');
  const [grpcServiceName, setGrpcServiceName] = useState(initial?.grpcServiceName || 'grpc');
  const [realityPublicKey, setRealityPublicKey] = useState(initial?.realityPublicKey || '');
  const [realityPrivateKey, setRealityPrivateKey] = useState(initial?.realityPrivateKey || '');
  const [realityShortId, setRealityShortId] = useState(initial?.realityShortId || '');
  const [realityDest, setRealityDest] = useState(initial?.realityDest || 'www.cloudflare.com:443');
  const [ssMethod, setSsMethod] = useState(initial?.ssMethod || '2022-blake3-aes-128-gcm');
  const [tuicCongestion, setTuicCongestion] = useState(initial?.tuicCongestion || 'bbr');
  const [tuicUdpRelay, setTuicUdpRelay] = useState(initial?.tuicUdpRelay || 'native');
  const [hy2Obfs, setHy2Obfs] = useState(initial?.hy2Obfs || 'none');
  const [hy2ObfsPassword, setHy2ObfsPassword] = useState(initial?.hy2ObfsPassword || '');
  const [hy2UpMbps, setHy2UpMbps] = useState(String(initial?.hy2UpMbps || 100));
  const [hy2DownMbps, setHy2DownMbps] = useState(String(initial?.hy2DownMbps || 300));
  const [generating, setGenerating] = useState(false);
  const [saving, setSaving] = useState(false);

  const handleProtocolChange = (next: ProtocolType) => {
    setProtocol(next);
    if (next === 'vless') {
      setNetwork('tcp');
      setSecurity('reality');
      setFlow('xtls-rprx-vision');
    } else if (next === 'vmess') {
      setNetwork('ws');
      setSecurity('tls');
      setFlow('');
    } else if (next === 'trojan') {
      setNetwork('tcp');
      setSecurity('tls');
      setFlow('');
    } else if (next === 'shadowsocks') {
      setNetwork('tcp');
      setSecurity('none');
      setFlow('');
    } else if (next === 'tuic' || next === 'hysteria2') {
      setNetwork('quic');
      setSecurity('tls');
      setAlpn('h3');
      setFlow('');
    }
  };

  const handleKeygen = async () => {
    setGenerating(true);
    try {
      const res = await fetch('/api/tools/keygen');
      if (res.ok) {
        const data = await res.json();
        setRealityPrivateKey(data.reality.privateKey);
        setRealityPublicKey(data.reality.publicKey);
        setRealityShortId(data.shortId);
      }
    } finally {
      setGenerating(false);
    }
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await onSave(
        {
          remark: remark.trim() || `${protocol.toUpperCase()} Edge Node`,
          tag: tag.trim() || `${protocol}-${port}`,
          protocol,
          serverAddress: serverAddress.trim(),
          port: Number(port) || 443,
          network,
          security,
          sni: sni.trim(),
          fingerprint,
          alpn: alpn.trim(),
          flow: protocol === 'vless' && network === 'tcp' ? flow : '',
          wsPath: wsPath.trim() || '/',
          wsHost: wsHost.trim(),
          grpcServiceName: grpcServiceName.trim() || 'grpc',
          realityPrivateKey: realityPrivateKey.trim(),
          realityPublicKey: realityPublicKey.trim(),
          realityShortId: realityShortId.trim(),
          realityDest: realityDest.trim(),
          ssMethod,
          tuicCongestion,
          tuicUdpRelay,
          hy2Obfs,
          hy2ObfsPassword: hy2ObfsPassword.trim(),
          hy2UpMbps: Number(hy2UpMbps) || 100,
          hy2DownMbps: Number(hy2DownMbps) || 200,
        },
        initial?.id
      );
      onClose();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/75 p-4 backdrop-blur-xs"
      onClick={onClose}
    >
      <form
        onSubmit={handleSubmit}
        onClick={(e) => e.stopPropagation()}
        className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-slate-200 bg-white p-6 shadow-xl dark:border-slate-800 dark:bg-slate-900"
      >
        <div className="flex items-center justify-between border-b border-slate-200 pb-4 dark:border-slate-800">
          <div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              {initial ? 'Edit Inbound Configuration' : 'Create Inbound Configuration'}
            </h2>
            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
              Configure edge listener parameters, transport, and TLS/Reality security.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close modal"
            className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-5 space-y-5 text-xs">
          <div>
            <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
              Protocol
            </label>
            <div className="grid grid-cols-3 gap-1.5 rounded-lg border border-slate-200 bg-slate-50 p-1 sm:grid-cols-6 dark:border-slate-800 dark:bg-slate-950">
              {PROTOCOLS.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => handleProtocolChange(p.id)}
                  className={`rounded-md px-2.5 py-2 text-xs font-medium transition-colors whitespace-nowrap ${
                    protocol === p.id
                      ? 'bg-orange-600 text-white'
                      : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'
                  }`}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                Remark
              </label>
              <input
                required
                value={remark}
                onChange={(e) => setRemark(e.target.value)}
                placeholder="Cloudflare Edge VLESS"
                className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
              />
            </div>
            <div>
              <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                Tag Identifier
              </label>
              <input
                value={tag}
                onChange={(e) => setTag(e.target.value)}
                placeholder={`${protocol}-${port}`}
                className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
              />
            </div>

            <div>
              <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                Server Address / Edge Host
              </label>
              <input
                required
                value={serverAddress}
                onChange={(e) => setServerAddress(e.target.value)}
                className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
              />
            </div>
            <div>
              <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                Port
              </label>
              <input
                required
                type="number"
                min={1}
                max={65535}
                value={port}
                onChange={(e) => setPort(e.target.value)}
                className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono tabular-nums text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
              />
            </div>
          </div>

          {protocol !== 'shadowsocks' && protocol !== 'tuic' && protocol !== 'hysteria2' && (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <div>
                <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                  Transport
                </label>
                <select
                  value={network}
                  onChange={(e) => setNetwork(e.target.value as NetworkType)}
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
                >
                  <option value="tcp">TCP</option>
                  <option value="ws">WebSocket (CDN)</option>
                  <option value="grpc">gRPC</option>
                </select>
              </div>
              <div>
                <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                  Security
                </label>
                <select
                  value={security}
                  onChange={(e) => setSecurity(e.target.value as SecurityType)}
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
                >
                  {protocol !== 'vmess' && <option value="reality">Reality</option>}
                  <option value="tls">TLS</option>
                  {protocol !== 'trojan' && <option value="none">None</option>}
                </select>
              </div>
              <div>
                <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                  uTLS Fingerprint
                </label>
                <select
                  value={fingerprint}
                  onChange={(e) => setFingerprint(e.target.value)}
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
                >
                  <option value="chrome">chrome</option>
                  <option value="firefox">firefox</option>
                  <option value="safari">safari</option>
                  <option value="ios">ios</option>
                  <option value="android">android</option>
                  <option value="random">random</option>
                </select>
              </div>
            </div>
          )}

          {network === 'ws' && (protocol === 'vless' || protocol === 'vmess' || protocol === 'trojan') && (
            <div className="grid grid-cols-1 gap-4 rounded-lg border border-slate-200 bg-slate-50 p-4 sm:grid-cols-2 dark:border-slate-800 dark:bg-slate-950">
              <div>
                <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                  WebSocket Path
                </label>
                <input
                  value={wsPath}
                  onChange={(e) => setWsPath(e.target.value)}
                  placeholder="/edge-ws"
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100"
                />
              </div>
              <div>
                <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                  WebSocket Host Header
                </label>
                <input
                  value={wsHost}
                  onChange={(e) => setWsHost(e.target.value)}
                  placeholder={serverAddress}
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100"
                />
              </div>
            </div>
          )}

          {network === 'grpc' && (protocol === 'vless' || protocol === 'vmess' || protocol === 'trojan') && (
            <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950">
              <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                gRPC Service Name
              </label>
              <input
                value={grpcServiceName}
                onChange={(e) => setGrpcServiceName(e.target.value)}
                placeholder="grpc"
                className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100"
              />
            </div>
          )}

          {security !== 'none' && protocol !== 'shadowsocks' && (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                  SNI (Server Name Indication)
                </label>
                <input
                  value={sni}
                  onChange={(e) => setSni(e.target.value)}
                  placeholder="www.cloudflare.com"
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
                />
              </div>
              {protocol === 'vless' && network === 'tcp' && (
                <div>
                  <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                    XTLS Flow
                  </label>
                  <select
                    value={flow}
                    onChange={(e) => setFlow(e.target.value)}
                    className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
                  >
                    <option value="xtls-rprx-vision">xtls-rprx-vision</option>
                    <option value="">None</option>
                  </select>
                </div>
              )}
              {security === 'tls' && (
                <div>
                  <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                    ALPN
                  </label>
                  <input
                    value={alpn}
                    onChange={(e) => setAlpn(e.target.value)}
                    placeholder="h2,http/1.1"
                    className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
                  />
                </div>
              )}
            </div>
          )}

          {security === 'reality' && (protocol === 'vless' || protocol === 'trojan') && (
            <div className="space-y-3 rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950">
              <div className="flex items-center justify-between">
                <span className="font-medium text-slate-800 dark:text-slate-200">
                  Reality X25519 Credentials
                </span>
                <button
                  type="button"
                  onClick={handleKeygen}
                  disabled={generating}
                  className="inline-flex items-center gap-1.5 rounded-md border border-orange-500/30 bg-orange-500/10 px-2.5 py-1 text-xs font-medium text-orange-600 transition-colors hover:bg-orange-500/20 dark:text-orange-400"
                >
                  {generating ? (
                    <RefreshCw className="h-3 w-3 animate-spin" />
                  ) : (
                    <KeyRound className="h-3 w-3" />
                  )}
                  Generate X25519 Keypair
                </button>
              </div>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <label className="mb-1 block text-slate-500 dark:text-slate-400">
                    Public Key (pbk)
                  </label>
                  <input
                    value={realityPublicKey}
                    onChange={(e) => setRealityPublicKey(e.target.value)}
                    placeholder="Auto-generated if left blank"
                    className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-slate-500 dark:text-slate-400">
                    Private Key (server)
                  </label>
                  <input
                    value={realityPrivateKey}
                    onChange={(e) => setRealityPrivateKey(e.target.value)}
                    placeholder="Auto-generated if left blank"
                    className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-slate-500 dark:text-slate-400">
                    Short ID (sid)
                  </label>
                  <input
                    value={realityShortId}
                    onChange={(e) => setRealityShortId(e.target.value)}
                    placeholder="e.g. a1b2c3d4e5f60718"
                    className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-slate-500 dark:text-slate-400">
                    Target Dest
                  </label>
                  <input
                    value={realityDest}
                    onChange={(e) => setRealityDest(e.target.value)}
                    placeholder="www.cloudflare.com:443"
                    className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100"
                  />
                </div>
              </div>
            </div>
          )}

          {protocol === 'shadowsocks' && (
            <div>
              <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                AEAD / SS2022 Cipher Method
              </label>
              <select
                value={ssMethod}
                onChange={(e) => setSsMethod(e.target.value)}
                className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
              >
                <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>
                <option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm</option>
                <option value="aes-256-gcm">aes-256-gcm</option>
                <option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option>
              </select>
            </div>
          )}

          {protocol === 'tuic' && (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                  Congestion Control
                </label>
                <select
                  value={tuicCongestion}
                  onChange={(e) => setTuicCongestion(e.target.value)}
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
                >
                  <option value="bbr">bbr</option>
                  <option value="cubic">cubic</option>
                  <option value="new_reno">new_reno</option>
                </select>
              </div>
              <div>
                <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                  UDP Relay Mode
                </label>
                <select
                  value={tuicUdpRelay}
                  onChange={(e) => setTuicUdpRelay(e.target.value)}
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
                >
                  <option value="native">native</option>
                  <option value="quic">quic</option>
                </select>
              </div>
            </div>
          )}

          {protocol === 'hysteria2' && (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                  Obfuscation
                </label>
                <select
                  value={hy2Obfs}
                  onChange={(e) => setHy2Obfs(e.target.value)}
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-slate-900 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
                >
                  <option value="none">None</option>
                  <option value="salamander">Salamander</option>
                </select>
              </div>
              {hy2Obfs === 'salamander' && (
                <div>
                  <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                    Salamander Password
                  </label>
                  <input
                    value={hy2ObfsPassword}
                    onChange={(e) => setHy2ObfsPassword(e.target.value)}
                    placeholder="Obfuscation secret"
                    className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
                  />
                </div>
              )}
              <div>
                <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                  Upload Bandwidth (Mbps)
                </label>
                <input
                  type="number"
                  value={hy2UpMbps}
                  onChange={(e) => setHy2UpMbps(e.target.value)}
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono tabular-nums text-slate-900 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
                />
              </div>
              <div>
                <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                  Download Bandwidth (Mbps)
                </label>
                <input
                  type="number"
                  value={hy2DownMbps}
                  onChange={(e) => setHy2DownMbps(e.target.value)}
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono tabular-nums text-slate-900 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
                />
              </div>
            </div>
          )}
        </div>

        <div className="mt-6 flex items-center justify-end gap-2 border-t border-slate-200 pt-4 dark:border-slate-800">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-slate-200 px-4 py-2 text-xs font-medium text-slate-700 transition-colors hover:bg-slate-50 whitespace-nowrap shrink-0 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={saving}
            className="rounded-lg bg-orange-600 px-4 py-2 text-xs font-medium text-white transition-colors hover:bg-orange-500 disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            {saving ? 'Saving...' : initial ? 'Update Inbound' : 'Create Inbound'}
          </button>
        </div>
      </form>
    </div>
  );
}
