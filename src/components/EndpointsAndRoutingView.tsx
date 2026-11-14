import { useState, type FormEvent } from 'react';
import { Check, Globe, Plus, Power, Trash2 } from 'lucide-react';
import type { BypassCountry, CleanEndpoint, PanelSettings } from '../lib/protocols';

interface EndpointsAndRoutingViewProps {
  endpoints: CleanEndpoint[];
  settings: PanelSettings;
  onRefresh: () => Promise<void>;
  onSaveSettings: (patch: Partial<PanelSettings>) => Promise<void>;
}

export function EndpointsAndRoutingView({
  endpoints,
  settings,
  onRefresh,
  onSaveSettings,
}: EndpointsAndRoutingViewProps) {
  const [label, setLabel] = useState('');
  const [address, setAddress] = useState('');
  const [port, setPort] = useState('443');
  const [adding, setAdding] = useState(false);

  const [workerRelayEnabled, setWorkerRelayEnabled] = useState(settings.workerRelayEnabled);
  const [workerRelayPath, setWorkerRelayPath] = useState(settings.workerRelayPath);
  const [workerProxyIp, setWorkerProxyIp] = useState(settings.workerProxyIp);
  const [fragmentEnabled, setFragmentEnabled] = useState(settings.fragmentEnabled);
  const [fragmentPackets, setFragmentPackets] = useState(settings.fragmentPackets);
  const [fragmentLength, setFragmentLength] = useState(settings.fragmentLength);
  const [fragmentInterval, setFragmentInterval] = useState(settings.fragmentInterval);
  const [muxEnabled, setMuxEnabled] = useState(settings.muxEnabled);
  const [muxConcurrency, setMuxConcurrency] = useState(String(settings.muxConcurrency || 4));
  const [bypassCountry, setBypassCountry] = useState<BypassCountry>(settings.bypassCountry);
  const [blockAds, setBlockAds] = useState(settings.blockAds);
  const [dnsServer, setDnsServer] = useState(settings.dnsServer);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const handleAddEndpoint = async (e: FormEvent) => {
    e.preventDefault();
    if (!address.trim()) return;
    setAdding(true);
    try {
      await fetch('/api/endpoints', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          label: label.trim() || 'CF Clean Edge',
          address: address.trim(),
          port: Number(port) || 443,
        }),
      });
      setLabel('');
      setAddress('');
      setPort('443');
      await onRefresh();
    } finally {
      setAdding(false);
    }
  };

  const toggleEndpoint = async (ep: CleanEndpoint) => {
    await fetch(`/api/endpoints/${ep.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !ep.enabled }),
    });
    await onRefresh();
  };

  const removeEndpoint = async (id: string) => {
    await fetch(`/api/endpoints/${id}`, { method: 'DELETE' });
    await onRefresh();
  };

  const handleSaveRouting = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await onSaveSettings({
        workerRelayEnabled,
        workerRelayPath: workerRelayPath.trim() || '/edge-ws',
        workerProxyIp: workerProxyIp.trim(),
        fragmentEnabled,
        fragmentPackets: fragmentPackets.trim() || 'tlshello',
        fragmentLength: fragmentLength.trim() || '100-200',
        fragmentInterval: fragmentInterval.trim() || '10-20',
        muxEnabled,
        muxConcurrency: Number(muxConcurrency) || 4,
        bypassCountry,
        blockAds,
        dnsServer: dnsServer.trim() || 'https://1.1.1.1/dns-query',
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 1800);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
      {/* Left: Serverless Relay, Fragment, Mux & Routing */}
      <form
        onSubmit={handleSaveRouting}
        className="space-y-5 rounded-xl border border-slate-200 bg-white p-5 text-xs lg:col-span-7 dark:border-slate-800 dark:bg-slate-900"
      >
        <div>
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            Edge Relay, TLS Fragment &amp; Client Routing
          </h2>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            Configure the built-in Cloudflare Worker VLESS-WS relay alongside Fragment, Mux, and Geo-routing rules embedded into exported Clash, Sing-box, and Xray configs.
          </p>
        </div>

        <div className="space-y-4 border-t border-slate-200 pt-4 dark:border-slate-800">
          <div className="flex items-center justify-between">
            <div>
              <div className="font-semibold text-slate-900 dark:text-slate-100">
                Built-in Worker VLESS-WS Relay
              </div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400">
                Uses <code className="font-mono">cloudflare:sockets</code> directly inside the Worker without a VPS.
              </div>
            </div>
            <label className="inline-flex cursor-pointer items-center gap-2 font-medium">
              <input
                type="checkbox"
                checked={workerRelayEnabled}
                onChange={(e) => setWorkerRelayEnabled(e.target.checked)}
                className="h-4 w-4 accent-orange-600"
              />
              <span>{workerRelayEnabled ? 'Enabled' : 'Disabled'}</span>
            </label>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <label className="mb-1 block font-medium text-slate-700 dark:text-slate-300">
                Relay WebSocket Path
              </label>
              <input
                value={workerRelayPath}
                onChange={(e) => setWorkerRelayPath(e.target.value)}
                className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
              />
            </div>
            <div>
              <label className="mb-1 block font-medium text-slate-700 dark:text-slate-300">
                Fallback ProxyIP (Host:Port)
              </label>
              <input
                value={workerProxyIp}
                onChange={(e) => setWorkerProxyIp(e.target.value)}
                placeholder="proxyip.example.com:443"
                className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
              />
            </div>
          </div>
        </div>

        <div className="space-y-3 border-t border-slate-200 pt-4 dark:border-slate-800">
          <div className="flex items-center justify-between">
            <span className="font-semibold text-slate-900 dark:text-slate-100">
              TLS Fragmentation (Anti-DPI)
            </span>
            <label className="inline-flex cursor-pointer items-center gap-2 font-medium">
              <input
                type="checkbox"
                checked={fragmentEnabled}
                onChange={(e) => setFragmentEnabled(e.target.checked)}
                className="h-4 w-4 accent-orange-600"
              />
              <span>{fragmentEnabled ? 'Enabled' : 'Disabled'}</span>
            </label>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="mb-1 block text-slate-600 dark:text-slate-400">Packets</label>
              <input
                value={fragmentPackets}
                onChange={(e) => setFragmentPackets(e.target.value)}
                className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
              />
            </div>
            <div>
              <label className="mb-1 block text-slate-600 dark:text-slate-400">Length (bytes)</label>
              <input
                value={fragmentLength}
                onChange={(e) => setFragmentLength(e.target.value)}
                className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
              />
            </div>
            <div>
              <label className="mb-1 block text-slate-600 dark:text-slate-400">Interval (ms)</label>
              <input
                value={fragmentInterval}
                onChange={(e) => setFragmentInterval(e.target.value)}
                className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
              />
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 border-t border-slate-200 pt-4 sm:grid-cols-2 dark:border-slate-800">
          <div>
            <label className="mb-1 block font-medium text-slate-700 dark:text-slate-300">
              GeoIP / GeoSite Direct Bypass
            </label>
            <select
              value={bypassCountry}
              onChange={(e) => setBypassCountry(e.target.value as BypassCountry)}
              className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-slate-900 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
            >
              <option value="none">None (Proxy All)</option>
              <option value="ir">Iran (IR Direct)</option>
              <option value="cn">China (CN Direct)</option>
              <option value="ru">Russia (RU Direct)</option>
            </select>
          </div>
          <div>
            <label className="mb-1 block font-medium text-slate-700 dark:text-slate-300">
              DoH DNS Resolver
            </label>
            <input
              value={dnsServer}
              onChange={(e) => setDnsServer(e.target.value)}
              className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
            />
          </div>
          <div className="flex items-center gap-6">
            <label className="inline-flex cursor-pointer items-center gap-2 font-medium text-slate-700 dark:text-slate-300">
              <input
                type="checkbox"
                checked={blockAds}
                onChange={(e) => setBlockAds(e.target.checked)}
                className="h-4 w-4 accent-orange-600"
              />
              Block Ads &amp; Trackers
            </label>
            <label className="inline-flex cursor-pointer items-center gap-2 font-medium text-slate-700 dark:text-slate-300">
              <input
                type="checkbox"
                checked={muxEnabled}
                onChange={(e) => setMuxEnabled(e.target.checked)}
                className="h-4 w-4 accent-orange-600"
              />
              Enable Mux
            </label>
          </div>
          {muxEnabled && (
            <div>
              <label className="mb-1 block font-medium text-slate-700 dark:text-slate-300">
                Mux Concurrency
              </label>
              <input
                type="number"
                min={1}
                max={32}
                value={muxConcurrency}
                onChange={(e) => setMuxConcurrency(e.target.value)}
                className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono tabular-nums text-slate-900 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
              />
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-3 border-t border-slate-200 pt-4 dark:border-slate-800">
          {saved && (
            <span className="inline-flex items-center gap-1 font-medium text-emerald-600 dark:text-emerald-400">
              <Check className="h-3.5 w-3.5" />
              Saved
            </span>
          )}
          <button
            type="submit"
            disabled={saving}
            className="rounded-lg bg-orange-600 px-4 py-2 font-medium text-white transition-colors hover:bg-orange-500 disabled:opacity-50"
          >
            {saving ? 'Saving...' : 'Save Relay & Routing'}
          </button>
        </div>
      </form>

      {/* Right: Clean IP / Edge Endpoints Pool */}
      <div className="space-y-4 rounded-xl border border-slate-200 bg-white p-5 text-xs lg:col-span-5 dark:border-slate-800 dark:bg-slate-900">
        <div>
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            Clean Cloudflare IP Pool ({endpoints.length})
          </h2>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            Active WebSocket inbounds automatically expand across every enabled Clean IP in generated subscriptions.
          </p>
        </div>

        <form onSubmit={handleAddEndpoint} className="space-y-2.5">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <input
              required
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="Label (e.g. MCI Clean)"
              className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
            />
            <div className="flex gap-2">
              <input
                required
                value={address}
                onChange={(e) => setAddress(e.target.value)}
                placeholder="104.16.132.229"
                className="min-w-0 flex-1 rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
              />
              <input
                type="number"
                value={port}
                onChange={(e) => setPort(e.target.value)}
                className="w-20 rounded-lg border border-slate-200 bg-white px-2.5 py-2 font-mono tabular-nums text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
              />
            </div>
          </div>
          <button
            type="submit"
            disabled={adding}
            className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg bg-slate-900 px-3 py-2 font-medium text-white transition-colors hover:bg-slate-800 dark:bg-slate-800 dark:hover:bg-slate-700"
          >
            <Plus className="h-3.5 w-3.5" />
            Add Clean Endpoint
          </button>
        </form>

        <div className="divide-y divide-slate-200 border-t border-slate-200 dark:divide-slate-800 dark:border-slate-800">
          {endpoints.length === 0 ? (
            <div className="py-6 text-center text-slate-500 dark:text-slate-400">
              No clean endpoints configured.
            </div>
          ) : (
            endpoints.map((ep) => (
              <div key={ep.id} className="flex items-center justify-between gap-3 py-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <Globe className="h-3.5 w-3.5 text-slate-400 shrink-0" />
                    <span className="truncate font-medium text-slate-900 dark:text-slate-100">
                      {ep.label}
                    </span>
                    <span
                      className={`text-[11px] font-medium ${
                        ep.enabled
                          ? 'text-emerald-600 dark:text-emerald-400'
                          : 'text-slate-400'
                      }`}
                    >
                      {ep.enabled ? 'Active' : 'Paused'}
                    </span>
                  </div>
                  <div className="mt-0.5 pl-5 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                    {ep.address}:{ep.port}
                  </div>
                </div>

                <div className="flex items-center gap-1.5 shrink-0">
                  <button
                    type="button"
                    onClick={() => toggleEndpoint(ep)}
                    title={ep.enabled ? 'Pause' : 'Enable'}
                    className="rounded-md border border-slate-200 p-1.5 text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                  >
                    <Power className="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => removeEndpoint(ep.id)}
                    title="Delete"
                    className="rounded-md border border-rose-200 p-1.5 text-rose-600 hover:bg-rose-50 dark:border-rose-900/50 dark:text-rose-400 dark:hover:bg-rose-950/60"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
