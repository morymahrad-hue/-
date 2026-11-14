import { useEffect, useState } from 'react';
import { Check, Copy, Download, QrCode, RefreshCw } from 'lucide-react';
import type { CleanEndpoint, InboundWithClients, PanelSettings } from '../lib/protocols';
import {
  buildClashMetaYaml,
  buildClientUri,
  buildSingboxJson,
  buildXrayJson,
  expandPairsWithCleanEndpoints,
  formatBytes,
  formatExpiry,
  toBase64Standard,
} from '../lib/protocols';

interface SubscriptionInspectorProps {
  inbounds: InboundWithClients[];
  endpoints: CleanEndpoint[];
  settings: PanelSettings;
  onOpenQr: (title: string, value: string, subtitle?: string) => void;
}

type ExportFormat = 'clash' | 'singbox' | 'xray' | 'base64' | 'raw';

export function SubscriptionInspector({
  inbounds,
  endpoints,
  settings,
  onOpenQr,
}: SubscriptionInspectorProps) {
  const subGroups = new Map<
    string,
    {
      subId: string;
      email: string;
      pairs: Array<{ inbound: InboundWithClients; client: InboundWithClients['clients'][number] }>;
    }
  >();

  for (const inbound of inbounds) {
    for (const client of inbound.clients) {
      const existing = subGroups.get(client.subId);
      if (existing) {
        existing.pairs.push({ inbound, client });
      } else {
        subGroups.set(client.subId, {
          subId: client.subId,
          email: client.email,
          pairs: [{ inbound, client }],
        });
      }
    }
  }

  const groups = Array.from(subGroups.values());
  const [selectedSubId, setSelectedSubId] = useState<string>(groups[0]?.subId || '');
  const [format, setFormat] = useState<ExportFormat>('clash');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    if (!selectedSubId && groups.length > 0) {
      setSelectedSubId(groups[0].subId);
    } else if (selectedSubId && !subGroups.has(selectedSubId) && groups.length > 0) {
      setSelectedSubId(groups[0].subId);
    }
  }, [groups.length, selectedSubId]);

  const activeGroup = groups.find((g) => g.subId === selectedSubId) || groups[0];

  const handleCopy = async (key: string, text: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  if (!activeGroup) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-10 text-center dark:border-slate-800 dark:bg-slate-900">
        <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
          No active client subscriptions yet
        </p>
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
          Add a client to any inbound to generate Base64, Clash Meta, Sing-box, and Xray subscription feeds.
        </p>
      </div>
    );
  }

  const origin = typeof window !== 'undefined' ? window.location.origin : 'https://edgepanel.workers.dev';
  const subPath = (settings.subPath || '/sub').replace(/\/+$/, '');
  const baseUrl = `${origin}${subPath}/${activeGroup.subId}`;
  const formatUrl = format === 'base64' ? baseUrl : `${baseUrl}?format=${format}`;

  const activePairs = activeGroup.pairs.filter((p) => p.inbound.enabled && p.client.enabled);
  const targets = expandPairsWithCleanEndpoints(activePairs, endpoints);
  const uris = targets.map(({ inbound, client, overrideHost, overridePort, labelSuffix }) =>
    buildClientUri(
      inbound,
      client,
      settings.edgeDomain || window.location.hostname,
      overrideHost,
      overridePort,
      labelSuffix
    )
  );

  let previewOutput = '';
  if (activePairs.length === 0) {
    previewOutput = '# All linked inbounds or clients for this subscription ID are currently disabled.';
  } else if (format === 'clash') {
    previewOutput = buildClashMetaYaml(activePairs, settings, endpoints);
  } else if (format === 'singbox') {
    previewOutput = buildSingboxJson(activePairs, settings, endpoints);
  } else if (format === 'xray') {
    previewOutput = buildXrayJson(activePairs, settings, endpoints);
  } else if (format === 'raw') {
    previewOutput = uris.join('\n');
  } else {
    previewOutput = toBase64Standard(uris.join('\n'));
  }

  const primaryClient = activeGroup.pairs[0].client;
  const totalUsed = primaryClient.upBytes + primaryClient.downBytes;
  const expiry = formatExpiry(primaryClient.expiryTime);

  const handleDownload = () => {
    const ext = format === 'clash' ? 'yaml' : format === 'singbox' || format === 'xray' ? 'json' : 'txt';
    const blob = new Blob([previewOutput], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activeGroup.subId}-${format}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
      <div className="space-y-3 lg:col-span-4">
        <div className="rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
          <div className="border-b border-slate-200 px-4 py-3 dark:border-slate-800">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Subscription Groups ({groups.length})
            </h2>
            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
              Select a subscriber token to preview client payloads.
            </p>
          </div>
          <div className="divide-y divide-slate-200 dark:divide-slate-800">
            {groups.map((g) => {
              const isSelected = g.subId === activeGroup.subId;
              return (
                <button
                  key={g.subId}
                  type="button"
                  onClick={() => setSelectedSubId(g.subId)}
                  className={`flex w-full items-center justify-between px-4 py-3 text-left transition-colors ${
                    isSelected
                      ? 'bg-orange-500/10 text-slate-900 dark:text-slate-100'
                      : 'text-slate-700 hover:bg-slate-50 dark:text-slate-300 dark:hover:bg-slate-800/40'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="truncate text-xs font-medium">{g.email}</div>
                    <div className="mt-0.5 truncate font-mono text-[11px] text-slate-500 dark:text-slate-400">
                      {g.subId} · {g.pairs.length} {g.pairs.length === 1 ? 'inbound' : 'inbounds'}
                    </div>
                  </div>
                  <span
                    className={`ml-3 text-[11px] font-medium whitespace-nowrap ${
                      isSelected ? 'text-orange-600 dark:text-orange-400' : 'text-slate-400'
                    }`}
                  >
                    {isSelected ? 'Selected' : 'Inspect'}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      <div className="space-y-4 lg:col-span-8">
        <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {activeGroup.email}
              </h3>
              <p className="mt-0.5 font-mono text-xs text-slate-500 dark:text-slate-400">
                Used {formatBytes(totalUsed)} /{' '}
                {primaryClient.totalGb ? `${primaryClient.totalGb} GB` : 'Unlimited'} · Expires:{' '}
                {expiry.label} · Expanded Nodes: {targets.length}
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => handleCopy('sub-url', formatUrl)}
                className="inline-flex items-center gap-1.5 rounded-lg bg-orange-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-orange-500 whitespace-nowrap shrink-0"
              >
                {copiedKey === 'sub-url' ? (
                  <Check className="h-3.5 w-3.5" />
                ) : (
                  <Copy className="h-3.5 w-3.5" />
                )}
                {copiedKey === 'sub-url' ? 'Copied URL' : 'Copy Endpoint URL'}
              </button>
              <button
                type="button"
                onClick={() =>
                  onOpenQr(`${activeGroup.email} Subscription`, formatUrl, `Format: ${format.toUpperCase()}`)
                }
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-700 transition-colors hover:bg-slate-50 whitespace-nowrap shrink-0 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
              >
                <QrCode className="h-3.5 w-3.5" />
                QR Code
              </button>
              <button
                type="button"
                onClick={handleDownload}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-700 transition-colors hover:bg-slate-50 whitespace-nowrap shrink-0 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
              >
                <Download className="h-3.5 w-3.5" />
                Download
              </button>
            </div>
          </div>

          <div className="mt-4 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-xs text-slate-700 break-all dark:border-slate-800 dark:bg-slate-950 dark:text-slate-300">
            GET {formatUrl}
          </div>

          <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-1 overflow-x-auto rounded-lg border border-slate-200 bg-slate-50 p-1 dark:border-slate-800 dark:bg-slate-950">
              {(
                [
                  { id: 'clash', label: 'Clash Meta' },
                  { id: 'singbox', label: 'Sing-box' },
                  { id: 'xray', label: 'Xray JSON' },
                  { id: 'base64', label: 'v2rayNG' },
                  { id: 'raw', label: 'Raw URIs' },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setFormat(tab.id)}
                  className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                    format === tab.id
                      ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-800 dark:text-slate-100'
                      : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <button
              type="button"
              onClick={() => handleCopy('payload', previewOutput)}
              className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
            >
              {copiedKey === 'payload' ? (
                <Check className="h-3.5 w-3.5 text-emerald-500" />
              ) : (
                <RefreshCw className="h-3.5 w-3.5" />
              )}
              {copiedKey === 'payload' ? 'Copied Payload' : 'Copy Output'}
            </button>
          </div>

          <pre className="mt-3 max-h-[460px] overflow-auto rounded-lg border border-slate-200 bg-slate-50 p-4 font-mono text-xs leading-relaxed text-slate-800 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200">
            {previewOutput}
          </pre>
        </div>
      </div>
    </div>
  );
}
