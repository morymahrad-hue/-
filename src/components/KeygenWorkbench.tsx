import { useState } from 'react';
import { Check, Copy, KeyRound, RefreshCw } from 'lucide-react';
import {
  generateRealityKeypair,
  generateShortId,
  generateSs2022Key,
  generateUuid,
} from '../lib/protocols';

export function KeygenWorkbench() {
  const [reality, setReality] = useState(() => generateRealityKeypair());
  const [uuid, setUuid] = useState(() => generateUuid());
  const [shortId, setShortId] = useState(() => generateShortId(8));
  const [ss128, setSs128] = useState(() => generateSs2022Key(128));
  const [ss256, setSs256] = useState(() => generateSs2022Key(256));
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const regenerateAll = () => {
    setReality(generateRealityKeypair());
    setUuid(generateUuid());
    setShortId(generateShortId(8));
    setSs128(generateSs2022Key(128));
    setSs256(generateSs2022Key(256));
  };

  const copyField = async (id: string, value: string) => {
    await navigator.clipboard.writeText(value);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1600);
  };

  const rows = [
    {
      id: 'reality-pub',
      label: 'Reality X25519 Public Key (pbk)',
      hint: 'Distributed to clients in vless:// links, Clash Meta, and Sing-box configs.',
      value: reality.publicKey,
    },
    {
      id: 'reality-priv',
      label: 'Reality X25519 Private Key',
      hint: 'Kept confidential in inbound server configuration.',
      value: reality.privateKey,
    },
    {
      id: 'short-id',
      label: 'Reality Short ID (sid)',
      hint: '8-byte hex handshake discriminator.',
      value: shortId,
    },
    {
      id: 'uuid',
      label: 'Client UUID v4',
      hint: 'Standard identifier for VLESS, VMess, and TUIC v5 clients.',
      value: uuid,
    },
    {
      id: 'ss128',
      label: 'Shadowsocks 2022-blake3-aes-128-gcm Key',
      hint: '16-byte Base64 pre-shared key.',
      value: ss128,
    },
    {
      id: 'ss256',
      label: 'Shadowsocks 2022-blake3-aes-256-gcm Key',
      hint: '32-byte Base64 pre-shared key.',
      value: ss256,
    },
  ];

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
        <div>
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            Cryptographic Key &amp; Credential Workbench
          </h2>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            Pure RFC 7748 Curve25519 scalar multiplication and Web Crypto CSPRNG running locally with zero external calls.
          </p>
        </div>
        <button
          type="button"
          onClick={regenerateAll}
          className="inline-flex items-center gap-1.5 rounded-lg bg-orange-600 px-4 py-2 text-xs font-medium text-white transition-colors hover:bg-orange-500 whitespace-nowrap shrink-0"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Rotate All Credentials
        </button>
      </div>

      <div className="divide-y divide-slate-200 rounded-xl border border-slate-200 bg-white dark:divide-slate-800 dark:border-slate-800 dark:bg-slate-900">
        {rows.map((row) => (
          <div
            key={row.id}
            className="flex flex-col justify-between gap-3 p-5 sm:flex-row sm:items-center"
          >
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 text-xs font-medium text-slate-900 dark:text-slate-100">
                <KeyRound className="h-3.5 w-3.5 text-slate-400 shrink-0" />
                <span>{row.label}</span>
              </div>
              <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{row.hint}</p>
              <div className="mt-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-xs text-slate-800 break-all dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200">
                {row.value}
              </div>
            </div>
            <button
              type="button"
              onClick={() => copyField(row.id, row.value)}
              className="inline-flex items-center gap-1.5 self-start rounded-lg border border-slate-200 px-3 py-2 text-xs font-medium text-slate-700 transition-colors hover:bg-slate-50 whitespace-nowrap shrink-0 sm:self-center dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
            >
              {copiedId === row.id ? (
                <Check className="h-3.5 w-3.5 text-emerald-500" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
              {copiedId === row.id ? 'Copied' : 'Copy'}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
