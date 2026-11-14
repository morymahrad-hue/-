import { useState, type FormEvent } from 'react';
import { Check, Copy, Users, X } from 'lucide-react';
import type { ClientConfig, InboundConfig } from '../lib/protocols';

interface BatchClientModalProps {
  inbound: InboundConfig;
  subPath: string;
  onClose: () => void;
  onCreated: () => Promise<void>;
}

export function BatchClientModal({
  inbound,
  subPath,
  onClose,
  onCreated,
}: BatchClientModalProps) {
  const [prefix, setPrefix] = useState('vip-user');
  const [count, setCount] = useState('5');
  const [totalGb, setTotalGb] = useState('100');
  const [expiryDays, setExpiryDays] = useState('30');
  const [submitting, setSubmitting] = useState(false);
  const [createdClients, setCreatedClients] = useState<ClientConfig[]>([]);
  const [copied, setCopied] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      const days = Number(expiryDays) || 0;
      const res = await fetch('/api/clients/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          inboundId: inbound.id,
          prefix: prefix.trim() || 'user',
          count: Number(count) || 5,
          totalGb: Number(totalGb) || 0,
          expiryTime: days > 0 ? Date.now() + days * 86400000 : 0,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setCreatedClients(data.clients || []);
        await onCreated();
      }
    } finally {
      setSubmitting(false);
    }
  };

  const cleanSubPath = (subPath || '/sub').replace(/\/+$/, '');
  const subLines = createdClients
    .map((c) => `${c.email}: ${window.location.origin}${cleanSubPath}/${c.subId}`)
    .join('\n');

  const handleCopyAll = async () => {
    await navigator.clipboard.writeText(subLines);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/75 p-4 backdrop-blur-xs"
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-lg rounded-xl border border-slate-200 bg-white p-6 shadow-xl dark:border-slate-800 dark:bg-slate-900"
      >
        <div className="flex items-center justify-between border-b border-slate-200 pb-4 dark:border-slate-800">
          <div className="flex items-center gap-2.5">
            <Users className="h-4 w-4 text-orange-500" />
            <div>
              <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                Batch Generate Clients
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {inbound.remark || inbound.tag} · {inbound.protocol.toUpperCase()}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close modal"
            className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {createdClients.length === 0 ? (
          <form onSubmit={handleSubmit} className="mt-5 space-y-4 text-xs">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                  Email / Label Prefix
                </label>
                <input
                  required
                  value={prefix}
                  onChange={(e) => setPrefix(e.target.value)}
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
                />
              </div>
              <div>
                <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                  Client Count (1–50)
                </label>
                <input
                  type="number"
                  min={1}
                  max={50}
                  required
                  value={count}
                  onChange={(e) => setCount(e.target.value)}
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono tabular-nums text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
                />
              </div>
              <div>
                <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                  Quota Per Client (GB)
                </label>
                <input
                  type="number"
                  min={0}
                  value={totalGb}
                  onChange={(e) => setTotalGb(e.target.value)}
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono tabular-nums text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
                />
              </div>
              <div>
                <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                  Expiry (Days, 0 = Never)
                </label>
                <input
                  type="number"
                  min={0}
                  value={expiryDays}
                  onChange={(e) => setExpiryDays(e.target.value)}
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono tabular-nums text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 border-t border-slate-200 pt-4 dark:border-slate-800">
              <button
                type="button"
                onClick={onClose}
                className="rounded-lg border border-slate-200 px-4 py-2 font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="rounded-lg bg-orange-600 px-4 py-2 font-medium text-white hover:bg-orange-500 disabled:opacity-50"
              >
                {submitting ? 'Generating...' : `Create ${count} Clients`}
              </button>
            </div>
          </form>
        ) : (
          <div className="mt-5 space-y-4 text-xs">
            <div className="font-medium text-emerald-600 dark:text-emerald-400">
              Created {createdClients.length} clients with unique subscription tokens.
            </div>
            <pre className="max-h-60 overflow-auto rounded-lg border border-slate-200 bg-slate-50 p-3 font-mono text-[11px] text-slate-800 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200">
              {subLines}
            </pre>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={handleCopyAll}
                className="inline-flex items-center gap-1.5 rounded-lg bg-orange-600 px-4 py-2 font-medium text-white hover:bg-orange-500"
              >
                {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                {copied ? 'Copied All' : 'Copy All Links'}
              </button>
              <button
                type="button"
                onClick={onClose}
                className="rounded-lg border border-slate-200 px-4 py-2 font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
              >
                Done
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
