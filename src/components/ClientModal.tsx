import { useState, type FormEvent } from 'react';
import { RefreshCw, X } from 'lucide-react';
import type { ClientConfig, InboundConfig } from '../lib/protocols';
import { generatePassword, generateSs2022Key, generateSubId, generateUuid } from '../lib/protocols';

interface ClientModalProps {
  inbound: InboundConfig;
  initial?: ClientConfig | null;
  onClose: () => void;
  onSave: (payload: Partial<ClientConfig>, existingId?: string) => Promise<void>;
}

export function ClientModal({ inbound, initial, onClose, onSave }: ClientModalProps) {
  const defaultCred = () => {
    if (inbound.protocol === 'shadowsocks') {
      return inbound.ssMethod.includes('2022')
        ? generateSs2022Key(inbound.ssMethod.includes('256') ? 256 : 128)
        : generatePassword(20);
    }
    if (inbound.protocol === 'trojan' || inbound.protocol === 'hysteria2') {
      return generatePassword(20);
    }
    return generateUuid();
  };

  const [email, setEmail] = useState(initial?.email || '');
  const [credential, setCredential] = useState(initial?.credential || defaultCred());
  const [secondaryPassword, setSecondaryPassword] = useState(
    initial?.secondaryPassword || (inbound.protocol === 'tuic' ? generatePassword(16) : '')
  );
  const [subId, setSubId] = useState(initial?.subId || generateSubId());
  const [totalGb, setTotalGb] = useState(String(initial?.totalGb ?? 100));
  const [expiryDate, setExpiryDate] = useState(
    initial?.expiryTime && initial.expiryTime > 0
      ? new Date(initial.expiryTime).toISOString().slice(0, 10)
      : new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10)
  );
  const [neverExpires, setNeverExpires] = useState(initial ? initial.expiryTime === 0 : false);
  const [saving, setSaving] = useState(false);

  const setPresetDays = (days: number) => {
    setNeverExpires(false);
    setExpiryDate(new Date(Date.now() + days * 86400000).toISOString().slice(0, 10));
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const expiryTime = neverExpires ? 0 : new Date(`${expiryDate}T23:59:59Z`).getTime();
      await onSave(
        {
          inboundId: inbound.id,
          email: email.trim(),
          credential: credential.trim(),
          secondaryPassword: secondaryPassword.trim(),
          subId: subId.trim(),
          totalGb: Number(totalGb) || 0,
          expiryTime,
        },
        initial?.id
      );
      onClose();
    } finally {
      setSaving(false);
    }
  };

  const credLabel =
    inbound.protocol === 'vless' || inbound.protocol === 'vmess' || inbound.protocol === 'tuic'
      ? 'Client UUID'
      : 'Password / Key';

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/75 p-4 backdrop-blur-xs"
      onClick={onClose}
    >
      <form
        onSubmit={handleSubmit}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-lg rounded-xl border border-slate-200 bg-white p-6 shadow-xl dark:border-slate-800 dark:bg-slate-900"
      >
        <div className="flex items-center justify-between border-b border-slate-200 pb-4 dark:border-slate-800">
          <div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              {initial ? 'Edit Client' : 'Add Client'}
            </h2>
            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
              {inbound.remark || inbound.tag} · {inbound.protocol.toUpperCase()} : {inbound.port}
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

        <div className="mt-5 space-y-4 text-xs">
          <div>
            <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
              Client Email / Remark
            </label>
            <input
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="alex@team.dev"
              className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
            />
          </div>

          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <label className="font-medium text-slate-700 dark:text-slate-300">{credLabel}</label>
              <button
                type="button"
                onClick={() => setCredential(defaultCred())}
                className="inline-flex items-center gap-1 text-orange-600 hover:text-orange-500 dark:text-orange-400"
              >
                <RefreshCw className="h-3 w-3" />
                Regenerate
              </button>
            </div>
            <input
              required
              value={credential}
              onChange={(e) => setCredential(e.target.value)}
              className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
            />
          </div>

          {inbound.protocol === 'tuic' && (
            <div>
              <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                TUIC Password
              </label>
              <input
                required
                value={secondaryPassword}
                onChange={(e) => setSecondaryPassword(e.target.value)}
                className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
              />
            </div>
          )}

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                Subscription Group ID
              </label>
              <input
                required
                value={subId}
                onChange={(e) => setSubId(e.target.value)}
                className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
              />
              <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
                Reuse an ID across inbounds to bundle nodes into one link.
              </p>
            </div>

            <div>
              <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
                Traffic Quota (GB, 0 = Unlimited)
              </label>
              <input
                type="number"
                min={0}
                step={1}
                value={totalGb}
                onChange={(e) => setTotalGb(e.target.value)}
                className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono tabular-nums text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
              />
            </div>
          </div>

          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <label className="font-medium text-slate-700 dark:text-slate-300">Expiry Date</label>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setPresetDays(30)}
                  className="text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
                >
                  +30d
                </button>
                <button
                  type="button"
                  onClick={() => setPresetDays(90)}
                  className="text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
                >
                  +90d
                </button>
                <button
                  type="button"
                  onClick={() => setNeverExpires(true)}
                  className={`${
                    neverExpires
                      ? 'font-semibold text-orange-600 dark:text-orange-400'
                      : 'text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'
                  }`}
                >
                  Never
                </button>
              </div>
            </div>
            <input
              type="date"
              disabled={neverExpires}
              value={expiryDate}
              onChange={(e) => {
                setNeverExpires(false);
                setExpiryDate(e.target.value);
              }}
              className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 disabled:opacity-50 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
            />
          </div>
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
            {saving ? 'Saving...' : initial ? 'Update Client' : 'Add Client'}
          </button>
        </div>
      </form>
    </div>
  );
}
