import { useState, type FormEvent } from 'react';
import { Check } from 'lucide-react';
import type { PanelSettings } from '../lib/protocols';

interface SettingsViewProps {
  settings: PanelSettings;
  onSave: (next: Partial<PanelSettings>) => Promise<void>;
}

export function SettingsView({ settings, onSave }: SettingsViewProps) {
  const [panelTitle, setPanelTitle] = useState(settings.panelTitle);
  const [edgeDomain, setEdgeDomain] = useState(settings.edgeDomain);
  const [subPath, setSubPath] = useState(settings.subPath);
  const [defaultSni, setDefaultSni] = useState(settings.defaultSni);
  const [defaultFingerprint, setDefaultFingerprint] = useState(settings.defaultFingerprint);
  const [clashMixedPort, setClashMixedPort] = useState(String(settings.clashMixedPort));
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await onSave({
        panelTitle: panelTitle.trim() || 'EdgePanel',
        edgeDomain: edgeDomain.trim(),
        subPath: subPath.trim() || '/sub',
        defaultSni: defaultSni.trim() || 'www.cloudflare.com',
        defaultFingerprint,
        clashMixedPort: Number(clashMixedPort) || 7890,
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } finally {
      setSaving(false);
    }
  };

  return (
    <form
      onSubmit={handleSubmit}
      className="max-w-2xl rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-slate-900"
    >
      <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
        Panel &amp; Subscription Defaults
      </h2>
      <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
        Configure default edge hostname, subscription routing prefix, and generated client profile parameters.
      </p>

      <div className="mt-5 grid grid-cols-1 gap-4 text-xs sm:grid-cols-2">
        <div>
          <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
            Panel Name
          </label>
          <input
            value={panelTitle}
            onChange={(e) => setPanelTitle(e.target.value)}
            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
          />
        </div>
        <div>
          <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
            Default Edge Domain
          </label>
          <input
            value={edgeDomain}
            onChange={(e) => setEdgeDomain(e.target.value)}
            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
          />
        </div>
        <div>
          <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
            Subscription Route Path
          </label>
          <input
            value={subPath}
            onChange={(e) => setSubPath(e.target.value)}
            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
          />
        </div>
        <div>
          <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
            Default Reality / TLS SNI
          </label>
          <input
            value={defaultSni}
            onChange={(e) => setDefaultSni(e.target.value)}
            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
          />
        </div>
        <div>
          <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
            Default uTLS Fingerprint
          </label>
          <select
            value={defaultFingerprint}
            onChange={(e) => setDefaultFingerprint(e.target.value)}
            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
          >
            <option value="chrome">chrome</option>
            <option value="firefox">firefox</option>
            <option value="safari">safari</option>
            <option value="ios">ios</option>
          </select>
        </div>
        <div>
          <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
            Clash Meta Mixed Port
          </label>
          <input
            type="number"
            value={clashMixedPort}
            onChange={(e) => setClashMixedPort(e.target.value)}
            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono tabular-nums text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
          />
        </div>
      </div>

      <div className="mt-6 flex items-center justify-end gap-3 border-t border-slate-200 pt-4 dark:border-slate-800">
        {saved && (
          <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-600 dark:text-emerald-400">
            <Check className="h-3.5 w-3.5" />
            Saved
          </span>
        )}
        <button
          type="submit"
          disabled={saving}
          className="rounded-lg bg-orange-600 px-4 py-2 text-xs font-medium text-white transition-colors hover:bg-orange-500 disabled:opacity-50 whitespace-nowrap shrink-0"
        >
          {saving ? 'Saving...' : 'Save Settings'}
        </button>
      </div>
    </form>
  );
}
