import { useEffect, useState, type ChangeEvent } from 'react';
import { Check, Download, RefreshCw, Upload } from 'lucide-react';
import type { AccessLogEntry } from '../lib/protocols';

interface BackupAndLogsViewProps {
  onRestored: () => Promise<void>;
}

export function BackupAndLogsView({ onRestored }: BackupAndLogsViewProps) {
  const [logs, setLogs] = useState<AccessLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/logs');
      const data = await res.json();
      setLogs(data.logs || []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const handleExportBackup = async () => {
    const res = await fetch('/api/backup');
    const data = await res.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `edgepanel-backup-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setStatusMsg('Backup JSON downloaded');
    setTimeout(() => setStatusMsg(null), 2200);
  };

  const handleRestoreFile = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const res = await fetch('/api/backup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(parsed),
      });
      if (!res.ok) throw new Error('Restore failed');
      setStatusMsg('Database restored from JSON snapshot');
      await onRestored();
    } catch {
      setStatusMsg('Invalid backup JSON file');
    } finally {
      e.target.value = '';
      setTimeout(() => setStatusMsg(null), 2500);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
        <div>
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            Snapshot Backup &amp; Restore
          </h2>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            Export all inbounds, clients, clean endpoints, and routing settings as portable JSON, or restore into D1/KV anytime.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {statusMsg && (
            <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-600 dark:text-emerald-400">
              <Check className="h-3.5 w-3.5" />
              {statusMsg}
            </span>
          )}
          <button
            type="button"
            onClick={handleExportBackup}
            className="inline-flex items-center gap-1.5 rounded-lg bg-orange-600 px-3.5 py-2 text-xs font-medium text-white transition-colors hover:bg-orange-500 whitespace-nowrap"
          >
            <Download className="h-3.5 w-3.5" />
            Export Backup JSON
          </button>
          <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-slate-200 px-3.5 py-2 text-xs font-medium text-slate-700 transition-colors hover:bg-slate-50 whitespace-nowrap dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800">
            <Upload className="h-3.5 w-3.5" />
            Restore JSON
            <input type="file" accept=".json,application/json" onChange={handleRestoreFile} className="hidden" />
          </label>
        </div>
      </div>

      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3.5 dark:border-slate-800">
          <div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Subscription &amp; Edge Access Logs
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Tracks client subscription pulls, requested formats, and Cloudflare edge country codes.
            </p>
          </div>
          <button
            type="button"
            onClick={fetchLogs}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-800 dark:bg-slate-950/60 dark:text-slate-400">
              <tr>
                <th className="px-5 py-2.5 font-medium">Timestamp</th>
                <th className="px-5 py-2.5 font-medium">Client</th>
                <th className="px-5 py-2.5 font-medium">Format</th>
                <th className="px-5 py-2.5 font-medium">Country / IP</th>
                <th className="px-5 py-2.5 font-medium">User-Agent</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {loading ? (
                <tr>
                  <td colSpan={5} className="px-5 py-6 text-slate-500">
                    Loading logs...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-5 py-6 text-center text-slate-500">
                    No subscription fetches recorded yet.
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                    <td className="px-5 py-3 font-mono tabular-nums text-slate-500 dark:text-slate-400 whitespace-nowrap">
                      {new Date(log.timestamp).toISOString().slice(0, 19).replace('T', ' ')}
                    </td>
                    <td className="px-5 py-3 font-medium text-slate-900 dark:text-slate-100">
                      {log.clientEmail || log.subId}
                    </td>
                    <td className="px-5 py-3 font-mono text-orange-600 dark:text-orange-400">
                      {log.format.toUpperCase()}
                    </td>
                    <td className="px-5 py-3 font-mono tabular-nums text-slate-600 dark:text-slate-300 whitespace-nowrap">
                      {log.country || '—'} · {log.ip}
                    </td>
                    <td className="max-w-xs truncate px-5 py-3 font-mono text-slate-500 dark:text-slate-400">
                      {log.userAgent || '—'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
