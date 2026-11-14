import { useEffect, useState } from 'react';
import { Check, Copy, Download, FileCode2, FolderGit2 } from 'lucide-react';

interface DeliverableFile {
  path: string;
  content: string;
}

export function WorkerDeliverables() {
  const [files, setFiles] = useState<DeliverableFile[]>([]);
  const [selectedPath, setSelectedPath] = useState<string>('wrangler.toml');
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    fetch('/api/deliverables')
      .then((r) => r.json())
      .then((data) => {
        const list = (data.files || []) as DeliverableFile[];
        setFiles(list);
        if (list.length > 0) setSelectedPath(list[0].path);
      })
      .finally(() => setLoading(false));
  }, []);

  const activeFile = files.find((f) => f.path === selectedPath);

  const handleCopy = async () => {
    if (!activeFile) return;
    await navigator.clipboard.writeText(activeFile.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  const handleDownload = (file: DeliverableFile) => {
    const blob = new Blob([file.content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = file.path.split('/').pop() || 'file.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Cloudflare Workers GitHub Repository
            </h2>
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
              Zero-VPS ES Module bundle ready for Git-to-Workers automatic deployment. All source files are located in{' '}
              <code className="font-mono text-slate-800 dark:text-slate-200">cloudflare-worker/</code>.
            </p>
          </div>
          <div className="text-xs font-mono text-slate-500 dark:text-slate-400">
            D1 SQLite · Workers KV · Web Crypto HMAC · Tailwind CDN
          </div>
        </div>

        <div className="mt-4 grid grid-cols-1 gap-3 border-t border-slate-200 pt-4 text-xs sm:grid-cols-4 dark:border-slate-800">
          <div>
            <div className="font-semibold text-slate-900 dark:text-slate-100">01. Create Storage</div>
            <div className="mt-1 font-mono text-[11px] text-slate-500 dark:text-slate-400">
              npx wrangler d1 create edgepanel-db
            </div>
          </div>
          <div>
            <div className="font-semibold text-slate-900 dark:text-slate-100">02. Push to GitHub</div>
            <div className="mt-1 font-mono text-[11px] text-slate-500 dark:text-slate-400">
              git push origin main
            </div>
          </div>
          <div>
            <div className="font-semibold text-slate-900 dark:text-slate-100">03. Connect Git</div>
            <div className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
              Workers &amp; Pages -&gt; Import Repository
            </div>
          </div>
          <div>
            <div className="font-semibold text-slate-900 dark:text-slate-100">04. Add Secrets</div>
            <div className="mt-1 font-mono text-[11px] text-slate-500 dark:text-slate-400">
              ADMIN_USERNAME, ADMIN_PASSWORD
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <div className="lg:col-span-3">
          <div className="rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
            <div className="flex items-center gap-2 border-b border-slate-200 px-4 py-3 text-xs font-semibold text-slate-900 dark:border-slate-800 dark:text-slate-100">
              <FolderGit2 className="h-4 w-4 text-orange-500" />
              Repository Files
            </div>
            <div className="divide-y divide-slate-200 dark:divide-slate-800">
              {loading ? (
                <div className="p-4 text-xs text-slate-500">Loading repository files...</div>
              ) : (
                files.map((f) => {
                  const active = f.path === selectedPath;
                  return (
                    <button
                      key={f.path}
                      type="button"
                      onClick={() => setSelectedPath(f.path)}
                      className={`flex w-full items-center gap-2.5 px-4 py-2.5 text-left font-mono text-xs transition-colors ${
                        active
                          ? 'bg-orange-500/10 font-medium text-orange-600 dark:text-orange-400'
                          : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800/40 dark:hover:text-slate-100'
                      }`}
                    >
                      <FileCode2 className="h-3.5 w-3.5 shrink-0" />
                      <span className="truncate">{f.path}</span>
                    </button>
                  );
                })
              )}
            </div>
          </div>
        </div>

        <div className="lg:col-span-9">
          <div className="rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
            <div className="flex items-center justify-between border-b border-slate-200 px-4 py-3 dark:border-slate-800">
              <div className="font-mono text-xs font-medium text-slate-900 dark:text-slate-100">
                cloudflare-worker/{activeFile?.path || ''}
              </div>
              {activeFile && (
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleCopy}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-700 transition-colors hover:bg-slate-50 whitespace-nowrap shrink-0 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                  >
                    {copied ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
                    {copied ? 'Copied' : 'Copy File'}
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDownload(activeFile)}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-orange-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-orange-500 whitespace-nowrap shrink-0"
                  >
                    <Download className="h-3.5 w-3.5" />
                    Download
                  </button>
                </div>
              )}
            </div>
            <pre className="max-h-[560px] overflow-auto p-4 font-mono text-xs leading-relaxed text-slate-800 dark:text-slate-200">
              {activeFile?.content || ''}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
