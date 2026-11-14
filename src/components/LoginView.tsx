import { useState, type FormEvent } from 'react';
import { Lock } from 'lucide-react';

interface LoginViewProps {
  hint?: { username: string; password: string };
  onSuccess: () => Promise<void>;
}

export function LoginView({ hint, onSuccess }: LoginViewProps) {
  const [username, setUsername] = useState(hint?.username || 'admin');
  const [password, setPassword] = useState(hint?.password || '');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error || 'Authentication failed');
        return;
      }
      await onSuccess();
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50 p-6 dark:bg-slate-950">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900"
      >
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-orange-600 text-white">
            <Lock className="h-4 w-4" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              EdgePanel Admin
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              HMAC-SHA256 Signed Session Gate
            </p>
          </div>
        </div>

        <div className="mt-5 space-y-3 text-xs">
          <div>
            <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
              Admin Username
            </label>
            <input
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
            />
          </div>
          <div>
            <label className="mb-1.5 block font-medium text-slate-700 dark:text-slate-300">
              Admin Password
            </label>
            <input
              required
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-slate-900 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
            />
          </div>
        </div>

        {hint && (
          <div className="mt-3 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-[11px] text-slate-600 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-400">
            Preview env: {hint.username} / {hint.password}
          </div>
        )}

        {error && (
          <div className="mt-3 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-600 dark:text-rose-400">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={submitting}
          className="mt-5 w-full rounded-lg bg-orange-600 px-4 py-2.5 text-xs font-medium text-white transition-colors hover:bg-orange-500 disabled:opacity-50"
        >
          {submitting ? 'Verifying...' : 'Sign In'}
        </button>
      </form>
    </div>
  );
}
