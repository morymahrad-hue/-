import { useCallback, useEffect, useState } from 'react';
import {
  Check,
  CheckCircle2,
  Clock,
  Copy,
  DatabaseBackup,
  Edit3,
  FolderGit2,
  KeyRound,
  Link2,
  LogOut,
  Menu,
  Moon,
  Network,
  Plus,
  Power,
  QrCode,
  RotateCcw,
  Search,
  Server,
  Settings as SettingsIcon,
  Sliders,
  Sun,
  Trash2,
  UserPlus,
  Users,
  X,
  XCircle,
} from 'lucide-react';
import { BackupAndLogsView } from './components/BackupAndLogsView';
import { BatchClientModal } from './components/BatchClientModal';
import { ClientModal } from './components/ClientModal';
import { EndpointsAndRoutingView } from './components/EndpointsAndRoutingView';
import { InboundModal } from './components/InboundModal';
import { KeygenWorkbench } from './components/KeygenWorkbench';
import { LoginView } from './components/LoginView';
import { QrModal } from './components/QrModal';
import { SettingsView } from './components/SettingsView';
import { SubscriptionInspector } from './components/SubscriptionInspector';
import { WorkerDeliverables } from './components/WorkerDeliverables';
import {
  buildClientUri,
  formatBytes,
  formatExpiry,
  type CleanEndpoint,
  type ClientConfig,
  type InboundConfig,
  type InboundWithClients,
  type OverviewStats,
  type PanelSettings,
  type ProtocolType,
} from './lib/protocols';

type NavTab =
  | 'inbounds'
  | 'subscriptions'
  | 'routing'
  | 'keygen'
  | 'backup'
  | 'deliverables'
  | 'settings';

type Lang = 'en' | 'fa';

const LABELS: Record<
  Lang,
  {
    nav: Record<NavTab, string>;
    newInbound: string;
    activeInbounds: string;
    clients: string;
    traffic: string;
    cleanIps: string;
    addClient: string;
    batch: string;
    signOut: string;
    searchPlaceholder: string;
  }
> = {
  en: {
    nav: {
      inbounds: 'Inbounds & Clients',
      subscriptions: 'Subscriptions',
      routing: 'Relay, Clean IPs & Fragment',
      keygen: 'Key & Config Tools',
      backup: 'Backup & Access Logs',
      deliverables: 'Worker Repository',
      settings: 'Settings',
    },
    newInbound: 'New Inbound',
    activeInbounds: 'Active Inbounds',
    clients: 'Provisioned Clients',
    traffic: 'Aggregate Traffic',
    cleanIps: 'Clean Edge IPs',
    addClient: 'Add Client',
    batch: 'Batch',
    signOut: 'Sign Out',
    searchPlaceholder: 'Filter by remark, protocol, or client...',
  },
  fa: {
    nav: {
      inbounds: 'ورودی‌ها و کاربران',
      subscriptions: 'لینک‌های اشتراک',
      routing: 'رله ورکر، آی‌پی تمیز و فرگمنت',
      keygen: 'تولید کلید و UUID',
      backup: 'بکاپ و گزارش اتصال',
      deliverables: 'سورس ورکر و استقرار',
      settings: 'تنظیمات پنل',
    },
    newInbound: 'ورودی جدید',
    activeInbounds: 'ورودی‌های فعال',
    clients: 'کاربران ثبت‌شده',
    traffic: 'حجم مصرفی کل',
    cleanIps: 'آی‌پی‌های تمیز فعال',
    addClient: 'افزودن کاربر',
    batch: 'ساخت گروهی',
    signOut: 'خروج',
    searchPlaceholder: 'جستجو بر اساس نام، پروتکل یا کاربر...',
  },
};

const NAV_ORDER: Array<{ id: NavTab; icon: typeof Server }> = [
  { id: 'inbounds', icon: Server },
  { id: 'subscriptions', icon: Link2 },
  { id: 'routing', icon: Network },
  { id: 'keygen', icon: KeyRound },
  { id: 'backup', icon: DatabaseBackup },
  { id: 'deliverables', icon: FolderGit2 },
  { id: 'settings', icon: SettingsIcon },
];

const PROTOCOL_FILTERS: Array<{ id: 'all' | ProtocolType; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'vless', label: 'VLESS' },
  { id: 'vmess', label: 'VMess' },
  { id: 'trojan', label: 'Trojan' },
  { id: 'shadowsocks', label: 'Shadowsocks' },
  { id: 'tuic', label: 'TUIC' },
  { id: 'hysteria2', label: 'Hysteria2' },
];

export default function App() {
  const [dark, setDark] = useState(true);
  const [lang, setLang] = useState<Lang>('en');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<NavTab>('inbounds');

  const [authChecked, setAuthChecked] = useState(false);
  const [authenticated, setAuthenticated] = useState(true);
  const [username, setUsername] = useState('admin');
  const [previewHint, setPreviewHint] = useState<{ username: string; password: string } | undefined>();

  const [loading, setLoading] = useState(true);
  const [inbounds, setInbounds] = useState<InboundWithClients[]>([]);
  const [endpoints, setEndpoints] = useState<CleanEndpoint[]>([]);
  const [overview, setOverview] = useState<OverviewStats | null>(null);
  const [settings, setSettings] = useState<PanelSettings>({
    panelTitle: 'EdgePanel',
    edgeDomain: typeof window !== 'undefined' ? window.location.hostname : 'edge.example.com',
    subPath: '/sub',
    defaultSni: 'www.cloudflare.com',
    defaultFingerprint: 'chrome',
    allowInsecureTls: false,
    clashMixedPort: 7890,
    workerRelayEnabled: true,
    workerRelayPath: '/edge-ws',
    workerProxyIp: '',
    fragmentEnabled: true,
    fragmentPackets: 'tlshello',
    fragmentLength: '100-200',
    fragmentInterval: '10-20',
    muxEnabled: false,
    muxConcurrency: 4,
    bypassCountry: 'ir',
    blockAds: true,
    dnsServer: 'https://1.1.1.1/dns-query',
  });

  const [protocolFilter, setProtocolFilter] = useState<'all' | ProtocolType>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const [inboundModal, setInboundModal] = useState<{ open: boolean; editing?: InboundConfig | null }>({
    open: false,
  });
  const [clientModal, setClientModal] = useState<{
    open: boolean;
    inbound?: InboundConfig;
    editing?: ClientConfig | null;
  }>({ open: false });
  const [batchModal, setBatchModal] = useState<{ open: boolean; inbound?: InboundConfig }>({
    open: false,
  });
  const [qrModal, setQrModal] = useState<{ title: string; subtitle?: string; value: string } | null>(
    null
  );
  const [toast, setToast] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    const root = document.documentElement;
    if (dark) root.classList.add('dark');
    else root.classList.remove('dark');
  }, [dark]);

  const notify = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast((curr) => (curr === msg ? null : curr)), 2600);
  };

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const sessionRes = await fetch('/api/auth/session');
      const sessionData = await sessionRes.json();
      setPreviewHint(sessionData.previewHint);
      if (!sessionData.authenticated) {
        setAuthenticated(false);
        setAuthChecked(true);
        return;
      }
      setAuthenticated(true);
      setUsername(sessionData.username || 'admin');
      setAuthChecked(true);

      const [ovRes, inbRes, epRes, setRes] = await Promise.all([
        fetch('/api/overview'),
        fetch('/api/inbounds'),
        fetch('/api/endpoints'),
        fetch('/api/settings'),
      ]);
      if (ovRes.status === 401 || inbRes.status === 401) {
        setAuthenticated(false);
        return;
      }
      const [ovData, inbData, epData, setData] = await Promise.all([
        ovRes.json(),
        inbRes.json(),
        epRes.json(),
        setRes.json(),
      ]);
      setOverview(ovData);
      setInbounds(inbData.inbounds || []);
      setEndpoints(epData.endpoints || []);
      if (setData.settings) setSettings(setData.settings);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  const handleLogout = async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    setAuthenticated(false);
  };

  const handleSaveInbound = async (payload: Partial<InboundConfig>, existingId?: string) => {
    const url = existingId ? `/api/inbounds/${existingId}` : '/api/inbounds';
    const method = existingId ? 'PUT' : 'POST';
    const res = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      notify(err.error || 'Failed to save inbound');
      return;
    }
    notify(existingId ? 'Inbound updated' : 'Inbound created');
    await fetchAll();
  };

  const handleToggleInbound = async (inbound: InboundConfig) => {
    await fetch(`/api/inbounds/${inbound.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !inbound.enabled }),
    });
    notify(inbound.enabled ? 'Inbound disabled' : 'Inbound enabled');
    await fetchAll();
  };

  const handleDeleteInbound = async (id: string) => {
    await fetch(`/api/inbounds/${id}`, { method: 'DELETE' });
    notify('Inbound removed');
    await fetchAll();
  };

  const handleSaveClient = async (payload: Partial<ClientConfig>, existingId?: string) => {
    const url = existingId ? `/api/clients/${existingId}` : '/api/clients';
    const method = existingId ? 'PUT' : 'POST';
    const res = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      notify(err.error || 'Failed to save client');
      return;
    }
    notify(existingId ? 'Client updated' : 'Client added');
    await fetchAll();
  };

  const handleToggleClient = async (client: ClientConfig) => {
    await fetch(`/api/clients/${client.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !client.enabled }),
    });
    notify(client.enabled ? 'Client suspended' : 'Client enabled');
    await fetchAll();
  };

  const handleResetTraffic = async (id: string) => {
    await fetch(`/api/clients/${id}/reset-traffic`, { method: 'POST' });
    notify('Traffic counters reset');
    await fetchAll();
  };

  const handleDeleteClient = async (id: string) => {
    await fetch(`/api/clients/${id}`, { method: 'DELETE' });
    notify('Client deleted');
    await fetchAll();
  };

  const handleSaveSettings = async (next: Partial<PanelSettings>) => {
    const res = await fetch('/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(next),
    });
    if (res.ok) {
      const data = await res.json();
      setSettings(data.settings);
      notify('Settings saved');
    }
  };

  const copyString = async (key: string, text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedId(key);
    notify(label);
    setTimeout(() => setCopiedId((curr) => (curr === key ? null : curr)), 1600);
  };

  if (authChecked && !authenticated) {
    return <LoginView hint={previewHint} onSuccess={fetchAll} />;
  }

  const t = LABELS[lang];
  const filteredInbounds = inbounds.filter((inb) => {
    if (protocolFilter !== 'all' && inb.protocol !== protocolFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase();
      const inboundHit = `${inb.remark} ${inb.tag} ${inb.protocol} ${inb.serverAddress} ${inb.port}`
        .toLowerCase()
        .includes(q);
      const clientHit = inb.clients.some(
        (c) => c.email.toLowerCase().includes(q) || c.subId.toLowerCase().includes(q)
      );
      return inboundHit || clientHit;
    }
    return true;
  });

  const totalBytes = (overview?.totalUpBytes || 0) + (overview?.totalDownBytes || 0);

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
      <div className="flex min-h-screen">
        {/* Desktop Sidebar */}
        <aside className="hidden w-64 shrink-0 flex-col border-r border-slate-200 bg-white lg:flex dark:border-slate-800 dark:bg-slate-900">
          <div className="flex h-14 items-center border-b border-slate-200 px-5 dark:border-slate-800">
            <span className="font-display text-base font-bold tracking-tight text-slate-900 whitespace-nowrap dark:text-slate-100">
              {settings.panelTitle || 'EdgePanel'}
            </span>
          </div>

          <nav className="flex-1 space-y-1 p-3">
            {NAV_ORDER.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveTab(item.id)}
                  className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-xs font-medium transition-colors whitespace-nowrap ${
                    isActive
                      ? 'bg-orange-500/10 text-orange-600 dark:text-orange-400'
                      : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800/60 dark:hover:text-slate-100'
                  }`}
                >
                  <Icon className="h-4 w-4 shrink-0" />
                  <span className="truncate">{t.nav[item.id]}</span>
                </button>
              );
            })}
          </nav>

          <div className="border-t border-slate-200 p-4 dark:border-slate-800">
            <div className="flex items-center justify-between gap-2">
              <div className="min-w-0">
                <div className="truncate text-xs font-medium text-slate-900 dark:text-slate-100">
                  {username}
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400">Administrator</div>
              </div>
              <button
                type="button"
                onClick={handleLogout}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs font-medium text-slate-600 transition-colors hover:bg-slate-50 hover:text-slate-900 whitespace-nowrap shrink-0 dark:border-slate-700 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100"
              >
                <LogOut className="h-3.5 w-3.5" />
                {t.signOut}
              </button>
            </div>
          </div>
        </aside>

        {/* Mobile Drawer */}
        {mobileMenuOpen && (
          <div
            className="fixed inset-0 z-40 bg-slate-950/60 lg:hidden"
            onClick={() => setMobileMenuOpen(false)}
          >
            <aside
              className="flex h-full w-64 flex-col border-r border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex h-14 items-center justify-between border-b border-slate-200 px-5 dark:border-slate-800">
                <span className="font-display text-base font-bold text-slate-900 dark:text-slate-100">
                  {settings.panelTitle || 'EdgePanel'}
                </span>
                <button
                  type="button"
                  onClick={() => setMobileMenuOpen(false)}
                  className="rounded-lg p-1 text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
              <nav className="flex-1 space-y-1 p-3">
                {NAV_ORDER.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => {
                        setActiveTab(item.id);
                        setMobileMenuOpen(false);
                      }}
                      className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-xs font-medium transition-colors ${
                        isActive
                          ? 'bg-orange-500/10 text-orange-600 dark:text-orange-400'
                          : 'text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800/60'
                      }`}
                    >
                      <Icon className="h-4 w-4 shrink-0" />
                      <span>{t.nav[item.id]}</span>
                    </button>
                  );
                })}
              </nav>
            </aside>
          </div>
        )}

        {/* Main Workspace */}
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="flex h-14 items-center justify-between gap-8 border-b border-slate-200 bg-white px-4 sm:px-6 dark:border-slate-800 dark:bg-slate-900">
            <div className="flex min-w-0 items-center gap-3">
              <button
                type="button"
                onClick={() => setMobileMenuOpen(true)}
                aria-label="Open navigation"
                className="rounded-lg p-1.5 text-slate-600 hover:bg-slate-100 lg:hidden dark:text-slate-400 dark:hover:bg-slate-800"
              >
                <Menu className="h-4 w-4" />
              </button>
              <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                <span className="hidden sm:inline whitespace-nowrap">{settings.panelTitle}</span>
                <span className="hidden sm:inline" aria-hidden="true">
                  /
                </span>
                <span className="truncate font-medium text-slate-900 dark:text-slate-100">
                  {t.nav[activeTab]}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => setLang((l) => (l === 'en' ? 'fa' : 'en'))}
                className="rounded-lg border border-slate-200 px-2.5 py-1.5 font-mono text-xs font-medium text-slate-600 transition-colors hover:bg-slate-50 hover:text-slate-900 whitespace-nowrap dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
              >
                {lang === 'en' ? 'FA' : 'EN'}
              </button>
              <button
                type="button"
                onClick={() => setDark((d) => !d)}
                aria-label="Toggle theme"
                className="rounded-lg border border-slate-200 p-2 text-slate-600 transition-colors hover:bg-slate-50 hover:text-slate-900 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
              >
                {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
              </button>
              <button
                type="button"
                onClick={() => setInboundModal({ open: true, editing: null })}
                className="inline-flex items-center gap-1.5 rounded-lg bg-orange-600 px-3.5 py-2 text-xs font-medium text-white transition-colors hover:bg-orange-500 whitespace-nowrap shrink-0"
              >
                <Plus className="h-3.5 w-3.5" />
                {t.newInbound}
              </button>
            </div>
          </header>

          <main className="mx-auto w-full max-w-7xl flex-1 space-y-6 p-4 sm:p-6">
            {activeTab === 'inbounds' && (
              <>
                <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
                  <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
                    <div className="text-xs text-slate-500 dark:text-slate-400">
                      {t.activeInbounds}
                    </div>
                    <div className="mt-1.5 font-display text-2xl font-semibold tabular-nums text-slate-900 dark:text-slate-100">
                      {overview ? `${overview.activeInbounds} / ${overview.totalInbounds}` : '—'}
                    </div>
                  </div>
                  <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
                    <div className="text-xs text-slate-500 dark:text-slate-400">{t.clients}</div>
                    <div className="mt-1.5 font-display text-2xl font-semibold tabular-nums text-slate-900 dark:text-slate-100">
                      {overview ? `${overview.activeClients} / ${overview.totalClients}` : '—'}
                    </div>
                  </div>
                  <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
                    <div className="text-xs text-slate-500 dark:text-slate-400">{t.traffic}</div>
                    <div className="mt-1.5 font-display text-2xl font-semibold tabular-nums text-slate-900 dark:text-slate-100">
                      {overview ? formatBytes(totalBytes) : '—'}
                    </div>
                  </div>
                  <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
                    <div className="text-xs text-slate-500 dark:text-slate-400">{t.cleanIps}</div>
                    <div className="mt-1.5 font-display text-2xl font-semibold tabular-nums text-slate-900 dark:text-slate-100">
                      {overview ? overview.cleanEndpointsCount : '—'}
                    </div>
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-4">
                  <div className="flex items-center gap-1 overflow-x-auto rounded-lg border border-slate-200 bg-white p-1 dark:border-slate-800 dark:bg-slate-900">
                    {PROTOCOL_FILTERS.map((f) => (
                      <button
                        key={f.id}
                        type="button"
                        onClick={() => setProtocolFilter(f.id)}
                        className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                          protocolFilter === f.id
                            ? 'bg-slate-900 text-white dark:bg-slate-800 dark:text-slate-100'
                            : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'
                        }`}
                      >
                        {f.label}
                      </button>
                    ))}
                  </div>

                  <div className="relative w-full sm:w-72">
                    <Search className="pointer-events-none absolute top-1/2 left-3 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
                    <input
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder={t.searchPlaceholder}
                      className="w-full rounded-lg border border-slate-200 bg-white py-2 pr-3 pl-8 text-xs text-slate-900 placeholder:text-slate-400 focus:border-orange-500 focus:outline-none dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100"
                    />
                  </div>
                </div>

                {loading ? (
                  <div className="space-y-4">
                    {[1, 2].map((idx) => (
                      <div
                        key={idx}
                        className="h-44 animate-pulse rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900"
                      />
                    ))}
                  </div>
                ) : filteredInbounds.length === 0 ? (
                  <div className="rounded-xl border border-slate-200 bg-white p-12 text-center dark:border-slate-800 dark:bg-slate-900">
                    <Sliders className="mx-auto h-6 w-6 text-slate-400" />
                    <h3 className="mt-3 text-sm font-semibold text-slate-900 dark:text-slate-100">
                      No matching inbound configurations
                    </h3>
                    <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                      Create an inbound listener for VLESS Reality, VMess, Trojan, Shadowsocks, TUIC, or Hysteria2.
                    </p>
                    <button
                      type="button"
                      onClick={() => setInboundModal({ open: true, editing: null })}
                      className="mt-4 inline-flex items-center gap-1.5 rounded-lg bg-orange-600 px-4 py-2 text-xs font-medium text-white transition-colors hover:bg-orange-500"
                    >
                      <Plus className="h-3.5 w-3.5" />
                      {t.newInbound}
                    </button>
                  </div>
                ) : (
                  <div className="space-y-5">
                    {filteredInbounds.map((inb) => (
                      <section
                        key={inb.id}
                        className="overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 px-5 py-4 dark:border-slate-800">
                          <div className="min-w-0">
                            <div className="flex items-center gap-3">
                              <h3 className="truncate text-sm font-semibold text-slate-900 dark:text-slate-100">
                                {inb.remark || inb.tag}
                              </h3>
                              <span
                                className={`inline-flex items-center gap-1 text-xs font-medium ${
                                  inb.enabled
                                    ? 'text-emerald-600 dark:text-emerald-400'
                                    : 'text-rose-600 dark:text-rose-400'
                                }`}
                              >
                                {inb.enabled ? (
                                  <CheckCircle2 className="h-3.5 w-3.5" />
                                ) : (
                                  <XCircle className="h-3.5 w-3.5" />
                                )}
                                {inb.enabled ? 'Active' : 'Disabled'}
                              </span>
                            </div>
                            <div className="mt-1 flex flex-wrap items-center gap-2 font-mono text-xs text-slate-500 dark:text-slate-400">
                              <span>{inb.protocol.toUpperCase()}</span>
                              <span aria-hidden="true">·</span>
                              <span>{inb.network.toUpperCase()}</span>
                              <span aria-hidden="true">·</span>
                              <span>{inb.security.toUpperCase()}</span>
                              <span aria-hidden="true">·</span>
                              <span className="tabular-nums">
                                {inb.serverAddress || settings.edgeDomain}:{inb.port}
                              </span>
                              {inb.sni && (
                                <>
                                  <span aria-hidden="true">·</span>
                                  <span>SNI {inb.sni}</span>
                                </>
                              )}
                            </div>
                          </div>

                          <div className="flex flex-wrap items-center gap-2 shrink-0">
                            <button
                              type="button"
                              onClick={() =>
                                setClientModal({ open: true, inbound: inb, editing: null })
                              }
                              className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-slate-800 whitespace-nowrap dark:bg-slate-800 dark:hover:bg-slate-700"
                            >
                              <UserPlus className="h-3.5 w-3.5" />
                              {t.addClient}
                            </button>
                            <button
                              type="button"
                              onClick={() => setBatchModal({ open: true, inbound: inb })}
                              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-700 transition-colors hover:bg-slate-50 whitespace-nowrap dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                            >
                              <Users className="h-3.5 w-3.5" />
                              {t.batch}
                            </button>
                            <button
                              type="button"
                              onClick={() => setInboundModal({ open: true, editing: inb })}
                              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-700 transition-colors hover:bg-slate-50 whitespace-nowrap dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                            >
                              <Edit3 className="h-3.5 w-3.5" />
                              Edit
                            </button>
                            <button
                              type="button"
                              onClick={() => handleToggleInbound(inb)}
                              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-700 transition-colors hover:bg-slate-50 whitespace-nowrap dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                            >
                              <Power className="h-3.5 w-3.5" />
                              {inb.enabled ? 'Disable' : 'Enable'}
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDeleteInbound(inb.id)}
                              aria-label="Delete inbound"
                              className="rounded-lg border border-rose-200 p-1.5 text-rose-600 transition-colors hover:bg-rose-50 dark:border-rose-900/50 dark:text-rose-400 dark:hover:bg-rose-950/60"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </div>
                        </div>

                        <div className="overflow-x-auto">
                          <table className="w-full text-left text-xs">
                            <thead className="border-b border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-800 dark:bg-slate-950/50 dark:text-slate-400">
                              <tr>
                                <th className="px-5 py-2.5 font-medium">Client</th>
                                <th className="px-5 py-2.5 font-medium">Sub Token</th>
                                <th className="px-5 py-2.5 font-medium">Traffic Usage</th>
                                <th className="px-5 py-2.5 font-medium">Expiry</th>
                                <th className="px-5 py-2.5 font-medium">Status</th>
                                <th className="px-5 py-2.5 text-right font-medium">Actions</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-200 dark:divide-slate-800/80">
                              {inb.clients.length === 0 ? (
                                <tr>
                                  <td
                                    colSpan={6}
                                    className="px-5 py-4 text-slate-500 dark:text-slate-400"
                                  >
                                    No clients configured on this inbound yet.
                                  </td>
                                </tr>
                              ) : (
                                inb.clients.map((client) => {
                                  const used = client.upBytes + client.downBytes;
                                  const quotaBytes = client.totalGb * 1024 ** 3;
                                  const pct =
                                    client.totalGb > 0
                                      ? Math.min(100, Math.round((used / quotaBytes) * 100))
                                      : 0;
                                  const exp = formatExpiry(client.expiryTime);
                                  const uri = buildClientUri(
                                    inb,
                                    client,
                                    settings.edgeDomain || window.location.hostname
                                  );
                                  const subUrl = `${window.location.origin}${(
                                    settings.subPath || '/sub'
                                  ).replace(/\/+$/, '')}/${client.subId}`;

                                  const isQuotaExceeded =
                                    client.totalGb > 0 && used >= quotaBytes;
                                  const effectiveStatus = !client.enabled
                                    ? { label: 'Disabled', cls: 'text-rose-600 dark:text-rose-400' }
                                    : exp.state === 'expired'
                                    ? { label: 'Expired', cls: 'text-rose-600 dark:text-rose-400' }
                                    : isQuotaExceeded
                                    ? { label: 'Quota Full', cls: 'text-rose-600 dark:text-rose-400' }
                                    : exp.state === 'expiring'
                                    ? { label: 'Expiring', cls: 'text-amber-600 dark:text-amber-400' }
                                    : {
                                        label: 'Active',
                                        cls: 'text-emerald-600 dark:text-emerald-400',
                                      };

                                  return (
                                    <tr
                                      key={client.id}
                                      className="transition-colors hover:bg-slate-50/70 dark:hover:bg-slate-800/30"
                                    >
                                      <td className="px-5 py-3 font-medium text-slate-900 dark:text-slate-100">
                                        {client.email}
                                      </td>
                                      <td className="px-5 py-3 font-mono text-slate-600 dark:text-slate-400">
                                        {client.subId}
                                      </td>
                                      <td className="px-5 py-3">
                                        <div className="flex items-center gap-3">
                                          <span className="font-mono tabular-nums text-slate-700 dark:text-slate-300 whitespace-nowrap">
                                            {formatBytes(used)} /{' '}
                                            {client.totalGb ? `${client.totalGb} GB` : 'Unlimited'}
                                          </span>
                                          {client.totalGb > 0 && (
                                            <div className="hidden h-1.5 w-20 overflow-hidden rounded-full bg-slate-200 sm:block dark:bg-slate-800">
                                              <div
                                                className={`h-full ${
                                                  pct >= 90
                                                    ? 'bg-rose-500'
                                                    : pct >= 70
                                                    ? 'bg-amber-500'
                                                    : 'bg-orange-500'
                                                }`}
                                                style={{ width: `${pct}%` }}
                                              />
                                            </div>
                                          )}
                                        </div>
                                      </td>
                                      <td className="px-5 py-3 font-mono tabular-nums text-slate-600 dark:text-slate-400 whitespace-nowrap">
                                        {exp.label}
                                      </td>
                                      <td className="px-5 py-3 whitespace-nowrap">
                                        <span
                                          className={`inline-flex items-center gap-1 font-medium ${effectiveStatus.cls}`}
                                        >
                                          {effectiveStatus.label === 'Expiring' ? (
                                            <Clock className="h-3.5 w-3.5" />
                                          ) : effectiveStatus.label === 'Active' ? (
                                            <CheckCircle2 className="h-3.5 w-3.5" />
                                          ) : (
                                            <XCircle className="h-3.5 w-3.5" />
                                          )}
                                          {effectiveStatus.label}
                                        </span>
                                      </td>
                                      <td className="px-5 py-3 text-right whitespace-nowrap">
                                        <div className="inline-flex items-center gap-1.5">
                                          <button
                                            type="button"
                                            onClick={() =>
                                              copyString(
                                                `uri-${client.id}`,
                                                uri,
                                                'Node URI copied'
                                              )
                                            }
                                            className="inline-flex items-center gap-1 rounded-md border border-slate-200 px-2 py-1 font-medium text-slate-700 transition-colors hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                                          >
                                            {copiedId === `uri-${client.id}` ? (
                                              <Check className="h-3 w-3 text-emerald-500" />
                                            ) : (
                                              <Copy className="h-3 w-3" />
                                            )}
                                            URI
                                          </button>
                                          <button
                                            type="button"
                                            onClick={() =>
                                              copyString(
                                                `sub-${client.id}`,
                                                subUrl,
                                                'Subscription URL copied'
                                              )
                                            }
                                            className="inline-flex items-center gap-1 rounded-md border border-orange-500/30 bg-orange-500/10 px-2 py-1 font-medium text-orange-600 transition-colors hover:bg-orange-500/20 dark:text-orange-400"
                                          >
                                            {copiedId === `sub-${client.id}` ? (
                                              <Check className="h-3 w-3" />
                                            ) : (
                                              <Link2 className="h-3 w-3" />
                                            )}
                                            Sub
                                          </button>
                                          <button
                                            type="button"
                                            onClick={() =>
                                              setQrModal({
                                                title: `${client.email} (${inb.protocol.toUpperCase()})`,
                                                subtitle: inb.remark || inb.tag,
                                                value: uri,
                                              })
                                            }
                                            title="Show QR Code"
                                            className="rounded-md border border-slate-200 p-1 text-slate-600 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                                          >
                                            <QrCode className="h-3.5 w-3.5" />
                                          </button>
                                          <button
                                            type="button"
                                            onClick={() =>
                                              setClientModal({
                                                open: true,
                                                inbound: inb,
                                                editing: client,
                                              })
                                            }
                                            title="Edit Client"
                                            className="rounded-md border border-slate-200 p-1 text-slate-600 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                                          >
                                            <Edit3 className="h-3.5 w-3.5" />
                                          </button>
                                          <button
                                            type="button"
                                            onClick={() => handleResetTraffic(client.id)}
                                            title="Reset Traffic"
                                            className="rounded-md border border-slate-200 p-1 text-slate-600 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                                          >
                                            <RotateCcw className="h-3.5 w-3.5" />
                                          </button>
                                          <button
                                            type="button"
                                            onClick={() => handleToggleClient(client)}
                                            title={client.enabled ? 'Disable Client' : 'Enable Client'}
                                            className="rounded-md border border-slate-200 p-1 text-slate-600 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                                          >
                                            <Power className="h-3.5 w-3.5" />
                                          </button>
                                          <button
                                            type="button"
                                            onClick={() => handleDeleteClient(client.id)}
                                            title="Delete Client"
                                            className="rounded-md border border-rose-200 p-1 text-rose-600 hover:bg-rose-50 dark:border-rose-900/50 dark:text-rose-400 dark:hover:bg-rose-950/60"
                                          >
                                            <Trash2 className="h-3.5 w-3.5" />
                                          </button>
                                        </div>
                                      </td>
                                    </tr>
                                  );
                                })
                              )}
                            </tbody>
                          </table>
                        </div>
                      </section>
                    ))}
                  </div>
                )}
              </>
            )}

            {activeTab === 'subscriptions' && (
              <SubscriptionInspector
                inbounds={inbounds}
                endpoints={endpoints}
                settings={settings}
                onOpenQr={(title, value, subtitle) => setQrModal({ title, value, subtitle })}
              />
            )}

            {activeTab === 'routing' && (
              <EndpointsAndRoutingView
                endpoints={endpoints}
                settings={settings}
                onRefresh={fetchAll}
                onSaveSettings={handleSaveSettings}
              />
            )}

            {activeTab === 'keygen' && <KeygenWorkbench />}

            {activeTab === 'backup' && <BackupAndLogsView onRestored={fetchAll} />}

            {activeTab === 'deliverables' && <WorkerDeliverables />}

            {activeTab === 'settings' && (
              <SettingsView settings={settings} onSave={handleSaveSettings} />
            )}
          </main>
        </div>
      </div>

      {inboundModal.open && (
        <InboundModal
          initial={inboundModal.editing}
          defaultHost={settings.edgeDomain || window.location.hostname}
          defaultSni={settings.defaultSni || 'www.cloudflare.com'}
          onClose={() => setInboundModal({ open: false })}
          onSave={handleSaveInbound}
        />
      )}

      {clientModal.open && clientModal.inbound && (
        <ClientModal
          inbound={clientModal.inbound}
          initial={clientModal.editing}
          onClose={() => setClientModal({ open: false })}
          onSave={handleSaveClient}
        />
      )}

      {batchModal.open && batchModal.inbound && (
        <BatchClientModal
          inbound={batchModal.inbound}
          subPath={settings.subPath}
          onClose={() => setBatchModal({ open: false })}
          onCreated={fetchAll}
        />
      )}

      {qrModal && (
        <QrModal
          title={qrModal.title}
          subtitle={qrModal.subtitle}
          value={qrModal.value}
          onClose={() => setQrModal(null)}
        />
      )}

      {toast && (
        <div className="fixed right-5 bottom-5 z-50 rounded-lg border border-slate-200 bg-white px-4 py-2.5 text-xs font-medium text-slate-900 shadow-lg dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100">
          {toast}
        </div>
      )}
    </div>
  );
}
