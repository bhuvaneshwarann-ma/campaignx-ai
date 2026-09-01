import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Flame,
  AlertTriangle,
  Radio,
  ExternalLink,
  RefreshCw,
  Activity,
  Layers,
  Sparkles,
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { api } from '../services/api';
import { DashboardData } from '../types';

interface DashboardPageProps {
  onSelectCampaign: (id: string) => void;
  onOpenSearch: () => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onSelectCampaign, onOpenSearch }) => {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const [isSyncing, setIsSyncing] = useState(false);
  const [syncStatusMsg, setSyncStatusMsg] = useState<string | null>(null);
  const [liveStream, setLiveStream] = useState<any[]>([]);

  const fetchMetrics = async (showLoading = false) => {
    if (showLoading) setLoading(true);
    try {
      const res = await api.getDashboard();
      setData(res);
      setLastUpdated(new Date());
      // Also fetch live telemetry stream
      const streamRes = await api.getFeedStream(6);
      if (streamRes && streamRes.events) {
        setLiveStream(streamRes.events);
      }
    } catch (e) {
      console.error(e);
    } finally {
      if (showLoading) setLoading(false);
    }
  };

  const handleSyncLiveFeeds = async () => {
    setIsSyncing(true);
    setSyncStatusMsg('Connecting to URLhaus & ThreatFox live feeds...');
    try {
      const res = await api.syncLiveFeed(25);
      setSyncStatusMsg(`Successfully ingested ${res.ingested_count} real-time threats and clustered ${res.new_campaigns} new live campaigns!`);
      await fetchMetrics(false);
      setTimeout(() => setSyncStatusMsg(null), 6000);
    } catch (e: any) {
      setSyncStatusMsg(`Sync error: ${e.message || 'Failed to fetch live feed'}`);
      setTimeout(() => setSyncStatusMsg(null), 5000);
    } finally {
      setIsSyncing(false);
    }
  };

  useEffect(() => {
    fetchMetrics(true);
    // Real-time polling every 3 seconds
    const interval = setInterval(() => {
      fetchMetrics(false);
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !data) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  const channelChartData = Object.entries(data.channel_distribution || {}).map(([name, value]) => ({
    name: name.replace('_', ' ').toUpperCase(),
    value,
  }));

  const languageChartData = Object.entries(data.language_distribution || {}).map(([name, value]) => ({
    name: name.toUpperCase(),
    value,
  }));

  const COLORS = ['#06b6d4', '#3b82f6', '#8b5cf6', '#10b981', '#f59e0b'];

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6">
      {/* Top Banner / Headline */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-2xl font-extrabold text-white tracking-tight">Security Operations Center (SOC)</h1>
            <span className="px-2.5 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[11px] font-mono font-bold flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              REAL-TIME ONLINE MODE
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">Live threat & scam intelligence synthesis with real-time URLhaus, ThreatFox & DNS feeds</p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={handleSyncLiveFeeds}
            disabled={isSyncing}
            className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-600/20 transition disabled:opacity-60"
          >
            <Sparkles className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
            <span>{isSyncing ? 'Syncing Live Feeds...' : 'Sync Live Threat Feeds'}</span>
          </button>
          <button
            onClick={() => fetchMetrics(true)}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Sync Status Banner */}
      {syncStatusMsg && (
        <div className="p-3 rounded-xl bg-cyan-950/60 border border-cyan-500/30 text-cyan-200 text-xs flex items-center justify-between animate-in fade-in slide-in-from-top duration-300">
          <div className="flex items-center space-x-2">
            <Sparkles className="w-4 h-4 text-cyan-400 flex-shrink-0" />
            <span className="font-mono">{syncStatusMsg}</span>
          </div>
          <button onClick={() => setSyncStatusMsg(null)} className="text-cyan-400 hover:text-white text-xs font-bold ml-4">✕</button>
        </div>
      )}



      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Active Campaigns */}
        <div className="p-4 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Active Campaigns</span>
            <Flame className="w-4 h-4 text-rose-400" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold text-white font-mono">{data.summary.active_campaigns}</span>
            <span className="text-xs font-semibold text-rose-400">Syndicates</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-2">Corroborated across multi-channel telemetry</p>
        </div>

        {/* Emerging Campaigns */}
        <div className="p-4 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Emerging Threats</span>
            <Activity className="w-4 h-4 text-amber-400" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold text-amber-400 font-mono">{data.summary.emerging_campaigns || 1}</span>
            <span className="text-xs font-semibold text-amber-300">New Cluster</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-2">Dynamic real-time anomaly detection</p>
        </div>

        {/* Telemetry Incidents */}
        <div className="p-4 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Telemetry Incidents</span>
            <AlertTriangle className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold text-white font-mono">{data.summary.total_incidents}</span>
            <span className="text-xs font-semibold text-cyan-400">Ingested</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-2">Multilingual SMS, WhatsApp & IOC streams</p>
        </div>

        {/* Extracted Entities */}
        <div className="p-4 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Resolved Entities</span>
            <Layers className="w-4 h-4 text-purple-400" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold text-white font-mono">{data.summary.total_entities}</span>
            <span className="text-xs font-semibold text-purple-400">Canonical</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-2">Phones, UPIs, Domains, Hashes, IPs</p>
        </div>
      </div>

      {/* Main Grid: Campaigns Table & Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Top Active Campaigns List */}
        <div className="lg:col-span-2 p-5 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-bold text-white">Active Threat & Scam Campaigns</h2>
              <p className="text-xs text-slate-400">Clustered via deterministic multi-factor corroboration</p>
            </div>
          </div>

          <div className="space-y-2.5">
            {data.top_campaigns.map((camp) => (
              <div
                key={camp.campaign_id}
                onClick={() => onSelectCampaign(camp.campaign_id)}
                className="p-3.5 rounded-xl bg-slate-900/70 hover:bg-slate-800/80 border border-slate-800 hover:border-cyan-500/40 transition cursor-pointer flex items-center justify-between group"
              >
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[10px] font-mono font-bold">
                      {camp.campaign_id}
                    </span>
                    <h3 className="text-sm font-semibold text-white group-hover:text-cyan-300 transition">
                      {camp.name}
                    </h3>
                  </div>
                  <div className="flex items-center space-x-4 text-[11px] text-slate-400">
                    <span>Incidents: <strong className="text-slate-200 font-mono">{camp.incident_count}</strong></span>
                    <span>Confidence: <strong className="text-cyan-400 font-mono">{Math.round(camp.confidence * 100)}%</strong></span>
                  </div>
                </div>

                <div className="flex items-center space-x-3">
                  <div className="text-right">
                    <span className="text-[10px] uppercase font-semibold text-slate-400 block">Risk Score</span>
                    <span className="text-sm font-extrabold text-rose-400 font-mono">{camp.risk_score}</span>
                  </div>
                  <ExternalLink className="w-4 h-4 text-slate-400 group-hover:text-cyan-400 transition" />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Provider Health Matrix & Live Stream */}
        <div className="space-y-6">
          <div className="p-5 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-bold text-white">Threat Provider Health</h2>
              <Radio className="w-4 h-4 text-emerald-400" />
            </div>
            <p className="text-xs text-slate-400">Authoritative feed status & circuit breakers</p>

            <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
              {Object.entries(data.provider_health || {}).map(([pname, pstatus]) => {
                const isOnline = pstatus === 'ONLINE';
                return (
                  <div key={pname} className="flex items-center justify-between p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 text-xs">
                    <span className="font-semibold text-slate-200">{pname}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold ${
                      isOnline
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        : 'bg-slate-800 text-slate-400 border border-slate-700'
                    }`}>
                      {pstatus}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Live Telemetry Stream */}
          <div className="p-5 rounded-2xl bg-[#111827]/90 border border-cyan-500/20 shadow-lg space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
                <h2 className="text-sm font-bold text-white">Live Ingested Telemetry</h2>
              </div>
              <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                REAL-TIME STREAM
              </span>
            </div>

            {liveStream && liveStream.length > 0 ? (
              <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                {liveStream.map((ev, idx) => (
                  <div key={idx} className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 text-xs space-y-1 hover:border-cyan-500/40 transition">
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="font-mono text-cyan-400 font-bold">{ev.id}</span>
                      <span className="text-slate-400">{ev.source}</span>
                    </div>
                    <p className="text-slate-300 text-[11px] font-mono truncate">{ev.content_preview}</p>
                    <div className="flex items-center justify-between text-[10px] text-slate-400 pt-0.5">
                      <span className="text-rose-400 font-semibold">{ev.malware || ev.threat}</span>
                      <span className="text-amber-400 font-mono">Risk {ev.risk_score}</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-4 text-xs text-slate-400 space-y-2">
                <p>Click <strong className="text-cyan-400">"Sync Live Threat Feeds"</strong> to stream active real-world threat telemetry.</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Telemetry Distribution Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Channel Volume */}
        <div className="p-5 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg">
          <h2 className="text-base font-bold text-white mb-1">Telemetry by Channel</h2>
          <p className="text-xs text-slate-400 mb-4">Ingestion distribution across communication vectors</p>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={channelChartData}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#fff' }}
                />
                <Bar dataKey="value" fill="#06b6d4" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Multilingual Breakdown */}
        <div className="p-5 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg">
          <h2 className="text-base font-bold text-white mb-1">Multilingual Telemetry</h2>
          <p className="text-xs text-slate-400 mb-4">Language distribution across Indian regional languages</p>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={languageChartData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                >
                  {languageChartData.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#fff' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};
