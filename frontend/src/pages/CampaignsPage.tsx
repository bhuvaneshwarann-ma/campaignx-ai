import React, { useState, useEffect } from 'react';
import {
  Flame,
  ShieldAlert,
  CheckCircle2,
  Network,
  RefreshCw,
  Layers,
  ArrowRight,
  ExternalLink,
  ShieldCheck,
} from 'lucide-react';
import { api } from '../services/api';
import { CampaignSummary, CampaignDetail } from '../types';
import { ThreatGraphView } from '../components/ThreatGraphView';

interface CampaignsPageProps {
  selectedCampaignId?: string;
  onOpenEvidence: (evidence: any) => void;
}

export const CampaignsPage: React.FC<CampaignsPageProps> = ({
  selectedCampaignId,
  onOpenEvidence,
}) => {
  const [campaigns, setCampaigns] = useState<CampaignSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string>(selectedCampaignId || '');
  const [detail, setDetail] = useState<CampaignDetail | null>(null);
  const [graphData, setGraphData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const fetchCampaigns = async () => {
    setLoading(true);
    try {
      const res = await api.getCampaigns();
      setCampaigns(res.items);
      if (res.items.length > 0 && !selectedId) {
        setSelectedId(res.items[0].campaign_id);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const fetchCampaignDetail = async (id: string) => {
    try {
      const d = await api.getCampaign(id);
      setDetail(d);
      const g = await api.getCampaignGraph(id);
      setGraphData(g);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchCampaigns();
  }, []);

  useEffect(() => {
    if (selectedId) {
      fetchCampaignDetail(selectedId);
    }
  }, [selectedId]);

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">Threat & Scam Campaign Intelligence</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Discovered syndicates clustered by deterministic multi-factor infrastructure overlap
        </p>
      </div>

      {/* Main Two-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Campaigns List */}
        <div className="space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-card-border">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300">All Campaigns ({campaigns.length})</h2>
            <button onClick={fetchCampaigns} className="p-1 text-slate-400 hover:text-white transition">
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-2.5">
            {campaigns.map((camp) => {
              const isSelected = selectedId === camp.campaign_id;
              return (
                <div
                  key={camp.campaign_id}
                  onClick={() => setSelectedId(camp.campaign_id)}
                  className={`p-4 rounded-xl border transition cursor-pointer space-y-2 ${
                    isSelected
                      ? 'bg-slate-900 border-cyan-500 shadow-lg shadow-cyan-500/10'
                      : 'bg-[#111827]/80 hover:bg-slate-900/60 border-card-border hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 font-mono text-[10px] font-bold">
                      {camp.campaign_id}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 text-[10px] font-bold">
                      {Math.round(camp.confidence * 100)}% CONFIDENCE
                    </span>
                  </div>

                  <h3 className="text-sm font-bold text-white leading-snug">{camp.name}</h3>

                  <div className="flex items-center justify-between text-xs text-slate-400 pt-1">
                    <span>Incidents: <strong className="text-slate-200 font-mono">{camp.incident_count}</strong></span>
                    <span className="text-rose-400 font-mono font-bold">Risk: {camp.risk_score}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Selected Campaign Deep Dive & Graph */}
        <div className="lg:col-span-2 space-y-6">
          {detail ? (
            <div className="space-y-6">
              {/* Campaign Headline Card */}
              <div className="p-5 rounded-2xl bg-[#111827]/90 border border-card-border shadow-xl space-y-4">
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="px-2.5 py-1 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 text-xs font-mono font-bold">
                        {detail.campaign_id}
                      </span>
                      <span className="px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-xs font-semibold uppercase">
                        {detail.status}
                      </span>
                    </div>
                    <h2 className="text-xl font-extrabold text-white">{detail.name}</h2>
                    <p className="text-xs text-slate-400">{detail.description}</p>
                  </div>

                  <div className="text-right shrink-0">
                    <span className="text-[10px] uppercase font-bold text-slate-400 block">Risk Rating</span>
                    <span className="text-3xl font-extrabold text-rose-400 font-mono">{detail.risk_score}</span>
                  </div>
                </div>

                {/* WHY THIS IS A CAMPAIGN Checklist */}
                <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
                  <div className="flex items-center space-x-2 text-xs font-bold uppercase tracking-wider text-cyan-400">
                    <ShieldCheck className="w-4 h-4" />
                    <span>Why This Is A Verified Campaign</span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs text-slate-200">
                    {detail.why_campaign.map((reason, idx) => (
                      <div key={idx} className="flex items-center space-x-2">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        <span>{reason}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Shared Infrastructure Pills */}
                <div className="space-y-2">
                  <span className="text-[11px] font-semibold uppercase text-slate-400 tracking-wider block">
                    Shared Corroborated Infrastructure ({detail.shared_infrastructure.length})
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {detail.shared_infrastructure.map((infra, idx) => (
                      <span
                        key={idx}
                        className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-cyan-300 flex items-center space-x-1.5"
                      >
                        <Network className="w-3 h-3 text-cyan-400" />
                        <span>{infra}</span>
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Campaign Threat Graph */}
              <div className="p-5 rounded-2xl bg-[#111827]/90 border border-card-border shadow-xl space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-base font-bold text-white">Campaign Relationship Graph</h3>
                  <span className="text-xs text-slate-400">Click any node or link to inspect evidence</span>
                </div>
                <div className="h-[420px]">
                  {graphData && <ThreatGraphView graphData={graphData} />}
                </div>
              </div>

              {/* Correlated Incidents Stream */}
              <div className="p-5 rounded-2xl bg-[#111827]/90 border border-card-border shadow-xl space-y-3">
                <h3 className="text-base font-bold text-white">Correlated Incident Telemetry ({detail.incidents.length})</h3>
                <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                  {detail.incidents.map((inc) => (
                    <div
                      key={inc.incident_id}
                      className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between text-xs"
                    >
                      <div className="space-y-0.5">
                        <div className="flex items-center space-x-2">
                          <span className="font-mono font-bold text-cyan-300">{inc.incident_id}</span>
                          <span className="text-[10px] uppercase font-semibold text-purple-300">{inc.channel}</span>
                        </div>
                        <p className="text-slate-300 truncate max-w-md">{inc.preview}</p>
                      </div>
                      <button
                        onClick={() => onOpenEvidence({
                          claim: `Incident ${inc.incident_id} is a verified member of campaign ${detail.name}`,
                          type: 'OBSERVED',
                          source: 'Hybrid Correlation Engine',
                          confidence: detail.campaign_confidence,
                          supporting_incident_ids: [inc.incident_id]
                        })}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs transition"
                      >
                        Evidence
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="flex items-center justify-center h-96 text-slate-400">
              <p>Select a campaign to inspect deep evidence.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
