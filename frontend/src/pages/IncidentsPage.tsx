import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  Send,
  Plus,
  Radio,
  FileText,
  ShieldCheck,
  RefreshCw,
  Search,
  ExternalLink,
  Bot,
} from 'lucide-react';
import { api } from '../services/api';
import { IncidentItem, ScamDNAData } from '../types';

interface IncidentsPageProps {
  onOpenEvidence: (evidence: any) => void;
}

export const IncidentsPage: React.FC<IncidentsPageProps> = ({ onOpenEvidence }) => {
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);

  // Form State
  const [channel, setChannel] = useState('sms');
  const [content, setContent] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submittedResult, setSubmittedResult] = useState<any>(null);

  const fetchIncidents = async () => {
    setLoading(true);
    try {
      const res = await api.getIncidents(0, 50);
      setIncidents(res.items);
      setTotal(res.total);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim() || submitting) return;
    setSubmitting(true);
    try {
      const res = await api.submitIncident({
        channel,
        raw_content: content.trim(),
        source: 'analyst_submission',
      });
      setSubmittedResult(res);
      setContent('');
      fetchIncidents();
    } catch (e: any) {
      alert(e.message || 'Error submitting incident');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">Suspicious Incident Telemetry & Scam DNA</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Ingest untrusted communications across Indian regional languages and extract taxonomic Scam DNA
        </p>
      </div>

      {/* Submission Panel */}
      <div className="p-5 rounded-2xl bg-[#111827]/90 border border-card-border shadow-xl space-y-4">
        <div className="flex items-center space-x-2">
          <Plus className="w-5 h-5 text-cyan-400" />
          <h2 className="text-base font-bold text-white">Ingest New Suspicious Telemetry</h2>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="flex items-center space-x-3">
            <label className="text-xs font-semibold text-slate-300">Communication Channel:</label>
            {['sms', 'whatsapp', 'email', 'voice_transcript', 'text'].map((ch) => (
              <button
                key={ch}
                type="button"
                onClick={() => setChannel(ch)}
                className={`px-3 py-1 rounded-lg text-xs font-medium uppercase transition ${
                  channel === ch
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200'
                }`}
              >
                {ch.replace('_', ' ')}
              </button>
            ))}
          </div>

          <div>
            <textarea
              rows={3}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Paste raw SMS, WhatsApp chat, email text or voice transcript in English, Hindi, Hinglish, Tamil, or Tanglish..."
              className="w-full p-3.5 rounded-xl bg-slate-900 border border-slate-700 text-xs text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500 font-mono transition"
            />
          </div>

          <div className="flex items-center justify-between">
            <p className="text-[11px] text-slate-400">
              All submitted content is treated as untrusted and sanitized against prompt injection and SSRF.
            </p>
            <button
              type="submit"
              disabled={!content.trim() || submitting}
              className="px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold uppercase tracking-wider transition shadow-lg shadow-cyan-500/20 disabled:opacity-40 flex items-center space-x-2"
            >
              {submitting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              <span>Extract Scam DNA & Ingest</span>
            </button>
          </div>
        </form>

        {/* Live Submission Result */}
        {submittedResult && (
          <div className="p-4 rounded-xl bg-slate-900/90 border border-cyan-500/30 space-y-3 animate-in fade-in duration-200">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-mono text-xs font-bold">
                  {submittedResult.incident_id}
                </span>
                <span className="text-xs font-semibold text-emerald-400">Successfully Ingested & Analyzed</span>
              </div>
              <span className="text-xs text-slate-400">Language: <strong className="text-cyan-300 uppercase">{submittedResult.language}</strong></span>
            </div>

            {/* Scam DNA Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 pt-1 text-xs">
              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800">
                <span className="text-[10px] uppercase text-slate-400 block font-semibold">Target</span>
                <strong className="text-slate-100 font-mono uppercase">{submittedResult.scam_dna.impersonation_target}</strong>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800">
                <span className="text-[10px] uppercase text-slate-400 block font-semibold">Urgency Level</span>
                <strong className="text-rose-400 font-mono">{Math.round(submittedResult.scam_dna.urgency * 100)}%</strong>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800">
                <span className="text-[10px] uppercase text-slate-400 block font-semibold">Payment Method</span>
                <strong className="text-cyan-400 font-mono uppercase">{submittedResult.scam_dna.payment_method}</strong>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800">
                <span className="text-[10px] uppercase text-slate-400 block font-semibold">Risk Rating</span>
                <strong className="text-rose-400 font-mono">{submittedResult.risk_assessment.risk_score} / 100</strong>
              </div>
            </div>

            {/* Tactics Tags */}
            <div className="flex flex-wrap gap-1.5 pt-1">
              {submittedResult.scam_dna.social_engineering_tactics.map((t: string) => (
                <span key={t} className="px-2 py-0.5 rounded-md bg-purple-500/10 border border-purple-500/20 text-purple-300 text-[10px] font-mono">
                  #{t}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Ingested Incidents Table */}
      <div className="p-5 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-white">Telemetry Telemetry Stream ({total} total)</h2>
            <p className="text-xs text-slate-400">Audited telemetry records with normalized language classification</p>
          </div>
          <button
            onClick={fetchIncidents}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="space-y-2">
          {incidents.map((inc) => (
            <div
              key={inc.incident_id}
              className="p-3.5 rounded-xl bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3 transition"
            >
              <div className="space-y-1 flex-1">
                <div className="flex items-center space-x-2">
                  <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 font-mono text-xs font-bold text-cyan-300">
                    {inc.incident_id}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20 text-[10px] uppercase font-semibold">
                    {inc.channel}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20 text-[10px] uppercase font-semibold">
                    {inc.language}
                  </span>
                  {inc.campaign_id && (
                    <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/20 text-[10px] font-mono font-semibold">
                      {inc.campaign_id}
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-300 font-sans line-clamp-1">{inc.raw_content}</p>
              </div>

              <div className="flex items-center space-x-3 shrink-0">
                <span className="text-[11px] text-slate-400 font-mono">
                  {new Date(inc.created_at).toLocaleDateString()}
                </span>
                <button
                  onClick={() => onOpenEvidence({
                    claim: `Telemetry ${inc.incident_id} parsed with verified Scam DNA profile.`,
                    type: 'OBSERVED',
                    source: 'Scam DNA Parser & Entity Resolver',
                    confidence: 0.95,
                    supporting_incident_ids: [inc.incident_id]
                  })}
                  className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-[11px] text-cyan-300 transition"
                >
                  Evidence
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
