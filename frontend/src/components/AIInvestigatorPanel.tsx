import React, { useState } from 'react';
import { Sparkles, Send, Bot, ShieldCheck, AlertCircle, ArrowRight, RefreshCw, X } from 'lucide-react';
import { api } from '../services/api';
import { AIAnalysisResponse } from '../types';

interface AIInvestigatorPanelProps {
  currentIncidentId?: string;
  currentCampaignId?: string;
  context?: any;
  onClose?: () => void;
}

export const AIInvestigatorPanel: React.FC<AIInvestigatorPanelProps> = ({
  currentIncidentId,
  currentCampaignId,
  context,
  onClose,
}) => {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState<AIAnalysisResponse | null>(null);

  const presetQuestions = [
    'Why are these incidents connected?',
    'What infrastructure is reused?',
    'What makes this campaign suspicious?',
    'What should I investigate next?',
    'Which ATT&CK techniques are supported by evidence?',
  ];

  const handleAsk = async (q: string) => {
    if (!q.trim() || loading) return;
    setLoading(true);
    try {
      const res = await api.runAIAnalysis({
        query: q,
        incident_id: currentIncidentId,
        campaign_id: currentCampaignId,
        context: context || {},
      });
      setResponse(res);
    } catch (e: any) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full bg-[#0e1422] border-l border-card-border p-4 w-84 md:w-96 shrink-0 shadow-2xl z-20">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-card-border mb-4">
        <div className="flex items-center space-x-2">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-tr from-cyan-500 to-purple-600 flex items-center justify-center shrink-0">
            <Bot className="w-4 h-4 text-white" />
          </div>
          <div>
            <h3 className="font-bold text-sm text-white">AI Investigator</h3>
            <p className="text-[10px] text-slate-400">Strictly Grounded in Telemetry</p>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <span className="px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            Grounded
          </span>
          {onClose && (
            <button
              onClick={onClose}
              className="p-1 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 transition"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>


      {/* Preset Quick Actions */}
      <div className="mb-3">
        <p className="text-[11px] font-semibold uppercase text-slate-400 mb-2 tracking-wider">Suggested Investigation Questions</p>
        <div className="space-y-1.5">
          {presetQuestions.map((pq, idx) => (
            <button
              key={idx}
              onClick={() => {
                setQuery(pq);
                handleAsk(pq);
              }}
              className="w-full text-left px-2.5 py-1.5 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-800 text-[11px] text-slate-300 transition flex items-center justify-between group"
            >
              <span className="truncate">{pq}</span>
              <ArrowRight className="w-3 h-3 text-cyan-400 opacity-0 group-hover:opacity-100 transition shrink-0 ml-1" />
            </button>
          ))}
        </div>
      </div>

      {/* Results / Response Container */}
      <div className="flex-1 overflow-y-auto space-y-3 pr-1 my-2">
        {loading && (
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-center py-8">
            <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin mx-auto mb-2" />
            <p className="text-xs text-slate-400 font-medium">Synthesizing verified telemetry...</p>
          </div>
        )}

        {!loading && response && (
          <div className="space-y-3 animate-in fade-in duration-200">
            {/* Summary */}
            <div className="p-3.5 rounded-xl bg-cyan-950/30 border border-cyan-500/30">
              <p className="text-[10px] font-bold uppercase tracking-wider text-cyan-400 mb-1">Investigation Summary</p>
              <p className="text-xs text-slate-200 leading-relaxed font-medium">{response.summary}</p>
            </div>

            {/* Evidence Grounding */}
            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <div className="flex items-center space-x-1.5 text-[10px] font-bold uppercase text-emerald-400 mb-1">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>Verified Evidence</span>
              </div>
              <pre className="text-[11px] text-slate-300 font-sans whitespace-pre-wrap leading-relaxed">
                {response.evidence_text}
              </pre>
            </div>

            {/* Detailed Analysis */}
            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <p className="text-[10px] font-bold uppercase text-slate-400 mb-1">Analysis & Correlation</p>
              <p className="text-xs text-slate-300 leading-relaxed">{response.analysis_text}</p>
            </div>

            {/* Next Steps */}
            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
              <p className="text-[10px] font-bold uppercase text-amber-400 mb-1">Recommended Pivots</p>
              <pre className="text-[11px] text-slate-300 font-sans whitespace-pre-wrap leading-relaxed">
                {response.next_steps_text}
              </pre>
            </div>

            {/* Model Provenance */}
            <div className="flex items-center justify-between text-[10px] text-slate-400 px-1 pt-1">
              <span>Provider: {response.provider_used}</span>
              <span className="font-mono">{Math.round(response.confidence_score * 100)}% confidence</span>
            </div>
          </div>
        )}

        {!loading && !response && (
          <div className="text-center py-12 px-4 rounded-xl border border-dashed border-slate-800">
            <Bot className="w-8 h-8 text-slate-400 mx-auto mb-2" />
            <p className="text-xs font-semibold text-slate-400">Ask a Question</p>
            <p className="text-[11px] text-slate-400 mt-1">
              AI answers are strictly derived from verified threat relationships.
            </p>
          </div>
        )}
      </div>

      {/* Input */}
      <div className="pt-2 border-t border-card-border">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleAsk(query);
          }}
          className="relative"
        >
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Ask AI Investigator..."
            className="w-full pl-3.5 pr-10 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-xs text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500 transition"
          />
          <button
            type="submit"
            disabled={!query.trim() || loading}
            className="absolute right-2 top-2 p-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-30 transition"
          >
            <Send className="w-3.5 h-3.5" />
          </button>
        </form>
      </div>
    </div>
  );
};
