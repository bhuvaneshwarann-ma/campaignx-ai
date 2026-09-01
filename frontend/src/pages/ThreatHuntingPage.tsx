import React, { useState } from 'react';
import { Crosshair, ShieldAlert, ArrowRight, Play, RefreshCw, Layers } from 'lucide-react';
import { api } from '../services/api';
import { ThreatGraphView } from '../components/ThreatGraphView';

interface ThreatHuntingPageProps {
  onOpenEvidence: (evidence: any) => void;
}

export const ThreatHuntingPage: React.FC<ThreatHuntingPageProps> = ({ onOpenEvidence }) => {
  const [seed, setSeed] = useState('+919876543210');
  const [mode, setMode] = useState<'LITE' | 'DEEP'>('DEEP');
  const [depth, setDepth] = useState(3);
  const [loading, setLoading] = useState(false);
  const [huntResult, setHuntResult] = useState<any>(null);

  const executeHunt = async () => {
    if (!seed.trim() || loading) return;
    setLoading(true);
    try {
      const res = await api.runThreatHunt(seed.trim(), mode, depth);
      setHuntResult(res);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">Threat Hunting Console</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Execute structured IOC pivoting across domains, IPs, malware binaries, and MITRE ATT&CK techniques
        </p>
      </div>

      {/* Control Panel */}
      <div className="p-5 rounded-2xl bg-[#111827]/90 border border-card-border shadow-xl space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
          {/* Seed Input */}
          <div className="space-y-1.5 md:col-span-1">
            <label className="text-xs font-semibold uppercase text-slate-300">Seed Indicator (IOC / Phone / UPI / IP)</label>
            <input
              type="text"
              value={seed}
              onChange={(e) => setSeed(e.target.value)}
              placeholder="e.g. +919876543210 or 185.220.101.5"
              className="w-full px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Mode & Depth */}
          <div className="flex items-center space-x-3">
            <div className="space-y-1.5 flex-1">
              <label className="text-xs font-semibold uppercase text-slate-300">Hunting Mode</label>
              <div className="flex rounded-xl bg-slate-900 border border-slate-700 p-1">
                <button
                  type="button"
                  onClick={() => setMode('LITE')}
                  className={`flex-1 py-1 text-xs font-bold rounded-lg transition ${
                    mode === 'LITE' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Lite (Direct)
                </button>
                <button
                  type="button"
                  onClick={() => setMode('DEEP')}
                  className={`flex-1 py-1 text-xs font-bold rounded-lg transition ${
                    mode === 'DEEP' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Deep (Multi-Hop)
                </button>
              </div>
            </div>

            <div className="space-y-1.5 w-24">
              <label className="text-xs font-semibold uppercase text-slate-300">Max Depth</label>
              <select
                value={depth}
                onChange={(e) => setDepth(Number(e.target.value))}
                className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-cyan-400 font-bold focus:outline-none"
              >
                <option value={1}>1 Hop</option>
                <option value={2}>2 Hops</option>
                <option value={3}>3 Hops</option>
                <option value={4}>4 Hops</option>
                <option value={5}>5 Hops</option>
              </select>
            </div>
          </div>

          {/* Launch Button */}
          <button
            onClick={executeHunt}
            disabled={!seed.trim() || loading}
            className="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-bold uppercase tracking-wider transition shadow-lg shadow-cyan-500/20 disabled:opacity-40 flex items-center justify-center space-x-2"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            <span>Execute Hunt Query</span>
          </button>
        </div>
      </div>

      {/* Hunt Graph & Pivot Recommendations */}
      {huntResult && (
        <div className="space-y-6 animate-in fade-in duration-300">
          <div className="p-5 rounded-2xl bg-[#111827]/90 border border-card-border shadow-xl space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold text-white">Discovered Expansion Graph</h2>
                <p className="text-xs text-slate-400">
                  Explored {huntResult.pivots_discovered} multi-hop nodes linked to seed {huntResult.seed_indicator}
                </p>
              </div>
            </div>
            <div className="h-[480px]">
              <ThreatGraphView graphData={huntResult.graph} />
            </div>
          </div>

          {/* Pivot Recommendations */}
          <div className="p-5 rounded-2xl bg-[#111827]/90 border border-card-border shadow-xl space-y-3">
            <h3 className="text-sm font-bold uppercase tracking-wider text-cyan-400">Recommended Analyst Actions</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {huntResult.recommendations.map((rec: string, idx: number) => (
                <div key={idx} className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 text-xs text-slate-200">
                  <span className="text-cyan-400 font-bold block mb-1">Pivot #{idx + 1}</span>
                  {rec}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
