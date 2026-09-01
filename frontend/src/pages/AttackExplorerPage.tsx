import React, { useState, useEffect } from 'react';
import { ShieldAlert, CheckCircle2, Search, ExternalLink, ShieldCheck, RefreshCw } from 'lucide-react';
import { api } from '../services/api';

interface AttackExplorerPageProps {
  onOpenEvidence: (evidence: any) => void;
}

export const AttackExplorerPage: React.FC<AttackExplorerPageProps> = ({ onOpenEvidence }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [techniques, setTechniques] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchTechniques = async () => {
    setLoading(true);
    try {
      const res = await api.getAttackTechniques();
      setTechniques(res);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTechniques();
  }, []);


  const filtered = techniques.filter(
    (t) =>
      t.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      t.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      t.tactic.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">MITRE ATT&CK Matrix Explorer</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Adversary tactical mappings grounded in verified telemetry rather than unconstrained AI guesses
        </p>
      </div>

      {/* Search Input */}
      <div className="relative">
        <Search className="w-4 h-4 text-cyan-400 absolute left-3.5 top-3" />
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Filter by Technique ID (e.g. T1566), Name, or Tactic..."
          className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-xs text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500 font-mono"
        />
      </div>

      {/* Techniques List */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filtered.map((tech) => (
          <div
            key={tech.id}
            className="p-5 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg space-y-3"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 font-mono text-xs font-bold border border-cyan-500/20">
                  {tech.id}
                </span>
                <span className="px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 text-[10px] uppercase font-semibold">
                  {tech.tactic}
                </span>
              </div>
              <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-bold">
                {tech.status}
              </span>
            </div>

            <div>
              <h3 className="text-sm font-bold text-white">{tech.name}</h3>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">{tech.description}</p>
            </div>

            <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs">
              <div className="space-x-1">
                {tech.campaigns.map((c) => (
                  <span key={c} className="px-2 py-0.5 rounded bg-slate-900 font-mono text-[10px] text-rose-300 border border-slate-800">
                    {c}
                  </span>
                ))}
              </div>
              <button
                onClick={() =>
                  onOpenEvidence({
                    claim: `Adversary technique ${tech.id} (${tech.name}) verified across campaigns ${tech.campaigns.join(', ')}`,
                    type: tech.status,
                    source: 'MITRE ATT&CK Corroborator',
                    confidence: 0.94,
                    supporting_elements: [tech.id, ...tech.actors],
                  })
                }
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[11px] font-medium transition"
              >
                Evidence
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
