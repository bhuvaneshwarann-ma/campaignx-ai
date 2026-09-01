import React from 'react';
import { X, CheckCircle2, AlertCircle, ShieldCheck, Database, Calendar } from 'lucide-react';

export interface EvidenceRecord {
  claim: string;
  type: 'OBSERVED' | 'INFERRED' | 'PREDICTED';
  source: string;
  confidence: number;
  supporting_incident_ids?: string[];
  supporting_elements?: string[];
  timestamp?: string;
  scoring_factors?: Record<string, any>;
}

interface EvidenceDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  evidence: EvidenceRecord | null;
}

export const EvidenceDrawer: React.FC<EvidenceDrawerProps> = ({ isOpen, onClose, evidence }) => {
  if (!isOpen || !evidence) return null;

  const typeColor = {
    OBSERVED: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    INFERRED: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
    PREDICTED: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  }[evidence.type] || 'bg-slate-500/10 text-slate-400 border-slate-500/30';

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm transition-opacity">
      <div className="w-full max-w-md bg-[#0e1422] border-l border-card-border h-full shadow-2xl flex flex-col p-6 overflow-y-auto animate-in slide-in-from-right duration-200">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-card-border mb-6">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            <h3 className="font-bold text-base text-white">Canonical Evidence Record</h3>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Claim */}
        <div className="space-y-4 flex-1">
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
            <p className="text-[11px] font-semibold uppercase text-slate-400 tracking-wider mb-1">Intelligence Claim</p>
            <p className="text-sm font-medium text-slate-100 leading-relaxed">{evidence.claim}</p>
          </div>

          {/* Classification & Confidence Matrix */}
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
              <p className="text-[10px] uppercase font-semibold text-slate-400 mb-1">Evidence Type</p>
              <span className={`inline-flex px-2.5 py-1 text-xs font-semibold rounded-full border ${typeColor}`}>
                {evidence.type}
              </span>
            </div>
            <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
              <p className="text-[10px] uppercase font-semibold text-slate-400 mb-1">Verified Confidence</p>
              <p className="text-base font-bold text-cyan-400 font-mono">
                {Math.round(evidence.confidence * 100)}%
              </p>
            </div>
          </div>

          {/* Source Provenance */}
          <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center space-x-3">
            <Database className="w-4 h-4 text-slate-400" />
            <div>
              <p className="text-[10px] uppercase font-semibold text-slate-400">Provenance Source</p>
              <p className="text-xs font-medium text-slate-200">{evidence.source}</p>
            </div>
          </div>

          {/* Supporting Incidents */}
          {evidence.supporting_incident_ids && evidence.supporting_incident_ids.length > 0 && (
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <p className="text-[11px] font-semibold uppercase text-slate-400 mb-2">Supporting Telemetry</p>
              <div className="flex flex-wrap gap-2">
                {evidence.supporting_incident_ids.map((id) => (
                  <span key={id} className="px-2.5 py-1 rounded bg-slate-800 border border-slate-700 text-xs font-mono text-cyan-300">
                    {id}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Supporting Infrastructure Elements */}
          {evidence.supporting_elements && evidence.supporting_elements.length > 0 && (
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <p className="text-[11px] font-semibold uppercase text-slate-400 mb-2">Corroborated Elements</p>
              <ul className="space-y-1.5 text-xs text-slate-300">
                {evidence.supporting_elements.map((elem, idx) => (
                  <li key={idx} className="flex items-center space-x-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    <span className="font-mono">{elem}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="pt-4 border-t border-card-border text-center">
          <p className="text-[11px] text-slate-400">
            Cryptographically logged to immutable audit ledger.
          </p>
        </div>
      </div>
    </div>
  );
};
