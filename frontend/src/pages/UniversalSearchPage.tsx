import React, { useState } from 'react';
import { Search, ShieldAlert, ArrowRight, Activity, ShieldCheck, RefreshCw, FileCode, Layers } from 'lucide-react';
import { api } from '../services/api';
import { IOCLookupResponse } from '../types';
import { ThreatGraphView } from '../components/ThreatGraphView';

interface UniversalSearchPageProps {
  onOpenEvidence: (evidence: any) => void;
}

export const UniversalSearchPage: React.FC<UniversalSearchPageProps> = ({ onOpenEvidence }) => {
  const [query, setQuery] = useState('');
  const [depth, setDepth] = useState(2);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<IOCLookupResponse | null>(null);

  const sampleIOCs = [
    { label: 'C2 IP (185.220.101.5)', val: '185.220.101.5' },
    { label: 'Phish Domain (sbi-kyc-verify-online.com)', val: 'sbi-kyc-verify-online.com' },
    { label: 'Malware Hash (SHA256)', val: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
    { label: 'Scam UPI (sbikyc.verify@okhdfcbank)', val: 'sbikyc.verify@okhdfcbank' },
    { label: 'Scam Phone (+919876543210)', val: '+919876543210' },
  ];

  const handleSearch = async (searchTerm: string) => {
    if (!searchTerm.trim()) return;
    setLoading(true);
    try {
      const res = await api.lookupIOC(searchTerm.trim(), depth);
      setResult(res);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6">
      {/* Search Header */}
      <div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">Universal Investigation Console</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Enter an IP, hash, domain, URL, CVE, email, phone, UPI or paste raw telemetry
        </p>
      </div>

      {/* Main Search Input */}
      <div className="p-4 rounded-2xl bg-[#111827]/90 border border-card-border shadow-xl space-y-3">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSearch(query);
          }}
          className="flex items-center space-x-3"
        >
          <div className="relative flex-1">
            <Search className="w-5 h-5 text-cyan-400 absolute left-4 top-3.5" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search an IP, hash, domain, URL, CVE, email, phone, UPI or paste a suspicious message..."
              className="w-full pl-12 pr-4 py-3 rounded-xl bg-slate-900 border border-slate-700 text-sm text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500 font-mono shadow-inner transition"
            />
          </div>

          {/* Depth Selector */}
          <div className="flex items-center space-x-2 bg-slate-900 px-3 py-2.5 rounded-xl border border-slate-700">
            <span className="text-xs text-slate-400">Depth:</span>
            <select
              value={depth}
              onChange={(e) => setDepth(Number(e.target.value))}
              className="bg-transparent text-xs text-cyan-400 font-bold focus:outline-none"
            >
              <option value={1}>1 Hop (Lite)</option>
              <option value={2}>2 Hops</option>
              <option value={3}>3 Hops (Deep)</option>
              <option value={4}>4 Hops</option>
              <option value={5}>5 Hops</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={loading || !query.trim()}
            className="px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-bold tracking-wider uppercase transition shadow-lg shadow-cyan-500/20 disabled:opacity-40"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin mx-auto" /> : 'Investigate'}
          </button>
        </form>

        {/* Quick Sample Queries */}
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-[11px] text-slate-400">Quick Samples:</span>
          {sampleIOCs.map((sample, idx) => (
            <button
              key={idx}
              onClick={() => {
                setQuery(sample.val);
                handleSearch(sample.val);
              }}
              className="px-2.5 py-1 rounded-lg bg-slate-800/80 hover:bg-slate-700 border border-slate-700 text-[11px] font-mono text-cyan-300 transition"
            >
              {sample.label}
            </button>
          ))}
        </div>
      </div>

      {/* Investigation Results */}
      {result && (
        <div className="space-y-6 animate-in fade-in duration-300">
          {/* Summary & Risk Metrics Header */}
          <div className="p-5 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center space-x-2">
                <span className="px-2.5 py-1 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 text-xs font-mono font-bold">
                  {result.detected_type}
                </span>
                <span className="text-lg font-bold text-white font-mono">{result.canonical_value}</span>
              </div>
              <p className="text-xs text-slate-400">
                Pseudonymized Audit Handle: <span className="font-mono text-slate-300">{result.masked_value}</span>
              </p>
            </div>

            {/* Risk Badge */}
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <span className="text-[10px] uppercase font-bold text-slate-400 block">Calculated Risk Score</span>
                <span className={`text-2xl font-extrabold font-mono ${
                  result.risk_assessment.risk_score >= 80 ? 'text-rose-400' : 'text-emerald-400'
                }`}>
                  {result.risk_assessment.risk_score} / 100 ({result.risk_assessment.severity})
                </span>
              </div>
              <button
                onClick={() => onOpenEvidence({
                  claim: `Authoritative consensus verified risk ${result.risk_assessment.risk_score} for ${result.canonical_value}`,
                  type: 'OBSERVED',
                  source: 'Multi-Provider Risk Engine',
                  confidence: 0.96,
                  supporting_elements: [result.canonical_value]
                })}
                className="px-3 py-2 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 text-xs font-semibold transition flex items-center space-x-1.5"
              >
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>View Evidence</span>
              </button>
            </div>
          </div>

          {/* Threat Intelligence Graph */}
          <div className="p-5 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold text-white">Threat Infrastructure Graph</h2>
                <p className="text-xs text-slate-400">Multi-hop relationship pivots & adversary technique links</p>
              </div>
            </div>
            <div className="h-[450px]">
              <ThreatGraphView graphData={result.graph} />
            </div>
          </div>

          {/* Provider Veracity Breakdown */}
          <div className="p-5 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg space-y-4">
            <h2 className="text-base font-bold text-white">Threat Intelligence Provider Reports</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
              {result.providers.map((prov, idx) => (
                <div key={idx} className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-xs text-slate-200">{prov.provider_name}</span>
                    <span className={`px-2 py-0.5 text-[9px] font-bold rounded ${
                      prov.verdict === 'MALICIOUS' ? 'bg-rose-500/20 text-rose-300' : (
                        prov.verdict === 'CLEAN' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-800 text-slate-400'
                      )
                    }`}>
                      {prov.verdict}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    <div>Status: <span className="text-slate-300 font-mono">{prov.status}</span></div>
                    {prov.detections > 0 && (
                      <div>Detections: <span className="text-rose-400 font-mono font-bold">{prov.detections} / {prov.total_engines}</span></div>
                    )}
                    {prov.message && <div className="text-slate-400 text-[10px] mt-1">{prov.message}</div>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
