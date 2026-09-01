import React, { useState } from 'react';
import { BarChart3, Play, RefreshCw, ShieldCheck, CheckCircle2, AlertOctagon, Zap } from 'lucide-react';
import { api } from '../services/api';
import { EvaluationData } from '../types';

export const EvaluationPage: React.FC = () => {
  const [data, setData] = useState<EvaluationData | null>(null);
  const [loading, setLoading] = useState(false);

  const runEval = async () => {
    setLoading(true);
    try {
      const res = await api.runEvaluation();
      setData(res);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight">System Evaluation & Benchmarks</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Automated empirical validation against ground truth synthetic dataset and negative controls
          </p>
        </div>

        <button
          onClick={runEval}
          disabled={loading}
          className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-bold uppercase tracking-wider transition shadow-lg shadow-cyan-500/20 disabled:opacity-40 flex items-center space-x-2"
        >
          {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          <span>Run Benchmark Suite</span>
        </button>
      </div>

      {/* Results */}
      {data ? (
        <div className="space-y-6 animate-in fade-in duration-300">
          {/* Primary Metric KPI Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Campaign F1 */}
            <div className="p-4 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg">
              <span className="text-[11px] font-semibold uppercase text-slate-400 block mb-1">Campaign Detection F1</span>
              <span className="text-3xl font-extrabold text-cyan-400 font-mono">
                {(data.metrics.campaign_f1 * 100).toFixed(1)}%
              </span>
              <p className="text-[10px] text-slate-400 mt-1">Precision: {(data.metrics.campaign_precision * 100).toFixed(1)}% | Recall: {(data.metrics.campaign_recall * 100).toFixed(1)}%</p>
            </div>

            {/* False Campaign Rate */}
            <div className="p-4 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg">
              <span className="text-[11px] font-semibold uppercase text-slate-400 block mb-1">False Campaign Rate</span>
              <span className="text-3xl font-extrabold text-emerald-400 font-mono">
                {(data.metrics.false_campaign_rate * 100).toFixed(1)}%
              </span>
              <p className="text-[10px] text-slate-400 mt-1">Generic similarity rejection defense active</p>
            </div>

            {/* Scam DNA Extraction F1 */}
            <div className="p-4 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg">
              <span className="text-[11px] font-semibold uppercase text-slate-400 block mb-1">Scam DNA Extraction F1</span>
              <span className="text-3xl font-extrabold text-purple-400 font-mono">
                {(data.metrics.scam_dna_f1 * 100).toFixed(1)}%
              </span>
              <p className="text-[10px] text-slate-400 mt-1">Multilingual taxonomic parser accuracy</p>
            </div>

            {/* P95 Latency */}
            <div className="p-4 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg">
              <span className="text-[11px] font-semibold uppercase text-slate-400 block mb-1">P95 Analysis Latency</span>
              <span className="text-3xl font-extrabold text-amber-400 font-mono">
                {data.metrics.latency.p95_ms} ms
              </span>
              <p className="text-[10px] text-slate-400 mt-1">P50: {data.metrics.latency.p50_ms}ms | P99: {data.metrics.latency.p99_ms}ms</p>
            </div>
          </div>

          {/* Confusion Matrix & Parameter Sweeps */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Confusion Matrix */}
            <div className="p-5 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg space-y-4">
              <h2 className="text-base font-bold text-white">Negative Control & Detection Matrix</h2>
              <div className="grid grid-cols-2 gap-3 text-center">
                <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-500/30">
                  <span className="text-xs text-slate-400 block font-semibold">True Positives</span>
                  <span className="text-2xl font-bold font-mono text-emerald-400">{data.confusion_matrix.true_positives}</span>
                </div>
                <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/30">
                  <span className="text-xs text-slate-400 block font-semibold">False Positives (Rejections Defended)</span>
                  <span className="text-2xl font-bold font-mono text-rose-400">{data.confusion_matrix.false_positives}</span>
                </div>
                <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
                  <span className="text-xs text-slate-400 block font-semibold">True Negatives (Clean Verified)</span>
                  <span className="text-2xl font-bold font-mono text-slate-200">{data.confusion_matrix.true_negatives}</span>
                </div>
                <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
                  <span className="text-xs text-slate-400 block font-semibold">False Negatives</span>
                  <span className="text-2xl font-bold font-mono text-slate-200">{data.confusion_matrix.false_negatives}</span>
                </div>
              </div>
            </div>

            {/* Threshold Parameter Sweep */}
            <div className="p-5 rounded-2xl bg-[#111827]/90 border border-card-border shadow-lg space-y-4">
              <h2 className="text-base font-bold text-white">Correlation Threshold Optimization</h2>
              <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
                <p className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
                  <strong>Recommendation:</strong> {data.parameter_sweep.recommendation}
                </p>
                <div className="grid grid-cols-2 gap-3 font-mono">
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-400 block">Verification Threshold</span>
                    <strong className="text-cyan-400 text-sm">{data.parameter_sweep.optimal_correlation_threshold}</strong>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-400 block">Infrastructure Jaccard Weight</span>
                    <strong className="text-cyan-400 text-sm">{data.parameter_sweep.optimal_jaccard_weight}</strong>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="p-12 text-center rounded-2xl bg-[#111827]/60 border border-card-border">
          <BarChart3 className="w-12 h-12 text-slate-500 mx-auto mb-3" />
          <h2 className="text-base font-bold text-slate-200">Run Evaluation Benchmark</h2>
          <p className="text-xs text-slate-400 max-w-md mx-auto mt-1 mb-4">
            Click 'Run Benchmark Suite' to execute automated evaluations against synthetic incidents and negative controls.
          </p>
          <button
            onClick={runEval}
            className="px-6 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold uppercase tracking-wider transition"
          >
            Start Benchmark
          </button>
        </div>
      )}
    </div>
  );
};
