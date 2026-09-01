import React from 'react';
import { Shield, Radio, Search, Download, Bot, Sparkles } from 'lucide-react';

interface HeaderProps {
  onOpenSearch: () => void;
  onOpenReportModal: () => void;
  isOffline: boolean;
  aiPanelOpen?: boolean;
  onToggleAIPanel?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  onOpenSearch,
  onOpenReportModal,
  isOffline,
  aiPanelOpen = true,
  onToggleAIPanel,
}) => {
  return (
    <header className="h-16 border-b border-card-border bg-[#0e1422]/90 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-30 shrink-0">
      {/* Brand & Logo */}
      <div className="flex items-center space-x-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-500 flex items-center justify-center shadow-lg shadow-cyan-500/20 shrink-0">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <span className="font-bold text-lg tracking-wide text-white font-mono">
              CAMPAIGNX <span className="text-cyan-400">AI</span>
            </span>
            <span className="px-2 py-0.5 text-[10px] font-semibold tracking-wider uppercase rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              v1.0 SOC
            </span>
          </div>
          <p className="text-[11px] text-slate-400 hidden sm:block">Evidence-Driven Threat & Scam Intelligence</p>
        </div>
      </div>

      {/* Global Actions */}
      <div className="flex items-center space-x-3">
        {/* Universal Search Quick Button */}
        <button
          onClick={onOpenSearch}
          className="hidden md:flex items-center space-x-2 px-3.5 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-slate-300 text-xs transition shadow-sm"
        >
          <Search className="w-3.5 h-3.5 text-cyan-400" />
          <span>Investigate IOC / Message...</span>
          <kbd className="px-1.5 py-0.5 bg-slate-900 text-[10px] text-slate-400 rounded border border-slate-700">⌘K</kbd>
        </button>

        {/* Offline / Online Status Badge */}
        <div className="flex items-center space-x-1.5 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-medium shrink-0">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span>{isOffline ? 'OFFLINE READY' : 'LIVE INTELLIGENCE'}</span>
        </div>

        {/* Export Report Trigger */}
        <button
          onClick={onOpenReportModal}
          className="hidden sm:flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 text-xs font-medium transition shrink-0"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Export STIX</span>
        </button>

        {/* AI Investigator Panel Toggle */}
        {onToggleAIPanel && (
          <button
            onClick={onToggleAIPanel}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition shrink-0 ${
              aiPanelOpen
                ? 'bg-purple-600/30 border border-purple-500/40 text-purple-200'
                : 'bg-slate-800 border border-slate-700 text-slate-300 hover:text-white'
            }`}
          >
            <Bot className="w-3.5 h-3.5 text-cyan-400" />
            <span>AI Copilot</span>
          </button>
        )}
      </div>
    </header>
  );
};

