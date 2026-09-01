import React from 'react';
import {
  LayoutDashboard,
  Search,
  AlertTriangle,
  Flame,
  Network,
  Crosshair,
  ShieldAlert,
  BarChart3,
  FileText,
  Sparkles,
} from 'lucide-react';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  emergingCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, setActiveTab, emergingCount = 0 }) => {
  const navItems = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: LayoutDashboard },
    { id: 'investigate', label: 'Universal Search', icon: Search },
    { id: 'incidents', label: 'Incidents & Scam DNA', icon: AlertTriangle },
    { id: 'campaigns', label: 'Threat Campaigns', icon: Flame, badge: emergingCount > 0 ? `${emergingCount} New` : undefined },
    { id: 'graph', label: 'Threat Graph', icon: Network },
    { id: 'hunting', label: 'Threat Hunting', icon: Crosshair },
    { id: 'attack', label: 'MITRE ATT&CK', icon: ShieldAlert },
    { id: 'evaluation', label: 'Evaluation & Benchmarks', icon: BarChart3 },
    { id: 'reports', label: 'Intelligence Reports', icon: FileText },
  ];

  return (
    <aside className="w-64 border-r border-card-border bg-[#0e1422] flex flex-col justify-between p-4 shrink-0">
      <div className="space-y-1">
        <p className="px-3 py-2 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
          Intelligence Workspace
        </p>
        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-medium transition ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/10 text-cyan-300 border border-cyan-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span className="px-2 py-0.5 text-[10px] font-semibold rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30 animate-pulse">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Grounded AI Badge */}
      <div className="p-3.5 rounded-xl bg-gradient-to-b from-slate-800/80 to-slate-900/80 border border-slate-700/80">
        <div className="flex items-center space-x-2 text-xs font-semibold text-slate-200 mb-1">
          <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
          <span>Evidence-Grounded AI</span>
        </div>
        <p className="text-[11px] text-slate-400 leading-relaxed">
          Deterministic correlation enforced. No hallucinations or unverified campaign assertions.
        </p>
      </div>
    </aside>
  );
};
