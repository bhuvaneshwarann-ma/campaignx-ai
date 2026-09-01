import React, { useState } from 'react';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { EvidenceDrawer, EvidenceRecord } from './components/EvidenceDrawer';
import { AIInvestigatorPanel } from './components/AIInvestigatorPanel';

import { DashboardPage } from './pages/DashboardPage';
import { UniversalSearchPage } from './pages/UniversalSearchPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { CampaignsPage } from './pages/CampaignsPage';
import { ThreatHuntingPage } from './pages/ThreatHuntingPage';
import { EvaluationPage } from './pages/EvaluationPage';
import { AttackExplorerPage } from './pages/AttackExplorerPage';
import { ReportsPage } from './pages/ReportsPage';
import { ThreatGraphView } from './components/ThreatGraphView';

export function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedCampaignId, setSelectedCampaignId] = useState<string | undefined>();
  const [evidenceDrawerOpen, setEvidenceDrawerOpen] = useState(false);
  const [currentEvidence, setCurrentEvidence] = useState<EvidenceRecord | null>(null);
  const [aiPanelOpen, setAiPanelOpen] = useState(true);

  const handleOpenEvidence = (ev: EvidenceRecord) => {
    setCurrentEvidence(ev);
    setEvidenceDrawerOpen(true);
  };

  const handleSelectCampaign = (id: string) => {
    setSelectedCampaignId(id);
    setActiveTab('campaigns');
  };

  return (
    <div className="flex flex-col h-screen w-screen bg-[#0b0f17] text-slate-100 overflow-hidden font-sans">
      {/* Top Header */}
      <Header
        onOpenSearch={() => setActiveTab('investigate')}
        onOpenReportModal={() => setActiveTab('reports')}
        isOffline={true}
        aiPanelOpen={aiPanelOpen}
        onToggleAIPanel={() => setAiPanelOpen(!aiPanelOpen)}
      />

      {/* Main App Layout */}
      <div className="flex flex-1 min-h-0 overflow-hidden">
        {/* Left Navigation Sidebar */}
        <Sidebar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          emergingCount={1}
        />

        {/* Center Workspace */}
        <main className="flex-1 flex flex-col min-w-0 overflow-y-auto bg-[#0b0f17] relative">
          {activeTab === 'dashboard' && (
            <DashboardPage
              onSelectCampaign={handleSelectCampaign}
              onOpenSearch={() => setActiveTab('investigate')}
            />
          )}

          {activeTab === 'investigate' && (
            <UniversalSearchPage onOpenEvidence={handleOpenEvidence} />
          )}

          {activeTab === 'incidents' && (
            <IncidentsPage onOpenEvidence={handleOpenEvidence} />
          )}

          {activeTab === 'campaigns' && (
            <CampaignsPage
              selectedCampaignId={selectedCampaignId}
              onOpenEvidence={handleOpenEvidence}
            />
          )}

          {activeTab === 'hunting' && (
            <ThreatHuntingPage onOpenEvidence={handleOpenEvidence} />
          )}

          {activeTab === 'graph' && (
            <div className="flex-1 p-6 flex flex-col space-y-4 h-full">
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="text-2xl font-extrabold text-white tracking-tight">Global Threat Intelligence Graph</h1>
                  <p className="text-xs text-slate-400">Interactive topology connecting indicators, campaigns, and adversary techniques</p>
                </div>
              </div>
              <div className="flex-1 min-h-[550px] w-full rounded-2xl overflow-hidden border border-card-border">
                <ThreatGraphView
                  graphData={{
                    nodes: [
                      { id: 'CAM-001', data: { label: 'State Bank KYC Syndicate', type: 'Campaign', risk_score: 95 } },
                      { id: '+919876543210', data: { label: '+919876543210', type: 'Phone', risk_score: 90 } },
                      { id: 'sbikyc.verify@okhdfcbank', data: { label: 'sbikyc.verify@okhdfcbank', type: 'UPI', risk_score: 94 } },
                      { id: 'sbi-kyc-verify-online.com', data: { label: 'sbi-kyc-verify-online.com', type: 'Domain', risk_score: 96 } },
                      { id: '185.220.101.5', data: { label: '185.220.101.5', type: 'IP', risk_score: 92 } },
                      { id: 'FakeBank APK Stealer', data: { label: 'FakeBank APK Stealer', type: 'Malware', risk_score: 95 } },
                      { id: 'PhantomRaven', data: { label: 'PhantomRaven', type: 'ThreatActor', risk_score: 98 } },
                      { id: 'T1566.002', data: { label: 'Spearphishing Link (T1566.002)', type: 'ATT&CK', risk_score: 80 } },
                    ],
                    edges: [
                      { id: 'e1', source: 'CAM-001', target: '+919876543210', label: 'USES_PHONE' },
                      { id: 'e2', source: 'CAM-001', target: 'sbikyc.verify@okhdfcbank', label: 'USES_UPI' },
                      { id: 'e3', source: 'CAM-001', target: 'sbi-kyc-verify-online.com', label: 'USES_DOMAIN' },
                      { id: 'e4', source: 'sbi-kyc-verify-online.com', target: '185.220.101.5', label: 'RESOLVES_TO' },
                      { id: 'e5', source: '185.220.101.5', target: 'FakeBank APK Stealer', label: 'DELIVERS' },
                      { id: 'e6', source: 'FakeBank APK Stealer', target: 'PhantomRaven', label: 'ATTRIBUTED_TO' },
                      { id: 'e7', source: 'PhantomRaven', target: 'T1566.002', label: 'USES_TECHNIQUE' },
                    ],
                    stats: { node_count: 8, edge_count: 7, density: 0.125 },
                  }}
                  onNodeClick={(id) => handleOpenEvidence({
                    claim: `Threat graph node ${id} selected for deep evidence pivot.`,
                    type: 'OBSERVED',
                    source: 'Threat Graph Engine',
                    confidence: 0.96,
                    supporting_elements: [id]
                  })}
                />
              </div>
            </div>
          )}

          {activeTab === 'attack' && (
            <AttackExplorerPage onOpenEvidence={handleOpenEvidence} />
          )}

          {activeTab === 'evaluation' && (
            <EvaluationPage />
          )}

          {activeTab === 'reports' && (
            <ReportsPage />
          )}
        </main>

        {/* Collapsible Right AI Investigator Assistant */}
        {aiPanelOpen && (
          <AIInvestigatorPanel
            currentCampaignId={selectedCampaignId}
            onClose={() => setAiPanelOpen(false)}
          />
        )}
      </div>

      {/* Slide-out Evidence Drawer */}
      <EvidenceDrawer
        isOpen={evidenceDrawerOpen}
        onClose={() => setEvidenceDrawerOpen(false)}
        evidence={currentEvidence}
      />
    </div>
  );
}

