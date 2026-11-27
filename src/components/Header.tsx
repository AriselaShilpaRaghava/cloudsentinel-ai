import React from 'react';
import { PageId } from './Navigation';
import { Play, RotateCcw, Server } from 'lucide-react';

interface HeaderProps {
  currentPage: PageId;
  onRunDetection: () => void;
  isRunningDetection: boolean;
  onResetData: () => void;
  openstackConnected: boolean;
}

const PAGE_TITLES: Record<PageId, { title: string; subtitle: string }> = {
  dashboard: { title: 'Security Operations Center', subtitle: 'Real-time cloud audit telemetry & anomaly overview' },
  logs: { title: 'Cloud Audit Logs', subtitle: 'CSV ingestion, validation & audit trail browser' },
  preprocessing: { title: 'Feature Preprocessing', subtitle: 'Temporal parsing, categorical encoding & LSTM sequence generation' },
  detection: { title: 'AI Anomaly Detection', subtitle: 'Isolation Forest baseline & LSTM sequential neural detector' },
  threats: { title: 'Insider Threat Center', subtitle: 'Identified suspicious user activities & behavioral drift' },
  risk: { title: 'Risk Assessment Engine', subtitle: 'Quantitative user risk ranking & transparent formula analysis' },
  faas: { title: 'Serverless (FaaS) Monitoring', subtitle: 'Function execution duration, permissions & anomalous invocations' },
  policies: { title: 'Adaptive Security Policy Optimization', subtitle: 'Cost-aware risk reduction vs operational overhead trade-off' },
  openstack: { title: 'OpenStack Private Cloud Testbed', subtitle: 'Keystone, Nova, Swift, Neutron & Ceilometer integration adapter' },
  incidents: { title: 'Incident Response & Case Management', subtitle: 'SOC investigation notes, severity tracking & triage status' },
  performance: { title: 'Model Performance & Evaluation', subtitle: 'Empirical anomaly metrics, confusion matrix & latency' },
  reports: { title: 'Audit Reports & Compliance', subtitle: 'Automated executive summary & CSV compliance export' },
  settings: { title: 'System Settings & Health', subtitle: 'Database status, runtime environment & demo controls' },
};

export const Header: React.FC<HeaderProps> = ({
  currentPage,
  onRunDetection,
  isRunningDetection,
  onResetData,
  openstackConnected,
}) => {
  const current = PAGE_TITLES[currentPage] || { title: 'CloudSentinel AI', subtitle: 'SOC Monitor' };

  return (
    <header className="h-16 px-6 bg-[#0B1220] border-b border-[#1E2D4A] flex items-center justify-between gap-8 shrink-0 z-10">
      {/* Zone 1: Contextual Title & Breadcrumb */}
      <div className="flex items-center gap-3 min-w-0">
        <div>
          <h2 className="text-sm font-semibold text-[#F8FAFC] tracking-tight truncate">
            {current.title}
          </h2>
          <p className="text-xs text-[#94A3B8] truncate hidden sm:block">
            {current.subtitle}
          </p>
        </div>
      </div>

      {/* Zone 2: OpenStack Testbed Status Indicator */}
      <div className="hidden lg:flex items-center gap-2 px-3 py-1 bg-[#111C2E] border border-[#1E2D4A] rounded-md text-xs">
        <Server className="w-3.5 h-3.5 text-[#22D3EE]" />
        <span className="text-[#94A3B8]">Testbed:</span>
        <span className="font-mono text-[#F8FAFC]">
          {openstackConnected ? 'OpenStack Active' : 'OpenStack Simulation Mode'}
        </span>
      </div>

      {/* Zone 3: Primary Action Controls */}
      <div className="flex items-center gap-3 shrink-0">
        <button
          onClick={onResetData}
          title="Reset database to default state"
          className="px-3 py-1.5 text-xs font-medium text-[#94A3B8] hover:text-[#F8FAFC] bg-[#17243A] hover:bg-[#1E2F4C] border border-[#1E2D4A] rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Reset</span>
        </button>

        <button
          onClick={onRunDetection}
          disabled={isRunningDetection}
          className="px-3.5 py-1.5 text-xs font-medium text-white bg-[#2563EB] hover:bg-[#1D4ED8] rounded-lg transition-colors shadow-sm shadow-[#2563EB]/40 flex items-center gap-1.5 whitespace-nowrap disabled:opacity-50"
        >
          <Play className={`w-3.5 h-3.5 fill-current ${isRunningDetection ? 'animate-pulse' : ''}`} />
          <span>{isRunningDetection ? 'Analyzing...' : 'Run Detection'}</span>
        </button>
      </div>
    </header>
  );
};
