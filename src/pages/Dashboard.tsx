import React from 'react';
import { DashboardData, DetectionResult } from '../types';
import { PageId } from '../components/Navigation';
import {
  FileText,
  Users,
  ShieldCheck,
  AlertTriangle,
  Flame,
  Activity,
  Zap,
  Cpu,
  ArrowRight
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid
} from 'recharts';

interface DashboardProps {
  data: DashboardData | null;
  loading: boolean;
  onNavigate: (page: PageId) => void;
  onSelectResult: (result: DetectionResult) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  data,
  loading,
  onNavigate,
  onSelectResult,
}) => {
  if (loading || !data) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[400px]">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-[#2563EB] border-t-transparent rounded-full animate-spin" />
          <p className="text-xs text-[#94A3B8]">Loading SOC telemetry...</p>
        </div>
      </div>
    );
  }

  const { summary, risk_distribution, model_status, recent_suspicious } = data;

  const summaryCards = [
    {
      title: 'Total Audit Logs',
      value: summary.total_audit_logs,
      icon: FileText,
      color: 'text-[#22D3EE]',
      border: 'border-[#1E2D4A]',
      page: 'logs' as PageId
    },
    {
      title: 'Monitored Users',
      value: summary.monitored_users,
      icon: Users,
      color: 'text-[#38BDF8]',
      border: 'border-[#1E2D4A]',
      page: 'risk' as PageId
    },
    {
      title: 'Normal Activities',
      value: summary.normal_activities,
      icon: ShieldCheck,
      color: 'text-[#22C55E]',
      border: 'border-[#1E2D4A]',
      page: 'logs' as PageId
    },
    {
      title: 'Suspicious Activities',
      value: summary.suspicious_activities,
      icon: AlertTriangle,
      color: 'text-[#F59E0B]',
      border: 'border-[#1E2D4A]',
      page: 'threats' as PageId
    },
    {
      title: 'High-Risk Events',
      value: summary.high_risk_events,
      icon: Flame,
      color: 'text-[#EF4444]',
      border: 'border-[#EF4444]/30',
      page: 'threats' as PageId
    },
    {
      title: 'Active Incidents',
      value: summary.active_incidents,
      icon: Activity,
      color: 'text-[#A855F7]',
      border: 'border-[#1E2D4A]',
      page: 'incidents' as PageId
    },
    {
      title: 'FaaS Invocations',
      value: summary.faas_invocations,
      icon: Zap,
      color: 'text-[#FBBF24]',
      border: 'border-[#1E2D4A]',
      page: 'faas' as PageId
    },
    {
      title: 'Anomalous FaaS',
      value: summary.anomalous_faas,
      icon: Cpu,
      color: 'text-[#F43F5E]',
      border: 'border-[#1E2D4A]',
      page: 'faas' as PageId
    },
  ];

  // Timeline representation
  const timelineData = [
    { time: '08:00', normal: 12, suspicious: 0 },
    { time: '10:00', normal: 18, suspicious: 1 },
    { time: '12:00', normal: 15, suspicious: 0 },
    { time: '14:00', normal: 22, suspicious: 1 },
    { time: '16:00', normal: 19, suspicious: 0 },
    { time: '18:00', normal: 8, suspicious: 0 },
    { time: '20:00', normal: 3, suspicious: 1 },
    { time: '22:00', normal: 1, suspicious: 3 },
    { time: '00:00', normal: 0, suspicious: 5 },
    { time: '02:00', normal: 1, suspicious: 4 },
  ];

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* 8-Metric Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {summaryCards.map((card, i) => {
          const Icon = card.icon;
          return (
            <div
              key={i}
              onClick={() => onNavigate(card.page)}
              className={`p-4 bg-[#17243A] border ${card.border} rounded-xl hover:bg-[#1E2F4C] transition-all cursor-pointer shadow-sm`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs text-[#94A3B8] font-medium">{card.title}</span>
                <Icon className={`w-4 h-4 ${card.color}`} />
              </div>
              <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-[#F8FAFC]">
                {card.value.toLocaleString()}
              </div>
            </div>
          );
        })}
      </div>

      {/* Charts & Model Overview Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Distribution Donut Chart */}
        <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-[#1E2D4A]">
            <h3 className="text-xs font-semibold text-[#F8FAFC] tracking-tight">
              Risk Distribution
            </h3>
            <span className="text-[11px] text-[#94A3B8] font-mono">
              Empirical ML Breakdown
            </span>
          </div>

          <div className="h-48 my-auto relative">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={risk_distribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {risk_distribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#111C2E', borderColor: '#1E2D4A', borderRadius: '8px', color: '#F8FAFC' }}
                  itemStyle={{ color: '#F8FAFC' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="pt-3 border-t border-[#1E2D4A] flex justify-around text-xs">
            {risk_distribution.map((r) => (
              <div key={r.name} className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: r.color }} />
                <span className="text-[#94A3B8]">{r.name}:</span>
                <span className="font-mono tabular-nums font-semibold text-[#F8FAFC]">{r.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Activity Timeline Bar Chart */}
        <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl flex flex-col lg:col-span-2">
          <div className="flex items-center justify-between pb-3 border-b border-[#1E2D4A]">
            <div>
              <h3 className="text-xs font-semibold text-[#F8FAFC] tracking-tight">
                Activity & Anomaly Timeline (24h)
              </h3>
              <p className="text-[11px] text-[#94A3B8]">
                Normal access vs off-hours suspicious spikes
              </p>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <span className="flex items-center gap-1.5 text-[#94A3B8]">
                <span className="w-2 h-2 rounded-sm bg-[#22C55E]" /> Normal
              </span>
              <span className="flex items-center gap-1.5 text-[#94A3B8]">
                <span className="w-2 h-2 rounded-sm bg-[#EF4444]" /> Suspicious
              </span>
            </div>
          </div>

          <div className="h-56 mt-3">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={timelineData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E2D4A" vertical={false} />
                <XAxis dataKey="time" stroke="#64748B" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748B" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#111C2E', borderColor: '#1E2D4A', borderRadius: '8px', color: '#F8FAFC' }}
                />
                <Bar dataKey="normal" fill="#22C55E" stackId="a" radius={[0, 0, 0, 0]} />
                <Bar dataKey="suspicious" fill="#EF4444" stackId="a" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Model Status Card & Recent Flagged Events */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Model Status Overview */}
        <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-[#1E2D4A]">
            <h3 className="text-xs font-semibold text-[#F8FAFC] tracking-tight">
              Model Engine Status
            </h3>
            <button
              onClick={() => onNavigate('detection')}
              className="text-xs text-[#22D3EE] hover:underline flex items-center gap-1"
            >
              <span>Configure</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-3 text-xs">
            <div className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
              <div className="flex items-center justify-between">
                <span className="font-medium text-[#F8FAFC]">Isolation Forest (Baseline)</span>
                <span className="font-mono text-[11px] text-[#22C55E]">Ready & Active</span>
              </div>
              <p className="text-[11px] text-[#94A3B8] mt-1">
                Ensemble of 100 randomized trees calculating path length anomaly score.
              </p>
            </div>

            <div className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
              <div className="flex items-center justify-between">
                <span className="font-medium text-[#F8FAFC]">LSTM Sequential Autoencoder</span>
                <span className="font-mono text-[11px] text-[#22D3EE]">Trained (PyTorch)</span>
              </div>
              <p className="text-[11px] text-[#94A3B8] mt-1">
                Temporal sequence sliding window (W=5) detecting behavioral transition drift.
              </p>
            </div>

            <div className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
              <div className="flex items-center justify-between">
                <span className="font-medium text-[#F8FAFC]">Adaptive Policy Optimizer</span>
                <span className="font-mono text-[11px] text-[#38BDF8]">Cost-Aware</span>
              </div>
              <p className="text-[11px] text-[#94A3B8] mt-1">
                Multi-objective utility balancing security reduction against operational cost.
              </p>
            </div>
          </div>
        </div>

        {/* Recent Suspicious Events Table */}
        <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl lg:col-span-2 flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-[#1E2D4A]">
            <div>
              <h3 className="text-xs font-semibold text-[#F8FAFC] tracking-tight">
                Recent Suspicious Activity Alerts
              </h3>
              <p className="text-[11px] text-[#94A3B8]">
                Audit log anomalies flagged for human security investigation
              </p>
            </div>
            <button
              onClick={() => onNavigate('threats')}
              className="text-xs text-[#22D3EE] hover:underline flex items-center gap-1"
            >
              <span>View All</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="mt-3 flex-1 overflow-x-auto">
            {recent_suspicious.length === 0 ? (
              <div className="py-8 text-center text-xs text-[#94A3B8]">
                No suspicious events detected. All activities within normal baseline.
              </div>
            ) : (
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-[#1E2D4A] text-[#94A3B8]">
                    <th className="py-2 px-3 font-medium">Timestamp</th>
                    <th className="py-2 px-3 font-medium">User</th>
                    <th className="py-2 px-3 font-medium">Action</th>
                    <th className="py-2 px-3 font-medium">Resource</th>
                    <th className="py-2 px-3 font-medium text-right">Score</th>
                    <th className="py-2 px-3 font-medium text-right">Risk</th>
                    <th className="py-2 px-3 font-medium text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1E2D4A]">
                  {recent_suspicious.map((event) => (
                    <tr
                      key={event.id}
                      className="hover:bg-[#1E2F4C] transition-colors"
                    >
                      <td className="py-2 px-3 font-mono text-[#94A3B8] whitespace-nowrap">
                        {event.timestamp}
                      </td>
                      <td className="py-2 px-3 font-medium text-[#F8FAFC]">
                        {event.user_id}
                      </td>
                      <td className="py-2 px-3 font-mono text-[#22D3EE]">
                        {event.action}
                      </td>
                      <td className="py-2 px-3 text-[#94A3B8] truncate max-w-[120px]">
                        {event.resource}
                      </td>
                      <td className="py-2 px-3 font-mono tabular-nums text-right text-[#F8FAFC]">
                        {event.anomaly_score.toFixed(2)}
                      </td>
                      <td className="py-2 px-3 text-right">
                        <span
                          className={`font-semibold ${
                            event.risk_level === 'High Risk'
                              ? 'text-[#EF4444]'
                              : event.risk_level === 'Medium Risk'
                              ? 'text-[#F59E0B]'
                              : 'text-[#22C55E]'
                          }`}
                        >
                          {event.risk_level}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-right">
                        <button
                          onClick={() => {
                            onSelectResult(event);
                            onNavigate('threats');
                          }}
                          className="px-2 py-1 text-[11px] font-medium text-[#22D3EE] bg-[#111C2E] hover:bg-[#2563EB] hover:text-white rounded transition-colors"
                        >
                          Investigate
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
