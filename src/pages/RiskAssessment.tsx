import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { UserRiskProfile, DetectionResult } from '../types';
import {
  ShieldAlert,
  Flame,
  AlertTriangle,
  CheckCircle2,
  Users,
  Search,
  Filter,
  Calculator,
  Info
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid
} from 'recharts';

export const RiskAssessment: React.FC = () => {
  const [profiles, setProfiles] = useState<UserRiskProfile[]>([]);
  const [results, setResults] = useState<DetectionResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchUser, setSearchUser] = useState('');
  const [selectedUser, setSelectedUser] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        const [riskRes, detRes] = await Promise.all([
          api.getRiskSummary(),
          api.getDetectionResults({ limit: 100 })
        ]);
        setProfiles(riskRes.user_profiles);
        setResults(detRes);
        if (riskRes.user_profiles.length > 0) {
          setSelectedUser(riskRes.user_profiles[0].user_id);
        }
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const filteredProfiles = profiles.filter((p) =>
    searchUser === '' || p.user_id.toLowerCase().includes(searchUser.toLowerCase())
  );

  const activeUserLogs = results.filter((r) => r.user_id === selectedUser);

  const chartData = profiles.slice(0, 8).map((p) => ({
    user: p.user_id.replace('usr_', ''),
    avgScore: p.avg_score,
    maxScore: p.max_score,
    highRisk: p.high_risk
  }));

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Risk Scoring Methodology Card */}
      <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-[#1E2D4A]">
          <div className="flex items-center gap-2">
            <Calculator className="w-4 h-4 text-[#22D3EE]" />
            <h3 className="text-xs font-semibold text-[#F8FAFC] tracking-tight">
              Transparent Risk Assessment Formulation
            </h3>
          </div>
          <span className="text-[11px] font-mono text-[#38BDF8]">
            Multi-factor Quantitative Synthesis
          </span>
        </div>

        <div className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg font-mono text-xs text-[#22D3EE] overflow-x-auto">
          Risk = (0.40 × ML_Score) + (0.25 × ActionRisk) + (0.20 × ResourceSensitivity) + (0.10 × OffHours) + (0.05 × FailureStatus)
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs pt-1">
          <div className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
            <span className="font-semibold text-[#22C55E]">Normal (&lt; 0.40)</span>
            <p className="text-[#94A3B8] text-[11px] mt-1">
              Routine developer or ops activities occurring within regular business hours on expected resources.
            </p>
          </div>
          <div className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
            <span className="font-semibold text-[#F59E0B]">Medium Risk (0.40 - 0.70)</span>
            <p className="text-[#94A3B8] text-[11px] mt-1">
              Minor behavioural drift, off-hours read operations, or mild deviation from user historical patterns.
            </p>
          </div>
          <div className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
            <span className="font-semibold text-[#EF4444]">High Risk (&gt;= 0.70)</span>
            <p className="text-[#94A3B8] text-[11px] mt-1">
              Privilege escalation, bulk customer exfiltration, key export attempts, or off-hours administrative bursts.
            </p>
          </div>
        </div>
      </div>

      {/* User Risk Comparison Chart & Profile List */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* User Risk Score Chart */}
        <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl lg:col-span-2 flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-[#1E2D4A]">
            <div>
              <h3 className="text-xs font-semibold text-[#F8FAFC] tracking-tight">
                User Risk Profile Distribution
              </h3>
              <p className="text-[11px] text-[#94A3B8]">
                Average vs Maximum anomaly score per monitored user identity
              </p>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <span className="flex items-center gap-1.5 text-[#94A3B8]">
                <span className="w-2 h-2 rounded-sm bg-[#38BDF8]" /> Avg Score
              </span>
              <span className="flex items-center gap-1.5 text-[#94A3B8]">
                <span className="w-2 h-2 rounded-sm bg-[#EF4444]" /> Max Score
              </span>
            </div>
          </div>

          <div className="h-64 mt-4">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E2D4A" vertical={false} />
                <XAxis dataKey="user" stroke="#64748B" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748B" fontSize={11} tickLine={false} domain={[0, 1]} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#111C2E', borderColor: '#1E2D4A', borderRadius: '8px', color: '#F8FAFC' }}
                />
                <Bar dataKey="avgScore" fill="#38BDF8" radius={[3, 3, 0, 0]} />
                <Bar dataKey="maxScore" fill="#EF4444" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Monitored User Ranking List */}
        <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl flex flex-col space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-[#1E2D4A]">
            <h3 className="text-xs font-semibold text-[#F8FAFC] tracking-tight">
              User Risk Registry
            </h3>
            <span className="text-[11px] font-mono text-[#94A3B8]">
              {profiles.length} Users
            </span>
          </div>

          <div className="flex items-center gap-2 bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-2.5 py-1 text-xs">
            <Search className="w-3 h-3 text-[#94A3B8]" />
            <input
              type="text"
              placeholder="Filter identities..."
              value={searchUser}
              onChange={(e) => setSearchUser(e.target.value)}
              className="bg-transparent text-[#F8FAFC] placeholder-[#64748B] focus:outline-none w-full text-xs"
            />
          </div>

          <div className="flex-1 overflow-y-auto space-y-2 max-h-[300px] pr-1">
            {filteredProfiles.map((p) => {
              const isSelected = selectedUser === p.user_id;
              return (
                <div
                  key={p.user_id}
                  onClick={() => setSelectedUser(p.user_id)}
                  className={`p-3 rounded-lg border text-xs cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-[#1E2F4C] border-[#2563EB]'
                      : 'bg-[#111C2E] border-[#1E2D4A] hover:bg-[#1E2F4C]/50'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-[#F8FAFC]">{p.user_id}</span>
                    <span
                      className={`font-semibold ${
                        p.high_risk > 0 ? 'text-[#EF4444]' : 'text-[#22C55E]'
                      }`}
                    >
                      {p.high_risk > 0 ? `${p.high_risk} High Risk` : 'Nominal'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between mt-1 text-[11px] text-[#94A3B8] font-mono">
                    <span>Events: {p.total_events}</span>
                    <span>Max Score: {p.max_score.toFixed(2)}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Selected User Activity History Table */}
      {selectedUser && (
        <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-[#1E2D4A]">
            <div>
              <h3 className="text-xs font-semibold text-[#F8FAFC] tracking-tight">
                Activity Audit Trail for <span className="text-[#22D3EE] font-mono">{selectedUser}</span>
              </h3>
              <p className="text-[11px] text-[#94A3B8]">
                Historical execution sequence and risk evaluations
              </p>
            </div>
            <span className="text-xs font-mono text-[#94A3B8]">
              {activeUserLogs.length} Records
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#1E2D4A] text-[#94A3B8]">
                  <th className="py-2 px-3 font-medium">Timestamp</th>
                  <th className="py-2 px-3 font-medium">Action</th>
                  <th className="py-2 px-3 font-medium">Resource</th>
                  <th className="py-2 px-3 font-medium">IP Address</th>
                  <th className="py-2 px-3 font-medium text-right">Anomaly Score</th>
                  <th className="py-2 px-3 font-medium text-right">Assigned Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1E2D4A]">
                {activeUserLogs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-4 text-center text-[#94A3B8]">
                      No detailed logs recorded for this user.
                    </td>
                  </tr>
                ) : (
                  activeUserLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-[#1E2F4C] transition-colors">
                      <td className="py-2 px-3 font-mono text-[#94A3B8]">{log.timestamp}</td>
                      <td className="py-2 px-3 font-mono text-[#22D3EE]">{log.action}</td>
                      <td className="py-2 px-3 text-[#F8FAFC]">{log.resource}</td>
                      <td className="py-2 px-3 font-mono text-[#94A3B8]">{log.source_ip}</td>
                      <td className="py-2 px-3 font-mono tabular-nums text-right text-[#F8FAFC]">
                        {log.anomaly_score.toFixed(2)}
                      </td>
                      <td className="py-2 px-3 text-right">
                        <span
                          className={`font-semibold ${
                            log.risk_level === 'High Risk'
                              ? 'text-[#EF4444]'
                              : log.risk_level === 'Medium Risk'
                              ? 'text-[#F59E0B]'
                              : 'text-[#22C55E]'
                          }`}
                        >
                          {log.risk_level}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
