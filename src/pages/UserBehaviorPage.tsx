import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import type { UserBehaviorProfile } from '../types/security';
import { DataStateWrapper, SectionHeader, SeverityText, SurfacePanel } from '../components/ui/SocPrimitives';

export function UserBehaviorPage() {
  const [profiles, setProfiles] = useState<UserBehaviorProfile[]>([]);
  const [selectedUser, setSelectedUser] = useState<UserBehaviorProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadProfiles = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getUbaProfiles();
      setProfiles(res.profiles);
      setSelectedUser((prev) =>
        prev ? res.profiles.find((p) => p.user_id === prev.user_id) || res.profiles[0] || null : res.profiles[0] || null,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load user behavior profiles.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadProfiles();
  }, []);

  return (
    <div className="space-y-6">
      <SectionHeader
        title="User Behaviour Analytics (UBA)"
        description="Baseline behavioral profiling across login frequency, operating hours, known IP footprints, API velocity, and transparent risk factor attribution."
      />

      <DataStateWrapper
        loading={loading}
        error={error}
        isEmpty={profiles.length === 0}
        emptyTitle="No user behavior profiles available"
        onRetry={loadProfiles}
      >
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
          <SurfacePanel title="Identity Risk Leaderboard" subtitle="Click an identity to inspect baseline deviations" className="xl:col-span-2">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2.5 pr-3 font-medium">Identity</th>
                    <th className="py-2.5 pr-3 font-medium">Privilege</th>
                    <th className="py-2.5 pr-3 font-medium">Baseline Hours</th>
                    <th className="py-2.5 pr-3 font-medium text-right">Logins (Base / Obs)</th>
                    <th className="py-2.5 pr-3 font-medium text-right">Anomalies</th>
                    <th className="py-2.5 pr-3 font-medium text-right">Risk Score</th>
                    <th className="py-2.5 font-medium">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {profiles.map((p) => (
                    <tr
                      key={p.user_id}
                      onClick={() => setSelectedUser(p)}
                      className={`cursor-pointer transition-colors ${
                        selectedUser?.user_id === p.user_id ? 'bg-indigo-950/35' : 'hover:bg-slate-800/40'
                      }`}
                    >
                      <td className="py-2.5 pr-3">
                        <div className="font-medium text-slate-100">{p.display_name}</div>
                        <div className="font-mono text-[11px] text-slate-400">{p.user_id}</div>
                      </td>
                      <td className="py-2.5 pr-3 text-slate-300 whitespace-nowrap">{p.privilege_level}</td>
                      <td className="py-2.5 pr-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">{p.normal_hours}</td>
                      <td className="py-2.5 pr-3 text-right font-mono tabular-nums text-slate-300">
                        {p.baseline_login_freq.toFixed(1)} / {p.observed_login_freq}
                      </td>
                      <td className="py-2.5 pr-3 text-right font-mono tabular-nums text-amber-300">{p.anomaly_count}</td>
                      <td className="py-2.5 pr-3 text-right font-mono tabular-nums font-semibold text-slate-100">
                        {p.current_risk_score}
                      </td>
                      <td className="py-2.5">
                        <SeverityText level={p.risk_level} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </SurfacePanel>

          {selectedUser && (
            <div className="space-y-5">
              <SurfacePanel
                title={selectedUser.display_name}
                subtitle={`${selectedUser.department} · ${selectedUser.active_status}`}
              >
                <div className="space-y-4 text-xs">
                  <div className="grid grid-cols-2 gap-3 pb-3 border-b border-slate-800">
                    <div>
                      <span className="text-slate-400 block">Risk Score</span>
                      <span className="text-xl font-mono tabular-nums font-semibold text-slate-100">
                        {selectedUser.current_risk_score}/100
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-400 block">Known vs Observed IPs</span>
                      <span className="font-mono text-[11px] text-slate-300">
                        {selectedUser.known_ips.join(', ') || 'None'} → {selectedUser.observed_ips.join(', ')}
                      </span>
                    </div>
                  </div>

                  {/* Risk Factor Contribution Breakdown */}
                  <div>
                    <div className="font-medium text-slate-200 mb-2">Risk Score Factor Attribution</div>
                    <div className="space-y-2">
                      {[
                        { label: 'Anomaly Signal', val: selectedUser.factor_breakdown.anomaly_contribution },
                        { label: 'Privilege Level', val: selectedUser.factor_breakdown.privilege_contribution },
                        { label: 'Resource Sensitivity', val: selectedUser.factor_breakdown.resource_contribution },
                        { label: 'Action Criticality', val: selectedUser.factor_breakdown.action_contribution },
                        { label: 'Event Frequency', val: selectedUser.factor_breakdown.frequency_contribution },
                        { label: 'Evidence Strength', val: selectedUser.factor_breakdown.evidence_contribution },
                      ].map((f) => (
                        <div key={f.label} className="flex items-center justify-between gap-3">
                          <span className="text-slate-400">{f.label}</span>
                          <div className="flex items-center gap-2 w-36">
                            <div className="flex-1 h-1.5 bg-slate-800 rounded-sm overflow-hidden">
                              <div className="h-full bg-indigo-500" style={{ width: `${Math.min(100, f.val * 2.5)}%` }} />
                            </div>
                            <span className="font-mono tabular-nums text-slate-200 w-9 text-right">+{f.val}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* 24-Hour Activity Distribution */}
                  <div className="pt-2 border-t border-slate-800">
                    <div className="font-medium text-slate-200 mb-2">24-Hour Activity Distribution (UTC)</div>
                    <div className="flex items-end gap-1 h-14">
                      {selectedUser.hourly_activity.map((count, hr) => {
                        const maxH = Math.max(1, ...selectedUser.hourly_activity);
                        const hPct = Math.round((count / maxH) * 100);
                        const offHour = hr < 7 || hr >= 20;
                        return (
                          <div key={hr} className="flex-1 flex flex-col items-center gap-1" title={`${hr}:00 UTC — ${count} events`}>
                            <div className="w-full bg-slate-800/70 rounded-t-sm flex items-end h-10">
                              <div
                                className={`w-full rounded-t-sm ${
                                  count === 0 ? '' : offHour ? 'bg-amber-500' : 'bg-indigo-500'
                                }`}
                                style={{ height: `${count > 0 ? Math.max(18, hPct) : 0}%` }}
                              />
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    <div className="flex justify-between text-[10px] font-mono text-slate-500 mt-1">
                      <span>00:00</span>
                      <span>08:00</span>
                      <span>16:00</span>
                      <span>23:00</span>
                    </div>
                  </div>

                  {/* Recent Activity Timeline */}
                  <div className="pt-2 border-t border-slate-800">
                    <div className="font-medium text-slate-200 mb-2">Recent Activity Timeline</div>
                    <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                      {selectedUser.recent_actions.map((act) => (
                        <div key={act.event_id} className="p-2 bg-slate-950/70 border border-slate-800 rounded">
                          <div className="flex items-center justify-between">
                            <span className={`font-mono font-medium ${act.is_anomalous ? 'text-rose-400' : 'text-indigo-300'}`}>
                              {act.action}
                            </span>
                            <span className="font-mono text-[10px] text-slate-500">
                              {act.event_time.replace('T', ' ').slice(0, 19)}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-400 truncate mt-0.5">
                            {act.resource} · {act.source_ip}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </SurfacePanel>
            </div>
          )}
        </div>
      </DataStateWrapper>
    </div>
  );
}
