import React, { useEffect, useState } from 'react';
import { UserPlus } from 'lucide-react';
import { api } from '../services/api';
import type { AuditTrailEntry, AuthUser, UserRole } from '../types/security';
import { DataStateWrapper, SectionHeader, StatusText, SurfacePanel } from '../components/ui/SocPrimitives';

export function SettingsUsersPage({
  currentUser,
  onSwitchUser,
}: {
  currentUser: AuthUser;
  onSwitchUser: (user: AuthUser) => void;
}) {
  const [users, setUsers] = useState<AuthUser[]>([]);
  const [auditTrail, setAuditTrail] = useState<AuditTrailEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);

  // Create user form
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<UserRole>('Security Analyst');
  const [department, setDepartment] = useState('SOC Tier-1');

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getUsersAndTrail();
      setUsers(res.users);
      setAuditTrail(res.auditTrail);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load user management data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setFeedback(null);
    try {
      const res = await api.createUser({ full_name: fullName, email, role, department });
      setUsers((prev) => [...prev, res.user]);
      setFullName('');
      setEmail('');
      setFeedback(`Provisioned ${res.user.full_name} (${res.user.role}).`);
      await loadData();
    } catch (err) {
      setFeedback(err instanceof Error ? err.message : 'Failed to create user.');
    }
  };

  const handleRoleChange = async (userId: string, nextRole: UserRole) => {
    setFeedback(null);
    try {
      const res = await api.updateUser(userId, { role: nextRole });
      setUsers((prev) => prev.map((u) => (u.user_id === userId ? res.user : u)));
      setFeedback(`Updated role for ${res.user.full_name} to ${nextRole}.`);
      await loadData();
    } catch (err) {
      setFeedback(err instanceof Error ? err.message : 'Role update failed.');
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Settings, RBAC User Management & Audit Trail"
        description="Manage Admin, Security Analyst, and Viewer access roles, test RBAC enforcement by switching active session profiles, and inspect immutable administrative audit logs."
      />

      {feedback && (
        <div className="px-4 py-2 bg-slate-900 border border-indigo-500/40 rounded text-xs text-indigo-200">
          {feedback}
        </div>
      )}

      <DataStateWrapper loading={loading} error={error} onRetry={loadData}>
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
          <SurfacePanel
            title="Platform Users & RBAC Session Switcher"
            subtitle="Click 'Sign In As' to verify RBAC restrictions across Admin, Security Analyst, and Viewer roles"
            className="xl:col-span-2"
          >
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2.5 pr-3 font-medium">User</th>
                    <th className="py-2.5 pr-3 font-medium">Department</th>
                    <th className="py-2.5 pr-3 font-medium">Role</th>
                    <th className="py-2.5 pr-3 font-medium">Status</th>
                    <th className="py-2.5 font-medium text-right">Session Control</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {users.map((u) => (
                    <tr key={u.user_id} className="hover:bg-slate-800/40">
                      <td className="py-2.5 pr-3">
                        <div className="font-medium text-slate-100">{u.full_name}</div>
                        <div className="font-mono text-[11px] text-slate-400">{u.email}</div>
                      </td>
                      <td className="py-2.5 pr-3 text-slate-300">{u.department}</td>
                      <td className="py-2.5 pr-3">
                        <select
                          value={u.role}
                          disabled={currentUser.role !== 'Admin' || u.user_id === currentUser.user_id}
                          onChange={(e) => handleRoleChange(u.user_id, e.target.value as UserRole)}
                          className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 disabled:opacity-60"
                        >
                          <option value="Admin">Admin</option>
                          <option value="Security Analyst">Security Analyst</option>
                          <option value="Viewer">Viewer</option>
                        </select>
                      </td>
                      <td className="py-2.5 pr-3">
                        <StatusText status={u.is_active ? 'Active' : 'Inactive'} />
                      </td>
                      <td className="py-2.5 text-right">
                        {currentUser.user_id === u.user_id ? (
                          <span className="font-mono text-[11px] text-emerald-400">Active Session</span>
                        ) : (
                          <button
                            type="button"
                            onClick={() => onSwitchUser(u)}
                            className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-100 rounded border border-slate-700 transition-colors whitespace-nowrap"
                          >
                            Sign In As
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </SurfacePanel>

          <SurfacePanel title="Provision New User" subtitle="Admin role required">
            <form onSubmit={handleCreateUser} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 mb-1">Full Name</label>
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Nadia Alvarez"
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                />
              </div>
              <div>
                <label className="block text-slate-300 mb-1">Email</label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="n.alvarez@cloudsentinel.local"
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                />
              </div>
              <div>
                <label className="block text-slate-300 mb-1">RBAC Role</label>
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value as UserRole)}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                >
                  <option value="Security Analyst">Security Analyst</option>
                  <option value="Viewer">Viewer</option>
                  <option value="Admin">Admin</option>
                </select>
              </div>
              <div>
                <label className="block text-slate-300 mb-1">Department</label>
                <input
                  type="text"
                  value={department}
                  onChange={(e) => setDepartment(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                />
              </div>
              <button
                type="submit"
                disabled={currentUser.role !== 'Admin'}
                className="w-full inline-flex items-center justify-center gap-2 py-2 px-4 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium rounded transition-colors"
              >
                <UserPlus className="w-3.5 h-3.5" />
                Provision User
              </button>
              {currentUser.role !== 'Admin' && (
                <p className="text-[11px] text-amber-400">Only Admin accounts can provision or modify user roles.</p>
              )}
            </form>
          </SurfacePanel>
        </div>

        <SurfacePanel
          title="Administrative & Security Action Audit Trail"
          subtitle="Immutable log of logins, policy approvals, dataset uploads, incident updates, and ML runs"
        >
          <div className="overflow-x-auto max-h-80 overflow-y-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2 pr-3 font-medium">Timestamp (UTC)</th>
                  <th className="py-2 pr-3 font-medium">Actor</th>
                  <th className="py-2 pr-3 font-medium">Role</th>
                  <th className="py-2 pr-3 font-medium">Action Type</th>
                  <th className="py-2 pr-3 font-medium">Target</th>
                  <th className="py-2 font-medium">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {auditTrail.map((entry) => (
                  <tr key={entry.trail_id} className="hover:bg-slate-800/30">
                    <td className="py-2 pr-3 font-mono tabular-nums text-slate-400 whitespace-nowrap">
                      {entry.timestamp.replace('T', ' ').slice(0, 19)}
                    </td>
                    <td className="py-2 pr-3 text-slate-100 whitespace-nowrap">{entry.actor}</td>
                    <td className="py-2 pr-3 text-slate-300 whitespace-nowrap">{entry.actor_role}</td>
                    <td className="py-2 pr-3 font-mono text-indigo-300 whitespace-nowrap">{entry.action_type}</td>
                    <td className="py-2 pr-3 font-mono text-slate-300 whitespace-nowrap">{entry.target}</td>
                    <td className="py-2 text-slate-300">{entry.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </SurfacePanel>
      </DataStateWrapper>
    </div>
  );
}
