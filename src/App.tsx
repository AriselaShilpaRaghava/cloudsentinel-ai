import React, { useEffect, useState } from 'react';
import {
  Activity,
  AlertOctagon,
  BarChart3,
  BrainCircuit,
  Cloud,
  DollarSign,
  FileBarChart,
  FileSearch,
  LayoutDashboard,
  Menu,
  Settings,
  ShieldCheck,
  Users,
  X,
} from 'lucide-react';
import { api, setApiSessionUser } from './services/api';
import type { AuthUser } from './types/security';
import { DashboardPage } from './pages/DashboardPage';
import { CloudEnvironmentsPage } from './pages/CloudEnvironmentsPage';
import { AuditLogsPage } from './pages/AuditLogsPage';
import { UserBehaviorPage } from './pages/UserBehaviorPage';
import { ThreatDetectionPage } from './pages/ThreatDetectionPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { SecurityPoliciesPage } from './pages/SecurityPoliciesPage';
import { CostOptimizationPage } from './pages/CostOptimizationPage';
import { ModelEvaluationPage } from './pages/ModelEvaluationPage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsUsersPage } from './pages/SettingsUsersPage';

interface NavItem {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}

const NAV_ITEMS: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'cloud-environments', label: 'Cloud Environments', icon: Cloud },
  { id: 'audit-logs', label: 'Audit Log Monitoring', icon: FileSearch },
  { id: 'user-behavior', label: 'User Behaviour Analytics', icon: Users },
  { id: 'threat-detection', label: 'AI Threat Detection', icon: BrainCircuit },
  { id: 'incidents', label: 'Incident Management', icon: AlertOctagon },
  { id: 'security-policies', label: 'Security Policies', icon: ShieldCheck },
  { id: 'cost-optimization', label: 'Cost Optimization', icon: DollarSign },
  { id: 'model-evaluation', label: 'Model Evaluation', icon: BarChart3 },
  { id: 'reports', label: 'Reports & Analytics', icon: FileBarChart },
  { id: 'settings-users', label: 'Settings & Users', icon: Settings },
];

export default function App() {
  const [activePage, setActivePage] = useState<string>('dashboard');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [directoryUsers, setDirectoryUsers] = useState<AuthUser[]>([]);
  const [currentUser, setCurrentUser] = useState<AuthUser>({
    user_id: 'usr-admin-01',
    username: 's.raghava',
    full_name: 'Shilpa Raghava',
    email: 'admin@cloudsentinel.local',
    role: 'Admin',
    department: 'Security Operations & Cloud Architecture',
    last_login: '2026-11-15T08:42:10Z',
    is_active: true,
  });

  useEffect(() => {
    setApiSessionUser(currentUser);
  }, [currentUser]);

  useEffect(() => {
    api
      .getUsersDirectory()
      .then((res) => {
        if (res.users && res.users.length > 0) {
          setDirectoryUsers(res.users);
          setCurrentUser(res.users[0]);
          setApiSessionUser(res.users[0]);
        }
      })
      .catch(() => {
        // Fallback already initialized
      });
  }, []);

  const handleSwitchUser = async (user: AuthUser) => {
    try {
      const res = await api.login({ user_id: user.user_id });
      setCurrentUser(res.user);
      setApiSessionUser(res.user);
    } catch {
      setCurrentUser(user);
      setApiSessionUser(user);
    }
  };

  const activeNav = NAV_ITEMS.find((n) => n.id === activePage) || NAV_ITEMS[0];

  const renderPage = () => {
    switch (activePage) {
      case 'dashboard':
        return <DashboardPage onNavigate={setActivePage} />;
      case 'cloud-environments':
        return <CloudEnvironmentsPage currentUser={currentUser} />;
      case 'audit-logs':
        return <AuditLogsPage currentUser={currentUser} />;
      case 'user-behavior':
        return <UserBehaviorPage />;
      case 'threat-detection':
        return <ThreatDetectionPage currentUser={currentUser} onNavigate={setActivePage} />;
      case 'incidents':
        return <IncidentsPage currentUser={currentUser} />;
      case 'security-policies':
        return <SecurityPoliciesPage currentUser={currentUser} />;
      case 'cost-optimization':
        return <CostOptimizationPage currentUser={currentUser} />;
      case 'model-evaluation':
        return <ModelEvaluationPage currentUser={currentUser} />;
      case 'reports':
        return <ReportsPage />;
      case 'settings-users':
        return <SettingsUsersPage currentUser={currentUser} onSwitchUser={handleSwitchUser} />;
      default:
        return <DashboardPage onNavigate={setActivePage} />;
    }
  };

  return (
    <div className="min-h-screen bg-[#0B1120] text-slate-100 flex">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex lg:flex-col w-64 shrink-0 bg-[#0D1526] border-r border-slate-800/90">
        <div className="h-14 px-5 flex items-center gap-2.5 border-b border-slate-800/90">
          <Activity className="w-5 h-5 text-indigo-400 shrink-0" aria-hidden="true" />
          <span className="font-display font-semibold text-base tracking-tight text-slate-100 whitespace-nowrap">
            CloudSentinel AI
          </span>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto" aria-label="Primary SOC Navigation">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activePage === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActivePage(item.id)}
                className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-medium transition-colors text-left whitespace-nowrap ${
                  isActive
                    ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/30'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50 border border-transparent'
                }`}
              >
                <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-indigo-400' : 'text-slate-500'}`} />
                <span className="truncate">{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-800/90 text-xs">
          <div className="text-slate-400">Active Session</div>
          <div className="font-medium text-slate-100 mt-0.5 truncate">{currentUser.full_name}</div>
          <div className="text-[11px] font-mono text-indigo-300 mt-0.5">{currentUser.role}</div>
        </div>
      </aside>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div className="fixed inset-0 bg-black/60" onClick={() => setMobileMenuOpen(false)} />
          <aside className="relative w-64 bg-[#0D1526] border-r border-slate-800 flex flex-col z-10">
            <div className="h-14 px-4 flex items-center justify-between border-b border-slate-800">
              <span className="font-display font-semibold text-base text-slate-100">CloudSentinel AI</span>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                aria-label="Close navigation menu"
                className="p-1.5 text-slate-400 hover:text-slate-100"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
              {NAV_ITEMS.map((item) => {
                const Icon = item.icon;
                const isActive = activePage === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      setActivePage(item.id);
                      setMobileMenuOpen(false);
                    }}
                    className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-md text-xs font-medium text-left ${
                      isActive
                        ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/30'
                        : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50 border border-transparent'
                    }`}
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </nav>
          </aside>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="h-14 px-4 sm:px-6 bg-[#0D1526] border-b border-slate-800/90 flex items-center justify-between gap-4 shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Open navigation menu"
              className="lg:hidden p-1.5 text-slate-300 hover:text-white rounded border border-slate-800"
            >
              <Menu className="w-4 h-4" />
            </button>
            <div className="text-xs text-slate-400 flex items-center gap-2 truncate">
              <span className="text-slate-300 font-medium whitespace-nowrap">CloudSentinel AI</span>
              <span aria-hidden="true">/</span>
              <span className="text-slate-100 font-medium truncate">{activeNav.label}</span>
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <label htmlFor="session-role-switch" className="hidden sm:inline text-xs text-slate-400 whitespace-nowrap">
              RBAC Session:
            </label>
            <select
              id="session-role-switch"
              value={currentUser.user_id}
              onChange={(e) => {
                const picked = directoryUsers.find((u) => u.user_id === e.target.value);
                if (picked) handleSwitchUser(picked);
              }}
              className="bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
            >
              {directoryUsers.length > 0 ? (
                directoryUsers.map((u) => (
                  <option key={u.user_id} value={u.user_id}>
                    {u.full_name} ({u.role})
                  </option>
                ))
              ) : (
                <option value={currentUser.user_id}>
                  {currentUser.full_name} ({currentUser.role})
                </option>
              )}
            </select>
          </div>
        </header>

        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-[1440px] w-full mx-auto">
          {renderPage()}
        </main>
      </div>
    </div>
  );
}
