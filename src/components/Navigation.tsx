import React from 'react';
import {
  LayoutDashboard,
  FileText,
  Cpu,
  BrainCircuit,
  AlertTriangle,
  ShieldAlert,
  Zap,
  Scale,
  Layers,
  Activity,
  BarChart3,
  FileSpreadsheet,
  Settings,
  Shield,
  Download,
  RefreshCw
} from 'lucide-react';

export type PageId =
  | 'dashboard'
  | 'logs'
  | 'preprocessing'
  | 'detection'
  | 'threats'
  | 'risk'
  | 'faas'
  | 'policies'
  | 'openstack'
  | 'incidents'
  | 'performance'
  | 'reports'
  | 'settings';

interface NavigationProps {
  currentPage: PageId;
  onSelectPage: (page: PageId) => void;
  onSeedDemo: () => void;
  isSeeding: boolean;
}

export const Navigation: React.FC<NavigationProps> = ({
  currentPage,
  onSelectPage,
  onSeedDemo,
  isSeeding,
}) => {
  const navItems: Array<{ id: PageId; label: string; icon: React.ComponentType<{ className?: string }> }> = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: LayoutDashboard },
    { id: 'logs', label: 'Audit Log Manager', icon: FileText },
    { id: 'preprocessing', label: 'Data Preprocessing', icon: Cpu },
    { id: 'detection', label: 'Anomaly Detection', icon: BrainCircuit },
    { id: 'threats', label: 'Insider Threat Center', icon: AlertTriangle },
    { id: 'risk', label: 'Risk Assessment', icon: ShieldAlert },
    { id: 'faas', label: 'Serverless / FaaS', icon: Zap },
    { id: 'policies', label: 'Policy Optimization', icon: Scale },
    { id: 'openstack', label: 'OpenStack Testbed', icon: Layers },
    { id: 'incidents', label: 'Incident Response', icon: Activity },
    { id: 'performance', label: 'Model Performance', icon: BarChart3 },
    { id: 'reports', label: 'Reports & Export', icon: FileSpreadsheet },
    { id: 'settings', label: 'System Settings', icon: Settings },
  ];

  const handleDownloadSampleCsv = () => {
    const csvContent = `timestamp,user_id,action,resource,source_ip,status
2026-03-10 08:30:15,usr_dev_alice,login,auth_service,192.168.1.45,success
2026-03-10 08:35:22,usr_dev_alice,read,repo_frontend,192.168.1.45,success
2026-03-10 08:42:10,usr_dev_alice,commit,repo_frontend,192.168.1.45,success
2026-03-10 09:05:00,usr_ops_bob,login,auth_service,192.168.1.52,success
2026-03-10 09:12:44,usr_ops_bob,describe_instances,compute_nova,192.168.1.52,success
2026-03-10 23:42:15,usr_dev_dave,login,auth_service,198.51.100.23,success
2026-03-10 23:44:02,usr_dev_dave,assume_role,role_cloud_admin,198.51.100.23,failure
2026-03-10 23:45:01,usr_dev_dave,assume_role,role_cloud_admin,198.51.100.23,success
2026-03-10 23:51:14,usr_dev_dave,download_bulk,customer_pii_vault,198.51.100.23,success
2026-03-10 23:56:02,usr_dev_dave,delete_logs,cloud_audit_trail,198.51.100.23,failure
2026-03-11 02:15:10,usr_ops_eve,login,auth_service,203.0.113.88,success
2026-03-11 02:17:30,usr_ops_eve,export_keys,kms_keystone,203.0.113.88,success`;

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sample_audit_logs.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <aside className="w-64 bg-[#111C2E] border-r border-[#1E2D4A] flex flex-col shrink-0 min-h-screen text-[#94A3B8] select-none">
      {/* Brand Header */}
      <div className="p-5 border-b border-[#1E2D4A]">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-[#2563EB]/20 border border-[#2563EB]/40 flex items-center justify-center text-[#22D3EE]">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-bold text-[#F8FAFC] tracking-tight leading-none">
              CloudSentinel AI
            </h1>
            <p className="text-[11px] text-[#94A3B8] mt-1 font-mono">
              FaaS & Cloud SOC
            </p>
          </div>
        </div>
      </div>

      {/* Nav List */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentPage === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectPage(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2 text-xs font-medium rounded-lg transition-colors text-left ${
                isActive
                  ? 'bg-[#2563EB] text-white shadow-sm shadow-[#2563EB]/30'
                  : 'text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#17243A]'
              }`}
            >
              <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-white' : 'text-[#94A3B8]'}`} />
              <span className="truncate">{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Quick Action Footer */}
      <div className="p-3 border-t border-[#1E2D4A] space-y-2 bg-[#0E1726]">
        <button
          onClick={handleDownloadSampleCsv}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium text-[#22D3EE] bg-[#17243A] hover:bg-[#1E2F4C] border border-[#1E2D4A] rounded-lg transition-colors"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Sample Audit CSV</span>
        </button>

        <button
          type="button"
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            onSeedDemo();
          }}
          disabled={isSeeding}
          title="Load synthetic audit log dataset into SQLite database"
          className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium text-[#F8FAFC] bg-[#1E2D4A] hover:bg-[#2563EB] border border-[#2563EB]/30 rounded-lg transition-colors disabled:opacity-50 cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isSeeding ? 'animate-spin text-[#22D3EE]' : ''}`} />
          <span>{isSeeding ? 'Loading Demo Data...' : 'Load Demo Data'}</span>
        </button>

        <div className="text-[10px] text-center text-[#64748B] pt-1 font-mono">
          OpenStack Testbed · B.Tech Final Year
        </div>
      </div>
    </aside>
  );
};
