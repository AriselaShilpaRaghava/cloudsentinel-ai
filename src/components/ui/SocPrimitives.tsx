import React from 'react';
import { AlertTriangle, CheckCircle2, Info, ShieldAlert, XCircle } from 'lucide-react';
import type { RiskLevel } from '../../types/security';

export function SeverityText({ level }: { level: RiskLevel }) {
  const styles: Record<RiskLevel, { color: string; icon: React.ReactNode }> = {
    Critical: {
      color: 'text-rose-400',
      icon: <ShieldAlert className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />,
    },
    High: {
      color: 'text-amber-400',
      icon: <AlertTriangle className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />,
    },
    Medium: {
      color: 'text-sky-400',
      icon: <Info className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />,
    },
    Low: {
      color: 'text-emerald-400',
      icon: <CheckCircle2 className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />,
    },
  };

  const cfg = styles[level];
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium whitespace-nowrap ${cfg.color}`}>
      {cfg.icon}
      <span>{level}</span>
    </span>
  );
}

export function StatusText({ status }: { status: string }) {
  const lower = status.toLowerCase();
  let color = 'text-slate-300';
  let icon: React.ReactNode = null;

  if (lower.includes('success') || lower.includes('approved') || lower.includes('resolved') || lower.includes('verified')) {
    color = 'text-emerald-400';
    icon = <CheckCircle2 className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />;
  } else if (lower.includes('fail') || lower.includes('denied') || lower.includes('rejected') || lower.includes('critical')) {
    color = 'text-rose-400';
    icon = <XCircle className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />;
  } else if (lower.includes('pending') || lower.includes('investigating') || lower.includes('additional') || lower.includes('open')) {
    color = 'text-amber-400';
    icon = <AlertTriangle className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />;
  }

  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium whitespace-nowrap ${color}`}>
      {icon}
      <span>{status}</span>
    </span>
  );
}

export function SectionHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-800/80">
      <div>
        <h2 className="text-xl font-semibold tracking-tight text-slate-100">{title}</h2>
        {description && <p className="mt-1 text-sm text-slate-400 max-w-3xl">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-3 shrink-0">{actions}</div>}
    </div>
  );
}

export function SurfacePanel({
  title,
  subtitle,
  rightSlot,
  children,
  className = '',
}: {
  title?: string;
  subtitle?: string;
  rightSlot?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`bg-[#0F172A] border border-slate-800/90 rounded-lg p-5 ${className}`}>
      {(title || rightSlot) && (
        <div className="flex items-start justify-between gap-4 mb-4">
          <div>
            {title && <h3 className="text-sm font-semibold text-slate-100">{title}</h3>}
            {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
          </div>
          {rightSlot && <div className="shrink-0">{rightSlot}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function DataStateWrapper({
  loading,
  error,
  isEmpty,
  emptyTitle,
  emptyDescription,
  emptyAction,
  onRetry,
  children,
}: {
  loading: boolean;
  error: string | null;
  isEmpty?: boolean;
  emptyTitle?: string;
  emptyDescription?: string;
  emptyAction?: React.ReactNode;
  onRetry?: () => void;
  children: React.ReactNode;
}) {
  if (loading) {
    return (
      <div className="space-y-3 py-6" aria-busy="true">
        <div className="h-9 bg-slate-800/50 rounded animate-pulse" />
        <div className="h-9 bg-slate-800/40 rounded animate-pulse" />
        <div className="h-9 bg-slate-800/30 rounded animate-pulse" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="border border-rose-500/30 bg-rose-950/20 rounded-lg p-5 flex items-center justify-between gap-4">
        <div className="flex items-start gap-3">
          <XCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-rose-200">Unable to complete operation</p>
            <p className="text-xs text-rose-300/80 mt-0.5">{error}</p>
          </div>
        </div>
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="px-3 py-1.5 text-xs font-medium text-rose-200 border border-rose-500/40 rounded hover:bg-rose-900/30 transition-colors whitespace-nowrap shrink-0"
          >
            Retry
          </button>
        )}
      </div>
    );
  }

  if (isEmpty) {
    return (
      <div className="border border-slate-800 bg-slate-900/40 rounded-lg p-8 text-center">
        <p className="text-sm font-medium text-slate-200">{emptyTitle || 'No matching records'}</p>
        {emptyDescription && <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">{emptyDescription}</p>}
        {emptyAction && <div className="mt-4 flex justify-center">{emptyAction}</div>}
      </div>
    );
  }

  return <>{children}</>;
}

export function SimulationNotice({
  connected,
  label,
}: {
  connected: boolean;
  label: string;
}) {
  return (
    <div
      className={`border rounded-lg px-4 py-2.5 text-xs flex flex-wrap items-center justify-between gap-2 ${
        connected
          ? 'border-emerald-500/30 bg-emerald-950/20 text-emerald-200'
          : 'border-indigo-500/30 bg-indigo-950/20 text-indigo-200'
      }`}
    >
      <div className="flex items-center gap-2">
        <Info className="w-4 h-4 shrink-0" aria-hidden="true" />
        <span className="font-medium">{connected ? 'External ML Service Active:' : 'Execution Mode:'}</span>
        <span className="text-slate-300">{label}</span>
      </div>
      {!connected && (
        <span className="text-slate-400">
          Dataset includes simulated cloud & CERT-mapped samples. PyTorch LSTM requires Python ML service connection.
        </span>
      )}
    </div>
  );
}
