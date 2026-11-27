import React, { useState } from 'react';
import type { RiskLevel } from '../../types/security';

export function ThreatTimelineChart({
  data,
}: {
  data: Array<{
    bucket: string;
    total_events: number;
    suspicious_events: number;
    critical_alerts: number;
  }>;
}) {
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  if (!data || data.length === 0) {
    return <p className="text-xs text-slate-400 py-8 text-center">No timeline buckets available.</p>;
  }

  const width = 640;
  const height = 210;
  const padL = 36;
  const padR = 16;
  const padT = 16;
  const padB = 34;
  const innerW = width - padL - padR;
  const innerH = height - padT - padB;

  const maxVal = Math.max(4, ...data.map((d) => d.total_events));
  const stepX = data.length > 1 ? innerW / (data.length - 1) : innerW / 2;

  const toX = (i: number) => (data.length === 1 ? padL + innerW / 2 : padL + i * stepX);
  const toY = (v: number) => padT + innerH - (v / maxVal) * innerH;

  const buildPath = (vals: number[]) =>
    vals.map((v, i) => `${i === 0 ? 'M' : 'L'} ${toX(i).toFixed(1)} ${toY(v).toFixed(1)}`).join(' ');

  const totalPath = buildPath(data.map((d) => d.total_events));
  const suspPath = buildPath(data.map((d) => d.suspicious_events));
  const critPath = buildPath(data.map((d) => d.critical_alerts));

  const areaTotal = `${totalPath} L ${toX(data.length - 1).toFixed(1)} ${padT + innerH} L ${toX(0).toFixed(
    1,
  )} ${padT + innerH} Z`;

  return (
    <div className="relative">
      <div className="flex items-center justify-end gap-5 mb-2 text-xs text-slate-400">
        <span className="inline-flex items-center gap-1.5">
          <span className="w-3 h-0.5 bg-indigo-400 inline-block" /> Total Events
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="w-3 h-0.5 bg-amber-400 inline-block" /> Suspicious
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="w-3 h-0.5 bg-rose-400 inline-block" /> Critical
        </span>
      </div>
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-52 overflow-visible" role="img" aria-label="Threat detection timeline">
        {[0, 0.25, 0.5, 0.75, 1].map((t) => {
          const y = padT + innerH * (1 - t);
          const val = Math.round(maxVal * t);
          return (
            <g key={t}>
              <line x1={padL} y1={y} x2={width - padR} y2={y} stroke="#1E293B" strokeDasharray="3 3" />
              <text x={padL - 8} y={y + 3} textAnchor="end" className="fill-slate-500 text-[10px] font-mono">
                {val}
              </text>
            </g>
          );
        })}

        <path d={areaTotal} fill="rgba(99, 102, 241, 0.10)" />
        <path d={totalPath} fill="none" stroke="#818CF8" strokeWidth={2} />
        <path d={suspPath} fill="none" stroke="#FBBF24" strokeWidth={2} />
        <path d={critPath} fill="none" stroke="#FB7185" strokeWidth={2} />

        {data.map((d, i) => {
          const x = toX(i);
          return (
            <g
              key={d.bucket}
              onMouseEnter={() => setHoverIdx(i)}
              onMouseLeave={() => setHoverIdx(null)}
              className="cursor-pointer"
            >
              <rect x={x - 18} y={padT} width={36} height={innerH + 10} fill="transparent" />
              <circle cx={x} cy={toY(d.total_events)} r={hoverIdx === i ? 4.5 : 3} fill="#818CF8" />
              <circle cx={x} cy={toY(d.suspicious_events)} r={hoverIdx === i ? 4.5 : 3} fill="#FBBF24" />
              <circle cx={x} cy={toY(d.critical_alerts)} r={hoverIdx === i ? 4.5 : 3} fill="#FB7185" />
              <text
                x={x}
                y={height - 10}
                textAnchor="middle"
                className="fill-slate-400 text-[9px] font-mono"
              >
                {d.bucket}
              </text>
            </g>
          );
        })}
      </svg>

      {hoverIdx !== null && data[hoverIdx] && (
        <div className="mt-2 px-3 py-1.5 bg-slate-900 border border-slate-700 rounded text-xs flex items-center justify-between font-mono tabular-nums text-slate-200">
          <span>Window: {data[hoverIdx].bucket} UTC</span>
          <span>
            Total: {data[hoverIdx].total_events} · Suspicious: {data[hoverIdx].suspicious_events} · Critical:{' '}
            {data[hoverIdx].critical_alerts}
          </span>
        </div>
      )}
    </div>
  );
}

export function RiskDistributionBars({
  data,
}: {
  data: Array<{ level: RiskLevel; count: number }>;
}) {
  const total = data.reduce((s, d) => s + d.count, 0) || 1;
  const colorMap: Record<RiskLevel, string> = {
    Critical: 'bg-rose-500',
    High: 'bg-amber-500',
    Medium: 'bg-sky-500',
    Low: 'bg-emerald-500',
  };

  return (
    <div className="space-y-3.5">
      {data.map((item) => {
        const pct = Math.round((item.count / total) * 100);
        return (
          <div key={item.level} className="space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="font-medium text-slate-200">{item.level} Risk</span>
              <span className="font-mono tabular-nums text-slate-400">
                {item.count} events ({pct}%)
              </span>
            </div>
            <div className="h-2 w-full bg-slate-800/80 rounded-sm overflow-hidden">
              <div
                className={`h-full ${colorMap[item.level]} transition-all duration-300`}
                style={{ width: `${Math.max(pct, item.count > 0 ? 4 : 0)}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function CurveChart({
  title,
  xLabel,
  yLabel,
  points,
  color = '#818CF8',
  diagonalBaseline = false,
}: {
  title: string;
  xLabel: string;
  yLabel: string;
  points: Array<{ x: number; y: number }>;
  color?: string;
  diagonalBaseline?: boolean;
}) {
  const width = 320;
  const height = 210;
  const pad = 34;
  const inner = width - pad * 2;
  const innerH = height - pad * 2;

  const toX = (v: number) => pad + v * inner;
  const toY = (v: number) => pad + innerH - v * innerH;

  const path = points
    .map((p, idx) => `${idx === 0 ? 'M' : 'L'} ${toX(p.x).toFixed(1)} ${toY(p.y).toFixed(1)}`)
    .join(' ');

  return (
    <div className="bg-slate-900/40 border border-slate-800/80 rounded-lg p-3">
      <div className="text-xs font-medium text-slate-200 mb-2">{title}</div>
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-44">
        {[0, 0.5, 1].map((tick) => (
          <g key={tick}>
            <line
              x1={pad}
              y1={toY(tick)}
              x2={width - pad}
              y2={toY(tick)}
              stroke="#1E293B"
              strokeDasharray="2 2"
            />
            <text x={pad - 6} y={toY(tick) + 3} textAnchor="end" className="fill-slate-500 text-[9px] font-mono">
              {tick.toFixed(1)}
            </text>
            <text x={toX(tick)} y={height - pad + 14} textAnchor="middle" className="fill-slate-500 text-[9px] font-mono">
              {tick.toFixed(1)}
            </text>
          </g>
        ))}
        {diagonalBaseline && (
          <line
            x1={toX(0)}
            y1={toY(0)}
            x2={toX(1)}
            y2={toY(1)}
            stroke="#475569"
            strokeDasharray="4 4"
            strokeWidth={1}
          />
        )}
        <path d={path} fill="none" stroke={color} strokeWidth={2.2} />
        {points.map((p, i) => (
          <circle key={i} cx={toX(p.x)} cy={toY(p.y)} r={2.8} fill={color} />
        ))}
        <text x={width / 2} y={height - 4} textAnchor="middle" className="fill-slate-400 text-[9px]">
          {xLabel}
        </text>
        <text
          x={10}
          y={height / 2}
          textAnchor="middle"
          transform={`rotate(-90 10 ${height / 2})`}
          className="fill-slate-400 text-[9px]"
        >
          {yLabel}
        </text>
      </svg>
    </div>
  );
}

export function BeforeAfterComparisonChart({
  items,
}: {
  items: Array<{
    label: string;
    beforeRisk: number;
    afterRisk: number;
    beforeCost: number;
    afterCost: number;
  }>;
}) {
  return (
    <div className="space-y-4">
      {items.map((item) => (
        <div key={item.label} className="border-b border-slate-800/70 pb-3 last:border-b-0 last:pb-0">
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs mb-2">
            <span className="font-medium text-slate-200 truncate max-w-md">{item.label}</span>
            <span className="font-mono tabular-nums text-slate-400">
              Risk {item.beforeRisk} → {item.afterRisk} · Cost ${item.beforeCost} → ${item.afterCost}/mo
            </span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <div className="flex justify-between text-[11px] text-slate-400 mb-1">
                <span>Residual Risk</span>
                <span className="font-mono tabular-nums">{item.beforeRisk}% vs {item.afterRisk}%</span>
              </div>
              <div className="space-y-1">
                <div className="h-1.5 bg-slate-800 rounded-sm overflow-hidden">
                  <div className="h-full bg-rose-500/80" style={{ width: `${item.beforeRisk}%` }} />
                </div>
                <div className="h-1.5 bg-slate-800 rounded-sm overflow-hidden">
                  <div className="h-full bg-emerald-500" style={{ width: `${item.afterRisk}%` }} />
                </div>
              </div>
            </div>
            <div>
              <div className="flex justify-between text-[11px] text-slate-400 mb-1">
                <span>Monthly Cost</span>
                <span className="font-mono tabular-nums">${item.beforeCost} vs ${item.afterCost}</span>
              </div>
              <div className="space-y-1">
                <div className="h-1.5 bg-slate-800 rounded-sm overflow-hidden">
                  <div
                    className="h-full bg-slate-500"
                    style={{ width: `${Math.min(100, (item.beforeCost / 600) * 100)}%` }}
                  />
                </div>
                <div className="h-1.5 bg-slate-800 rounded-sm overflow-hidden">
                  <div
                    className="h-full bg-indigo-400"
                    style={{ width: `${Math.min(100, (item.afterCost / 600) * 100)}%` }}
                  />
                </div>
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
