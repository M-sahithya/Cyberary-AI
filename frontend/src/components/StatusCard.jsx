import React from 'react';

/**
 * Dashboard metric card with icon, value, label, and optional trend indicator.
 */
export default function StatusCard({ icon: Icon, label, value, trend, color = 'cyan', subtitle }) {
  const colorMap = {
    cyan: {
      bg: 'bg-cyber-600/15',
      border: 'border-cyber-500/30',
      text: 'text-cyber-400',
      glow: 'shadow-glow-cyan',
      iconBg: 'bg-cyber-600/20',
    },
    red: {
      bg: 'bg-threat-critical/10',
      border: 'border-threat-critical/30',
      text: 'text-threat-critical',
      glow: 'shadow-glow-red',
      iconBg: 'bg-threat-critical/20',
    },
    green: {
      bg: 'bg-accent-green/10',
      border: 'border-accent-green/30',
      text: 'text-accent-green',
      glow: 'shadow-glow-green',
      iconBg: 'bg-accent-green/20',
    },
    purple: {
      bg: 'bg-accent-purple/10',
      border: 'border-accent-purple/30',
      text: 'text-accent-purple',
      glow: 'shadow-glow-purple',
      iconBg: 'bg-accent-purple/20',
    },
    orange: {
      bg: 'bg-accent-orange/10',
      border: 'border-accent-orange/30',
      text: 'text-accent-orange',
      iconBg: 'bg-accent-orange/20',
    },
    blue: {
      bg: 'bg-accent-blue/10',
      border: 'border-accent-blue/30',
      text: 'text-accent-blue',
      iconBg: 'bg-accent-blue/20',
    },
  };

  const c = colorMap[color] || colorMap.cyan;

  return (
    <div
      className={`glass-card p-5 border ${c.border} ${c.glow || ''}
        hover:scale-[1.02] transition-all duration-300 group`}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-2">
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
            {label}
          </p>
          <p className={`text-3xl font-bold ${c.text} tracking-tight`}>
            {value}
          </p>
          {subtitle && (
            <p className="text-xs text-gray-500">{subtitle}</p>
          )}
        </div>

        <div className={`p-2.5 rounded-xl ${c.iconBg} 
          group-hover:scale-110 transition-transform duration-300`}>
          {Icon && <Icon size={22} className={c.text} />}
        </div>
      </div>

      {trend && (
        <div className="mt-3 pt-3 border-t border-surface-400/10">
          <span
            className={`text-xs font-medium ${
              trend.direction === 'up' ? 'text-threat-critical' : 'text-accent-green'
            }`}
          >
            {trend.direction === 'up' ? '↑' : '↓'} {trend.value}
          </span>
          <span className="text-xs text-gray-500 ml-1.5">{trend.label}</span>
        </div>
      )}
    </div>
  );
}
