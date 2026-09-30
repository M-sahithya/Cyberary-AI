
import React, { useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Shield,
  Bug,
  MonitorSpeaker,
  AlertTriangle,
  FileSearch,
  Wrench,
  Server,
  Bot,
  ScrollText,
  Settings,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
  FlaskConical,
} from 'lucide-react';

const navItems = [
  { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/threats', label: 'Threats', icon: AlertTriangle },
  { path: '/honeypot', label: 'Honeypot', icon: Bug },
  { path: '/vulnerabilities', label: 'Vulnerabilities', icon: Shield },
  { path: '/cves', label: 'CVEs', icon: FileSearch },
  { path: '/mitre', label: 'MITRE ATT&CK', icon: MonitorSpeaker },
  { path: '/remediation', label: 'Remediation', icon: Wrench },
  { path: '/assets', label: 'Assets', icon: Server },
  { path: '/agents', label: 'AI Agents', icon: Bot },
  { path: '/evaluation', label: 'Research Evaluation', icon: FlaskConical },

  // Communication Security Gateway
  {
    path: '/communication-security',
    label: 'Communication Security',
    icon: ShieldCheck,
  },

  { path: '/audit-logs', label: 'Audit Logs', icon: ScrollText },
  { path: '/settings', label: 'Settings', icon: Settings },
];

export default function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();

  return (
    <aside
      className={`fixed left-0 top-0 h-full z-40 flex flex-col transition-all duration-300 ease-in-out
        ${collapsed ? 'w-[68px]' : 'w-[240px]'}
        bg-surface-800/95 backdrop-blur-lg border-r border-surface-400/20`}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 h-16 border-b border-surface-400/20">
        <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-gradient-to-br from-cyber-500 to-accent-purple">
          <ShieldCheck size={20} className="text-white" />
        </div>

        {!collapsed && (
          <div className="animate-fade-in">
            <h1 className="text-base font-bold text-gradient-cyber leading-tight">
              CYBERARY-AI
            </h1>

            <p className="text-[10px] text-gray-500 font-medium tracking-widest uppercase">
              Cyber Defense
            </p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 overflow-y-auto space-y-0.5 px-2">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = location.pathname.startsWith(item.path);

          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={`group flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium
                transition-all duration-200 relative
                ${
                  isActive
                    ? 'bg-cyber-600/15 text-cyber-400'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-surface-700/50'
                }`}
              title={collapsed ? item.label : undefined}
            >
              {isActive && (
                <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-6 rounded-r-full bg-cyber-400" />
              )}

              <Icon
                size={18}
                className={`flex-shrink-0 transition-colors duration-200 ${
                  isActive
                    ? 'text-cyber-400'
                    : 'text-gray-500 group-hover:text-gray-300'
                }`}
              />

              {!collapsed && (
                <span className="animate-fade-in truncate">
                  {item.label}
                </span>
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* Collapse toggle */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="flex items-center justify-center h-12 border-t border-surface-400/20
          text-gray-500 hover:text-gray-300 transition-colors duration-200"
      >
        {collapsed ? (
          <ChevronRight size={16} />
        ) : (
          <ChevronLeft size={16} />
        )}
      </button>
    </aside>
  );
}

