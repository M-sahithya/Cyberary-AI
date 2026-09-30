import React from 'react';
import { useAuth } from '../context/AuthContext';
import { useWebSocket } from '../hooks/useWebSocket';
import {
  Bell,
  Wifi,
  WifiOff,
  User,
  LogOut,
  FlaskConical,
} from 'lucide-react';

export default function TopBar() {
  const { user, logout, isAuthenticated } = useAuth();
  const { isConnected } = useWebSocket();

  if (!isAuthenticated) return null;

  return (
    <header className="fixed top-0 right-0 left-[240px] z-30 h-14
      bg-surface-800/80 backdrop-blur-lg border-b border-surface-400/20
      flex items-center justify-between px-6">

      {/* Left — Lab mode indicator */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full
          bg-accent-green/10 border border-accent-green/30">
          <FlaskConical size={14} className="text-accent-green" />
          <span className="text-xs font-semibold text-accent-green tracking-wide">
            LAB MODE
          </span>
        </div>

        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full
          bg-surface-700 border border-surface-400/30">
          {isConnected ? (
            <>
              <Wifi size={14} className="text-accent-green" />
              <span className="text-xs text-gray-400">Live Feed</span>
            </>
          ) : (
            <>
              <WifiOff size={14} className="text-threat-high" />
              <span className="text-xs text-gray-400">Disconnected</span>
            </>
          )}
        </div>
      </div>

      {/* Right — Notifications + User */}
      <div className="flex items-center gap-4">
        {/* Notifications */}
        <button className="relative p-2 rounded-lg text-gray-400 hover:text-gray-200
          hover:bg-surface-700/50 transition-colors duration-200">
          <Bell size={18} />
          <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-threat-critical
            animate-pulse" />
        </button>

        {/* User menu */}
        <div className="flex items-center gap-3 pl-4 border-l border-surface-400/20">
          <div className="text-right">
            <p className="text-sm font-medium text-gray-200">
              {user?.username || 'User'}
            </p>
            <p className="text-[10px] text-gray-500 uppercase tracking-wider">
              {user?.roles?.[0] || 'VIEWER'}
            </p>
          </div>
          <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyber-500 to-accent-purple
            flex items-center justify-center">
            <User size={14} className="text-white" />
          </div>
          <button
            onClick={logout}
            className="p-2 rounded-lg text-gray-500 hover:text-threat-critical
              hover:bg-threat-critical/10 transition-colors duration-200"
            title="Logout"
          >
            <LogOut size={16} />
          </button>
        </div>
      </div>
    </header>
  );
}
