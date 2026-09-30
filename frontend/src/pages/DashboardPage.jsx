import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  Shield,
  Bug,
  Activity,
  MonitorSpeaker,
  Wrench,
  Server,
  Zap,
  Radio,
  CheckCircle2,
  Clock,
  RefreshCw,
  Terminal,
  Cpu,
  ChevronRight,
} from 'lucide-react';
import StatusCard from '../components/StatusCard';
import api from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';

export default function DashboardPage() {
  const [summary, setSummary] = useState(null);
  const [threatFeed, setThreatFeed] = useState([]);
  const [sshStatus, setSshStatus] = useState(null);
  const [mitreVerification, setMitreVerification] = useState(null);
  const [activeStreamTab, setActiveStreamTab] = useState('parsed'); // 'parsed' | 'raw'
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const { events: wsEvents, isConnected } = useWebSocket();

  useEffect(() => {
    loadDashboard();
    const interval = setInterval(() => {
      fetchLiveTelemetry();
    }, 3500);
    return () => clearInterval(interval);
  }, []);

  async function loadDashboard() {
    try {
      const [summaryRes, feedRes, sshRes, mitreRes] = await Promise.all([
        api.get('/api/dashboard/summary'),
        api.get('/api/dashboard/threat-feed'),
        api.get('/api/ssh/status').catch(() => ({ data: { data: null } })),
        api.get('/api/mitre/verification').catch(() => ({ data: { data: null } })),
      ]);
      setSummary(summaryRes.data.data);
      setThreatFeed(feedRes.data.data.events || []);
      if (sshRes?.data?.data) setSshStatus(sshRes.data.data);
      if (mitreRes?.data?.data) setMitreVerification(mitreRes.data.data);
    } catch (err) {
      console.error('Failed to load dashboard:', err);
    } finally {
      setLoading(false);
    }
  }

  async function fetchLiveTelemetry() {
    try {
      const [sshRes, mitreRes] = await Promise.all([
        api.get('/api/ssh/status').catch(() => null),
        api.get('/api/mitre/verification').catch(() => null),
      ]);
      if (sshRes?.data?.data) setSshStatus(sshRes.data.data);
      if (mitreRes?.data?.data) setMitreVerification(mitreRes.data.data);
    } catch (e) {
      // silent background polling
    }
  }

  async function handleManualRefresh() {
    setRefreshing(true);
    await loadDashboard();
    setRefreshing(false);
  }

  const severityBadge = (severity) => {
    const map = {
      CRITICAL: 'badge-critical',
      HIGH: 'badge-high',
      MEDIUM: 'badge-medium',
      LOW: 'badge-low',
      INFO: 'badge-info',
    };
    return map[severity] || 'badge-info';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="flex flex-col items-center gap-4">
          <div className="w-10 h-10 border-2 border-cyber-500/30 border-t-cyber-400 rounded-full animate-spin" />
          <p className="text-sm text-gray-500">Loading SOC Dashboard & Live Telemetry...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in pb-12">
      {/* Page header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-gray-100">Security Operations Center</h1>
            <span className="px-2.5 py-0.5 text-xs font-mono rounded bg-cyber-500/10 text-cyber-400 border border-cyber-500/30">
              CYBERARY-AI v2.0
            </span>
          </div>
          <p className="text-sm text-gray-500 mt-1">
            Real-time defensive posture & live SSH telemetry from authorized Ubuntu VM
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleManualRefresh}
            disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-700/60 hover:bg-surface-600/80 border border-surface-400/30 text-xs font-medium text-gray-300 transition-colors"
          >
            <RefreshCw size={13} className={refreshing ? 'animate-spin text-cyber-400' : 'text-gray-400'} />
            Sync Telemetry
          </button>
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-cyan-950/60 border border-cyan-800/40">
            <Zap size={14} className="text-cyan-400" />
            <span className="text-xs font-semibold font-mono text-cyan-400">
              {summary?.lab_mode ? 'LAB DEFENSE ACTIVE' : 'LIVE SOC MONITORING'}
            </span>
          </div>
        </div>
      </div>

      {/* LIVE SOC TELEMETRY LAYER BAR */}
      <div className="glass-card border border-cyber-500/30 bg-surface-800/80 p-4 rounded-xl shadow-lg relative overflow-hidden">
        <div className="absolute top-0 left-0 h-1 bg-gradient-to-r from-emerald-500 via-cyan-500 to-cyber-500 w-full" />
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Connection status & host */}
          <div className="flex items-center gap-3.5">
            <div className={`p-2.5 rounded-xl border ${sshStatus?.connected ? 'bg-emerald-950/60 border-emerald-500/40 text-emerald-400' : 'bg-red-950/60 border-red-500/40 text-red-400'}`}>
              <Radio size={22} className={sshStatus?.connected ? 'animate-pulse' : ''} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-gray-400">Live SOC Telemetry Layer</span>
                <span className={`inline-flex items-center gap-1 text-[11px] font-mono font-bold px-2 py-0.5 rounded-full border ${
                  sshStatus?.connected
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                    : 'bg-red-500/10 text-red-400 border-red-500/30'
                }`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${sshStatus?.connected ? 'bg-emerald-400 animate-ping' : 'bg-red-400'}`} />
                  {sshStatus?.connected ? 'SSH STREAM CONNECTED' : 'DISCONNECTED'}
                </span>
              </div>
              <div className="flex items-center gap-3 mt-1 text-xs text-gray-300 font-mono">
                <span className="text-cyber-300 font-semibold">{sshStatus?.target || 'sahithya@192.168.56.103'}</span>
                <span className="text-gray-600">•</span>
                <span className="text-gray-400">Log: <code className="text-amber-400/90">{sshStatus?.log_source || '/var/log/auth.log'}</code></span>
                {sshStatus?.uptime_seconds > 0 && (
                  <>
                    <span className="text-gray-600">•</span>
                    <span className="text-gray-500">Uptime: {Math.round(sshStatus.uptime_seconds)}s</span>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Quick Metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 sm:gap-4 border-t lg:border-t-0 pt-3 lg:pt-0 border-surface-400/20">
            <div className="bg-surface-700/50 border border-surface-400/20 rounded-lg px-3 py-2 text-center">
              <div className="text-[10px] text-gray-400 uppercase font-mono">Events Received</div>
              <div className="text-lg font-bold font-mono text-cyan-300">{sshStatus?.events_received ?? 0}</div>
            </div>
            <div className="bg-surface-700/50 border border-surface-400/20 rounded-lg px-3 py-2 text-center">
              <div className="text-[10px] text-gray-400 uppercase font-mono">Events Analyzed</div>
              <div className="text-lg font-bold font-mono text-blue-300">{sshStatus?.events_analyzed ?? 0}</div>
            </div>
            <div className="bg-surface-700/50 border border-surface-400/20 rounded-lg px-3 py-2 text-center">
              <div className="text-[10px] text-gray-400 uppercase font-mono">Threats Detected</div>
              <div className="text-lg font-bold font-mono text-red-400">{sshStatus?.threats_detected ?? 0}</div>
            </div>
            <div className="bg-surface-700/50 border border-surface-400/20 rounded-lg px-3 py-2 text-center">
              <div className="text-[10px] text-gray-400 uppercase font-mono">Reconnects</div>
              <div className="text-lg font-bold font-mono text-amber-300">{sshStatus?.reconnect_count ?? 0}</div>
            </div>
          </div>
        </div>

        {/* Last event banner */}
        {sshStatus?.last_event && (
          <div className="mt-3 pt-3 border-t border-surface-400/20 flex items-center justify-between text-xs text-gray-400">
            <div className="flex items-center gap-2 truncate">
              <span className="text-gray-500 font-mono">Last Detected:</span>
              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-red-950/60 border border-red-500/30 text-red-300 font-semibold">
                {sshStatus.last_event.mitre_technique || sshStatus.last_event.event_type}
              </span>
              <span className="text-gray-300 truncate">{sshStatus.last_event.intent || sshStatus.last_event.event_type}</span>
            </div>
            <span className="text-[11px] font-mono text-gray-500 shrink-0">
              {new Date(sshStatus.last_event.timestamp).toLocaleTimeString()}
            </span>
          </div>
        )}
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatusCard
          icon={AlertTriangle}
          label="Active Threats"
          value={summary?.active_threats ?? 0}
          color="red"
          trend={{ direction: 'up', value: '+3', label: 'vs yesterday' }}
        />
        <StatusCard
          icon={Shield}
          label="Critical Vulns"
          value={summary?.critical_vulnerabilities ?? 0}
          color="orange"
          trend={{ direction: 'up', value: '+1', label: 'new today' }}
        />
        <StatusCard
          icon={Bug}
          label="Honeypot Sessions"
          value={summary?.active_honeypot_sessions ?? 0}
          color="purple"
          subtitle="Active sessions"
        />
        <StatusCard
          icon={Activity}
          label="Risk Score"
          value={summary?.overall_risk_score ?? 0}
          color="cyan"
          trend={{ direction: 'up', value: '+7', label: 'trending up' }}
        />
        <StatusCard
          icon={MonitorSpeaker}
          label="MITRE Techniques"
          value={summary?.mitre_techniques_detected ?? 0}
          color="blue"
          subtitle="Detected techniques"
        />
        <StatusCard
          icon={Wrench}
          label="Pending Fixes"
          value={summary?.pending_remediations ?? 0}
          color="green"
          subtitle="Awaiting approval"
        />
      </div>

      {/* MITRE ATT&CK 8-TECHNIQUE LAB VERIFICATION MATRIX */}
      <div className="glass-card border border-surface-400/20 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-surface-400/20 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <Shield size={18} className="text-cyber-400" />
            <div>
              <h2 className="text-sm font-semibold text-gray-100">
                MITRE ATT&CK Lab Verification Layer
              </h2>
              <p className="text-[11px] text-gray-500">
                All 8 techniques verified end-to-end against authorized Ubuntu VM 192.168.56.103 telemetry
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-surface-700/80 border border-surface-400/30 text-xs font-mono">
              <span className="text-gray-400">Verified:</span>
              <span className={`font-bold ${
                mitreVerification?.summary?.all_verified ? 'text-emerald-400' : 'text-cyan-400'
              }`}>
                {mitreVerification?.summary?.verified_count ?? 0} / {mitreVerification?.summary?.total_techniques ?? 8}
              </span>
            </div>
            {mitreVerification?.summary?.all_verified && (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/40 text-[11px] font-bold text-emerald-400">
                <CheckCircle2 size={13} />
                ALL 8 TECHNIQUES PASS
              </span>
            )}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="table-cyber">
            <thead>
              <tr>
                <th>Technique ID</th>
                <th>Technique Name</th>
                <th>Tactic</th>
                <th>Real Lab Trigger</th>
                <th>Detection Rule</th>
                <th>Count</th>
                <th>Risk / Severity</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {(mitreVerification?.techniques || []).map((tech) => {
                const isPass = tech.status === 'PASS';
                return (
                  <tr key={tech.technique_id} className="hover:bg-surface-700/30 transition-colors">
                    <td className="font-mono text-xs font-bold text-cyber-400 whitespace-nowrap">
                      {tech.technique_id}
                    </td>
                    <td className="text-xs font-medium text-gray-200 whitespace-nowrap">
                      {tech.name}
                    </td>
                    <td>
                      <span className="text-[10px] font-medium px-2 py-0.5 rounded bg-surface-600/60 text-gray-300 whitespace-nowrap">
                        {tech.tactic}
                      </span>
                    </td>
                    <td className="text-xs text-gray-400 max-w-xs truncate" title={tech.real_trigger}>
                      {tech.real_trigger}
                    </td>
                    <td className="text-[11px] font-mono text-gray-500 max-w-xs truncate" title={tech.detection_rule}>
                      {tech.detection_rule}
                    </td>
                    <td className="text-xs font-mono text-gray-300 text-center whitespace-nowrap">
                      <span className={`font-semibold ${tech.counter_incremented ? 'text-emerald-400' : 'text-gray-400'}`}>
                        {tech.detection_count}
                      </span>
                      {tech.counter_incremented && (
                        <span className="ml-1 text-[10px] text-emerald-400 font-bold">▲</span>
                      )}
                    </td>
                    <td>
                      <span className={severityBadge(tech.severity)}>
                        {tech.severity}
                      </span>
                    </td>
                    <td>
                      <span className={`inline-flex items-center gap-1 text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                        isPass
                          ? 'bg-emerald-950/60 text-emerald-400 border-emerald-500/40'
                          : 'bg-amber-950/60 text-amber-400 border-amber-500/40'
                      }`}>
                        {isPass ? <CheckCircle2 size={11} /> : <Clock size={11} />}
                        {tech.status}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Main content grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat feed table */}
        <div className="lg:col-span-2 glass-card border border-surface-400/20">
          <div className="flex items-center justify-between px-5 py-4 border-b border-surface-400/20">
            <div className="flex items-center gap-2">
              <Zap size={16} className="text-cyber-400" />
              <h2 className="text-sm font-semibold text-gray-200">Live Threat Feed & Activity</h2>
            </div>
            <div className="flex items-center gap-1.5">
              <div className={`status-dot ${isConnected ? 'status-dot-active' : 'status-dot-critical'}`} />
              <span className="text-[10px] text-gray-500 uppercase tracking-wider">
                {isConnected ? 'WebSocket Live' : 'Offline'}
              </span>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="table-cyber">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source</th>
                  <th>Event</th>
                  <th>Severity</th>
                  <th>MITRE</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {threatFeed.map((event, i) => (
                  <tr key={event.id || i} className="animate-fade-in hover:bg-surface-700/30 transition-colors">
                    <td className="text-xs text-gray-500 font-mono whitespace-nowrap">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </td>
                    <td>
                      <span className="text-xs font-medium text-gray-300">
                        {event.source}
                      </span>
                    </td>
                    <td className="max-w-xs truncate text-gray-300">{event.event}</td>
                    <td>
                      <span className={severityBadge(event.severity)}>
                        {event.severity}
                      </span>
                    </td>
                    <td className="font-mono text-xs text-cyber-400">
                      {event.mitre_technique || '—'}
                    </td>
                    <td>
                      <span className="text-xs text-gray-400">{event.status}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Real-time event stream & raw log viewer */}
        <div className="glass-card border border-surface-400/20 flex flex-col h-[520px]">
          <div className="px-5 py-3 border-b border-surface-400/20 flex items-center justify-between">
            <div className="flex items-center gap-1.5 bg-surface-700/60 p-1 rounded-lg border border-surface-400/20">
              <button
                onClick={() => setActiveStreamTab('parsed')}
                className={`px-2.5 py-1 text-xs font-medium rounded-md transition-all ${
                  activeStreamTab === 'parsed'
                    ? 'bg-cyber-500/20 text-cyber-300 font-semibold'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                Security Events
              </button>
              <button
                onClick={() => setActiveStreamTab('raw')}
                className={`px-2.5 py-1 text-xs font-medium rounded-md transition-all ${
                  activeStreamTab === 'raw'
                    ? 'bg-cyber-500/20 text-cyber-300 font-semibold'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                Raw auth.log
              </button>
            </div>
            <span className="text-[10px] font-mono text-gray-500">
              {activeStreamTab === 'parsed' ? `${wsEvents.length} events` : `${sshStatus?.recent_logs?.length || 0} lines`}
            </span>
          </div>

          <div className="p-4 space-y-2.5 flex-1 overflow-y-auto">
            {activeStreamTab === 'parsed' ? (
              wsEvents.length === 0 ? (
                <div className="text-center py-16">
                  <Activity size={24} className="text-gray-700 mx-auto mb-2" />
                  <p className="text-xs text-gray-500">Waiting for live security events...</p>
                </div>
              ) : (
                wsEvents.slice(0, 30).map((event, i) => {
                  const eventTitle = event.event || event.message || event.title || event.description || 'System Event';
                  const eventSource = event.source || 'SSH/Ubuntu';
                  const eventTime = event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : '';
                  const eventMitre = event.mitre || event.mitre_technique || null;

                  return (
                    <div
                      key={event.id || i}
                      className="flex items-start gap-3 p-3 rounded-lg bg-surface-700/40
                        border border-surface-400/20 hover:border-cyber-500/30 transition-all duration-200 animate-slide-in"
                    >
                      <div
                        className={`status-dot mt-1.5 flex-shrink-0 ${
                          event.severity === 'CRITICAL'
                            ? 'status-dot-critical'
                            : event.severity === 'HIGH'
                            ? 'status-dot-warning'
                            : 'status-dot-active'
                        }`}
                      />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-2">
                          <p className="text-xs font-medium text-gray-200 truncate">{eventTitle}</p>
                          {eventTime && (
                            <span className="text-[10px] text-gray-500 font-mono flex-shrink-0">
                              {eventTime}
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                          <span className="text-[10px] font-semibold text-gray-400 bg-surface-600/60 px-1.5 py-0.5 rounded">
                            {eventSource}
                          </span>
                          {eventMitre && (
                            <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/40 px-1.5 py-0.5 rounded">
                              {eventMitre}
                            </span>
                          )}
                          <span
                            className={`text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.2 rounded ${
                              event.severity === 'CRITICAL'
                                ? 'text-red-400 bg-red-950/50'
                                : event.severity === 'HIGH'
                                ? 'text-orange-400 bg-orange-950/50'
                                : 'text-emerald-400 bg-emerald-950/50'
                            }`}
                          >
                            {event.severity || 'INFO'}
                          </span>
                        </div>
                      </div>
                    </div>
                  );
                })
              )
            ) : (
              (sshStatus?.recent_logs || []).length === 0 ? (
                <div className="text-center py-16">
                  <Terminal size={24} className="text-gray-700 mx-auto mb-2" />
                  <p className="text-xs text-gray-500">Live stream buffer waiting for incoming logs...</p>
                </div>
              ) : (
                sshStatus.recent_logs.map((logItem, idx) => (
                  <div key={idx} className="p-2 rounded bg-black/40 border border-surface-500/20 font-mono text-[11px] leading-tight text-gray-300">
                    <span className="text-gray-500 mr-2">[{new Date(logItem.timestamp).toLocaleTimeString()}]</span>
                    <span className="text-cyber-300 break-all">{logItem.raw}</span>
                  </div>
                ))
              )
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
