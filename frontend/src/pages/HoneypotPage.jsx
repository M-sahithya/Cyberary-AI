import React, { useState, useEffect } from 'react';
import {
  Bug,
  Terminal,
  ShieldAlert,
  Play,
  Clock,
  Eye,
  Activity,
  Send,
  Zap,
  RotateCcw,
  Folder,
  Cpu,
  Download,
  Sparkles,
} from 'lucide-react';
import api from '../services/api';

export default function HoneypotPage() {
  const [sessions, setSessions] = useState([]);
  const [selectedSession, setSelectedSession] = useState(null);
  const [sessionDetail, setSessionDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [simCommand, setSimCommand] = useState('cat /etc/shadow');
  const [simulating, setSimulating] = useState(false);
  const [resetting, setResetting] = useState(false);

  useEffect(() => {
    fetchSessions();
  }, []);

  async function fetchSessions() {
    setLoading(true);
    try {
      const res = await api.get('/api/honeypot/sessions');
      const items = res.data.data.items || [];
      setSessions(items);
      if (items.length > 0 && !selectedSession) {
        selectSession(items[0].id);
      }
    } catch (err) {
      console.error('Failed to fetch honeypot sessions:', err);
    } finally {
      setLoading(false);
    }
  }

  async function selectSession(sessionId) {
    setSelectedSession(sessionId);
    try {
      const res = await api.get(`/api/honeypot/sessions/${sessionId}`);
      setSessionDetail(res.data.data);
    } catch (err) {
      console.error('Failed to fetch session detail:', err);
    }
  }

  async function handleResetSession() {
    if (!selectedSession || resetting) return;
    setResetting(true);
    try {
      await api.post(`/api/honeypot/sessions/${selectedSession}/reset`);
      await selectSession(selectedSession);
    } catch (err) {
      console.error('Failed to reset session:', err);
    } finally {
      setResetting(false);
    }
  }

  async function handleSimulateCommand(e, customCmd = null) {
    if (e) e.preventDefault();
    const commandToRun = (customCmd || simCommand || 'whoami').trim();
    setSimulating(true);

    try {
      await api.post('/api/honeypot/simulate-command', {
        command: commandToRun,
        session_id: selectedSession,
        attacker_ip: sessionDetail?.attacker_ip || '10.0.1.105',
      });
      // Refresh current session timeline and session list
      if (selectedSession) {
        await selectSession(selectedSession);
      }
      setSimCommand('');
    } catch (err) {
      console.error('Failed to simulate command:', err);
    } finally {
      setSimulating(false);
    }
  }

  function handleExportSessionLog() {
    if (!sessionDetail) return;
    const blob = new Blob([JSON.stringify(sessionDetail, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `honeypot-session-${selectedSession || 'trace'}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  const currentCwd = sessionDetail?.session_metadata?.cwd || '/root';
  const currentUser = sessionDetail?.username || 'root';
  const currentHost = sessionDetail?.session_metadata?.hostname || 'lab-honeypot-01';
  const currentEngine = sessionDetail?.session_metadata?.engine_used || 'shelLM Generative Core';
  const virtualFilesCount = Object.keys(sessionDetail?.session_metadata?.virtual_files || {}).length;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2.5">
            <Bug className="text-accent-purple" size={24} />
            Dynamic AI Honeypots (shelLM Core)
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Generative interactive Linux shell decoy environments maintaining stateful attacker telemetry and command sequences
          </p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-purple-950/60 border border-purple-800/40">
          <span className="status-dot status-dot-active" />
          <span className="text-xs font-mono text-purple-300">Generative Shell Engine Active</span>
        </div>
      </div>

      {/* Main Grid: Sessions List (Left) + Attacker Timeline & Console (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Sessions List */}
        <div className="glass-card border border-surface-400/20 p-4 space-y-3 h-fit">
          <h2 className="text-sm font-bold text-gray-200 uppercase tracking-wider mb-2">
            Attacker Sessions ({sessions.length})
          </h2>

          {loading ? (
            <p className="text-xs text-gray-500 py-6 text-center">Loading honeypot sessions...</p>
          ) : sessions.length === 0 ? (
            <p className="text-xs text-gray-500 py-6 text-center">No active honeypot sessions.</p>
          ) : (
            sessions.map((s) => (
              <div
                key={s.id}
                onClick={() => selectSession(s.id)}
                className={`p-3 rounded-lg border cursor-pointer transition-all duration-200 ${
                  selectedSession === s.id
                    ? 'bg-purple-950/40 border-purple-500/60 shadow-glow-purple'
                    : 'bg-surface-700/40 border-surface-400/20 hover:border-purple-500/30'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-purple-400">{s.session_code}</span>
                  <span
                    className={`text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.2 rounded ${
                      s.threat_level === 'CRITICAL'
                        ? 'text-red-400 bg-red-950/50'
                        : 'text-orange-400 bg-orange-950/50'
                    }`}
                  >
                    {s.threat_level}
                  </span>
                </div>
                <div className="text-xs text-gray-400 mt-1.5 space-y-0.5">
                  <p>IP: <span className="font-mono text-gray-300">{s.attacker_ip}</span></p>
                  <p>User: <span className="font-mono text-gray-300">{s.username}</span> ({s.protocol})</p>
                  <p className="text-[10px] text-gray-500">{s.command_count} commands logged</p>
                  {s.session_metadata?.human_vs_bot?.classification && s.session_metadata.human_vs_bot.classification !== 'INSUFFICIENT_DATA' && (
                    <span className={`inline-block text-[9px] font-bold px-1.5 py-0.2 rounded mt-1 ${
                      s.session_metadata.human_vs_bot.classification === 'HUMAN_ATTACKER'
                        ? 'text-amber-400 bg-amber-950/60 border border-amber-800/40'
                        : 'text-cyan-400 bg-cyan-950/60 border border-cyan-800/40'
                    }`}>
                      {s.session_metadata.human_vs_bot.classification === 'HUMAN_ATTACKER' ? '👤 Human Operator' : '🤖 Automated Bot'}
                    </span>
                  )}
                  {s.session_metadata?.cwd && (
                    <p className="text-[10px] font-mono text-cyan-400 truncate">cwd: {s.session_metadata.cwd}</p>
                  )}
                </div>
              </div>
            ))
          )}
        </div>

        {/* Right Column: Interactive Attacker Timeline & Simulation Console */}
        <div className="lg:col-span-2 space-y-4">
          {/* Active Session Context Bar */}
          {sessionDetail && (
            <div className="space-y-2">
              <div className="flex items-center justify-between flex-wrap gap-2 px-4 py-2.5 rounded-lg bg-surface-800/80 border border-surface-400/20 text-xs">
                <div className="flex items-center gap-4 flex-wrap">
                  <div className="flex items-center gap-1.5 text-cyan-300 font-mono">
                    <Folder size={14} className="text-cyan-400" />
                    <span>{currentUser}@{currentHost}:{currentCwd}#</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-gray-400">
                    <Cpu size={13} className="text-purple-400" />
                    <span className="text-[11px] font-mono">{currentEngine}</span>
                  </div>
                  {virtualFilesCount > 0 && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300 font-mono">
                      {virtualFilesCount} virtual file{virtualFilesCount > 1 ? 's' : ''} modified
                    </span>
                  )}
                </div>
                <button
                  onClick={handleResetSession}
                  disabled={resetting}
                  title="Reset session to clean baseline environment"
                  className="text-xs text-gray-400 hover:text-red-300 flex items-center gap-1 transition-colors px-2 py-1 rounded bg-surface-700/50 hover:bg-red-950/40 border border-surface-400/20"
                >
                  <RotateCcw size={12} className={resetting ? 'animate-spin' : ''} />
                  <span>{resetting ? 'Resetting...' : 'Reset Session'}</span>
                </button>
              </div>

              {/* Research Metrics Bar: Suspicion Analyzer, Human vs Bot, Breadcrumbs */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2 px-3 py-2 rounded-lg bg-surface-900/90 border border-surface-400/20 text-[11px]">
                {/* Suspicion Meter */}
                <div className="flex items-center justify-between px-2 py-1 bg-surface-800/60 rounded border border-surface-500/20">
                  <span className="text-gray-400">Suspicion Meter:</span>
                  <span className={`font-mono font-bold ${
                    (sessionDetail.session_metadata?.suspicion_score || 0) > 50
                      ? 'text-red-400'
                      : (sessionDetail.session_metadata?.suspicion_score || 0) > 20
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}>
                    {sessionDetail.session_metadata?.suspicion_score || 0}% ({sessionDetail.session_metadata?.suspicion_level || 'LOW'})
                  </span>
                </div>

                {/* Behavioral Classification */}
                <div className="flex items-center justify-between px-2 py-1 bg-surface-800/60 rounded border border-surface-500/20">
                  <span className="text-gray-400">Attacker Profile:</span>
                  <span className="font-mono font-bold text-cyan-300">
                    {sessionDetail.session_metadata?.human_vs_bot?.classification || 'Evaluating...'}
                  </span>
                </div>

                {/* Breadcrumbs Planted */}
                <div className="flex items-center justify-between px-2 py-1 bg-surface-800/60 rounded border border-surface-500/20">
                  <span className="text-gray-400">Canary Decoys:</span>
                  <span className="font-mono font-bold text-purple-300">
                    {sessionDetail.session_metadata?.planted_breadcrumbs?.length || 0} Planted
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Interactive Shell Command Simulation Box & Arsenal */}
          <div className="glass-card p-4 border border-surface-400/20 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-bold uppercase tracking-wider text-gray-300 flex items-center gap-2">
                <Zap size={14} className="text-cyan-400" />
                Simulate Attacker Shell Command in Generative Decoy
              </h2>
              <span className="text-[10px] font-mono text-purple-300 bg-purple-950/60 border border-purple-800/40 px-2 py-0.5 rounded">
                Stateful SSH Emulator
              </span>
            </div>

            <form onSubmit={handleSimulateCommand} className="flex gap-2">
              <div className="relative flex-1">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 font-mono text-xs text-cyan-400">
                  {currentUser}@{currentHost}:{currentCwd}#
                </span>
                <input
                  type="text"
                  value={simCommand}
                  onChange={(e) => setSimCommand(e.target.value)}
                  placeholder="e.g. whoami, uname -a, sudo -l, cat /etc/shadow..."
                  className="input-cyber font-mono text-xs pl-48"
                  style={{
                    paddingLeft: `${Math.min(Math.max((currentUser.length + currentHost.length + currentCwd.length + 3) * 7.5, 120), 280)}px`,
                  }}
                />
              </div>
              <button
                type="submit"
                disabled={simulating}
                className="btn-cyber px-4 text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
              >
                <Send size={13} className={simulating ? 'animate-spin' : ''} />
                {simulating ? 'Executing...' : 'Send'}
              </button>
            </form>

            {/* Quick Command Arsenal */}
            <div className="flex items-center gap-1.5 flex-wrap text-xs pt-2 border-t border-surface-400/10">
              <span className="text-[11px] text-gray-500 font-semibold flex items-center gap-1 mr-1">
                <Sparkles size={12} className="text-cyan-400" /> Attack Arsenal:
              </span>
              {[
                'whoami',
                'uname -a',
                'cat /etc/shadow',
                'sudo -l',
                'id',
                'ls -la /tmp',
                'cat /etc/passwd',
              ].map((cmd) => (
                <button
                  key={cmd}
                  type="button"
                  onClick={() => handleSimulateCommand(null, cmd)}
                  className="text-[11px] font-mono px-2 py-0.5 rounded bg-surface-700/60 hover:bg-purple-950 hover:text-purple-300 border border-surface-400/20 hover:border-purple-700/40 text-gray-300 transition-colors cursor-pointer"
                >
                  {cmd}
                </button>
              ))}
            </div>
          </div>

          {/* Attacker Timeline */}
          <div className="glass-card border border-surface-400/20 p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-surface-400/20 pb-3 flex-wrap gap-2">
              <div className="flex items-center gap-2">
                <Terminal size={18} className="text-cyan-400" />
                <h2 className="text-sm font-bold text-gray-100">
                  Attacker Command Sequence Timeline
                </h2>
              </div>
              <div className="flex items-center gap-2">
                {sessionDetail && (
                  <button
                    type="button"
                    onClick={handleExportSessionLog}
                    className="text-xs font-semibold text-gray-300 hover:text-white bg-surface-700/60 hover:bg-surface-600/80 px-2.5 py-1 rounded border border-surface-400/20 flex items-center gap-1.5 transition-colors"
                    title="Export session trace JSON"
                  >
                    <Download size={13} />
                    Export Trace
                  </button>
                )}
                {sessionDetail && (
                  <span className="text-xs font-mono text-gray-400">
                    Target: {sessionDetail.attacker_ip} · {sessionDetail.username}
                  </span>
                )}
              </div>
            </div>

            {!sessionDetail || sessionDetail.timeline.length === 0 ? (
              <p className="text-xs text-gray-500 py-8 text-center">No terminal commands logged yet.</p>
            ) : (
              <div className="space-y-4 relative before:absolute before:left-3.5 before:top-2 before:bottom-2 before:w-[2px] before:bg-surface-600/60 pl-8">
                {sessionDetail.timeline.map((evt, idx) => (
                  <div key={evt.id || idx} className="relative space-y-2 animate-slide-in">
                    {/* Dot on timeline */}
                    <div className="absolute -left-8 top-1 w-3.5 h-3.5 rounded-full bg-surface-900 border-2 border-cyan-400" />

                    <div className="bg-surface-700/50 border border-surface-400/20 rounded-lg p-3 space-y-2">
                      <div className="flex items-center justify-between flex-wrap gap-2">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono font-bold text-cyan-300">
                            {currentUser}@{currentHost}:{evt.event_metadata?.cwd || currentCwd}# {evt.command}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          {evt.event_metadata?.engine_used && (
                            <span className="text-[9px] font-mono text-gray-400 bg-surface-800 px-1.5 py-0.5 rounded border border-surface-600/40">
                              {evt.event_metadata.engine_used}
                            </span>
                          )}
                          <span className="text-[10px] text-gray-500 font-mono">
                            {new Date(evt.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                      </div>

                      {/* Decoy Response */}
                      <pre className="p-2.5 rounded bg-surface-900 border border-surface-400/30 text-xs font-mono text-gray-300 overflow-x-auto whitespace-pre-wrap">
                        {evt.response || '[no output]'}
                      </pre>

                      {/* AI Inferred Intent & MITRE tag */}
                      <div className="flex items-center gap-2 flex-wrap pt-1 border-t border-surface-400/10 text-xs">
                        <span className="text-xs text-gray-400">Intent:</span>
                        <span className="font-semibold text-purple-300">{evt.intent || 'Terminal Execution'}</span>
                        {evt.mitre_technique && (
                          <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/40 px-1.5 py-0.5 rounded ml-auto">
                            {evt.mitre_technique} ({evt.mitre_tactic})
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
