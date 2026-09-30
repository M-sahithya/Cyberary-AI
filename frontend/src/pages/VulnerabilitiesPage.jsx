import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  ShieldAlert,
  Play,
  CheckCircle2,
  AlertTriangle,
  Server,
  Zap,
  Search,
  Eye,
  Wrench,
  Download,
  ExternalLink,
  X,
  FileText,
} from 'lucide-react';
import api from '../services/api';

export default function VulnerabilitiesPage() {
  const [vulns, setVulns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [target, setTarget] = useState('lab-server-01');
  const [scanMessage, setScanMessage] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [selectedVuln, setSelectedVuln] = useState(null);

  const navigate = useNavigate();

  useEffect(() => {
    fetchVulnerabilities();
  }, []);

  async function fetchVulnerabilities() {
    setLoading(true);
    try {
      const res = await api.get('/api/vulnerabilities');
      setVulns(res.data.data.items || []);
    } catch (err) {
      console.error('Failed to fetch vulnerabilities:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleRunScan(e) {
    if (e) e.preventDefault();
    setScanning(true);
    setScanMessage(null);

    try {
      const res = await api.post('/api/vulnerabilities/scan', { target });
      const data = res.data.data;
      setScanMessage({
        type: 'success',
        text: `Ethical Assessment Complete on ${target}! ${data.findings_discovered} vulnerabilities identified. Remediation recommendations generated.`,
      });
      await fetchVulnerabilities();
    } catch (err) {
      const errMsg = err.response?.data?.error?.message || 'Scan failed or target not authorized.';
      setScanMessage({ type: 'error', text: errMsg });
    } finally {
      setScanning(false);
    }
  }

  function handleExportFindings() {
    const blob = new Blob([JSON.stringify(vulns, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `vulnerability-assessment-${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  const filteredVulns = vulns.filter((v) => {
    const matchesSearch =
      v.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      v.finding_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (v.cve_id && v.cve_id.toLowerCase().includes(searchTerm.toLowerCase())) ||
      v.asset_name.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity =
      !severityFilter ||
      (severityFilter === 'REMEDIATED' ? v.status === 'REMEDIATED' : v.severity === severityFilter);

    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2.5">
            <Shield className="text-threat-high" size={24} />
            Vulnerability Assessment & Findings
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Ethical vulnerability discovery & simulated attack vector analysis across authorized lab infrastructure
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleExportFindings}
            className="btn-cyber-outline px-3.5 py-1.5 text-xs font-semibold flex items-center gap-1.5"
            title="Export all vulnerability findings as JSON"
          >
            <Download size={14} />
            Export Findings
          </button>
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-orange-950/60 border border-orange-800/40">
            <span className="text-xs font-mono text-orange-400">{vulns.length} Identified Findings</span>
          </div>
        </div>
      </div>

      {/* Offensive AI Agent Trigger Console */}
      <div className="glass-card p-5 border border-surface-400/20 glow-border-cyan">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Zap size={16} className="text-cyan-400" />
            <h2 className="text-sm font-bold text-gray-100 uppercase tracking-wider">
              Offensive AI Agent — Ethical Lab Scanner
            </h2>
          </div>
          <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/30">
            Target Allowlist Active
          </span>
        </div>

        <form onSubmit={handleRunScan} className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 flex-1 min-w-[240px]">
            <Server size={16} className="text-gray-400" />
            <select
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="input-cyber py-2 text-xs"
            >
              <option value="lab-server-01">lab-server-01 (10.0.1.10) — Linux App Server</option>
              <option value="lab-server-02">lab-server-02 (10.0.1.11) — Linux DB Node</option>
              <option value="lab-honeypot-01">lab-honeypot-01 (10.0.1.20) — Decoy SSH</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={scanning}
            className="btn-cyber px-5 py-2 text-xs font-semibold flex items-center gap-2 cursor-pointer"
          >
            {scanning ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Simulating Ethical Attack...
              </>
            ) : (
              <>
                <Play size={14} />
                Run Lab Assessment Scan
              </>
            )}
          </button>
        </form>

        {scanMessage && (
          <div
            className={`mt-3 p-3 rounded-lg text-xs font-medium animate-slide-in ${
              scanMessage.type === 'success'
                ? 'bg-emerald-950/50 text-emerald-300 border border-emerald-800/40'
                : 'bg-red-950/50 text-red-300 border border-red-800/40'
            }`}
          >
            {scanMessage.text}
          </div>
        )}
      </div>

      {/* Filter and Severity Tabs Bar */}
      <div className="glass-card p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="relative flex-1 min-w-[260px]">
            <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500" />
            <input
              type="text"
              placeholder="Filter by title, finding ID, asset, or CVE ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="input-cyber pl-10 text-xs"
            />
          </div>

          {/* Quick Severity Filter Tabs */}
          <div className="flex items-center gap-1.5 flex-wrap">
            {[
              { id: '', label: 'All Findings' },
              { id: 'CRITICAL', label: 'Critical' },
              { id: 'HIGH', label: 'High' },
              { id: 'MEDIUM', label: 'Medium' },
              { id: 'REMEDIATED', label: 'Remediated' },
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setSeverityFilter(tab.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  severityFilter === tab.id
                    ? 'bg-cyber-500 text-surface-950 shadow-glow-cyan'
                    : 'bg-surface-700/60 text-gray-400 hover:text-gray-200 border border-surface-400/20'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Vulnerabilities Table */}
      <div className="glass-card border border-surface-400/20 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="table-cyber">
            <thead>
              <tr>
                <th>Finding ID</th>
                <th>Asset</th>
                <th>Vulnerability Title</th>
                <th>CVE ID</th>
                <th>CVSS Score</th>
                <th>Severity</th>
                <th>Service / Port</th>
                <th>Status</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="9" className="text-center py-10 text-gray-500">
                    Loading findings...
                  </td>
                </tr>
              ) : filteredVulns.length === 0 ? (
                <tr>
                  <td colSpan="9" className="text-center py-10 text-gray-500">
                    No vulnerabilities found matching the search/filter criteria.
                  </td>
                </tr>
              ) : (
                filteredVulns.map((v) => (
                  <tr key={v.id} className="hover:bg-surface-700/40 transition-colors">
                    <td className="font-mono text-xs font-bold text-cyber-400">{v.finding_id}</td>
                    <td className="font-mono text-xs text-gray-300">{v.asset_name}</td>
                    <td className="font-medium text-gray-200 max-w-xs truncate">{v.title}</td>
                    <td>
                      {v.cve_id ? (
                        <button
                          type="button"
                          onClick={() => navigate('/cves')}
                          className="font-mono text-xs text-cyan-400 bg-cyan-950/60 border border-cyan-800/40 hover:bg-cyan-900/60 px-2 py-0.5 rounded font-semibold flex items-center gap-1 transition-colors"
                        >
                          {v.cve_id}
                          <ExternalLink size={10} />
                        </button>
                      ) : (
                        <span className="text-xs text-gray-600">Local Config</span>
                      )}
                    </td>
                    <td>
                      <span className="font-mono text-xs font-bold text-gray-200">
                        {typeof v.cvss_score === 'number' ? v.cvss_score.toFixed(1) : v.cvss_score}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          v.severity === 'CRITICAL'
                            ? 'badge-critical'
                            : v.severity === 'HIGH'
                            ? 'badge-high'
                            : 'badge-medium'
                        }`}
                      >
                        {v.severity}
                      </span>
                    </td>
                    <td className="text-xs text-gray-400 font-mono">{v.affected_service}</td>
                    <td>
                      <span
                        className={`text-xs font-semibold px-2 py-0.5 rounded ${
                          v.status === 'REMEDIATED'
                            ? 'text-emerald-400 bg-emerald-950/50'
                            : 'text-orange-400 bg-orange-950/50'
                        }`}
                      >
                        {v.status}
                      </span>
                    </td>
                    <td className="text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          type="button"
                          onClick={() => setSelectedVuln(v)}
                          className="btn-cyber-outline py-1 px-2 text-xs flex items-center gap-1"
                          title="Inspect Finding Details"
                        >
                          <Eye size={12} />
                          Inspect
                        </button>
                        <button
                          type="button"
                          onClick={() => navigate('/remediation')}
                          className="btn-cyber py-1 px-2 text-xs flex items-center gap-1 font-semibold"
                          title="Navigate to Remediation Engine to approve/execute patch"
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

      {/* Vulnerability Detail Modal */}
      {selectedVuln && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 animate-fade-in">
          <div className="glass-card max-w-2xl w-full p-6 glow-border-cyan border border-cyber-500/30 space-y-4">
            <div className="flex items-center justify-between border-b border-surface-400/20 pb-3">
              <div className="flex items-center gap-3">
                <span
                  className={`badge ${
                    selectedVuln.severity === 'CRITICAL'
                      ? 'badge-critical'
                      : selectedVuln.severity === 'HIGH'
                      ? 'badge-high'
                      : 'badge-medium'
                  }`}
                >
                  {selectedVuln.severity}
                </span>
                <h2 className="text-lg font-bold text-gray-100">{selectedVuln.finding_id}</h2>
              </div>
              <button
                type="button"
                onClick={() => setSelectedVuln(null)}
                className="text-gray-400 hover:text-gray-200 p-1"
              >
                <X size={20} />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <p className="text-gray-500 uppercase tracking-wider font-semibold">Title</p>
                <p className="text-sm font-bold text-gray-200 mt-0.5">{selectedVuln.title}</p>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 p-3 rounded-lg bg-surface-900/80 border border-surface-400/20">
                <div>
                  <p className="text-gray-500">Asset Target</p>
                  <p className="font-mono text-cyan-300 mt-0.5">{selectedVuln.asset_name}</p>
                </div>
                <div>
                  <p className="text-gray-500">CVE ID</p>
                  <p className="font-mono text-cyan-400 mt-0.5">{selectedVuln.cve_id || 'N/A'}</p>
                </div>
                <div>
                  <p className="text-gray-500">CVSS v3.1</p>
                  <p className="font-mono font-bold text-red-400 mt-0.5">{selectedVuln.cvss_score}</p>
                </div>
                <div>
                  <p className="text-gray-500">Port / Service</p>
                  <p className="font-mono text-gray-300 mt-0.5">{selectedVuln.affected_service}</p>
                </div>
              </div>

              {selectedVuln.description && (
                <div>
                  <p className="text-gray-500 uppercase tracking-wider font-semibold">Dossier Summary</p>
                  <p className="text-gray-300 mt-1 leading-relaxed">{selectedVuln.description}</p>
                </div>
              )}

              {selectedVuln.remediation_recommendation && (
                <div className="p-3 rounded-lg bg-cyan-950/40 border border-cyan-800/40">
                  <p className="text-cyan-400 uppercase tracking-wider font-semibold flex items-center gap-1.5 mb-1">
                    <Wrench size={13} /> Recommended Lab Remediation
                  </p>
                  <p className="text-gray-300 font-mono text-[11px]">
                    {selectedVuln.remediation_recommendation}
                  </p>
                </div>
              )}
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-surface-400/20">
              <button
                type="button"
                onClick={() => setSelectedVuln(null)}
                className="btn-cyber-outline px-4 py-1.5 text-xs"
              >
                Close
              </button>
              <button
                type="button"
                onClick={() => {
                  setSelectedVuln(null);
                  navigate('/remediation');
                }}
                className="btn-cyber px-4 py-1.5 text-xs font-semibold flex items-center gap-1.5"
              >
                <Wrench size={13} />
                Open in Remediation Console
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
