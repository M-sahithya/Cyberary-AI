import React, { useState, useEffect } from 'react';
import {
  ScrollText,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Clock,
  User,
  Shield,
  Download,
  RefreshCw,
  Eye,
  X,
} from 'lucide-react';
import api from '../services/api';

export default function AuditLogsPage() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionFilter, setActionFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedLog, setSelectedLog] = useState(null);

  useEffect(() => {
    fetchLogs();
  }, [actionFilter]);

  async function fetchLogs() {
    setLoading(true);
    try {
      let url = '/api/audit-logs?';
      if (actionFilter) url += `action=${actionFilter}&`;
      const res = await api.get(url);
      setLogs(res.data.data.items || []);
    } catch (err) {
      console.error('Failed to fetch audit logs:', err);
    } finally {
      setLoading(false);
    }
  }

  function handleExportLogs() {
    const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `immutable-audit-trail-${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  const filteredLogs = logs.filter((l) =>
    l.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (l.target && l.target.toLowerCase().includes(searchTerm.toLowerCase())) ||
    (l.ip_address && l.ip_address.includes(searchTerm))
  );

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2.5">
            <ScrollText className="text-cyber-400" size={24} />
            Immutable Audit Trail & Forensics
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Cryptographically timestamped audit log of all sensitive user authentications, approvals, and agent activities
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={fetchLogs}
            disabled={loading}
            className="btn-cyber-outline px-3 py-1.5 text-xs font-semibold flex items-center gap-1.5"
            title="Refresh Audit Records"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>

          <button
            type="button"
            onClick={handleExportLogs}
            className="btn-cyber px-3.5 py-1.5 text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
            title="Export Immutable Audit Logs as JSON"
          >
            <Download size={14} />
            Export Audit Trail
          </button>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-cyan-950/60 border border-cyan-800/40">
            <span className="text-xs font-mono text-cyan-400">{logs.length} Recorded Entries</span>
          </div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="glass-card p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="relative flex-1 min-w-[260px]">
          <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            placeholder="Search by action, target identifier, or client IP..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="input-cyber pl-10 text-xs"
          />
        </div>

        <select
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value)}
          className="input-cyber py-2 text-xs w-auto"
        >
          <option value="">All Action Types</option>
          <option value="LOGIN_SUCCESS">LOGIN_SUCCESS</option>
          <option value="USER_REGISTER">USER_REGISTER</option>
          <option value="APPROVE_REMEDIATION">APPROVE_REMEDIATION</option>
          <option value="REJECT_REMEDIATION">REJECT_REMEDIATION</option>
          <option value="LAB_PATCH_EXECUTED">LAB_PATCH_EXECUTED</option>
          <option value="TARGET_REGISTERED">TARGET_REGISTERED</option>
        </select>
      </div>

      {/* Audit Logs Table */}
      <div className="glass-card border border-surface-400/20 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="table-cyber">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Action</th>
                <th>Target Object</th>
                <th>Type</th>
                <th>Client IP</th>
                <th>Result</th>
                <th>Details</th>
                <th className="text-right">Inspect</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="8" className="text-center py-10 text-gray-500 text-xs">
                    Loading audit trail...
                  </td>
                </tr>
              ) : filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan="8" className="text-center py-10 text-gray-500 text-xs">
                    No audit records match the criteria.
                  </td>
                </tr>
              ) : (
                filteredLogs.map((l) => (
                  <tr key={l.id} className="hover:bg-surface-700/40 transition-colors">
                    <td className="font-mono text-xs text-gray-400 whitespace-nowrap">
                      {new Date(l.timestamp).toLocaleString()}
                    </td>
                    <td>
                      <span className="font-mono text-xs font-bold text-cyan-400 bg-cyan-950/60 border border-cyan-800/40 px-2 py-0.5 rounded">
                        {l.action}
                      </span>
                    </td>
                    <td className="font-mono text-xs text-gray-200">{l.target || '—'}</td>
                    <td className="text-xs text-gray-400 uppercase">{l.target_type || 'system'}</td>
                    <td className="font-mono text-xs text-gray-500">{l.ip_address || '127.0.0.1'}</td>
                    <td>
                      <span
                        className={`text-xs font-semibold px-2 py-0.5 rounded ${
                          l.result === 'SUCCESS'
                            ? 'text-emerald-400 bg-emerald-950/50'
                            : 'text-red-400 bg-red-950/50'
                        }`}
                      >
                        {l.result}
                      </span>
                    </td>
                    <td className="text-xs text-gray-400 font-mono max-w-xs truncate">
                      {l.details ? JSON.stringify(l.details) : '—'}
                    </td>
                    <td className="text-right">
                      <button
                        type="button"
                        onClick={() => setSelectedLog(l)}
                        className="btn-cyber-outline py-1 px-2 text-xs flex items-center gap-1"
                        title="View Full Cryptographic Audit Detail"
                      >
                        <Eye size={12} />
                        View
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Forensic Log Detail Modal */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 animate-fade-in">
          <div className="glass-card max-w-xl w-full p-6 glow-border-cyan border border-cyber-500/30 space-y-4">
            <div className="flex items-center justify-between border-b border-surface-400/20 pb-3">
              <div className="flex items-center gap-2">
                <ScrollText size={18} className="text-cyan-400" />
                <h2 className="text-base font-bold text-gray-100 font-mono">{selectedLog.action}</h2>
              </div>
              <button
                type="button"
                onClick={() => setSelectedLog(null)}
                className="text-gray-400 hover:text-gray-200"
              >
                <X size={20} />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3 p-3 rounded-lg bg-surface-900/80 border border-surface-400/20">
                <div>
                  <p className="text-gray-500 font-semibold">Timestamp</p>
                  <p className="font-mono text-gray-200 mt-0.5">{new Date(selectedLog.timestamp).toISOString()}</p>
                </div>
                <div>
                  <p className="text-gray-500 font-semibold">Client IP</p>
                  <p className="font-mono text-cyan-300 mt-0.5">{selectedLog.ip_address || '127.0.0.1'}</p>
                </div>
                <div>
                  <p className="text-gray-500 font-semibold">Target Entity</p>
                  <p className="font-mono text-gray-200 mt-0.5">{selectedLog.target || 'N/A'}</p>
                </div>
                <div>
                  <p className="text-gray-500 font-semibold">Result Status</p>
                  <p className={`font-bold mt-0.5 ${selectedLog.result === 'SUCCESS' ? 'text-emerald-400' : 'text-red-400'}`}>
                    {selectedLog.result}
                  </p>
                </div>
              </div>

              <div>
                <p className="text-gray-500 font-semibold mb-1">Raw Cryptographic Forensic Payload</p>
                <pre className="p-3 rounded-lg bg-surface-900 border border-surface-400/30 text-xs font-mono text-cyan-300 overflow-x-auto max-h-56">
                  {JSON.stringify(selectedLog, null, 2)}
                </pre>
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-surface-400/20">
              <button
                type="button"
                onClick={() => setSelectedLog(null)}
                className="btn-cyber px-4 py-1.5 text-xs font-semibold"
              >
                Close Dossier
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
