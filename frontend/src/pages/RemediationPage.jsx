import React, { useState, useEffect } from 'react';
import {
  Wrench,
  CheckCircle2,
  XCircle,
  Play,
  Terminal,
  ShieldCheck,
  AlertTriangle,
  RotateCcw,
  Eye,
  X,
  FileCheck,
} from 'lucide-react';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';

export default function RemediationPage() {
  const [remediations, setRemediations] = useState([]);
  const [statusFilter, setStatusFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [activeItem, setActiveItem] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState(null);
  const { user } = useAuth();

  useEffect(() => {
    fetchRemediations();
  }, [statusFilter]);

  async function fetchRemediations() {
    setLoading(true);
    try {
      const res = await api.get(`/api/remediation${statusFilter ? `?status=${statusFilter}` : ''}`);
      setRemediations(res.data.data.items || []);
    } catch (err) {
      console.error('Failed to fetch remediations:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleApprove(code) {
    setActionLoading(true);
    setActionMessage(null);
    try {
      await api.post(`/api/remediation/${code}/approve`);
      setActionMessage({ type: 'success', text: `Remediation ${code} approved by human analyst.` });
      await fetchRemediations();
      setActiveItem(null);
    } catch (err) {
      setActionMessage({ type: 'error', text: err.response?.data?.error?.message || 'Approval failed.' });
    } finally {
      setActionLoading(false);
    }
  }

  async function handleReject(code) {
    setActionLoading(true);
    setActionMessage(null);
    try {
      await api.post(`/api/remediation/${code}/reject`);
      setActionMessage({ type: 'success', text: `Remediation ${code} rejected.` });
      await fetchRemediations();
      setActiveItem(null);
    } catch (err) {
      setActionMessage({ type: 'error', text: err.response?.data?.error?.message || 'Rejection failed.' });
    } finally {
      setActionLoading(false);
    }
  }

  async function handleExecute(code) {
    setActionLoading(true);
    setActionMessage(null);
    try {
      const res = await api.post(`/api/remediation/${code}/execute`);
      setActionMessage({
        type: 'success',
        text: `Patch executed on authorized lab target: ${res.data.data.verification_result}`,
      });
      await fetchRemediations();
      setActiveItem(null);
    } catch (err) {
      setActionMessage({ type: 'error', text: err.response?.data?.error?.message || 'Execution failed.' });
    } finally {
      setActionLoading(false);
    }
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2.5">
            <Wrench className="text-accent-green" size={24} />
            Defensive Remediation Engine
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            AI-generated patch recommendations with mandatory human-in-the-loop approval & safe lab execution
          </p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-950/60 border border-emerald-800/40">
          <ShieldCheck size={14} className="text-emerald-400" />
          <span className="text-xs font-mono text-emerald-400">Human Approval Mandatory</span>
        </div>
      </div>

      {actionMessage && (
        <div
          className={`p-3 rounded-lg text-xs font-medium animate-slide-in ${
            actionMessage.type === 'success'
              ? 'bg-emerald-950/50 text-emerald-300 border border-emerald-800/40'
              : 'bg-red-950/50 text-red-300 border border-red-800/40'
          }`}
        >
          {actionMessage.text}
        </div>
      )}

      {/* Filter Tabs */}
      <div className="flex items-center gap-2">
        {['', 'PENDING', 'APPROVED', 'COMPLETED', 'REJECTED'].map((st) => (
          <button
            key={st}
            onClick={() => setStatusFilter(st)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold uppercase tracking-wider transition-all ${
              statusFilter === st
                ? 'bg-cyber-600 text-white shadow-glow-cyan'
                : 'bg-surface-800 text-gray-400 hover:text-gray-200 border border-surface-400/20'
            }`}
          >
            {st || 'All Statuses'}
          </button>
        ))}
      </div>

      {/* Remediation Cards Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {loading ? (
          <div className="col-span-full py-12 text-center text-gray-500 text-xs">
            Loading remediation recommendations...
          </div>
        ) : remediations.length === 0 ? (
          <div className="col-span-full py-12 text-center text-gray-500 text-xs">
            No remediation recommendations matching filter.
          </div>
        ) : (
          remediations.map((item) => (
            <div
              key={item.id}
              className="glass-card p-5 border border-surface-400/20 hover:border-surface-400/40 transition-all duration-200 space-y-4 flex flex-col justify-between"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-cyber-400">{item.remediation_code}</span>
                  <span
                    className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
                      item.status === 'PENDING'
                        ? 'text-orange-400 bg-orange-950/50 border border-orange-800/30'
                        : item.status === 'APPROVED'
                        ? 'text-cyan-400 bg-cyan-950/50 border border-cyan-800/30'
                        : item.status === 'COMPLETED'
                        ? 'text-emerald-400 bg-emerald-950/50 border border-emerald-800/30'
                        : 'text-red-400 bg-red-950/50 border border-red-800/30'
                    }`}
                  >
                    {item.status}
                  </span>
                </div>

                <h3 className="text-sm font-bold text-gray-100">{item.issue}</h3>
                <p className="text-xs text-gray-300 bg-surface-900/60 p-3 rounded border border-surface-400/20">
                  {item.recommended_fix}
                </p>

                {/* Proposed Command Preview */}
                {item.proposed_command && (
                  <div>
                    <div className="flex items-center justify-between text-[11px] text-gray-500 mb-1">
                      <span className="flex items-center gap-1 font-semibold">
                        <Terminal size={12} />
                        Proposed Command
                      </span>
                      <span className="text-[10px] font-mono text-emerald-400">
                        {item.is_command_safe ? '✓ Safety Validator Passed' : '⚠️ Unverified'}
                      </span>
                    </div>
                    <pre className="p-2.5 rounded bg-surface-900 border border-surface-400/30 text-xs font-mono text-cyan-300 overflow-x-auto">
                      {item.proposed_command}
                    </pre>
                  </div>
                )}
              </div>

              {/* Action Buttons */}
              <div className="flex items-center justify-between pt-3 border-t border-surface-400/20">
                <button
                  onClick={() => setActiveItem(item)}
                  className="btn-cyber-outline py-1 px-3 text-xs flex items-center gap-1.5"
                >
                  <Eye size={13} />
                  Review Details
                </button>

                <div className="flex items-center gap-2">
                  {item.status === 'PENDING' && (
                    <>
                      <button
                        onClick={() => handleReject(item.remediation_code)}
                        disabled={actionLoading}
                        className="btn-danger py-1 px-3 text-xs flex items-center gap-1"
                      >
                        <XCircle size={13} />
                        Reject
                      </button>
                      <button
                        onClick={() => handleApprove(item.remediation_code)}
                        disabled={actionLoading}
                        className="btn-success py-1 px-3 text-xs flex items-center gap-1"
                      >
                        <CheckCircle2 size={13} />
                        Approve
                      </button>
                    </>
                  )}

                  {item.status === 'APPROVED' && (
                    <button
                      onClick={() => handleExecute(item.remediation_code)}
                      disabled={actionLoading}
                      className="btn-cyber py-1 px-4 text-xs flex items-center gap-1.5"
                    >
                      <Play size={13} />
                      Execute Lab Patch
                    </button>
                  )}

                  {item.status === 'COMPLETED' && (
                    <span className="text-xs font-mono text-emerald-400 flex items-center gap-1 font-semibold">
                      <FileCheck size={14} />
                      Patch Verified
                    </span>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Review Detail Modal */}
      {activeItem && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-fade-in">
          <div className="glass-card max-w-2xl w-full p-6 glow-border-cyan border border-cyber-500/30 space-y-4 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-surface-400/20 pb-3">
              <div>
                <span className="font-mono text-xs text-cyber-400 font-bold">
                  {activeItem.remediation_code}
                </span>
                <h2 className="text-lg font-bold text-gray-100 mt-1">{activeItem.issue}</h2>
              </div>
              <button onClick={() => setActiveItem(null)} className="text-gray-400 hover:text-gray-200 p-1">
                <X size={20} />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <p className="font-semibold text-gray-400 uppercase tracking-wider">Recommended Fix</p>
                <p className="text-gray-200 text-sm mt-0.5">{activeItem.recommended_fix}</p>
              </div>

              <div>
                <p className="font-semibold text-gray-400 uppercase tracking-wider">Proposed Shell Command</p>
                <pre className="mt-1 p-3 rounded bg-surface-900 border border-surface-400/30 text-xs font-mono text-cyan-300">
                  {activeItem.proposed_command}
                </pre>
              </div>

              <div>
                <p className="font-semibold text-gray-400 uppercase tracking-wider">Expected Verification Step</p>
                <pre className="mt-1 p-2.5 rounded bg-surface-900 border border-surface-400/30 text-xs font-mono text-emerald-400">
                  {activeItem.verification_step}
                </pre>
              </div>

              <div>
                <p className="font-semibold text-gray-400 uppercase tracking-wider">Rollback Plan</p>
                <pre className="mt-1 p-2.5 rounded bg-surface-900 border border-surface-400/30 text-xs font-mono text-orange-400">
                  {activeItem.rollback_plan}
                </pre>
              </div>
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-surface-400/20">
              <button onClick={() => setActiveItem(null)} className="btn-cyber-outline px-4 py-1.5 text-xs">
                Close
              </button>

              {activeItem.status === 'PENDING' && (
                <button
                  onClick={() => handleApprove(activeItem.remediation_code)}
                  className="btn-success px-4 py-1.5 text-xs flex items-center gap-1"
                >
                  <CheckCircle2 size={14} />
                  Approve Fix
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
