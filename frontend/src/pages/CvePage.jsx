import React, { useState, useEffect } from 'react';
import {
  FileSearch,
  Search,
  ExternalLink,
  ShieldAlert,
  AlertTriangle,
  BookOpen,
  Zap,
  Download,
  Sparkles,
} from 'lucide-react';
import api from '../services/api';

export default function CvePage() {
  const [cveList, setCveList] = useState([]);
  const [searchTerm, setSearchTerm] = useState('CVE-2024-6387');
  const [activeCve, setActiveCve] = useState(null);
  const [searching, setSearching] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchCveCatalog();
  }, []);

  async function fetchCveCatalog() {
    setLoading(true);
    try {
      const res = await api.get('/api/cve');
      const items = res.data.data.items || [];
      setCveList(items);
      if (items.length > 0) {
        setActiveCve(items[0]);
      }
    } catch (err) {
      console.error('Failed to fetch CVE catalog:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleSearch(e, customId = null) {
    if (e) e.preventDefault();
    const targetId = (customId || searchTerm || 'CVE-2024-6387').trim().toUpperCase();
    setSearchTerm(targetId);
    setSearching(true);

    try {
      const res = await api.get(`/api/cve/${targetId}`);
      setActiveCve(res.data.data);
    } catch (err) {
      console.error('CVE lookup failed:', err);
    } finally {
      setSearching(false);
    }
  }

  function handleQuickSelect(id) {
    setSearchTerm(id);
    handleSearch(null, id);
  }

  function handleExportDossier() {
    if (!activeCve) return;
    const blob = new Blob([JSON.stringify(activeCve, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${activeCve.cve_id || 'cve-dossier'}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2.5">
            <FileSearch className="text-cyber-400" size={24} />
            CVE / NVD Vulnerability Database
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            NIST National Vulnerability Database integration, CVSS v3.1 metrics, and exploitability analysis
          </p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-cyan-950/60 border border-cyan-800/40">
          <span className="text-xs font-mono text-cyan-400">NVD API 2.0 Connected</span>
        </div>
      </div>

      {/* Search Input Bar & Quick Benchmark Pills */}
      <div className="glass-card p-4 border border-surface-400/20 space-y-3">
        <form onSubmit={handleSearch} className="flex flex-wrap md:flex-nowrap gap-3">
          <div className="relative flex-1 min-w-[280px]">
            <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search CVE ID (e.g. CVE-2024-6387, CVE-2023-38408, CVE-2021-44228)..."
              className="input-cyber pl-10 font-mono text-xs uppercase"
            />
          </div>
          <button
            type="submit"
            disabled={searching}
            className="btn-cyber px-5 text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
          >
            <Search size={14} className={searching ? 'animate-spin' : ''} />
            {searching ? 'Querying NVD...' : 'Query CVE'}
          </button>
          {activeCve && (
            <button
              type="button"
              onClick={handleExportDossier}
              className="btn-cyber-outline px-4 text-xs font-semibold flex items-center gap-1.5"
              title="Export CVE Dossier as JSON"
            >
              <Download size={14} />
              Export Dossier
            </button>
          )}
        </form>

        {/* Quick Benchmark Pills */}
        <div className="flex items-center gap-2 flex-wrap text-xs pt-1 border-t border-surface-400/10">
          <span className="text-[11px] text-gray-500 font-semibold flex items-center gap-1">
            <Sparkles size={12} className="text-cyan-400" /> Quick Lookups:
          </span>
          {[
            { id: 'CVE-2024-6387', label: 'CVE-2024-6387 (regreSSHion)' },
            { id: 'CVE-2023-38408', label: 'CVE-2023-38408 (OpenSSH RCE)' },
            { id: 'CVE-2021-44228', label: 'CVE-2021-44228 (Log4Shell)' },
            { id: 'CVE-2024-3094', label: 'CVE-2024-3094 (XZ Backdoor)' },
          ].map((pill) => (
            <button
              key={pill.id}
              type="button"
              onClick={() => handleQuickSelect(pill.id)}
              className="text-[11px] font-mono px-2.5 py-1 rounded-md bg-surface-700/60 hover:bg-cyan-950 hover:text-cyan-300 border border-surface-400/20 hover:border-cyan-700/40 text-gray-300 transition-colors"
            >
              {pill.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main Grid: Active CVE Details (Left) + Indexed Catalog (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Active CVE Detailed Dossier */}
        <div className="lg:col-span-2 space-y-4">
          {activeCve ? (
            <div className="glass-card p-6 border border-cyber-500/30 glow-border-cyan space-y-5">
              <div className="flex items-start justify-between border-b border-surface-400/20 pb-4">
                <div>
                  <h2 className="text-2xl font-bold font-mono text-cyan-300">
                    {activeCve.cve_id}
                  </h2>
                  <p className="text-xs text-gray-500 mt-1 font-mono">
                    Source: {activeCve.source}
                  </p>
                </div>
                <div className="text-right">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-400">CVSS v3.1</span>
                    <span className="text-2xl font-extrabold font-mono text-red-400">
                      {typeof activeCve.cvss_score === 'number' ? activeCve.cvss_score.toFixed(1) : activeCve.cvss_score}
                    </span>
                  </div>
                  <span
                    className={`badge mt-1 ${
                      activeCve.severity === 'CRITICAL'
                        ? 'badge-critical'
                        : 'badge-high'
                    }`}
                  >
                    {activeCve.severity}
                  </span>
                </div>
              </div>

              {/* Description */}
              <div>
                <p className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-1">
                  Vulnerability Description
                </p>
                <p className="text-sm text-gray-200 leading-relaxed bg-surface-900/60 p-3.5 rounded-lg border border-surface-400/20">
                  {activeCve.description}
                </p>
              </div>

              {/* CVSS Vector & Affected Software */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-surface-700/30 p-3 rounded-lg border border-surface-400/20">
                  <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">
                    CVSS Vector String
                  </p>
                  <p className="text-xs font-mono text-cyan-400 truncate">
                    {activeCve.vector || 'N/A'}
                  </p>
                </div>
                <div className="bg-surface-700/30 p-3 rounded-lg border border-surface-400/20">
                  <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">
                    Affected Software
                  </p>
                  <p className="text-xs font-mono text-gray-300">
                    {activeCve.affected_software || 'See vendor bulletin'}
                  </p>
                </div>
              </div>

              {/* Remediation Recommendation */}
              {activeCve.remediation_recommendation && (
                <div>
                  <p className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-1">
                    Remediation Advisory
                  </p>
                  <div className="p-3 bg-emerald-950/40 border border-emerald-800/40 rounded-lg text-xs text-emerald-300 font-medium">
                    {activeCve.remediation_recommendation}
                  </div>
                </div>
              )}

              {/* Official References */}
              {activeCve.references && activeCve.references.length > 0 && (
                <div>
                  <p className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-2">
                    Official Advisory References
                  </p>
                  <ul className="space-y-1.5">
                    {activeCve.references.map((ref, idx) => (
                      <li key={idx}>
                        <a
                          href={ref}
                          target="_blank"
                          rel="noreferrer"
                          className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 truncate"
                        >
                          <ExternalLink size={12} className="flex-shrink-0" />
                          {ref}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : (
            <div className="glass-card p-12 text-center text-gray-500">
              Select or search a CVE ID to inspect detailed vulnerability intelligence.
            </div>
          )}
        </div>

        {/* Right Column: Lab Indexed Catalog */}
        <div className="glass-card p-4 border border-surface-400/20 space-y-3 h-fit">
          <h2 className="text-sm font-bold text-gray-200 uppercase tracking-wider mb-1 flex items-center gap-2">
            <BookOpen size={16} className="text-cyan-400" />
            Lab Indexed CVEs ({cveList.length})
          </h2>

          {loading ? (
            <p className="text-xs text-gray-500 py-6 text-center">Loading catalog...</p>
          ) : (
            cveList.map((item) => (
              <div
                key={item.cve_id}
                onClick={() => setActiveCve(item)}
                className={`p-3 rounded-lg border cursor-pointer transition-all duration-200 ${
                  activeCve?.cve_id === item.cve_id
                    ? 'bg-cyan-950/40 border-cyan-500/60 shadow-glow-cyan'
                    : 'bg-surface-700/40 border-surface-400/20 hover:border-cyan-500/30'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-cyan-400">{item.cve_id}</span>
                  <span className="font-mono text-xs font-bold text-red-400">
                    {item.cvss_score.toFixed(1)}
                  </span>
                </div>
                <p className="text-xs text-gray-400 mt-1 line-clamp-2">{item.description}</p>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
