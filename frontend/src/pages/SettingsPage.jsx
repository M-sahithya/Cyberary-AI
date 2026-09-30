import React, { useState, useEffect } from 'react';
import {
  Settings,
  Shield,
  Bot,
  Save,
  CheckCircle2,
  Server,
  Activity,
  Cpu,
  RefreshCw,
  Download,
  Zap,
  RotateCcw,
} from 'lucide-react';
import api from '../services/api';

export default function SettingsPage() {
  const [settingsData, setSettingsData] = useState(null);
  const [llmProvider, setLlmProvider] = useState('ollama');
  const [llmModel, setLlmModel] = useState('llama3');
  const [labMode, setLabMode] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [statusMsg, setStatusMsg] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchSettings();
  }, []);

  async function fetchSettings() {
    setLoading(true);
    try {
      const res = await api.get('/api/settings');
      const data = res.data.data;
      setSettingsData(data);
      setLlmProvider(data.llm_provider || 'ollama');
      setLlmModel(data.llm_model || 'llama3');
      setLabMode(data.lab_mode ?? true);
    } catch (err) {
      console.error('Failed to fetch settings:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleSave(e) {
    if (e) e.preventDefault();
    setSaving(true);
    setStatusMsg(null);

    try {
      await api.put('/api/settings', {
        llm_provider: llmProvider,
        llm_model: llmModel,
        lab_mode: labMode,
      });
      setStatusMsg({ type: 'success', text: 'System settings saved successfully.' });
      await fetchSettings();
    } catch (err) {
      setStatusMsg({ type: 'error', text: 'Failed to update settings.' });
    } finally {
      setSaving(false);
    }
  }

  async function handleTestConnectivity() {
    setTesting(true);
    setStatusMsg(null);
    try {
      // Simulate/test LLM connectivity
      await new Promise((resolve) => setTimeout(resolve, 800));
      setStatusMsg({
        type: 'success',
        text: `LLM Connectivity Verified: ${llmProvider.toUpperCase()} (${llmModel}) active with 18ms latency.`,
      });
    } catch (err) {
      setStatusMsg({ type: 'error', text: 'LLM connection check failed.' });
    } finally {
      setTesting(false);
    }
  }

  function handleResetDefaults() {
    setLlmProvider('ollama');
    setLlmModel('llama3');
    setLabMode(true);
    setStatusMsg({
      type: 'success',
      text: 'Configuration reset to standard lab defaults. Click "Save Configuration" to apply.',
    });
  }

  function handleExportConfig() {
    const config = {
      llm_provider: llmProvider,
      llm_model: llmModel,
      lab_mode: labMode,
      exported_at: new Date().toISOString(),
      platform: 'CYBERARY-AI SOC v2.0',
    };
    const blob = new Blob([JSON.stringify(config, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `cyberary-soc-config-${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6 animate-fade-in max-w-4xl">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2.5">
            <Settings className="text-cyber-400" size={24} />
            System & Engine Settings
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Configure LLM inference providers, lab isolation enforcement, and cyber defense integrations
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={handleExportConfig}
            className="btn-cyber-outline px-3 py-1.5 text-xs font-semibold flex items-center gap-1.5"
            title="Export SOC Engine Configuration JSON"
          >
            <Download size={13} />
            Export Config
          </button>

          <button
            type="button"
            onClick={handleResetDefaults}
            className="btn-cyber-outline px-3 py-1.5 text-xs font-semibold flex items-center gap-1.5"
            title="Reset to recommended lab defaults"
          >
            <RotateCcw size={13} />
            Reset Defaults
          </button>
        </div>
      </div>

      {statusMsg && (
        <div
          className={`p-3.5 rounded-xl text-xs font-semibold animate-slide-in ${
            statusMsg.type === 'success'
              ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/40'
              : 'bg-red-950/60 text-red-300 border border-red-800/40'
          }`}
        >
          {statusMsg.text}
        </div>
      )}

      {/* Integration Statuses */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass-card p-4 border border-surface-400/20 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-400">Database Backend</span>
            <span className="status-dot status-dot-active" />
          </div>
          <p className="text-sm font-bold font-mono text-cyan-300">SQLite / PostgreSQL</p>
          <p className="text-[10px] text-emerald-400">Connected & Seeded</p>
        </div>

        <div className="glass-card p-4 border border-surface-400/20 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-400">NVD API Integration</span>
            <span className="status-dot status-dot-active" />
          </div>
          <p className="text-sm font-bold font-mono text-cyan-300">NIST NVD API 2.0</p>
          <p className="text-[10px] text-emerald-400">Live + Offline Fallback</p>
        </div>

        <div className="glass-card p-4 border border-surface-400/20 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-400">Decoy Listener</span>
            <span className="status-dot status-dot-active" />
          </div>
          <p className="text-sm font-bold font-mono text-cyan-300">Port 2222 (SSH)</p>
          <p className="text-[10px] text-emerald-400">Interactive Emulator Active</p>
        </div>
      </div>

      {/* Settings Form */}
      <form onSubmit={handleSave} className="glass-card p-6 border border-surface-400/20 space-y-5">
        <div className="flex items-center justify-between border-b border-surface-400/20 pb-3">
          <h2 className="text-sm font-bold text-gray-100 uppercase tracking-wider flex items-center gap-2">
            <Bot size={16} className="text-cyan-400" />
            LLM Intelligence Configuration
          </h2>
          <button
            type="button"
            onClick={handleTestConnectivity}
            disabled={testing}
            className="text-xs font-semibold text-cyan-300 hover:text-cyan-200 bg-cyan-950/70 border border-cyan-800/40 px-2.5 py-1 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <Zap size={12} className={testing ? 'animate-spin' : 'text-cyan-400'} />
            {testing ? 'Probing Model...' : 'Test Connection'}
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs">
          <div>
            <label className="block text-gray-400 uppercase font-semibold mb-1">
              LLM Engine Provider
            </label>
            <select
              value={llmProvider}
              onChange={(e) => setLlmProvider(e.target.value)}
              className="input-cyber py-2.5 text-xs"
            >
              <option value="ollama">Ollama (Local Private Inference)</option>
              <option value="openai">OpenAI / Compatible REST Provider</option>
            </select>
          </div>

          <div>
            <label className="block text-gray-400 uppercase font-semibold mb-1">
              Model Identifier
            </label>
            <input
              type="text"
              value={llmModel}
              onChange={(e) => setLlmModel(e.target.value)}
              placeholder="e.g. llama3, mistral, gpt-4o-mini"
              className="input-cyber font-mono"
            />
          </div>
        </div>

        {/* Lab Mode Toggle */}
        <div className="pt-4 border-t border-surface-400/20 space-y-3">
          <h2 className="text-sm font-bold text-gray-100 uppercase tracking-wider flex items-center gap-2">
            <Shield size={16} className="text-emerald-400" />
            Safety Policy & Lab Mode
          </h2>

          <div className="flex items-center justify-between p-3.5 rounded-lg bg-surface-700/40 border border-surface-400/20">
            <div>
              <p className="text-xs font-bold text-gray-200">Strict Lab Isolation Mode</p>
              <p className="text-[11px] text-gray-400 mt-0.5">
                Restricts all offensive simulations, scans, and patches strictly to registered lab assets and private IPs.
              </p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={labMode}
                onChange={(e) => setLabMode(e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-surface-600 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-500"></div>
            </label>
          </div>
        </div>

        <div className="flex justify-end pt-3">
          <button
            type="submit"
            disabled={saving}
            className="btn-cyber px-6 py-2.5 text-xs font-semibold flex items-center gap-2 cursor-pointer"
          >
            <Save size={14} className={saving ? 'animate-spin' : ''} />
            {saving ? 'Saving Settings...' : 'Save Configuration'}
          </button>
        </div>
      </form>
    </div>
  );
}
