import React, { useState, useEffect } from 'react';
import {
  Bot,
  Play,
  CheckCircle2,
  Cpu,
  Activity,
  Zap,
  Layers,
  ShieldAlert,
  GitBranch,
  Network,
  Terminal,
  ArrowRight,
} from 'lucide-react';
import api from '../services/api';

export default function AgentsPage() {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [runningAgent, setRunningAgent] = useState(null);
  const [runMessage, setRunMessage] = useState(null);

  // Autonomous Exploit Planner state (Richard Fang et al. architecture)
  const [target, setTarget] = useState('lab-server-01');
  const [useCveDesc, setUseCveDesc] = useState(true);
  const [cveDesc, setCveDesc] = useState('OpenSSH 8.9p1 PKCS#11 provider arbitrary library execution allowing remote privilege escalation');
  const [enableConcurrency, setEnableConcurrency] = useState(true);
  const [planning, setPlanning] = useState(false);
  const [planResult, setPlanResult] = useState(null);

  useEffect(() => {
    fetchAgents();
  }, []);

  async function fetchAgents() {
    setLoading(true);
    try {
      const res = await api.get('/api/agents');
      setAgents(res.data.data.items || []);
    } catch (err) {
      console.error('Failed to fetch agents:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleTriggerAgent(agentId, agentName) {
    setRunningAgent(agentId);
    setRunMessage(null);

    try {
      const res = await api.post(`/api/agents/${agentId}/run`);
      setRunMessage({
        type: 'success',
        text: `${agentName}: ${res.data.data.summary}`,
      });
      await fetchAgents();
    } catch (err) {
      setRunMessage({
        type: 'error',
        text: `Failed to execute agent routine: ${err.message}`,
      });
    } finally {
      setRunningAgent(null);
    }
  }

  async function handleRunAutonomousPlan(e) {
    e.preventDefault();
    setPlanning(true);
    setPlanResult(null);
    setRunMessage(null);

    try {
      const payload = {
        target: target,
        cve_description: useCveDesc ? cveDesc : null,
        enable_concurrency: enableConcurrency,
      };
      const res = await api.post('/api/agents/offensive/autonomous-plan', payload);
      setPlanResult(res.data.data);
      setRunMessage({
        type: 'success',
        text: `Autonomous Exploit Assessment Completed: ${res.data.data.primary_vulnerability.type}`,
      });
      await fetchAgents();
    } catch (err) {
      setRunMessage({
        type: 'error',
        text: `Autonomous planning error: ${err.message}`,
      });
    } finally {
      setPlanning(false);
    }
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2.5">
            <Bot className="text-cyan-400" size={24} />
            Autonomous AI Agents Orchestrator
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Multi-agent architecture coordinating offensive simulation, generative decoy interaction, threat intel, and remediation
          </p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-cyan-950/60 border border-cyan-800/40">
          <span className="status-dot status-dot-active" />
          <span className="text-xs font-mono text-cyan-400">All Agents Autonomous & Online</span>
        </div>
      </div>

      {runMessage && (
        <div
          className={`p-3 rounded-lg text-xs font-medium animate-slide-in ${
            runMessage.type === 'success'
              ? 'bg-emerald-950/50 text-emerald-300 border border-emerald-800/40'
              : 'bg-red-950/50 text-red-300 border border-red-800/40'
          }`}
        >
          {runMessage.text}
        </div>
      )}

      {/* Autonomous Exploit Planner Console (Richard Fang et al. Future Work Architecture) */}
      <div className="glass-card border border-cyan-500/30 p-5 space-y-4 bg-surface-800/40">
        <div className="flex items-center justify-between flex-wrap gap-2 border-b border-surface-400/20 pb-3">
          <div className="flex items-center gap-2">
            <GitBranch className="text-cyan-400" size={20} />
            <div>
              <h2 className="text-sm font-bold text-gray-100">
                Autonomous One-Day Exploit Planner & Subagent Engine
              </h2>
              <p className="text-[11px] text-gray-400">
                Implements hierarchical planning with subagents, multi-vector exploration, and ACIDRain concurrency verification
              </p>
            </div>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
            Richard Fang et al. (2024) Framework
          </span>
        </div>

        <form onSubmit={handleRunAutonomousPlan} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label className="text-[11px] text-gray-400 block mb-1 font-semibold">Target Asset</label>
              <select
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="input-cyber text-xs w-full"
              >
                <option value="lab-server-01">lab-server-01 (10.0.1.10)</option>
                <option value="ubuntu-telemetry-vm">ubuntu-telemetry-vm (192.168.56.103)</option>
              </select>
            </div>

            <div>
              <label className="text-[11px] text-gray-400 block mb-1 font-semibold">Exploration Regime</label>
              <div className="flex items-center gap-3 pt-2">
                <label className="flex items-center gap-1.5 text-xs text-gray-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={useCveDesc}
                    onChange={(e) => setUseCveDesc(e.target.checked)}
                    className="rounded border-surface-400 bg-surface-900 text-cyan-500"
                  />
                  <span>Guided with CVE Description</span>
                </label>
              </div>
            </div>

            <div>
              <label className="text-[11px] text-gray-400 block mb-1 font-semibold">Concurrency (ACIDRain)</label>
              <div className="flex items-center gap-3 pt-2">
                <label className="flex items-center gap-1.5 text-xs text-gray-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableConcurrency}
                    onChange={(e) => setEnableConcurrency(e.target.checked)}
                    className="rounded border-surface-400 bg-surface-900 text-cyan-500"
                  />
                  <span>Test Race Conditions</span>
                </label>
              </div>
            </div>
          </div>

          {useCveDesc && (
            <div>
              <label className="text-[11px] text-gray-400 block mb-1 font-semibold">CVE Description Prompt</label>
              <input
                type="text"
                value={cveDesc}
                onChange={(e) => setCveDesc(e.target.value)}
                placeholder="Enter CVE description or vulnerability text..."
                className="input-cyber text-xs w-full font-mono"
              />
            </div>
          )}

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={planning}
              className="btn-cyber py-2 px-5 text-xs font-semibold flex items-center gap-2"
            >
              {planning ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Orchestrating Subagents...
                </>
              ) : (
                <>
                  <Zap size={14} />
                  Execute Autonomous Exploit Plan
                </>
              )}
            </button>
          </div>
        </form>

        {/* Plan Results Display */}
        {planResult && (
          <div className="p-4 rounded-lg bg-surface-900/90 border border-surface-400/20 space-y-3 animate-slide-in">
            <div className="flex items-center justify-between border-b border-surface-400/20 pb-2">
              <div className="flex items-center gap-2">
                <ShieldAlert size={16} className="text-amber-400" />
                <span className="text-xs font-bold text-gray-100">
                  Assessment ID: {planResult.assessment_id} ({planResult.cve_mode})
                </span>
              </div>
              <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/40 px-2 py-0.5 rounded">
                {planResult.verification_outcome?.verification_status}
              </span>
            </div>

            {/* Subagent Execution Tree */}
            <div className="space-y-1.5 pt-1">
              <p className="text-[10px] uppercase font-bold text-gray-400 tracking-wider">
                Multi-Subagent Execution Trace
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                {planResult.execution_log?.map((log, idx) => (
                  <div key={idx} className="p-2.5 rounded bg-surface-800/80 border border-surface-500/20 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-cyan-300 font-bold text-[11px]">{log.phase}</span>
                      <span className="text-[9px] font-mono text-purple-300 bg-purple-950/60 px-1.5 py-0.5 rounded border border-purple-800/40">
                        {log.subagent}
                      </span>
                    </div>
                    <p className="text-[11px] text-gray-300">{log.summary}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Defensive Countermeasure Synthesis */}
            {planResult.verification_outcome?.defensive_countermeasures && (
              <div className="p-3 rounded bg-surface-800/60 border border-emerald-500/30 text-xs space-y-1.5">
                <span className="text-[10px] uppercase font-bold text-emerald-400 tracking-wider flex items-center gap-1.5">
                  <CheckCircle2 size={13} />
                  Synthesized Defensive Countermeasure
                </span>
                <p className="text-gray-300 text-xs">
                  {planResult.verification_outcome.defensive_countermeasures.recommended_fix}
                </p>
                <code className="block p-2 rounded bg-surface-950 font-mono text-[11px] text-cyan-300 border border-surface-600/40">
                  {planResult.verification_outcome.defensive_countermeasures.proposed_patch}
                </code>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Agents Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {loading ? (
          <div className="col-span-full py-12 text-center text-gray-500 text-xs">
            Loading AI agents...
          </div>
        ) : (
          agents.map((agent) => (
            <div
              key={agent.id}
              className="glass-card p-5 border border-surface-400/20 hover:border-cyan-500/30 transition-all duration-200 space-y-4 flex flex-col justify-between"
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-base font-bold text-gray-100 flex items-center gap-2">
                      <Cpu size={16} className="text-cyan-400" />
                      {agent.name}
                    </h3>
                    <p className="text-xs text-gray-400 mt-0.5">{agent.role}</p>
                  </div>
                  <span className="flex items-center gap-1 text-[10px] font-semibold text-emerald-400 bg-emerald-950/60 border border-emerald-800/40 px-2 py-0.5 rounded">
                    <span className="status-dot status-dot-active" />
                    {agent.status}
                  </span>
                </div>

                <p className="text-xs text-gray-300 leading-relaxed bg-surface-900/60 p-3 rounded border border-surface-400/20">
                  {agent.description}
                </p>

                {/* Capabilities */}
                <div>
                  <p className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-1.5">
                    Core Capabilities
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {agent.capabilities?.map((cap, i) => (
                      <span
                        key={i}
                        className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/40 px-2 py-0.5 rounded"
                      >
                        {cap}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Action Trigger */}
              <div className="pt-3 border-t border-surface-400/20 flex items-center justify-between">
                <span className="text-[10px] text-gray-500 truncate max-w-[160px]">
                  {agent.last_task}
                </span>

                <button
                  onClick={() => handleTriggerAgent(agent.id, agent.name)}
                  disabled={runningAgent === agent.id}
                  className="btn-cyber py-1 px-3 text-xs font-semibold flex items-center gap-1.5"
                >
                  {runningAgent === agent.id ? (
                    <>
                      <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      Running...
                    </>
                  ) : (
                    <>
                      <Play size={12} />
                      Trigger Cycle
                    </>
                  )}
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
