import React, { useState, useEffect } from 'react';
import {
  MonitorSpeaker,
  Shield,
  Search,
  Filter,
  Eye,
  X,
  AlertTriangle,
  Layers,
  Activity,
} from 'lucide-react';
import api from '../services/api';

export default function MitrePage() {
  const [techniques, setTechniques] = useState([]);
  const [tactics, setTactics] = useState([]);
  const [selectedTactic, setSelectedTactic] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedTech, setSelectedTech] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchMitreData();
  }, [selectedTactic]);

  async function fetchMitreData() {
    setLoading(true);
    try {
      const [techRes, tactRes] = await Promise.all([
        api.get(`/api/mitre/techniques${selectedTactic ? `?tactic=${selectedTactic}` : ''}`),
        api.get('/api/mitre/tactics'),
      ]);
      setTechniques(techRes.data.data.items || []);
      setTactics(tactRes.data.data.items || []);
    } catch (err) {
      console.error('Failed to fetch MITRE data:', err);
    } finally {
      setLoading(false);
    }
  }

  async function inspectTechnique(techId) {
    try {
      const res = await api.get(`/api/mitre/${techId}`);
      setSelectedTech(res.data.data);
    } catch (err) {
      console.error('Failed to fetch technique detail:', err);
    }
  }

  const filteredTechniques = techniques.filter((t) =>
    t.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    t.technique_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
    t.tactic.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2.5">
            <MonitorSpeaker className="text-cyan-400" size={24} />
            MITRE ATT&CK Matrix & Coverage
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Enterprise tactic mapping, adversary technique detection counts, and correlated incident feeds
          </p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-cyan-950/60 border border-cyan-800/40">
          <span className="text-xs font-mono text-cyan-400">{techniques.length} Techniques Indexed</span>
        </div>
      </div>

      {/* Tactics Selector Tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-thin">
        <button
          onClick={() => setSelectedTactic('')}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all ${
            selectedTactic === ''
              ? 'bg-cyan-600 text-white shadow-glow-cyan'
              : 'bg-surface-800 text-gray-400 hover:text-gray-200 border border-surface-400/20'
          }`}
        >
          All Tactics ({techniques.length})
        </button>
        {tactics.map((tac) => (
          <button
            key={tac.id}
            onClick={() => setSelectedTactic(tac.name)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all ${
              selectedTactic === tac.name
                ? 'bg-cyan-600 text-white shadow-glow-cyan'
                : 'bg-surface-800 text-gray-400 hover:text-gray-200 border border-surface-400/20'
            }`}
          >
            {tac.name}
          </button>
        ))}
      </div>

      {/* Search Bar */}
      <div className="glass-card p-3 flex items-center gap-3">
        <Search size={16} className="text-gray-500 ml-2" />
        <input
          type="text"
          placeholder="Filter techniques by ID, name, or tactic..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="bg-transparent text-xs text-gray-200 focus:outline-none flex-1"
        />
      </div>

      {/* Technique Matrix Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {loading ? (
          <div className="col-span-full py-12 text-center text-gray-500 text-xs">
            Loading MITRE ATT&CK Matrix...
          </div>
        ) : filteredTechniques.length === 0 ? (
          <div className="col-span-full py-12 text-center text-gray-500 text-xs">
            No MITRE techniques found matching criteria.
          </div>
        ) : (
          filteredTechniques.map((tech) => (
            <div
              key={tech.technique_id}
              onClick={() => inspectTechnique(tech.technique_id)}
              className="glass-card p-4 border border-surface-400/20 hover:border-cyan-500/40 hover:scale-[1.02] cursor-pointer transition-all duration-200 space-y-3 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-cyan-400 bg-cyan-950/60 border border-cyan-800/40 px-2 py-0.5 rounded">
                    {tech.technique_id}
                  </span>
                  <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider bg-surface-700/60 px-2 py-0.5 rounded">
                    {tech.tactic}
                  </span>
                </div>
                <h3 className="text-sm font-bold text-gray-100 mt-2.5 line-clamp-1">{tech.name}</h3>
                <p className="text-xs text-gray-400 mt-1 line-clamp-2">{tech.description}</p>
              </div>

              <div className="flex items-center justify-between pt-2 border-t border-surface-400/10 text-xs">
                <span className="text-gray-500">Detections</span>
                <span className="font-mono font-bold text-emerald-400">
                  {tech.detection_count} events
                </span>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Technique Detail Modal */}
      {selectedTech && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-fade-in">
          <div className="glass-card max-w-2xl w-full p-6 glow-border-cyan border border-cyber-500/30 space-y-4 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-surface-400/20 pb-3">
              <div>
                <span className="font-mono text-xs text-cyan-400 bg-cyan-950/60 border border-cyan-800/40 px-2 py-0.5 rounded font-bold">
                  {selectedTech.technique_id}
                </span>
                <h2 className="text-lg font-bold text-gray-100 mt-1">{selectedTech.name}</h2>
              </div>
              <button onClick={() => setSelectedTech(null)} className="text-gray-400 hover:text-gray-200 p-1">
                <X size={20} />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <p className="font-semibold text-gray-400 uppercase tracking-wider">Tactic</p>
                <p className="text-gray-200 text-sm mt-0.5">{selectedTech.tactic}</p>
              </div>
              <div>
                <p className="font-semibold text-gray-400 uppercase tracking-wider">Description</p>
                <p className="text-gray-300 leading-relaxed mt-0.5">{selectedTech.description}</p>
              </div>

              {/* Associated Threat Events */}
              <div>
                <p className="font-semibold text-gray-400 uppercase tracking-wider mb-2">
                  Correlated Live Threat Events ({selectedTech.associated_threats?.length || 0})
                </p>
                {selectedTech.associated_threats?.length === 0 ? (
                  <p className="text-gray-500 italic">No live threat events currently tied to this technique.</p>
                ) : (
                  <div className="space-y-2">
                    {selectedTech.associated_threats?.map((t, idx) => (
                      <div key={idx} className="p-2.5 rounded bg-surface-700/50 border border-surface-400/20 flex items-center justify-between">
                        <div>
                          <p className="font-medium text-gray-200">{t.title}</p>
                          <p className="text-[10px] text-gray-500 font-mono mt-0.5">
                            {t.event_id} · {t.source} · {new Date(t.timestamp).toLocaleTimeString()}
                          </p>
                        </div>
                        <span className="badge badge-critical">{t.severity}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-surface-400/20">
              <button onClick={() => setSelectedTech(null)} className="btn-cyber px-4 py-2 text-xs">
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
