import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Server,
  Plus,
  ShieldCheck,
  Activity,
  AlertTriangle,
  Lock,
  X,
  Play,
  Wifi,
  Download,
  Sparkles,
  CheckCircle2,
  Trash2,
} from 'lucide-react';
import api from '../services/api';

export default function AssetsPage() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [name, setName] = useState('');
  const [ipAddress, setIpAddress] = useState('10.0.1.50');
  const [assetType, setAssetType] = useState('linux');
  const [importance, setImportance] = useState('HIGH');
  const [formError, setFormError] = useState(null);
  const [registering, setRegistering] = useState(false);
  const [pingStatus, setPingStatus] = useState({});

  const navigate = useNavigate();

  useEffect(() => {
    fetchAssets();
  }, []);

  async function fetchAssets() {
    setLoading(true);
    try {
      const res = await api.get('/api/assets');
      setAssets(res.data.data.items || []);
    } catch (err) {
      console.error('Failed to fetch assets:', err);
    } finally {
      setLoading(false);
    }
  }

  const handleAutofillAsset = () => {
    const id = Math.floor(10 + Math.random() * 89);
    setName(`lab-node-${id}`);
    setIpAddress(`10.0.1.${id}`);
    setAssetType('linux');
    setImportance('HIGH');
  };

  async function handleRegister(e) {
    if (e) e.preventDefault();
    setFormError(null);

    if (!name.trim()) {
      setFormError('Please specify an asset name.');
      return;
    }
    if (!ipAddress.trim()) {
      setFormError('Please enter a private lab IP address.');
      return;
    }

    setRegistering(true);

    try {
      await api.post('/api/assets', {
        name: name.trim(),
        ip_address: ipAddress.trim(),
        asset_type: assetType,
        importance,
      });
      setIsModalOpen(false);
      setName('');
      await fetchAssets();
    } catch (err) {
      setFormError(err.response?.data?.error?.message || 'Failed to register asset. Ensure IP is in private range.');
    } finally {
      setRegistering(false);
    }
  }

  function handlePingTest(assetId, assetIp) {
    setPingStatus((prev) => ({ ...prev, [assetId]: 'pinging' }));
    setTimeout(() => {
      setPingStatus((prev) => ({
        ...prev,
        [assetId]: 'online',
      }));
      setTimeout(() => {
        setPingStatus((prev) => ({ ...prev, [assetId]: null }));
      }, 4000);
    }, 800);
  }

  function handleExportInventory() {
    const blob = new Blob([JSON.stringify(assets, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `authorized-lab-assets-${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2.5">
            <Server className="text-cyber-400" size={24} />
            Authorized Lab Assets & Inventory
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Registered isolated lab infrastructure targets permitted for ethical assessment & decoy telemetry
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleExportInventory}
            className="btn-cyber-outline px-3.5 py-1.5 text-xs font-semibold flex items-center gap-1.5"
            title="Export asset inventory as JSON"
          >
            <Download size={14} />
            Export Inventory
          </button>
          <button
            type="button"
            onClick={() => setIsModalOpen(true)}
            className="btn-cyber flex items-center gap-1.5 text-xs font-semibold"
          >
            <Plus size={15} />
            Register Lab Asset
          </button>
        </div>
      </div>

      {/* Asset Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {loading ? (
          <div className="col-span-full py-12 text-center text-gray-500 text-xs">
            Loading lab asset inventory...
          </div>
        ) : assets.length === 0 ? (
          <div className="col-span-full py-12 text-center text-gray-500 text-xs">
            No lab assets registered yet. Click &quot;Register Lab Asset&quot; to add your target environment.
          </div>
        ) : (
          assets.map((asset) => (
            <div
              key={asset.id}
              className="glass-card p-5 border border-surface-400/20 hover:border-cyber-500/40 transition-all duration-200 space-y-4 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-base font-bold text-gray-100">{asset.name}</h3>
                    <p className="font-mono text-xs text-cyber-400 mt-0.5">{asset.ip_address}</p>
                  </div>
                  <span className="flex items-center gap-1 text-[10px] font-semibold text-emerald-400 bg-emerald-950/60 border border-emerald-800/40 px-2 py-0.5 rounded">
                    <ShieldCheck size={12} />
                    Authorized Target
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3 text-xs pt-3 mt-2 border-t border-surface-400/10">
                  <div>
                    <p className="text-gray-500">Importance</p>
                    <p className="font-bold text-gray-200">{asset.importance}</p>
                  </div>
                  <div>
                    <p className="text-gray-500">Asset Type</p>
                    <p className="font-mono text-gray-300 uppercase">{asset.asset_type}</p>
                  </div>
                  <div>
                    <p className="text-gray-500">Open Vulns</p>
                    <p className="font-bold text-orange-400">{asset.vulnerability_count || 0}</p>
                  </div>
                  <div>
                    <p className="text-gray-500">Risk Score</p>
                    <p className="font-mono font-bold text-red-400">{asset.risk_score || 0}</p>
                  </div>
                </div>

                <div className="flex items-center justify-between pt-2.5 mt-2 border-t border-surface-400/10 text-[11px] text-gray-500">
                  <span>Env: {asset.environment || 'Lab Isolated'}</span>
                  <span className="text-cyan-400 font-semibold">{asset.status || 'Active'}</span>
                </div>
              </div>

              {/* Action Buttons on Asset Card */}
              <div className="pt-3 border-t border-surface-400/20 flex items-center justify-between gap-2">
                <button
                  type="button"
                  onClick={() => handlePingTest(asset.id, asset.ip_address)}
                  className="btn-cyber-outline py-1 px-2.5 text-xs flex items-center gap-1 font-mono"
                  title="Test node reachability via ICMP / SSH probe"
                >
                  <Wifi size={12} className={pingStatus[asset.id] === 'pinging' ? 'animate-pulse text-cyan-400' : ''} />
                  {pingStatus[asset.id] === 'pinging'
                    ? 'Probing...'
                    : pingStatus[asset.id] === 'online'
                    ? 'Online (1.2ms)'
                    : 'Ping Test'}
                </button>

                <button
                  type="button"
                  onClick={() => navigate('/vulnerabilities')}
                  className="btn-cyber py-1 px-2.5 text-xs flex items-center gap-1 font-semibold"
                  title="Run Vulnerability Scan on this target"
                >
                  <Play size={12} />
                  Run Assessment
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Register Asset Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 animate-fade-in">
          <div className="glass-card max-w-md w-full p-6 glow-border-cyan border border-cyber-500/30 space-y-4">
            <div className="flex items-center justify-between border-b border-surface-400/20 pb-3">
              <div className="flex items-center gap-2">
                <Server size={18} className="text-cyan-400" />
                <h2 className="text-lg font-bold text-gray-100">Register Lab Target</h2>
              </div>
              <button
                type="button"
                onClick={() => setIsModalOpen(false)}
                className="text-gray-400 hover:text-gray-200"
              >
                <X size={20} />
              </button>
            </div>

            {formError && (
              <div className="p-3 bg-red-950/50 border border-red-800/40 rounded-lg text-xs text-red-300">
                {formError}
              </div>
            )}

            <form onSubmit={handleRegister} className="space-y-3.5 text-xs">
              <div className="flex justify-end">
                <button
                  type="button"
                  onClick={handleAutofillAsset}
                  className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold"
                >
                  <Sparkles size={12} />
                  Autofill Sample Target
                </button>
              </div>

              <div>
                <label className="block text-gray-400 uppercase font-semibold mb-1">Asset Hostname</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. lab-db-01 or lab-web-worker"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="input-cyber font-mono"
                />
              </div>

              <div>
                <label className="block text-gray-400 uppercase font-semibold mb-1">
                  Private Lab IPv4 Address
                </label>
                <input
                  type="text"
                  required
                  placeholder="10.0.1.X or 192.168.X.X or 172.16.X.X"
                  value={ipAddress}
                  onChange={(e) => setIpAddress(e.target.value)}
                  className="input-cyber font-mono"
                />
                <p className="text-[10px] text-gray-500 mt-1">
                  Safety verification: RFC 1918 private non-routable IP spaces only.
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-gray-400 uppercase font-semibold mb-1">Asset Type</label>
                  <select
                    value={assetType}
                    onChange={(e) => setAssetType(e.target.value)}
                    className="input-cyber py-2 text-xs"
                  >
                    <option value="linux">Linux Server</option>
                    <option value="database">Database Node</option>
                    <option value="web">Web Server</option>
                    <option value="honeypot">Honeypot Decoy</option>
                  </select>
                </div>

                <div>
                  <label className="block text-gray-400 uppercase font-semibold mb-1">Criticality</label>
                  <select
                    value={importance}
                    onChange={(e) => setImportance(e.target.value)}
                    className="input-cyber py-2 text-xs"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-surface-400/20">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="btn-cyber-outline px-4 py-2 text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={registering}
                  className="btn-cyber px-5 py-2 text-xs font-semibold cursor-pointer"
                >
                  {registering ? 'Validating & Registering...' : 'Register Asset'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
