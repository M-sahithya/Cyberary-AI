import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  ShieldCheck,
  Eye,
  EyeOff,
  AlertCircle,
  Terminal,
  Lock,
  User,
  Sparkles,
  ArrowRight,
  ShieldAlert,
} from 'lucide-react';

export default function LoginPage() {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('CyberaryAdmin123!');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleFillAdmin = () => {
    setUsername('admin');
    setPassword('CyberaryAdmin123!');
    setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!username.trim()) {
      setError('Please provide your operator handle or username.');
      return;
    }
    if (!password) {
      setError('Please enter your security passphrase.');
      return;
    }

    setLoading(true);

    try {
      await login(username.trim(), password);
      navigate('/dashboard', { replace: true });
    } catch (err) {
      const message =
        err.response?.data?.error?.message ||
        err.response?.data?.detail?.message ||
        err.response?.data?.detail ||
        'Authentication failed. Invalid operator credentials.';
      setError(typeof message === 'string' ? message : JSON.stringify(message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-surface-950 relative overflow-hidden py-10 px-4">
      {/* Background Cybernetic Effects */}
      <div className="absolute inset-0 pointer-events-none">
        {/* Futuristic glowing grid */}
        <div
          className="absolute inset-0 opacity-[0.04]"
          style={{
            backgroundImage: `linear-gradient(rgba(0, 229, 255, 0.4) 1px, transparent 1px),
              linear-gradient(90deg, rgba(0, 229, 255, 0.4) 1px, transparent 1px)`,
            backgroundSize: '48px 48px',
          }}
        />
        {/* Radial ambient glow circles */}
        <div className="absolute top-1/4 left-1/4 w-[450px] h-[450px] bg-cyber-500/10 rounded-full blur-[130px]" />
        <div className="absolute bottom-1/4 right-1/4 w-[400px] h-[400px] bg-purple-600/10 rounded-full blur-[130px]" />
      </div>

      <div className="relative w-full max-w-md">
        {/* Platform Branding */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-tr from-cyber-600 via-cyan-500 to-purple-600 p-0.5 shadow-glow-cyan mb-3">
            <div className="w-full h-full bg-surface-900 rounded-[14px] flex items-center justify-center">
              <ShieldCheck size={32} className="text-cyan-400" />
            </div>
          </div>
          <h1 className="text-2xl md:text-3xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-cyber-300 to-purple-400 tracking-tight">
            CYBERARY-AI
          </h1>
          <p className="text-xs md:text-sm text-gray-400 mt-1">
            Autonomous Cyber Defense & Offensive Operations Platform
          </p>
        </div>

        {/* Tab Navigation: Sign In / Create Account */}
        <div className="flex rounded-xl bg-surface-900/80 p-1.5 border border-surface-400/20 backdrop-blur-md mb-6">
          <div className="flex-1 py-2 text-center text-xs font-bold rounded-lg bg-cyber-500 text-surface-950 shadow-glow-cyan transition-all">
            Sign In to Existing Terminal
          </div>
          <Link
            to="/register"
            className="flex-1 py-2 text-center text-xs font-semibold rounded-lg text-gray-400 hover:text-gray-200 transition-all"
          >
            Create Lab Account
          </Link>
        </div>

        {/* Main Sign In Card */}
        <div className="glass-card p-6 md:p-8 border border-cyber-500/30 rounded-2xl shadow-2xl relative overflow-hidden backdrop-blur-xl">
          {/* Top Neon Accent Line */}
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 via-cyber-400 to-purple-500" />

          {/* Card Header & Auto-fill Action */}
          <div className="flex items-center justify-between pb-4 mb-4 border-b border-surface-400/20">
            <div>
              <h2 className="text-base font-bold text-gray-100 flex items-center gap-2">
                <Terminal size={16} className="text-cyan-400" />
                Terminal Authentication
              </h2>
              <p className="text-[11px] text-gray-400">
                Enter operator credentials to access the live SOC dashboard
              </p>
            </div>
            <button
              type="button"
              onClick={handleFillAdmin}
              className="text-[11px] font-semibold text-cyan-300 bg-cyan-950/70 border border-cyan-700/50 hover:bg-cyan-900/60 px-2.5 py-1.5 rounded-lg flex items-center gap-1.5 transition-colors"
              title="Populate pre-configured administrator credentials"
            >
              <Sparkles size={13} className="text-cyan-400" />
              Demo Fill
            </button>
          </div>

          {/* Error Banner */}
          {error && (
            <div className="flex items-start gap-2.5 p-3.5 mb-4 rounded-xl bg-red-950/50 border border-red-800/40 text-red-300 text-xs animate-slide-in">
              <AlertCircle size={16} className="text-red-400 flex-shrink-0 mt-0.5" />
              <div className="flex-1">{error}</div>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label
                htmlFor="username"
                className="block text-[11px] font-bold text-gray-300 uppercase tracking-wider mb-1.5"
              >
                Operator Handle / Username
              </label>
              <div className="relative">
                <User size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500" />
                <input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="input-cyber pl-10 text-xs font-mono"
                  placeholder="admin"
                  autoFocus
                  autoComplete="username"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label
                  htmlFor="password"
                  className="block text-[11px] font-bold text-gray-300 uppercase tracking-wider"
                >
                  Security Passphrase
                </label>
                <span className="text-[10px] text-gray-500 font-mono">LAB-ENCRYPTED</span>
              </div>
              <div className="relative">
                <Lock size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500" />
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input-cyber pl-10 pr-10 text-xs font-mono"
                  placeholder="Enter your security passphrase"
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200 transition-colors"
                >
                  {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            {/* Quick Demo Credentials Info Box */}
            <div className="p-2.5 rounded-lg bg-surface-900/80 border border-surface-400/20 text-[11px] text-gray-400 flex items-center justify-between font-mono">
              <span>Admin: <span className="text-cyan-400">admin</span></span>
              <span>Pass: <span className="text-cyan-400">CyberaryAdmin123!</span></span>
            </div>

            {/* Active & Fully Functional Submit Button */}
            <button
              type="submit"
              className="w-full py-3 px-4 rounded-xl font-bold text-xs uppercase tracking-wider transition-all duration-300 bg-gradient-to-r from-cyber-500 via-cyan-500 to-purple-600 text-surface-950 hover:brightness-110 shadow-glow-cyan flex items-center justify-center gap-2 group cursor-pointer"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-surface-950/40 border-t-surface-950 rounded-full animate-spin" />
                  Verifying Cryptographic Tokens...
                </>
              ) : (
                <>
                  <span>Authenticate & Enter SOC</span>
                  <ArrowRight size={15} className="group-hover:translate-x-1 transition-transform" />
                </>
              )}
            </button>
          </form>

          {/* Quick Switch to Register */}
          <div className="mt-5 pt-4 border-t border-surface-400/20 text-center text-xs text-gray-400">
            Need a new security analyst pass?{' '}
            <Link to="/register" className="text-cyan-400 hover:text-cyan-300 font-bold underline transition-colors">
              Create Lab Account
            </Link>
          </div>
        </div>

        {/* Lab Mode Active Indicator */}
        <div className="flex items-center justify-center gap-2 mt-4 text-[11px] text-gray-500 font-mono">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>CYBERARY-AI SOC LAB RUNTIME v2.0 • READY</span>
        </div>
      </div>
    </div>
  );
}
