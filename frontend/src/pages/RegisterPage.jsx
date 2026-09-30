import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  ShieldCheck,
  Eye,
  EyeOff,
  AlertCircle,
  User,
  Mail,
  Lock,
  CheckCircle2,
  Sparkles,
  ArrowRight,
  ShieldAlert,
  Terminal,
} from 'lucide-react';

export default function RegisterPage() {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [rolePersona, setRolePersona] = useState('SOC_ANALYST');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  const { register } = useAuth();
  const navigate = useNavigate();

  // Password strength calculator
  const calculatePasswordStrength = (pass) => {
    if (!pass) return { score: 0, label: 'Empty', color: 'bg-gray-600', text: 'text-gray-500' };
    let score = 0;
    if (pass.length >= 8) score += 1;
    if (/[A-Z]/.test(pass)) score += 1;
    if (/[0-9]/.test(pass)) score += 1;
    if (/[^A-Za-z0-9]/.test(pass)) score += 1;

    switch (score) {
      case 1:
        return { score: 25, label: 'Weak', color: 'bg-red-500', text: 'text-red-400' };
      case 2:
        return { score: 50, label: 'Fair', color: 'bg-amber-500', text: 'text-amber-400' };
      case 3:
        return { score: 75, label: 'Good', color: 'bg-blue-400', text: 'text-blue-400' };
      case 4:
        return { score: 100, label: 'Strong (Cyber-Grade)', color: 'bg-emerald-400', text: 'text-emerald-400' };
      default:
        return { score: 15, label: 'Very Weak', color: 'bg-red-600', text: 'text-red-400' };
    }
  };

  const strength = calculatePasswordStrength(password);

  const handleQuickFill = () => {
    const randomId = Math.floor(100 + Math.random() * 900);
    setUsername(`analyst_${randomId}`);
    setEmail(`analyst_${randomId}@soc.cyberary.local`);
    setPassword('CyberSecurity2026!');
    setConfirmPassword('CyberSecurity2026!');
    setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    // Client-side validations
    if (!username.trim() || username.length < 3) {
      setError('Username must be at least 3 characters long.');
      return;
    }
    if (!email.trim() || !email.includes('@')) {
      setError('Please provide a valid corporate or lab email address.');
      return;
    }
    if (!password || password.length < 8) {
      setError('Password must contain at least 8 characters for security compliance.');
      return;
    }
    if (password !== confirmPassword) {
      setError('Password confirmation does not match the entered password.');
      return;
    }

    setLoading(true);

    try {
      await register(username.trim(), email.trim(), password);
      setSuccess('Account created and identity authenticated! Redirecting to SOC dashboard...');
      setTimeout(() => {
        navigate('/dashboard', { replace: true });
      }, 1000);
    } catch (err) {
      const message =
        err.response?.data?.error?.message ||
        err.response?.data?.detail?.message ||
        err.response?.data?.detail ||
        'Registration failed. Username or email may already be in use.';
      setError(typeof message === 'string' ? message : JSON.stringify(message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-surface-950 relative overflow-hidden py-10 px-4">
      {/* Background Cybernetic Effects */}
      <div className="absolute inset-0 pointer-events-none">
        {/* Animated Grid lines */}
        <div
          className="absolute inset-0 opacity-[0.04]"
          style={{
            backgroundImage: `linear-gradient(rgba(0, 229, 255, 0.4) 1px, transparent 1px),
              linear-gradient(90deg, rgba(0, 229, 255, 0.4) 1px, transparent 1px)`,
            backgroundSize: '48px 48px',
          }}
        />
        {/* Radial Ambient Orbs */}
        <div className="absolute top-1/6 left-1/5 w-[500px] h-[500px] bg-cyber-500/10 rounded-full blur-[140px]" />
        <div className="absolute bottom-1/6 right-1/5 w-[450px] h-[450px] bg-purple-600/10 rounded-full blur-[140px]" />
      </div>

      <div className="relative w-full max-w-xl">
        {/* Card Header Branding */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-tr from-cyber-600 via-cyan-500 to-purple-600 p-0.5 shadow-glow-cyan mb-3">
            <div className="w-full h-full bg-surface-900 rounded-[14px] flex items-center justify-center">
              <ShieldCheck size={32} className="text-cyan-400" />
            </div>
          </div>
          <h1 className="text-2xl md:text-3xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-cyber-300 to-purple-400 tracking-tight">
            CYBERARY-AI PLATFORM
          </h1>
          <p className="text-xs md:text-sm text-gray-400 mt-1">
            Autonomous SOC Defense & Offensive Security Intelligence
          </p>
        </div>

        {/* Tab Navigation: Sign In / Create Account */}
        <div className="flex rounded-xl bg-surface-900/80 p-1.5 border border-surface-400/20 backdrop-blur-md mb-6">
          <Link
            to="/login"
            className="flex-1 py-2 text-center text-xs font-semibold rounded-lg text-gray-400 hover:text-gray-200 transition-all"
          >
            Sign In to Existing Terminal
          </Link>
          <div className="flex-1 py-2 text-center text-xs font-bold rounded-lg bg-cyber-500 text-surface-950 shadow-glow-cyan transition-all">
            Create Lab Account
          </div>
        </div>

        {/* Main Registration Card */}
        <div className="glass-card p-6 md:p-8 border border-cyber-500/30 rounded-2xl shadow-2xl relative overflow-hidden backdrop-blur-xl">
          {/* Subtle Top Accent Line */}
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 via-cyber-400 to-purple-500" />

          {/* Title & Quick Demo Fill */}
          <div className="flex items-center justify-between pb-4 mb-4 border-b border-surface-400/20">
            <div>
              <h2 className="text-base font-bold text-gray-100 flex items-center gap-2">
                <Terminal size={16} className="text-cyan-400" />
                Operator Enlistment
              </h2>
              <p className="text-[11px] text-gray-400">
                Register authorized credentials for isolated lab telemetry & agent control
              </p>
            </div>
            <button
              type="button"
              onClick={handleQuickFill}
              className="text-[11px] font-semibold text-cyan-300 bg-cyan-950/70 border border-cyan-700/50 hover:bg-cyan-900/60 px-2.5 py-1.5 rounded-lg flex items-center gap-1.5 transition-colors"
              title="Auto-fill with sample SOC analyst credentials"
            >
              <Sparkles size={13} className="text-cyan-400" />
              Demo Autofill
            </button>
          </div>

          {/* Feedback Messages */}
          {error && (
            <div className="flex items-start gap-2.5 p-3.5 mb-4 rounded-xl bg-red-950/50 border border-red-800/40 text-red-300 text-xs animate-slide-in">
              <AlertCircle size={16} className="text-red-400 flex-shrink-0 mt-0.5" />
              <div className="flex-1">{error}</div>
            </div>
          )}

          {success && (
            <div className="flex items-start gap-2.5 p-3.5 mb-4 rounded-xl bg-emerald-950/50 border border-emerald-800/40 text-emerald-300 text-xs animate-slide-in">
              <CheckCircle2 size={16} className="text-emerald-400 flex-shrink-0 mt-0.5" />
              <div className="flex-1">{success}</div>
            </div>
          )}

          {/* Registration Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Username & Email Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
              <div>
                <label className="block text-[11px] font-bold text-gray-300 uppercase tracking-wider mb-1">
                  Operator Handle / Username
                </label>
                <div className="relative">
                  <User size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500" />
                  <input
                    type="text"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="e.g. soc_lead"
                    className="input-cyber pl-10 text-xs font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-bold text-gray-300 uppercase tracking-wider mb-1">
                  SOC / Lab Email Address
                </label>
                <div className="relative">
                  <Mail size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500" />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="e.g. operator@cyberary.local"
                    className="input-cyber pl-10 text-xs font-mono"
                  />
                </div>
              </div>
            </div>

            {/* Password & Confirm Password Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
              <div>
                <label className="block text-[11px] font-bold text-gray-300 uppercase tracking-wider mb-1">
                  Security Passphrase
                </label>
                <div className="relative">
                  <Lock size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Min 8 characters"
                    className="input-cyber pl-10 pr-10 text-xs font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200"
                  >
                    {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-bold text-gray-300 uppercase tracking-wider mb-1">
                  Confirm Passphrase
                </label>
                <div className="relative">
                  <Lock size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500" />
                  <input
                    type={showConfirmPassword ? 'text' : 'password'}
                    required
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Repeat passphrase"
                    className="input-cyber pl-10 pr-10 text-xs font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200"
                  >
                    {showConfirmPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
              </div>
            </div>

            {/* Dynamic Password Strength Bar */}
            {password && (
              <div className="p-2.5 rounded-lg bg-surface-900/80 border border-surface-400/20 text-xs space-y-1.5 animate-fade-in">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-gray-400">Security Rigor:</span>
                  <span className={`font-mono font-bold ${strength.text}`}>{strength.label}</span>
                </div>
                <div className="h-1.5 w-full bg-surface-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 ${strength.color}`}
                    style={{ width: `${strength.score}%` }}
                  />
                </div>
              </div>
            )}

            {/* Operator Persona Selection */}
            <div>
              <label className="block text-[11px] font-bold text-gray-300 uppercase tracking-wider mb-1">
                Assigned Operational Role (Lab RBAC)
              </label>
              <div className="grid grid-cols-2 gap-2 text-xs">
                {[
                  { id: 'SOC_ANALYST', title: 'SOC Analyst', desc: 'Live Telemetry & Threat Defense' },
                  { id: 'PEN_TESTER', title: 'Offensive Operator', desc: 'Ethical Exploit Simulation' },
                  { id: 'INCIDENT_RESPONDER', title: 'Remediation Lead', desc: 'Patch Approval & Rollback' },
                  { id: 'SECURITY_AUDITOR', title: 'Compliance Auditor', desc: 'Forensic Audit Trails' },
                ].map((role) => (
                  <div
                    key={role.id}
                    onClick={() => setRolePersona(role.id)}
                    className={`p-2.5 rounded-lg border cursor-pointer transition-all ${
                      rolePersona === role.id
                        ? 'bg-cyber-500/10 border-cyber-500/60 shadow-glow-cyan/20'
                        : 'bg-surface-800/50 border-surface-400/20 hover:border-surface-400/40'
                    }`}
                  >
                    <p className={`font-bold text-[11px] ${rolePersona === role.id ? 'text-cyan-300' : 'text-gray-300'}`}>
                      {role.title}
                    </p>
                    <p className="text-[10px] text-gray-500 mt-0.5">{role.desc}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Lab Safety Policy Check */}
            <div className="p-3 rounded-lg bg-surface-900/60 border border-surface-400/20 flex items-start gap-2.5 text-[11px] text-gray-400">
              <ShieldAlert size={16} className="text-cyan-400 flex-shrink-0 mt-0.5" />
              <p>
                By enrolling, you acknowledge that all AI attack simulations, honeypot telemetry, and patches are restricted strictly to authorized lab assets.
              </p>
            </div>

            {/* Interactive Submit Button */}
            <button
              type="submit"
              className="w-full py-3 px-4 rounded-xl font-bold text-xs uppercase tracking-wider transition-all duration-300 bg-gradient-to-r from-cyber-500 via-cyan-500 to-purple-600 text-surface-950 hover:brightness-110 shadow-glow-cyan flex items-center justify-center gap-2 group cursor-pointer"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-surface-950/40 border-t-surface-950 rounded-full animate-spin" />
                  Initializing Identity & Generating Access Keys...
                </>
              ) : (
                <>
                  <span>Initialize Security Account</span>
                  <ArrowRight size={15} className="group-hover:translate-x-1 transition-transform" />
                </>
              )}
            </button>
          </form>

          {/* Quick Switch to Login */}
          <div className="mt-5 pt-4 border-t border-surface-400/20 text-center text-xs text-gray-400">
            Already have an active security pass?{' '}
            <Link to="/login" className="text-cyan-400 hover:text-cyan-300 font-bold underline transition-colors">
              Sign In to Terminal
            </Link>
          </div>
        </div>

        {/* Lab Mode Active Indicator */}
        <div className="flex items-center justify-center gap-2 mt-4 text-[11px] text-gray-500 font-mono">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>CYBERARY-AI SOC LAB RUNTIME v2.0 • ISOLATION ACTIVE</span>
        </div>
      </div>
    </div>
  );
}
