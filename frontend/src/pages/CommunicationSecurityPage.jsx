import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  AlertTriangle,
  Mail,
  Paperclip,
  Link as LinkIcon,
  User,
  Send,
  RefreshCw,
  Sparkles,
  Download,
} from 'lucide-react';
import { analyzeCommunication } from '../services/api';

const initialForm = {
  sender: '',
  recipient: '',
  subject: '',
  body: '',
  message_type: 'email',
  urls: '',
  attachments: '',
};

function getClassificationStyle(classification) {
  switch (classification) {
    case 'SAFE':
    case 'USEFUL':
      return {
        icon: ShieldCheck,
        box: 'border-green-500/30 bg-green-500/10',
        text: 'text-green-400',
      };

    case 'SUSPICIOUS':
      return {
        icon: AlertTriangle,
        box: 'border-yellow-500/30 bg-yellow-500/10',
        text: 'text-yellow-400',
      };

    case 'PHISHING':
    case 'MALICIOUS':
      return {
        icon: ShieldX,
        box: 'border-red-500/30 bg-red-500/10',
        text: 'text-red-400',
      };

    case 'CRITICAL_SECURITY_THREAT':
      return {
        icon: ShieldAlert,
        box: 'border-red-500/40 bg-red-500/15',
        text: 'text-red-300',
      };

    default:
      return {
        icon: ShieldAlert,
        box: 'border-gray-500/30 bg-gray-500/10',
        text: 'text-gray-400',
      };
  }
}

function getDecisionStyle(decision) {
  switch (decision) {
    case 'ALLOW':
      return 'bg-green-500/15 text-green-400 border-green-500/30';

    case 'QUARANTINE':
      return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30';

    case 'BLOCK':
      return 'bg-red-500/15 text-red-400 border-red-500/30';

    default:
      return 'bg-gray-500/15 text-gray-400 border-gray-500/30';
  }
}

export default function CommunicationSecurityPage() {
  const [form, setForm] = useState(initialForm);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleChange = (event) => {
    const { name, value } = event.target;

    setForm((previous) => ({
      ...previous,
      [name]: value,
    }));
  };

  const handleAnalyze = async (event) => {
    event.preventDefault();

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const payload = {
        sender: form.sender.trim(),
        recipient: form.recipient.trim(),
        subject: form.subject.trim(),
        body: form.body.trim(),
        message_type: form.message_type,
        urls: form.urls
          .split(/\s*,\s*|\s+/)
          .map((url) => url.trim())
          .filter(Boolean),
        attachments: form.attachments
          .split(/\s*,\s*|\s+/)
          .map((file) => file.trim())
          .filter(Boolean),
      };

      const response = await analyzeCommunication(payload);

      setResult(response);
    } catch (err) {
      console.error('Communication analysis failed:', err);

      const backendError = err?.response?.data;

      if (backendError?.detail) {
        setError(
          typeof backendError.detail === 'string'
            ? backendError.detail
            : JSON.stringify(backendError.detail)
        );
      } else {
        setError('Unable to analyze the communication. Please check the backend server.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setForm(initialForm);
    setResult(null);
    setError('');
  };

  const classification = result?.classification;
  const classificationStyle = getClassificationStyle(classification);
  const ClassificationIcon = classificationStyle.icon;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-11 h-11 rounded-xl bg-cyber-500/15 border border-cyber-500/20">
            <Mail size={22} className="text-cyber-400" />
          </div>

          <div>
            <h1 className="text-2xl font-bold text-white">
              Communication Security
            </h1>
            <p className="text-sm text-gray-500">
              AI-powered Email & Message Security Gateway
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Analyze Form */}
        <div className="bg-surface-800/80 border border-surface-400/20 rounded-xl p-6">
          <div className="flex items-center justify-between mb-5">
            <div>
              <h2 className="text-lg font-semibold text-white">
                Analyze Communication
              </h2>
              <p className="text-xs text-gray-500 mt-1">
                Submit an email or message for security analysis.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleReset}
                className="p-2 rounded-lg text-gray-500 hover:text-gray-300 hover:bg-surface-700 transition"
                title="Reset"
              >
                <RefreshCw size={17} />
              </button>
            </div>
          </div>

          {/* Quick Presets */}
          <div className="flex items-center gap-1.5 flex-wrap text-xs pb-4 mb-4 border-b border-surface-400/20">
            <span className="text-[11px] text-gray-500 font-semibold flex items-center gap-1 mr-1">
              <Sparkles size={12} className="text-cyan-400" /> Test Samples:
            </span>
            <button
              type="button"
              onClick={() => {
                setForm({
                  sender: 'ceo-office@corp-executive-payment.net',
                  recipient: 'finance-lead@company.local',
                  subject: 'URGENT: Confidential Acquisition Wire Payment Today',
                  body: 'Please initiate the wire transfer of $85,000 to the attached escrow account before 4:00 PM today. Treat with strict confidentiality.',
                  message_type: 'email',
                  urls: 'http://wire-escrow-portal.net/verify',
                  attachments: 'wire_instruction.pdf.exe',
                });
              }}
              className="text-[11px] px-2.5 py-1 rounded bg-red-950/50 hover:bg-red-900/60 border border-red-800/40 text-red-300 transition-colors"
            >
              CEO Wire Fraud
            </button>
            <button
              type="button"
              onClick={() => {
                setForm({
                  sender: 'account-security@office365-verify-portal.com',
                  recipient: 'analyst@company.local',
                  subject: 'Action Required: Microsoft 365 Passphrase Expired',
                  body: 'Your authentication credentials will expire in 2 hours. Log in immediately to avoid account lockout.',
                  message_type: 'email',
                  urls: 'http://login.microsoft.security-verify.com/login',
                  attachments: '',
                });
              }}
              className="text-[11px] px-2.5 py-1 rounded bg-amber-950/50 hover:bg-amber-900/60 border border-amber-800/40 text-amber-300 transition-colors"
            >
              Credential Harvester
            </button>
            <button
              type="button"
              onClick={() => {
                setForm({
                  sender: 'it-support@cyberary.local',
                  recipient: 'analyst@cyberary.local',
                  subject: 'Scheduled Maintenance Notice: VPN Firewall Update',
                  body: 'The infrastructure team will perform scheduled network maintenance on Saturday between 02:00 and 04:00 UTC.',
                  message_type: 'email',
                  urls: 'https://internal.cyberary.local/docs/maintenance',
                  attachments: '',
                });
              }}
              className="text-[11px] px-2.5 py-1 rounded bg-emerald-950/50 hover:bg-emerald-900/60 border border-emerald-800/40 text-emerald-300 transition-colors"
            >
              Normal IT Notice
            </button>
          </div>

          <form onSubmit={handleAnalyze} className="space-y-4">
            {/* Sender */}
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1.5">
                Sender
              </label>

              <div className="relative">
                <User
                  size={16}
                  className="absolute left-3 top-3 text-gray-600"
                />

                <input
                  name="sender"
                  value={form.sender}
                  onChange={handleChange}
                  required
                  placeholder="security@example.com"
                  className="w-full pl-9 pr-3 py-2.5 rounded-lg bg-surface-900 border border-surface-400/20 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyber-500/50"
                />
              </div>
            </div>

            {/* Recipient */}
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1.5">
                Recipient
              </label>

              <input
                name="recipient"
                value={form.recipient}
                onChange={handleChange}
                required
                placeholder="user@example.com"
                className="w-full px-3 py-2.5 rounded-lg bg-surface-900 border border-surface-400/20 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyber-500/50"
              />
            </div>

            {/* Message Type */}
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1.5">
                Message Type
              </label>

              <select
                name="message_type"
                value={form.message_type}
                onChange={handleChange}
                className="w-full px-3 py-2.5 rounded-lg bg-surface-900 border border-surface-400/20 text-sm text-gray-200 focus:outline-none focus:border-cyber-500/50"
              >
                <option value="email">Email</option>
                <option value="message">Message</option>
                <option value="chat">Chat</option>
              </select>
            </div>

            {/* Subject */}
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1.5">
                Subject
              </label>

              <input
                name="subject"
                value={form.subject}
                onChange={handleChange}
                required
                placeholder="URGENT: Verify Your Account"
                className="w-full px-3 py-2.5 rounded-lg bg-surface-900 border border-surface-400/20 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyber-500/50"
              />
            </div>

            {/* Body */}
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1.5">
                Message Content
              </label>

              <textarea
                name="body"
                value={form.body}
                onChange={handleChange}
                required
                rows={7}
                placeholder="Paste the email or message content here..."
                className="w-full px-3 py-2.5 rounded-lg bg-surface-900 border border-surface-400/20 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyber-500/50 resize-none"
              />
            </div>

            {/* URLs */}
            <div>
              <label className="flex items-center gap-2 text-xs font-medium text-gray-400 mb-1.5">
                <LinkIcon size={14} />
                URLs
              </label>

              <input
                name="urls"
                value={form.urls}
                onChange={handleChange}
                placeholder="https://example.com/login"
                className="w-full px-3 py-2.5 rounded-lg bg-surface-900 border border-surface-400/20 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyber-500/50"
              />

              <p className="text-[10px] text-gray-600 mt-1">
                Separate multiple URLs with spaces or commas.
              </p>
            </div>

            {/* Attachments */}
            <div>
              <label className="flex items-center gap-2 text-xs font-medium text-gray-400 mb-1.5">
                <Paperclip size={14} />
                Attachments
              </label>

              <input
                name="attachments"
                value={form.attachments}
                onChange={handleChange}
                placeholder="invoice.pdf, update.exe"
                className="w-full px-3 py-2.5 rounded-lg bg-surface-900 border border-surface-400/20 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyber-500/50"
              />
            </div>

            {/* Error */}
            {error && (
              <div className="p-3 rounded-lg border border-red-500/30 bg-red-500/10 text-sm text-red-400">
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 py-3 rounded-lg bg-cyber-600 hover:bg-cyber-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-semibold transition"
            >
              {loading ? (
                <>
                  <RefreshCw size={17} className="animate-spin" />
                  Analyzing Communication...
                </>
              ) : (
                <>
                  <Send size={17} />
                  Analyze Communication
                </>
              )}
            </button>
          </form>
        </div>

        {/* Result */}
        <div className="space-y-5">
          {!result && (
            <div className="h-full min-h-[500px] flex flex-col items-center justify-center bg-surface-800/50 border border-surface-400/20 rounded-xl text-center px-8">
              <ShieldCheck size={52} className="text-gray-700 mb-4" />

              <h3 className="text-lg font-semibold text-gray-400">
                Security Analysis
              </h3>

              <p className="text-sm text-gray-600 max-w-md mt-2">
                Submit a communication to receive its classification,
                contextual risk score, security decision and recommended action.
              </p>
            </div>
          )}

          {result && (
            <>
              {/* Classification */}
              <div
                className={`rounded-xl border p-5 ${classificationStyle.box}`}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <ClassificationIcon
                      size={30}
                      className={classificationStyle.text}
                    />

                    <div>
                      <p className="text-xs text-gray-500 uppercase tracking-wider">
                        Classification
                      </p>

                      <h2
                        className={`text-xl font-bold ${classificationStyle.text}`}
                      >
                        {classification || 'UNKNOWN'}
                      </h2>
                    </div>
                  </div>

                  <div className="text-right">
                    <p className="text-xs text-gray-500">
                      Risk Score
                    </p>

                    <p className={`text-3xl font-bold ${classificationStyle.text}`}>
                      {result.risk_score ?? 0}
                      <span className="text-sm text-gray-600">/100</span>
                    </p>
                  </div>
                </div>
              </div>

              {/* Decision */}
              <div className="bg-surface-800/80 border border-surface-400/20 rounded-xl p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-gray-500 uppercase tracking-wider">
                      Policy Decision
                    </p>

                    <p className="text-sm text-gray-400 mt-1">
                      Deterministic security policy
                    </p>
                  </div>

                  <span
                    className={`px-4 py-2 rounded-lg border text-sm font-bold ${getDecisionStyle(
                      result.policy_decision
                    )}`}
                  >
                    {result.policy_decision || 'UNKNOWN'}
                  </span>
                </div>
              </div>

              {/* Security details */}
              <div className="bg-surface-800/80 border border-surface-400/20 rounded-xl p-5">
                <h3 className="text-sm font-semibold text-white mb-4">
                  Security Assessment
                </h3>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-xs text-gray-500">Severity</p>
                    <p className="text-sm font-semibold text-gray-300 mt-1">
                      {result.severity || 'N/A'}
                    </p>
                  </div>

                  <div>
                    <p className="text-xs text-gray-500">Confidence</p>
                    <p className="text-sm font-semibold text-gray-300 mt-1">
                      {result.confidence ?? 0}%
                    </p>
                  </div>

                  <div>
                    <p className="text-xs text-gray-500">
                      Human Review
                    </p>
                    <p className="text-sm font-semibold text-gray-300 mt-1">
                      {result.human_review_required ? 'Required' : 'Not Required'}
                    </p>
                  </div>

                  <div>
                    <p className="text-xs text-gray-500">
                      Notification
                    </p>
                    <p className="text-sm font-semibold text-gray-300 mt-1">
                      {result.notification_required ? 'Triggered' : 'Suppressed'}
                    </p>
                  </div>
                </div>
              </div>

              {/* Reason */}
              <div className="bg-surface-800/80 border border-surface-400/20 rounded-xl p-5">
                <h3 className="text-sm font-semibold text-white mb-2">
                  Security Reason
                </h3>

                <p className="text-sm text-gray-400 leading-6">
                  {result.reason || 'No explanation provided.'}
                </p>

                {result.recommended_action && (
                  <div className="mt-4 pt-4 border-t border-surface-400/10">
                    <p className="text-xs text-gray-500 uppercase tracking-wider">
                      Recommended Action
                    </p>

                    <p className="text-sm text-cyber-400 font-medium mt-1">
                      {result.recommended_action}
                    </p>
                  </div>
                )}
              </div>

              {/* Analysis Components */}
              <div className="bg-surface-800/80 border border-surface-400/20 rounded-xl p-5">
                <h3 className="text-sm font-semibold text-white mb-4">
                  Analysis Pipeline
                </h3>

                <div className="space-y-3">
                  {[
                    ['Sender Analysis', result.sender_analysis],
                    ['Content Analysis', result.content_analysis],
                    ['URL Analysis', result.url_analysis],
                    ['Attachment Analysis', result.attachment_analysis],
                    ['Threat Intelligence', result.threat_intelligence],
                    ['LLM Analysis', result.llm_analysis],
                  ].map(([label, data]) => (
                    <div
                      key={label}
                      className="flex items-center justify-between p-3 rounded-lg bg-surface-900/60"
                    >
                      <span className="text-sm text-gray-400">
                        {label}
                      </span>

                      <span className="text-xs text-gray-500">
                        {data?.status ||
                          data?.risk_level ||
                          data?.reputation ||
                          'ANALYZED'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Notification */}
              {result.notification_required && (
                <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-5">
                  <div className="flex items-center gap-3">
                    <ShieldAlert size={22} className="text-red-400" />

                    <div>
                      <p className="text-sm font-semibold text-red-400">
                        Security Notification Triggered
                      </p>

                      <p className="text-xs text-gray-500 mt-1">
                        {result.notification_level || 'SECURITY_ALERT'}
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}