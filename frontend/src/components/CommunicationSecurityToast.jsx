
import React from 'react';
import {
  AlertTriangle,
  ShieldAlert,
  X,
  ExternalLink,
} from 'lucide-react';
import { useWebSocket } from '../context/WebSocketContext';

export default function CommunicationSecurityToast() {
  const {
    communicationNotification,
    clearCommunicationNotification,
  } = useWebSocket();

  if (!communicationNotification) {
    return null;
  }

  const notification = communicationNotification;

  const isCritical =
    notification.classification === 'CRITICAL_SECURITY_THREAT' ||
    notification.severity === 'CRITICAL';

  const isBlocked =
    notification.policy_decision === 'BLOCK';

  const title = isCritical
    ? 'CRITICAL SECURITY THREAT'
    : isBlocked
      ? 'Communication Blocked'
      : 'Security Review Required';

  const classificationLabel =
    notification.classification?.replaceAll('_', ' ') ||
    'SECURITY EVENT';

  return (
    <div className="fixed top-20 right-6 z-[100] w-[390px] max-w-[calc(100vw-2rem)] animate-fade-in">
      <div
        className={`rounded-xl border shadow-2xl backdrop-blur-xl overflow-hidden ${
          isCritical
            ? 'bg-red-950/95 border-red-500/50 shadow-red-950/50'
            : isBlocked
              ? 'bg-orange-950/95 border-orange-500/50 shadow-orange-950/50'
              : 'bg-yellow-950/95 border-yellow-500/50 shadow-yellow-950/50'
        }`}
      >
        {/* Header */}
        <div className="flex items-start gap-3 p-4">
          <div
            className={`flex items-center justify-center w-10 h-10 rounded-lg flex-shrink-0 ${
              isCritical
                ? 'bg-red-500/20'
                : isBlocked
                  ? 'bg-orange-500/20'
                  : 'bg-yellow-500/20'
            }`}
          >
            {isCritical ? (
              <ShieldAlert
                size={22}
                className="text-red-400"
              />
            ) : (
              <AlertTriangle
                size={22}
                className={
                  isBlocked
                    ? 'text-orange-400'
                    : 'text-yellow-400'
                }
              />
            )}
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex items-start justify-between gap-2">
              <div>
                <p
                  className={`text-sm font-bold ${
                    isCritical
                      ? 'text-red-300'
                      : isBlocked
                        ? 'text-orange-300'
                        : 'text-yellow-300'
                  }`}
                >
                  {title}
                </p>

                <p className="text-[11px] text-gray-400 mt-0.5">
                  Communication Security Gateway
                </p>
              </div>

              <button
                onClick={clearCommunicationNotification}
                className="text-gray-500 hover:text-gray-200 transition-colors"
                aria-label="Close notification"
              >
                <X size={17} />
              </button>
            </div>
          </div>
        </div>

        {/* Classification */}
        <div className="px-4 pb-3">
          <div className="flex items-center justify-between gap-3">
            <span className="text-xs text-gray-400">
              Classification
            </span>

            <span
              className={`px-2 py-1 rounded-md text-[10px] font-bold tracking-wide ${
                isCritical
                  ? 'bg-red-500/20 text-red-300'
                  : isBlocked
                    ? 'bg-orange-500/20 text-orange-300'
                    : 'bg-yellow-500/20 text-yellow-300'
              }`}
            >
              {classificationLabel}
            </span>
          </div>
        </div>

        {/* Event Details */}
        <div className="mx-4 mb-3 rounded-lg bg-black/20 border border-white/5 p-3 space-y-2">
          <div className="flex justify-between gap-4">
            <span className="text-xs text-gray-500">
              Sender
            </span>

            <span className="text-xs text-gray-300 truncate max-w-[230px]">
              {notification.sender || 'Unknown'}
            </span>
          </div>

          <div className="flex justify-between gap-4">
            <span className="text-xs text-gray-500">
              Subject
            </span>

            <span className="text-xs text-gray-300 truncate max-w-[230px]">
              {notification.subject || 'No subject'}
            </span>
          </div>

          <div className="flex justify-between gap-4">
            <span className="text-xs text-gray-500">
              Risk Score
            </span>

            <span
              className={`text-xs font-bold ${
                notification.risk_score >= 90
                  ? 'text-red-400'
                  : notification.risk_score >= 70
                    ? 'text-orange-400'
                    : 'text-yellow-400'
              }`}
            >
              {notification.risk_score}/100
            </span>
          </div>

          <div className="flex justify-between gap-4">
            <span className="text-xs text-gray-500">
              Decision
            </span>

            <span className="text-xs font-bold text-red-400">
              {notification.policy_decision || 'UNKNOWN'}
            </span>
          </div>
        </div>

        {/* Reason */}
        {notification.reason && (
          <div className="px-4 pb-3">
            <p className="text-xs leading-relaxed text-gray-300">
              {notification.reason}
            </p>
          </div>
        )}

        {/* Footer */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-white/5 bg-black/10">
          <span className="text-[10px] text-gray-500">
            Live security event
          </span>

          <button
            onClick={() => {
              window.location.href =
                '/communication-security';
            }}
            className={`flex items-center gap-1.5 text-xs font-medium transition-colors ${
              isCritical
                ? 'text-red-400 hover:text-red-300'
                : isBlocked
                  ? 'text-orange-400 hover:text-orange-300'
                  : 'text-yellow-400 hover:text-yellow-300'
            }`}
          >
            View Event
            <ExternalLink size={13} />
          </button>
        </div>
      </div>
    </div>
  );
}

