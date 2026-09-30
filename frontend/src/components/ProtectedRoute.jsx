import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

/**
 * Protected route wrapper — redirects to login if not authenticated.
 */
export default function ProtectedRoute({ children, requiredRole }) {
  const { isAuthenticated, loading, hasRole } = useAuth();

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-surface-900">
        <div className="flex flex-col items-center gap-4">
          <div className="w-10 h-10 border-2 border-cyber-500/30 border-t-cyber-400
            rounded-full animate-spin" />
          <p className="text-sm text-gray-500">Loading...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (requiredRole && !hasRole(requiredRole)) {
    return (
      <div className="flex items-center justify-center h-screen bg-surface-900">
        <div className="glass-card p-8 text-center max-w-md">
          <h2 className="text-xl font-bold text-threat-critical mb-2">Access Denied</h2>
          <p className="text-gray-400">
            You do not have the required role ({requiredRole}) to access this page.
          </p>
        </div>
      </div>
    );
  }

  return children;
}
