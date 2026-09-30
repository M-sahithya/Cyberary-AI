
import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './context/AuthContext';
import Sidebar from './components/Sidebar';
import TopBar from './components/TopBar';
import ProtectedRoute from './components/ProtectedRoute';

import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import DashboardPage from './pages/DashboardPage';
import ThreatsPage from './pages/ThreatsPage';
import HoneypotPage from './pages/HoneypotPage';
import VulnerabilitiesPage from './pages/VulnerabilitiesPage';
import CvePage from './pages/CvePage';
import MitrePage from './pages/MitrePage';
import RemediationPage from './pages/RemediationPage';
import AssetsPage from './pages/AssetsPage';
import AgentsPage from './pages/AgentsPage';
import EvaluationPage from './pages/EvaluationPage';
import AuditLogsPage from './pages/AuditLogsPage';
import SettingsPage from './pages/SettingsPage';
import CommunicationSecurityPage from './pages/CommunicationSecurityPage';
import CommunicationSecurityToast from './components/CommunicationSecurityToast';
function AppLayout({ children }) {
  return (
    <div className="flex min-h-screen bg-surface-900">
      <Sidebar />

      <div className="flex-1 ml-[240px]">
        <TopBar />

        <main className="pt-14 p-6">
          {children}
        </main>
      </div>
    </div>
  );
}

export default function App() {
  const { isAuthenticated } = useAuth();

  return (
    <Routes>
      {/* =====================================================
          Public Routes
      ====================================================== */}

      <Route
        path="/login"
        element={
          isAuthenticated ? (
            <Navigate to="/dashboard" replace />
          ) : (
            <LoginPage />
          )
        }
      />

      <Route
        path="/register"
        element={
          isAuthenticated ? (
            <Navigate to="/dashboard" replace />
          ) : (
            <RegisterPage />
          )
        }
      />

      {/* =====================================================
          Protected Routes
      ====================================================== */}

      <Route
        path="/dashboard"
        element={
          <ProtectedRoute>
            <AppLayout>
              <DashboardPage />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      <Route
        path="/threats"
        element={
          <ProtectedRoute>
            <AppLayout>
              <ThreatsPage />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      <Route
        path="/honeypot"
        element={
          <ProtectedRoute>
            <AppLayout>
              <HoneypotPage />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      <Route
        path="/honeypot/:sessionId"
        element={
          <ProtectedRoute>
            <AppLayout>
              <HoneypotPage />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      <Route
        path="/vulnerabilities"
        element={
          <ProtectedRoute>
            <AppLayout>
              <VulnerabilitiesPage />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      <Route
        path="/cves"
        element={
          <ProtectedRoute>
            <AppLayout>
              <CvePage />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      <Route
        path="/mitre"
        element={
          <ProtectedRoute>
            <AppLayout>
              <MitrePage />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      <Route
        path="/remediation"
        element={
          <ProtectedRoute>
            <AppLayout>
              <RemediationPage />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      <Route
        path="/assets"
        element={
          <ProtectedRoute>
            <AppLayout>
              <AssetsPage />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      <Route
        path="/agents"
        element={
          <ProtectedRoute>
            <AppLayout>
              <AgentsPage />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      <Route
        path="/evaluation"
        element={
          <ProtectedRoute>
            <AppLayout>
              <EvaluationPage />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      <Route
        path="/audit-logs"
        element={
          <ProtectedRoute>
            <AppLayout>
              <AuditLogsPage />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      {/* =====================================================
          Communication Security Gateway
      ====================================================== */}

      <Route
        path="/communication-security"
        element={
          <ProtectedRoute>
            <AppLayout>
              <CommunicationSecurityPage />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      <Route
        path="/settings"
        element={
          <ProtectedRoute>
            <AppLayout>
              <SettingsPage />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      {/* =====================================================
          Default Redirect
      ====================================================== */}

      <Route
        path="*"
        element={<Navigate to="/dashboard" replace />}
      />
    </Routes>
  );
}

