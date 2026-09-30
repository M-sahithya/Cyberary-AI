
import axios from 'axios';

const API_BASE_URL =
  import.meta.env.VITE_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 15000,
});

// ============================================================
// Request Interceptor — Attach JWT Token
// ============================================================

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('cyberary_token');

    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    return config;
  },
  (error) => Promise.reject(error)
);

// ============================================================
// Response Interceptor — Global Error Handling
// ============================================================

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response) {
      const { status } = error.response;

      // Auto logout on 401 Unauthorized
      if (status === 401) {
        localStorage.removeItem('cyberary_token');
        localStorage.removeItem('cyberary_user');

        if (window.location.pathname !== '/login') {
          window.location.href = '/login';
        }
      }
    }

    return Promise.reject(error);
  }
);

// ============================================================
// Communication Security Gateway
// ============================================================

/**
 * Analyze an email/message using the Communication Security Gateway.
 *
 * Backend:
 * POST /api/communication/analyze
 */
export const analyzeCommunication = async (payload) => {
  const response = await api.post(
    '/api/communication/analyze',
    payload
  );

  return response.data;
};

/**
 * Get communication security events.
 *
 * Backend:
 * GET /api/communication/events
 */
export const getCommunicationEvents = async (params = {}) => {
  const response = await api.get(
    '/api/communication/events',
    { params }
  );

  return response.data;
};

/**
 * Get a single communication security event.
 *
 * Backend:
 * GET /api/communication/events/{event_id}
 */
export const getCommunicationEvent = async (eventId) => {
  const response = await api.get(
    `/api/communication/events/${eventId}`
  );

  return response.data;
};

/**
 * Submit human review for a communication security event.
 *
 * Backend:
 * POST /api/communication/events/{event_id}/review
 */
export const reviewCommunicationEvent = async (
  eventId,
  payload
) => {
  const response = await api.post(
    `/api/communication/events/${eventId}/review`,
    payload
  );

  return response.data;
};

// ============================================================
// Export Axios Instance
// ============================================================

export default api;

