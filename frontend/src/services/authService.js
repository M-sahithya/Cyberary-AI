import api from './api';

/**
 * Authentication service — login, register, profile.
 */
const authService = {
  /**
   * Login with username and password.
   * @returns {Promise<{access_token, user}>}
   */
  async login(username, password) {
    const response = await api.post('/api/auth/login', { username, password });
    const { data } = response.data;
    if (data?.access_token) {
      localStorage.setItem('cyberary_token', data.access_token);
      localStorage.setItem('cyberary_user', JSON.stringify(data.user));
    }
    return data;
  },

  /**
   * Register a new user account.
   */
  async register(username, email, password) {
    const response = await api.post('/api/auth/register', { username, email, password });
    return response.data;
  },

  /**
   * Get current user profile.
   */
  async getProfile() {
    const response = await api.get('/api/auth/me');
    return response.data.data;
  },

  /**
   * Logout — clear stored credentials.
   */
  logout() {
    localStorage.removeItem('cyberary_token');
    localStorage.removeItem('cyberary_user');
  },

  /**
   * Check if user is authenticated.
   */
  isAuthenticated() {
    return !!localStorage.getItem('cyberary_token');
  },

  /**
   * Get stored user info.
   */
  getStoredUser() {
    const user = localStorage.getItem('cyberary_user');
    return user ? JSON.parse(user) : null;
  },

  /**
   * Get stored token.
   */
  getToken() {
    return localStorage.getItem('cyberary_token');
  },
};

export default authService;
