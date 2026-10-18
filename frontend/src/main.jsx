import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import axios from 'axios'

// Set backend URL for all axios requests.
// In development: Vite proxy handles /api/* → localhost:5000, baseURL stays empty.
// In production:  VITE_API_BASE_URL is set in render.yaml → points to Flask backend.
const _apiBase = import.meta.env.VITE_API_BASE_URL || '';
if (_apiBase) {
    axios.defaults.baseURL = _apiBase;
}
axios.defaults.withCredentials = true;

function getCookie(name) {
    if (typeof document === 'undefined') return null;
    const match = document.cookie.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
    return match ? decodeURIComponent(match[1]) : null;
}

// Support Bearer token authentication & CSRF protection
axios.interceptors.request.use((config) => {
    try {
        const token = localStorage.getItem('securax_token');
        if (token && !config.headers.Authorization) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        const method = (config.method || 'get').toUpperCase();
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && !config.headers['X-CSRFToken']) {
            const csrfToken = getCookie('csrftoken') || getCookie('csrf_token');
            if (csrfToken) {
                config.headers['X-CSRFToken'] = csrfToken;
            }
        }
    } catch {
        /* ignore */
    }
    return config;
});

// Capture CSRF token from incoming responses if sent by backend
axios.interceptors.response.use(
    (response) => {
        const csrfHeader = response?.headers && (response.headers['x-csrftoken'] || response.headers['X-CSRFToken']);
        if (csrfHeader && typeof document !== 'undefined') {
            document.cookie = `csrftoken=${csrfHeader}; path=/; SameSite=Lax`;
        }
        return response;
    },
    (error) => Promise.reject(error)
);

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
