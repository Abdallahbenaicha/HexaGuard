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

// Support Bearer token authentication (PWA / Mobile API fallback)
axios.interceptors.request.use((config) => {
    try {
        const token = localStorage.getItem('securax_token');
        if (token && !config.headers.Authorization) {
            config.headers.Authorization = `Bearer ${token}`;
        }
    } catch (e) {}
    return config;
});

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
