// API Configuration for TapIn Attendance System
const CONFIG = {
    // Dynamic API base URL - works for both localhost and production
    API_BASE_URL: window.location.hostname === 'localhost'
        ? "http://localhost:5000"
        : "https://tapin-attendance-app.onrender.com",

    // Environment settings
    DEBUG: window.location.hostname === 'localhost',
    VERSION: '1.0.0',

    // App settings
    APP_NAME: 'TapIn',
    DEFAULT_TIMEOUT: 10000, // 10 seconds

    // Feature flags
    ENABLE_NOTIFICATIONS: true,
    ENABLE_QR_ATTENDANCE: true,
    ENABLE_ANALYTICS: true,

    // Security settings
    CSRF_TOKEN: null, // Will be set by server if needed

    // UI settings
    THEME: localStorage.getItem('theme') || 'light',
    SIDEBAR_COLLAPSED: localStorage.getItem('sidebarCollapsed') === 'true'
};

// Make it globally available
window.CONFIG = CONFIG;

// Utility function to get full API URL
window.getApiUrl = function(path) {
    if (!path.startsWith('/')) path = '/' + path;
    if (!path.startsWith('/api')) {
        path = '/api' + path;
    }
    return `${CONFIG.API_BASE_URL}${path}`;
};

// Utility function for API calls
window.apiCall = async function(path, options = {}) {
    const url = getApiUrl(path);
    const token = sessionStorage.getItem('tapin_token');

    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
            ...options.headers
        }
    };

    try {
        const response = await fetch(url, { ...defaultOptions, ...options });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
};

// Initialize config on page load
document.addEventListener('DOMContentLoaded', function() {
    console.log(`TapIn ${CONFIG.VERSION} initialized in ${CONFIG.DEBUG ? 'development' : 'production'} mode`);
});
