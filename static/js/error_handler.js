(function() {
  'use strict';

  // Global error handler for uncaught exceptions
  window.onerror = function(msg, url, lineNo, columnNo, error) {
    console.error('Uncaught Error:', {
      message: msg,
      url: url,
      line: lineNo,
      column: columnNo,
      error: error
    });

    // User-friendly message
    let userMsg = 'An unexpected error occurred. Please refresh the page and try again.';
    if (msg.includes('Script error') || !msg) {
      userMsg = 'A script error occurred. Please check your connection.';
    } else if (msg.includes('Network') || msg.includes('fetch')) {
      userMsg = 'Network issue. Please check your internet connection and try again.';
    }

    // Show toast or alert
    showErrorToast(userMsg);
    return false; // Let default handler run too
  };

  // Global promise rejection handler
  window.addEventListener('unhandledrejection', function(event) {
    console.error('Unhandled Promise Rejection:', event.reason);

    let userMsg = 'An operation failed. Please try again.';
    if (event.reason && event.reason.message) {
      const reason = event.reason.message.toLowerCase();
      if (reason.includes('network') || reason.includes('fetch')) {
        userMsg = 'Network error. Please check your connection.';
      } else if (reason.includes('token') || reason.includes('auth')) {
        userMsg = 'Session expired. Please log in again.';
        // Optionally redirect to login
        setTimeout(() => {
          if (confirm('Session expired. Redirect to login?')) {
            window.location.href = window.location.pathname.includes('lecturer') ? '/lecturer_login' : '/student_login';
          }
        }, 1000);
      }
    }

    showErrorToast(userMsg);
    event.preventDefault(); // Prevent default browser handling
  });

  // Function to show error toast (simple div for now)
  function showErrorToast(message, duration = 5000) {
    // Remove existing toast
    const existing = document.getElementById('error-toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.id = 'error-toast';
    toast.style.cssText = `
      position: fixed; top: 20px; right: 20px; background: #f44336; color: white;
      padding: 16px; border-radius: 4px; z-index: 10000; max-width: 300px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.2); font-family: Arial, sans-serif;
    `;
    toast.textContent = message;

    document.body.appendChild(toast);

    // Auto remove
    setTimeout(() => {
      if (toast.parentNode) toast.remove();
    }, duration);
  }

  // Optional: Enhance fetch with error handling
  const originalFetch = window.fetch;
  window.fetch = function(...args) {
    return originalFetch.apply(this, args).catch(error => {
      console.error('Fetch Error:', error);
      showErrorToast('Failed to connect to server. Please try again.');
      throw error;
    });
  };

  // Init function to call in pages
  window.setupErrorHandler = function() {
    console.log('Error handler initialized');
    // Any additional setup
  };

})();