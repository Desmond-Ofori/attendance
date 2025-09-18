// static/js/auth.js
// Central auth manager + register/login helpers

(function (window) {
  // authManager singleton
  const authManager = {
    getToken() {
      return sessionStorage.getItem("tapin_token");
    },
    setToken(token) {
      sessionStorage.setItem("tapin_token", token);
    },
    setRole(role) {
      sessionStorage.setItem("tapin_role", role);
    },
    clear() {
      sessionStorage.removeItem("tapin_token");
      sessionStorage.removeItem("tapin_role");
    },

    // apiCall: always call window.getApiUrl(endpoint) where endpoint does NOT start with /api
    async apiCall(endpoint, options = {}) {
      try {
        // ensure endpoint starts with '/'
        if (!endpoint.startsWith("/")) endpoint = "/" + endpoint;

        // window.getApiUrl should already handle base URL — but we standardize to /api prefix
        const url = window.getApiUrl(endpoint);

        const headers = {
          "Content-Type": "application/json",
          ...(options.headers || {}),
        };

        const token = this.getToken();
        if (token) headers["Authorization"] = `Bearer ${token}`;

        const response = await fetch(url, {
          ...options,
          headers,
          credentials: "same-origin",
        });

        let data;
        try {
          data = await response.json();
        } catch (err) {
          const text = await response.text();
          data = { error: text || `HTTP ${response.status}` };
        }

        if (!response.ok) {
          return { error: data.error || data.message || `HTTP ${response.status}: ${response.statusText}` };
        }
        return data;
      } catch (err) {
        console.error("[authManager.apiCall] network error", err);
        return { error: "Network error: " + (err.message || err) };
      }
    },
  };

  // On account page, support old-style ?verify_token=... common in your logs:
  function handleLegacyVerifyQuery() {
    try {
      const params = new URLSearchParams(window.location.search);
      const verifyToken = params.get("verify_token") || params.get("token");
      const role = params.get("role") || params.get("r");
      if (verifyToken) {
        // normalize to the verify_success page so it consistently stores token + role
        window.location.href = `/static/verify_success.html?token=${encodeURIComponent(verifyToken)}${role ? "&role=" + encodeURIComponent(role) : ""}`;
      }
    } catch (e) {
      console.error("handleLegacyVerifyQuery error", e);
    }
  }

  // auto-run on pages that include this script (account page)
  document.addEventListener("DOMContentLoaded", () => {
    handleLegacyVerifyQuery();
  });

  // expose authManager for other uses
  window.authManager = authManager;

})(window);

window.AuthManager = {
    login: async function(credentials) {
        try {
            const response = await fetch(`/api/auth/login/${credentials.role}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(credentials),
                credentials: 'include' // Important for sessions
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // Store token and user data
                if (data.access_token) {
                    sessionStorage.setItem('tapin_token', data.access_token);
                }
                if (data.user) {
                    sessionStorage.setItem('user', JSON.stringify(data.user));
                }
                
                // Redirect based on verification status
                if (data.redirect_url) {
                    window.location.href = data.redirect_url;
                } else if (data.user && data.user.is_verified) {
                    window.location.href = data.user.role === 'lecturer' 
                        ? '/lecturer/dashboard' 
                        : '/student/dashboard';
                } else {
                    window.location.href = data.user.role === 'lecturer' 
                        ? '/lecturer/initial-home' 
                        : '/student/initial-home';
                }
                
                return { success: true };
            } else {
                return { success: false, error: data.error || 'Login failed' };
            }
        } catch (error) {
            console.error('Login error:', error);
            return { success: false, error: 'Network error. Please try again.' };
        }
    },
    
    register: async function(role, userData, submitBtn) {
        try {
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Registering...';
            }

            const response = await fetch(`/api/auth/register/${role}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(userData),
                credentials: 'include' // Important for sessions
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // Store token and user data
                if (data.access_token) {
                    sessionStorage.setItem('tapin_token', data.access_token);
                }
                if (data.user) {
                    sessionStorage.setItem('user', JSON.stringify(data.user));
                }
                
                // Redirect based on verification status
                if (data.redirect_url) {
                    window.location.href = data.redirect_url;
                } else if (data.user && data.user.is_verified) {
                    window.location.href = data.user.role === 'lecturer'
                        ? '/lecturer/dashboard'
                        : '/student/dashboard';
                } else {
                    window.location.href = data.user.role === 'lecturer'
                        ? '/lecturer/initial-home'
                        : '/student/initial-home';
                }
                
                return { success: true };
            } else {
                return { success: false, error: data.error || 'Registration failed' };
            }
        } catch (error) {
            console.error('Registration error:', error);
            return { success: false, error: 'Network error. Please try again.' };
        } finally {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Register';
            }
        }
    }
};
