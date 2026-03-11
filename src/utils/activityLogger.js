const API = 'http://127.0.0.1:8000';

/**
 * Logs a user activity event to the backend.
 * Silently fails — never disrupts the user experience.
 *
 * @param {string} action  - What the user did, e.g. "PAGE_VIEW", "FILTER_CHANGED", "EXPORT"
 * @param {string} page    - Which page, e.g. "Dashboard", "Traffic Analysis"
 * @param {string} details - Optional extra detail, e.g. "Protocol: TCP", "Search: port scan"
 */
export const logActivity = async (action, page, details = '') => {
    try {
        const user = JSON.parse(localStorage.getItem('user') || '{}');
        if (!user.username) return;   // Not logged in — skip

        await fetch(`${API}/auth/activity`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: user.username,
                user_id: user.id || null,
                action,
                page,
                details: String(details),
            }),
        });
    } catch {
        // Never throw — activity logging is non-critical
    }
};
