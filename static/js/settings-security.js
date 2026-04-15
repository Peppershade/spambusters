// Spambusters - Security settings JS

function parseUserAgent(ua) {
    if (!ua || ua === 'Unknown') return 'Unknown';
    let browser = 'Unknown Browser';
    let os = 'Unknown OS';

    if (ua.includes('Firefox/')) browser = 'Firefox';
    else if (ua.includes('Edg/')) browser = 'Edge';
    else if (ua.includes('Chrome/')) browser = 'Chrome';
    else if (ua.includes('Safari/') && !ua.includes('Chrome')) browser = 'Safari';
    else if (ua.includes('Opera') || ua.includes('OPR/')) browser = 'Opera';

    if (ua.includes('Windows')) os = 'Windows';
    else if (ua.includes('Mac OS')) os = 'macOS';
    else if (ua.includes('Linux')) os = 'Linux';
    else if (ua.includes('Android')) os = 'Android';
    else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';

    return browser + ' on ' + os;
}

function formatDate(dateStr) {
    if (!dateStr) return 'Unknown';
    try {
        const d = new Date(dateStr);
        return d.toLocaleString();
    } catch { return dateStr; }
}

function loadSessions() {
    fetch('/api/sessions')
        .then(r => r.json())
        .then(sessions => {
            const loading = document.getElementById('sessions-loading');
            const container = document.getElementById('sessions-container');
            const tbody = document.getElementById('sessions-body');
            const revokeAllBtn = document.getElementById('revoke-all-btn');

            loading.style.display = 'none';
            container.style.display = 'block';
            tbody.innerHTML = '';

            if (sessions.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No active sessions found</td></tr>';
                return;
            }

            let otherCount = 0;
            sessions.forEach(s => {
                if (!s.is_current) otherCount++;
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${s.is_current
                        ? '<span class="badge badge-safe">Current</span>'
                        : '<span class="badge badge-muted">Active</span>'}</td>
                    <td><code>${s.ip_address}</code></td>
                    <td>${parseUserAgent(s.user_agent)}</td>
                    <td>${formatDate(s.created_at)}</td>
                    <td>${s.is_current
                        ? '<span style="color: var(--text-muted); font-size: 12px;">This session</span>'
                        : `<button onclick="revokeSession(${s.id}, this)" class="btn btn-danger" style="padding: 4px 12px; font-size: 12px;">Revoke</button>`
                    }</td>
                `;
                tbody.appendChild(row);
            });

            if (otherCount > 0) {
                revokeAllBtn.style.display = 'inline-block';
            }
        })
        .catch(() => {
            document.getElementById('sessions-loading').innerHTML =
                '<span style="color: var(--text-muted);">Failed to load sessions.</span>';
        });
}

function revokeSession(sessionId, btn) {
    btn.disabled = true;
    btn.textContent = 'Revoking...';

    fetch(`/api/sessions/${sessionId}/revoke`, {
        method: 'POST',
        headers: {'X-CSRFToken': getCsrfToken()}
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            btn.closest('tr').remove();
        } else {
            btn.disabled = false;
            btn.textContent = 'Revoke';
        }
    })
    .catch(() => {
        btn.disabled = false;
        btn.textContent = 'Revoke';
    });
}

function revokeAllSessions() {
    if (!confirm('Revoke all other sessions? Those devices will be logged out.')) return;

    fetch('/api/sessions/revoke-all', {
        method: 'POST',
        headers: {'X-CSRFToken': getCsrfToken()}
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) loadSessions();
    });
}

document.addEventListener('DOMContentLoaded', loadSessions);
