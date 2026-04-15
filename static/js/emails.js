// Spambusters - Emails page JS

function showExplanation(emailId) {
    const modal = document.getElementById('explainModal');
    const content = document.getElementById('explainContent');

    modal.style.display = 'flex';
    content.innerHTML = '<div class="loading" style="text-align: center; padding: 40px;">Loading...</div>';

    fetch(`/api/explain/${emailId}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                content.innerHTML = `<div class="error">${escapeHtml(data.error)}</div>`;
                return;
            }

            const scorePercent = Math.round(data.spam_score * 100);
            const isSpam = data.is_spam;
            const explanation = data.explanation;

            let html = `
                <div class="score-display">
                    <div class="score-value ${isSpam ? 'spam' : 'safe'}">${scorePercent}%</div>
                    <div class="score-label">
                        ${isSpam ? 'Classified as SPAM' : 'Classified as SAFE'}
                    </div>
                </div>

                <h4 style="margin-bottom: 12px;">Contributing Factors</h4>
            `;

            if (explanation.reasons && explanation.reasons.length > 0) {
                explanation.reasons.forEach(reason => {
                    html += `
                        <div class="reason-item ${escapeHtml(reason.severity)}">
                            <div class="reason-type">${escapeHtml(reason.type)}</div>
                            <div class="reason-detail">${escapeHtml(reason.detail)}</div>
                        </div>
                    `;
                });
            }

            if (explanation.keywords_found && explanation.keywords_found.length > 0) {
                html += `
                    <div class="keywords-list">
                        <h4>Suspicious Keywords Found</h4>
                        <div>
                            ${explanation.keywords_found.map(kw => `<span class="keyword-tag">${escapeHtml(kw)}</span>`).join('')}
                        </div>
                    </div>
                `;
            }

            if (explanation.obfuscated_keywords_found && explanation.obfuscated_keywords_found.length > 0) {
                html += `
                    <div class="keywords-list" style="border-left: 3px solid #8b0000;">
                        <h4>Hidden Keywords (Unicode Obfuscated)</h4>
                        <div>
                            ${explanation.obfuscated_keywords_found.map(kw => `<span class="keyword-tag" style="background: rgba(139,0,0,0.3); border-color: #8b0000;">${escapeHtml(kw)}</span>`).join('')}
                        </div>
                    </div>
                `;
            }

            if (explanation.features) {
                html += `
                    <div style="margin-top: 15px; padding: 12px; background: var(--bg-secondary); border-radius: 8px;">
                        <h4 style="margin: 0 0 8px 0; font-size: 13px; color: var(--text-muted);">Feature Analysis</h4>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; font-size: 13px;">
                            <div>URLs: <strong>${explanation.features.url_count}</strong></div>
                            <div>Emails: <strong>${explanation.features.email_count}</strong></div>
                            <div>Uppercase: <strong>${Math.round(explanation.features.uppercase_ratio * 100)}%</strong></div>
                            <div>Exclamations: <strong>${explanation.features.exclamation_count}</strong></div>
                            <div>Spam Keywords: <strong>${explanation.features.spam_keyword_count}</strong></div>
                            <div>Suspicious Unicode: <strong style="color: ${explanation.features.has_suspicious_scripts ? '#ef4444' : 'inherit'};">${explanation.features.suspicious_char_count || 0}</strong></div>
                        </div>
                    </div>
                `;
            }

            content.innerHTML = html;
        })
        .catch(error => {
            content.innerHTML = `<div class="error">Failed to load explanation: ${escapeHtml(String(error))}</div>`;
        });
}

function closeExplainModal() {
    document.getElementById('explainModal').style.display = 'none';
}

// Close modal on backdrop click
document.getElementById('explainModal').addEventListener('click', function(e) {
    if (e.target === this) {
        closeExplainModal();
    }
});

// Email Preview Modal
function showPreview(emailId) {
    const modal = document.getElementById('previewModal');
    const content = document.getElementById('previewContent');
    const subject = document.getElementById('previewSubject');

    modal.style.display = 'flex';
    subject.textContent = 'Loading...';
    content.innerHTML = '<div class="loading" style="text-align: center; padding: 40px;">Loading...</div>';

    fetch(`/api/email/${emailId}/preview`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                content.innerHTML = `<div class="error">${data.error}</div>`;
                return;
            }

            subject.textContent = data.subject;

            const scorePercent = Math.round(data.spam_score * 100);
            const scoreClass = data.spam_score < 0.5 ? 'safe' : 'spam';

            let senderDisplay = escapeHtml(data.sender);
            const senderParts = data.sender.split('<');
            if (senderParts.length > 1) {
                senderDisplay = `${escapeHtml(senderParts[0].trim().replace(/"/g, ''))} &lt;${escapeHtml(senderParts[1])}`;
            }

            let html = `
                <div class="preview-meta">
                    <span class="preview-meta-label">From</span>
                    <span class="preview-meta-value">${senderDisplay}</span>
                    <span class="preview-meta-label">Date</span>
                    <span class="preview-meta-value">${escapeHtml(data.received_at || 'Unknown')}</span>
                    <span class="preview-meta-label">Threat</span>
                    <span class="preview-meta-value">
                        <span class="score-value ${scoreClass}" style="font-size: 16px; font-weight: 700;">${scorePercent}%</span>
                        <span style="color: var(--text-muted); margin-left: 8px;">${data.is_spam ? 'Spam' : 'Safe'}</span>
                    </span>
                </div>
                <div class="preview-body">${escapeHtml(data.content)}</div>
            `;

            if (data.truncated) {
                html += '<div class="preview-truncated">Content truncated (showing first 5000 characters)</div>';
            }

            content.innerHTML = html;
        })
        .catch(error => {
            content.innerHTML = `<div class="error">Failed to load email: ${escapeHtml(String(error))}</div>`;
        });
}

function closePreviewModal() {
    document.getElementById('previewModal').style.display = 'none';
}

document.getElementById('previewModal').addEventListener('click', function(e) {
    if (e.target === this) {
        closePreviewModal();
    }
});

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Close modals on Escape key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeExplainModal();
        closePreviewModal();
        closeAllDropdowns();
    }
});

// Toggle dropdown actions
function toggleActions(emailId) {
    const dropdown = document.getElementById(`actions-${emailId}`);
    const isVisible = dropdown.style.display !== 'none';

    closeAllDropdowns();

    dropdown.style.display = isVisible ? 'none' : 'block';
}

function closeAllDropdowns() {
    document.querySelectorAll('.dropdown-actions').forEach(d => d.style.display = 'none');
}

// Close dropdowns when clicking outside
document.addEventListener('click', function(e) {
    if (!e.target.closest('.dropdown-actions') && !e.target.closest('[onclick*="toggleActions"]')) {
        closeAllDropdowns();
    }
});

// Whitelist sender
function whitelistSender(emailId, btn) {
    fetch(`/senders/quick-add/${emailId}/whitelist`, {
        method: 'POST',
        headers: {'X-CSRFToken': getCsrfToken()}
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            btn.textContent = 'Whitelisted';
            btn.disabled = true;
            closeAllDropdowns();
        }
    });
}

// Blacklist sender
function blacklistSender(emailId, btn) {
    fetch(`/senders/quick-add/${emailId}/blacklist`, {
        method: 'POST',
        headers: {'X-CSRFToken': getCsrfToken()}
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            btn.textContent = 'Blacklisted';
            btn.disabled = true;
            closeAllDropdowns();
        }
    });
}

// Test warning injection
function testWarning(emailId, btn) {
    if (!confirm('This will inject a spam warning into the actual email via IMAP. Continue?')) return;
    btn.textContent = 'Injecting...';
    btn.disabled = true;
    fetch(`/api/email/${emailId}/test-warning`, {
        method: 'POST',
        headers: {'X-CSRFToken': getCsrfToken()}
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            btn.textContent = 'Warning injected';
            closeAllDropdowns();
        } else {
            btn.textContent = 'Failed';
            alert(data.error || 'Failed to inject warning');
        }
    })
    .catch(err => {
        btn.textContent = 'Error';
        alert('Request failed: ' + err);
    });
}

// Restore email
function restoreEmail(emailId, btn) {
    fetch(`/api/email/${emailId}/restore`, {
        method: 'POST',
        headers: {'X-CSRFToken': getCsrfToken()}
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            btn.textContent = 'Restored';
            btn.disabled = true;
            closeAllDropdowns();
            location.reload();
        } else {
            alert(data.error || 'Failed to restore');
        }
    });
}
