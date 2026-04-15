// Spambusters - Core application JS
// Shared across all authenticated pages (loaded from base.html)

// CSRF token helper - reads from <meta name="csrf-token">
function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

// Sidebar toggle for mobile
function toggleSidebar() {
    document.querySelector('.sidebar').classList.toggle('open');
    document.querySelector('.sidebar-overlay').classList.toggle('open');
}

function closeSidebar() {
    document.querySelector('.sidebar').classList.remove('open');
    document.querySelector('.sidebar-overlay').classList.remove('open');
}

// Close sidebar when clicking a link (mobile)
document.querySelectorAll('.sidebar .nav-link').forEach(link => {
    link.addEventListener('click', () => {
        if (window.innerWidth <= 768) {
            closeSidebar();
        }
    });
});

// AJAX label function - no page refresh (used on dashboard + emails)
function labelEmail(emailId, isSpam, button) {
    const row = button.closest('tr');
    const actionsCell = button.closest('td');

    const buttons = actionsCell.querySelectorAll('button');
    buttons.forEach(btn => btn.disabled = true);

    fetch(`/email/${emailId}/label`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify({ is_spam: isSpam })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const badge = document.createElement('span');
            badge.className = `badge ${isSpam ? 'badge-spam' : 'badge-safe'}`;
            badge.textContent = isSpam ? 'SPAM' : 'SAFE';
            actionsCell.innerHTML = '';
            actionsCell.appendChild(badge);
            row.style.opacity = '0.6';

            if (window.location.pathname === '/dashboard') {
                setTimeout(() => {
                    const nextRow = row.nextElementSibling;
                    if (nextRow && nextRow.querySelector('details')) {
                        nextRow.remove();
                    }
                    row.remove();
                }, 400);
            }
        }
    })
    .catch(error => {
        console.error('Error:', error);
        buttons.forEach(btn => btn.disabled = false);
    });
}

// Register service worker for PWA
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/service-worker.js')
        .then(reg => {
            reg.addEventListener('updatefound', () => {
                const newWorker = reg.installing;
                if (!newWorker) return;
                newWorker.addEventListener('statechange', () => {
                    if (newWorker.state === 'activated' && navigator.serviceWorker.controller) {
                        const banner = document.createElement('div');
                        banner.className = 'flash info';
                        banner.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9999;text-align:center;padding:10px;cursor:pointer;';
                        banner.textContent = 'New version available — click to refresh';
                        banner.addEventListener('click', () => window.location.reload());
                        document.body.prepend(banner);
                    }
                });
            });
        })
        .catch(err => console.warn('SW registration failed:', err));
}

// Capture install prompt for potential future use
let deferredInstallPrompt = null;
window.addEventListener('beforeinstallprompt', e => {
    e.preventDefault();
    deferredInstallPrompt = e;
});
