// Spambusters - Discord settings JS

function clearForm() {
    if (confirm('Clear all Discord settings? You will stop receiving notifications.')) {
        document.getElementById('webhook_url').value = '';
        document.getElementById('webhook_secret').value = '';
        document.getElementById('bot_token').value = '';
        document.getElementById('channel_id').value = '';
        document.getElementById('notify_threshold').value = '0.7';
        document.getElementById('threshold_value').textContent = '0.7';
    }
}

function startBot() {
    fetch('/api/discord/start', {
        method: 'POST',
        headers: {'X-CSRFToken': getCsrfToken()}
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert(data.error || 'Failed to start bot');
            }
        })
        .catch(err => alert('Error: ' + err));
}

function stopBot() {
    fetch('/api/discord/stop', {
        method: 'POST',
        headers: {'X-CSRFToken': getCsrfToken()}
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert(data.error || 'Failed to stop bot');
            }
        })
        .catch(err => alert('Error: ' + err));
}
