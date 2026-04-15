// Spambusters - Notification settings JS

function updateWarningPreview() {
    const htmlTpl = document.getElementById('warning_html').value;
    const preview = document.getElementById('warning-preview');
    if (preview) {
        preview.innerHTML = htmlTpl.replace(/\{score\}/g, '85');
    }
}

// Initialize preview on page load
document.addEventListener('DOMContentLoaded', function() {
    updateWarningPreview();
});
