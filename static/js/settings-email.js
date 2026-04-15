// Spambusters - Email (IMAP) settings JS

function clearForm() {
    if (confirm('Clear all IMAP settings? You will need to re-enter your credentials.')) {
        document.getElementById('imap_server').value = '';
        document.getElementById('imap_port').value = '993';
        document.getElementById('email_address').value = '';
        document.getElementById('email_password').value = '';
    }
}
