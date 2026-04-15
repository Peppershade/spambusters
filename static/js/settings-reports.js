// Spambusters - Report settings JS

function sendTestReport() {
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '/settings/smtp/report-test';
    const csrf = document.createElement('input');
    csrf.type = 'hidden';
    csrf.name = 'csrf_token';
    csrf.value = getCsrfToken();
    form.appendChild(csrf);
    document.body.appendChild(form);
    form.submit();
}
