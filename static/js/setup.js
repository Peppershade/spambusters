// Spambusters - Setup page JS

function toggle2FA() {
    const checkbox = document.getElementById('enable_2fa');
    const section = document.getElementById('twofa-section');
    const totpInput = document.getElementById('totp_code');

    if (checkbox.checked) {
        section.style.display = 'block';
        totpInput.required = true;
    } else {
        section.style.display = 'none';
        totpInput.required = false;
        totpInput.value = '';
    }
}
