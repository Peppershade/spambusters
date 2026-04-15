// Spambusters - Admin password confirmation validation
// Used on create_user and edit_user pages

document.addEventListener('DOMContentLoaded', function() {
    // create_user form
    const createForm = document.getElementById('password');
    if (createForm) {
        createForm.closest('form').addEventListener('submit', function(e) {
            const password = document.getElementById('password').value;
            const confirm = document.getElementById('password_confirm').value;
            if (password !== confirm) {
                e.preventDefault();
                alert('Passwords do not match!');
                document.getElementById('password_confirm').focus();
            }
        });
    }

    // edit_user form
    const editField = document.getElementById('new_password');
    if (editField) {
        editField.closest('form').addEventListener('submit', function(e) {
            const password = document.getElementById('new_password').value;
            const confirm = document.getElementById('new_password_confirm').value;
            if (password !== confirm) {
                e.preventDefault();
                alert('Passwords do not match!');
                document.getElementById('new_password_confirm').focus();
            }
        });
    }
});
