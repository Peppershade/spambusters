// Spambusters - Scanning settings JS

function updateThresholdDisplay() {
    const deleteVal = parseFloat(document.getElementById('threshold-delete-input').value);
    const moveVal = parseFloat(document.getElementById('threshold-move-input').value);
    const warnVal = parseFloat(document.getElementById('threshold-warn-input').value);

    document.getElementById('threshold-delete-val').textContent = deleteVal.toFixed(2);
    document.getElementById('threshold-move-val').textContent = moveVal.toFixed(2);
    document.getElementById('threshold-warn-val').textContent = warnVal.toFixed(2);

    // Update the 4-zone visual bar
    const safePct = warnVal * 100;
    const warnPct = Math.max(0, (moveVal - warnVal)) * 100;
    const movePct = Math.max(0, (deleteVal - moveVal)) * 100;
    const deletePct = Math.max(0, (1.0 - deleteVal)) * 100;

    document.getElementById('zone-safe').style.width = safePct + '%';
    document.getElementById('zone-warn').style.width = warnPct + '%';
    document.getElementById('zone-move').style.width = movePct + '%';
    document.getElementById('zone-delete').style.width = deletePct + '%';
}

// Initialize threshold display on load
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('threshold-delete-input')) {
        updateThresholdDisplay();
    }
});
