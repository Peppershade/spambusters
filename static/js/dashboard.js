// Spambusters - Dashboard charts JS
// Reads chart data from data-* attributes and JSON data islands

(function() {
    const pieCanvas = document.getElementById('spamPieChart');
    if (!pieCanvas) return;

    // Guard against double-init (e.g. stale SW cache serving old inline scripts)
    if (pieCanvas.dataset.chartInit) return;
    pieCanvas.dataset.chartInit = '1';

    const spamCount = parseInt(pieCanvas.dataset.spam, 10);
    const safeCount = parseInt(pieCanvas.dataset.safe, 10);

    // Spam vs Safe doughnut chart
    new Chart(pieCanvas.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['Spam', 'Safe'],
            datasets: [{
                data: [spamCount, safeCount],
                backgroundColor: ['#ef4444', '#10b981'],
                borderColor: ['rgba(239, 68, 68, 0.8)', 'rgba(16, 185, 129, 0.8)'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', padding: 16 }
                }
            }
        }
    });

    // Threat activity line chart
    fetch('/api/chart-data?days=30')
        .then(response => response.json())
        .then(data => {
            const spamCanvas = document.getElementById('spamChart');
            if (!spamCanvas || Chart.getChart(spamCanvas)) return;

            new Chart(spamCanvas.getContext('2d'), {
                type: 'line',
                data: {
                    labels: data.map(d => d.date),
                    datasets: [
                        {
                            label: 'Spam',
                            data: data.map(d => d.spam),
                            borderColor: '#ef4444',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            fill: true,
                            tension: 0.3
                        },
                        {
                            label: 'Safe',
                            data: data.map(d => d.safe),
                            borderColor: '#10b981',
                            backgroundColor: 'rgba(16, 185, 129, 0.1)',
                            fill: true,
                            tension: 0.3
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: { color: '#94a3b8' }
                        }
                    },
                    scales: {
                        x: {
                            grid: { color: 'rgba(45, 55, 72, 0.5)' },
                            ticks: { color: '#64748b' }
                        },
                        y: {
                            beginAtZero: true,
                            grid: { color: 'rgba(45, 55, 72, 0.5)' },
                            ticks: { color: '#64748b' }
                        }
                    }
                }
            });
        });

    // Actions breakdown doughnut chart
    const actionsEl = document.getElementById('actionsData');
    const actionsCanvas = document.getElementById('actionsChart');
    if (actionsEl && actionsCanvas) {
        const actionsData = JSON.parse(actionsEl.textContent);
        const labels = Object.keys(actionsData);
        const values = Object.values(actionsData);

        new Chart(actionsCanvas.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6', '#6b7280'],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#94a3b8', padding: 16 }
                    }
                }
            }
        });
    }
})();
