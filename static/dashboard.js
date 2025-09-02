const ctx = document.getElementById('campaignChart').getContext('2d');
const campaignChart = new Chart(ctx, {
    type: 'bar',
    data: {
        labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'],
        datasets: [
            {
                label: 'Phishing Emails Sent',
                data: chartData.emailsSent,
                backgroundColor: 'rgba(0, 77, 153, 0.5)',
                borderColor: '#004d99',
                borderWidth: 1,
                yAxisID: 'y', // Left axis
            },
            {
                label: 'Click-Through Rate (%)',
                data: chartData.ctr,
                type: 'line',
                borderColor: '#e67e22',
                backgroundColor: '#e67e22',
                tension: 0.4,
                yAxisID: 'y1', // Right axis
            }
        ]
    },
    options: {
        responsive: true,
        interaction: {
            mode: 'index',
            intersect: false,
        },
        stacked: false,
        scales: {
            y: {
                type: 'linear',
                position: 'left',
                title: {
                    display: true,
                    text: 'Emails Sent'
                }
            },
            y1: {
                type: 'linear',
                position: 'right',
                title: {
                    display: true,
                    text: 'Click-Through Rate (%)'
                },
                min: 0,
                max: 100, // Keeps CTR as percentage
                ticks: {
                    callback: function(value) {
                        return value + '%';
                    }
                },
                grid: {
                    drawOnChartArea: false // Avoid grid overlap
                }
            }
        },
        plugins: {
            tooltip: { mode: 'index', intersect: false },
            legend: { position: 'top' }
        }
    }
});
