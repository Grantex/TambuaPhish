const ctx = document.getElementById('campaignChart').getContext('2d');
const campaignChart = new Chart(ctx, {
    type: 'bar',
    data: {
        labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May','Jun','July','Aug','Sep','Oct','Nov','Dec'],
        datasets: [
            {
                label: 'Phishing Emails Sent',
                data: [120, 90, 150, 130, 170],
                backgroundColor: 'rgba(0, 77, 153, 0.5)',
                borderColor: '#004d99',
                borderWidth: 1,
                yAxisID: 'y',
            },
            {
                label: 'Click-Through Rate (%)',
                data: [22, 18, 30, 25, 28],
                type: 'line',
                borderColor: '#e67e22',
                backgroundColor: '#e67e22',
                tension: 0.4,
                yAxisID: 'y1',
            }
        ]
    },
    options: {
        responsive: true,
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
                grid: {
                    drawOnChartArea: false,
                }
            }
        },
        plugins: {
            tooltip: {
                mode: 'index',
                intersect: false,
            },
            legend: {
                position: 'top',
            }
        },
    }
});
