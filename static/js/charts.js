/**
 * Chart initialization for Reports & Analytics page
 * Reads data from embedded JSON and renders Chart.js visualizations
 */

document.addEventListener('DOMContentLoaded', function() {
    // Read chart data from JSON script tag
    const dataElement = document.getElementById('chart-data');
    if (!dataElement) {
        console.error('Chart data element not found');
        return;
    }

    let chartData;
    try {
        chartData = JSON.parse(dataElement.textContent);
    } catch (e) {
        console.error('Failed to parse chart data:', e);
        return;
    }

    const { labels, tempData, humidityData } = chartData;

    // Verify canvas elements exist
    const tempCanvas = document.getElementById('tempChart');
    const humidityCanvas = document.getElementById('humidityChart');

    if (!tempCanvas || !humidityCanvas) {
        console.error('Chart canvas elements not found');
        return;
    }

    // Temperature Chart
    const tempCtx = tempCanvas.getContext('2d');
    new Chart(tempCtx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Temperature (°F)',
                data: tempData,
                borderColor: 'rgb(220, 53, 69)',
                backgroundColor: 'rgba(220, 53, 69, 0.1)',
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    min: 60,
                    max: 85,
                    title: { display: true, text: '°F' }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });

    // Humidity Chart
    const humidityCtx = humidityCanvas.getContext('2d');
    new Chart(humidityCtx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Humidity (%)',
                data: humidityData,
                borderColor: 'rgb(13, 110, 253)',
                backgroundColor: 'rgba(13, 110, 253, 0.1)',
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    min: 20,
                    max: 70,
                    title: { display: true, text: '%' }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
});
