// /opt/mcr-srt-streamer/app/static/js/smpte_details.js

$(document).ready(function() {
    // --- Configuration ---
    const MAX_CHART_POINTS = 60; // Number of data points to show on charts
    const REFRESH_INTERVAL_MS = 2500; // How often to refresh stats (e.g., 2.5 seconds)

    // --- Get Pair ID from URL ---
    const pathParts = window.location.pathname.split('/');
    const pairId = pathParts[pathParts.length - 1];
    const statsApiUrl = `/smpte2022_7/api/stats/${pairId}`;

    // --- Chart Initialization ---
    let leg1RttChart, leg1LossChart, leg1RateChart;
    let leg2RttChart, leg2LossChart, leg2RateChart;

    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            x: {
                // type: 'time', // REMOVED: This requires a date adapter library
                ticks: { display: false }, // Hide x-axis labels for simplicity
                grid: { display: false }
            },
            y: {
                beginAtZero: true,
                ticks: { font: { size: 10 } },
                grid: { color: 'rgba(200, 200, 200, 0.2)' }
            }
        },
        plugins: {
            legend: { display: false },
            tooltip: { enabled: true } // Enable tooltips now that x-axis isn't time
        },
        elements: {
            point: { radius: 1, hitRadius: 5 }, // Show small points, increase hit radius
            line: { tension: 0.1, borderWidth: 2 }
        },
        animation: { duration: 0 } // Disable animation for faster updates
    };

    function createStatChart(canvasId, label, borderColor, yAxisLabel = '') {
        const ctx = document.getElementById(canvasId);
        if (!ctx) {
            console.error(`Canvas element with ID ${canvasId} not found.`);
            return null;
        }
        const scalesOptions = JSON.parse(JSON.stringify(chartOptions.scales)); // Deep copy
        if (yAxisLabel) {
            scalesOptions.y.title = { display: true, text: yAxisLabel, font: { size: 10 } };
        }

        return new Chart(ctx, {
            type: 'line',
            data: {
                labels: [], // Will just be indices now
                datasets: [{
                    label: label,
                    data: [],
                    borderColor: borderColor,
                    fill: false
                }]
            },
            options: { ...chartOptions, scales: scalesOptions } // Use modified scales
        });
    }

    function initCharts() {
        // Leg 1 Charts
        leg1RttChart = createStatChart('leg1-rtt-chart', 'RTT', 'rgb(255, 99, 132)', 'ms');
        leg1LossChart = createStatChart('leg1-loss-chart', 'Pkt Loss', 'rgb(255, 159, 64)', '%');
        leg1RateChart = createStatChart('leg1-rate-chart', 'Send Rate', 'rgb(75, 192, 192)', 'Mbps');
        // Leg 2 Charts
        leg2RttChart = createStatChart('leg2-rtt-chart', 'RTT', 'rgb(255, 99, 132)', 'ms');
        leg2LossChart = createStatChart('leg2-loss-chart', 'Pkt Loss', 'rgb(255, 159, 64)', '%');
        leg2RateChart = createStatChart('leg2-rate-chart', 'Send Rate', 'rgb(75, 192, 192)', 'Mbps');
    }

    function updateChart(chart, newDataPoint) {
        if (!chart) return;
        const data = chart.data.datasets[0].data;
        const labels = chart.data.labels;
        const nextLabel = labels.length > 0 ? (parseInt(labels[labels.length - 1]) + 1) : 1;

        // Ensure null is pushed if data is missing/invalid for chart continuity
        data.push(typeof newDataPoint === 'number' ? newDataPoint : null);
        labels.push(nextLabel.toString()); // Push simple label

        if (data.length > MAX_CHART_POINTS) {
            data.shift();
            labels.shift();
        }
        chart.update();
    }

    // --- Stats Update Function ---
    function updateStats() {
        $('#refresh-indicator-details').removeClass('d-none');

        $.getJSON(statsApiUrl, function(response) { // Uses updated URL
            if (!response || response.error) {
                console.error("Error fetching SMPTE stats:", response ? response.error : "Empty response");
                // Optionally display an error message on the page
                $('#leg1-rtt').text('Error'); // Indicate error on fields
                $('#leg2-rtt').text('Error');
                return;
            }

            const leg1 = response.leg1_stats || {};
            const leg2 = response.leg2_stats || {};

            // --- Update Leg 1 Table ---
            $('#leg1-rtt').text(leg1.rtt_ms !== undefined ? leg1.rtt_ms.toFixed(2) : '--');
            $('#leg1-pktLoss').text(leg1.packet_loss_percent !== undefined ? leg1.packet_loss_percent.toFixed(2) : '--');
            $('#leg1-sendRate').text(leg1.bitrate_mbps !== undefined ? leg1.bitrate_mbps.toFixed(2) : '--');
            $('#leg1-recvRate').text(leg1.receive_rate_mbps !== undefined ? leg1.receive_rate_mbps.toFixed(2) : '--'); // Assuming receive_rate_mbps exists
            $('#leg1-sndBuf').text(leg1.send_buffer_level_ms !== undefined ? leg1.send_buffer_level_ms : '--');
            $('#leg1-rcvBuf').text(leg1.recv_buffer_level_ms !== undefined ? leg1.recv_buffer_level_ms : '--');
            $('#leg1-pktSent').text(leg1.packets_sent_total !== undefined ? leg1.packets_sent_total : '--');
            $('#leg1-pktLost').text(leg1.packets_lost_total !== undefined ? leg1.packets_lost_total : '--');
            $('#leg1-pktRetrans').text(leg1.packets_retransmitted_total !== undefined ? leg1.packets_retransmitted_total : '--');

             // --- Update Leg 2 Table ---
            $('#leg2-rtt').text(leg2.rtt_ms !== undefined ? leg2.rtt_ms.toFixed(2) : '--');
            $('#leg2-pktLoss').text(leg2.packet_loss_percent !== undefined ? leg2.packet_loss_percent.toFixed(2) : '--');
            $('#leg2-sendRate').text(leg2.bitrate_mbps !== undefined ? leg2.bitrate_mbps.toFixed(2) : '--');
            $('#leg2-recvRate').text(leg2.receive_rate_mbps !== undefined ? leg2.receive_rate_mbps.toFixed(2) : '--');
            $('#leg2-sndBuf').text(leg2.send_buffer_level_ms !== undefined ? leg2.send_buffer_level_ms : '--');
            $('#leg2-rcvBuf').text(leg2.recv_buffer_level_ms !== undefined ? leg2.recv_buffer_level_ms : '--');
            $('#leg2-pktSent').text(leg2.packets_sent_total !== undefined ? leg2.packets_sent_total : '--');
            $('#leg2-pktLost').text(leg2.packets_lost_total !== undefined ? leg2.packets_lost_total : '--');
            $('#leg2-pktRetrans').text(leg2.packets_retransmitted_total !== undefined ? leg2.packets_retransmitted_total : '--');

            // --- Update Charts ---
            updateChart(leg1RttChart, leg1.rtt_ms !== undefined ? leg1.rtt_ms : null);
            updateChart(leg1LossChart, leg1.packet_loss_percent !== undefined ? leg1.packet_loss_percent : null);
            updateChart(leg1RateChart, leg1.bitrate_mbps !== undefined ? leg1.bitrate_mbps : null);

            updateChart(leg2RttChart, leg2.rtt_ms !== undefined ? leg2.rtt_ms : null);
            updateChart(leg2LossChart, leg2.packet_loss_percent !== undefined ? leg2.packet_loss_percent : null);
            updateChart(leg2RateChart, leg2.bitrate_mbps !== undefined ? leg2.bitrate_mbps : null);

        }).fail(function(jqXHR, textStatus, errorThrown) {
            console.error(`Failed to fetch SMPTE stats from ${statsApiUrl}:`, textStatus, errorThrown, jqXHR.status, jqXHR.responseText);
             $('#leg1-rtt').text('API Err'); // Indicate error on fields
             $('#leg2-rtt').text('API Err');
        }).always(function() {
            // Hide refresh indicator slightly later
            setTimeout(function() { $('#refresh-indicator-details').addClass('d-none'); }, 300);
        });
    }

    // --- Stop Button ---
    $('#stop-pair-button').on('click', function(e) {
        e.preventDefault(); // Prevent default button action
        if (confirm(`Are you sure you want to stop SMPTE Pair ${pairId}?`)) {
            $('#stop-pair-form').submit(); // Submit the hidden form
        }
    });

    // --- Initial Load & Interval ---
    if (!pairId || isNaN(parseInt(pairId))) {
        console.error("Invalid or missing Pair ID in URL.");
        // Display error on page? Add an element with id="page-error-message" maybe
        $('#pair-id-display').text('INVALID');
        $('.container').prepend('<div class="alert alert-danger">Invalid Pair ID found in URL. Cannot load details.</div>');
    } else {
        console.log(`Initializing details page for SMPTE Pair ID: ${pairId}`);
        initCharts();
        updateStats(); // Initial fetch
        setInterval(updateStats, REFRESH_INTERVAL_MS); // Periodic refresh
    }

}); // End document.ready

