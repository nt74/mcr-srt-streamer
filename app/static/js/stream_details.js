// /opt/mcr-srt-streamer/app/static/js/stream_details.js

document.addEventListener('DOMContentLoaded', function() {
    const streamInfoDiv = document.getElementById('stream-info');
    const streamKey = streamInfoDiv ? streamInfoDiv.dataset.streamKey : null;

    if (!streamKey) {
        console.error("Stream key not found in data-stream-key attribute.");
        const body = document.querySelector('.container');
        if (body) {
            const errorDiv = document.createElement('div');
            errorDiv.className = 'alert alert-danger';
            errorDiv.textContent = 'Error: Could not identify stream key for fetching details.';
            body.prepend(errorDiv);
        }
        return;
    }
    console.log("Stream Details JS loaded for key:", streamKey);

    let statsChart = null;
    const maxChartPoints = 30; // Number of data points to show on the chart
    const chartData = {
        labels: [],
        datasets: [
            { label: 'Bitrate (Mbps)', data: [], yAxisID: 'yBitrate', borderColor: 'rgba(40, 167, 69, 1)', backgroundColor: 'rgba(40, 167, 69, 0.1)', borderWidth: 1.5, tension: 0.1, pointRadius: 1, fill: true },
            { label: 'RTT (ms)', data: [], yAxisID: 'yRtt', borderColor: 'rgba(23, 162, 184, 1)', backgroundColor: 'rgba(23, 162, 184, 0.1)', borderWidth: 1.5, tension: 0.1, pointRadius: 1, fill: false },
            { label: 'Loss (%)', data: [], yAxisID: 'yLoss', borderColor: 'rgba(220, 53, 69, 1)', backgroundColor: 'rgba(220, 53, 69, 0.1)', borderWidth: 1.5, tension: 0.1, pointRadius: 1, fill: false }
        ]
    };

    // --- Helper Functions ---
    function setText(id, text) {
        const elem = document.getElementById(id);
        if (elem) elem.textContent = text ?? 'N/A'; // Use nullish coalescing for default
    }
    function setWidth(id, percentage) {
        const elem = document.getElementById(id);
        if (elem) elem.style.width = `${Math.max(0, Math.min(100, percentage || 0))}%`; // Handle null/undefined percentage
    }
    // formatBytes is assumed to be loaded globally from app.js

    // --- Chart Initialization ---
    function initChart() {
        const ctx = document.getElementById('stats-chart')?.getContext('2d');
        if (!ctx) { console.error("Chart canvas not found."); return; }
        try {
            statsChart = new Chart(ctx, {
                type: 'line',
                data: chartData,
                options: {
                    responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
                    scales: {
                        x: { ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 10 } },
                        yBitrate: { type: 'linear', display: true, position: 'left', title: { display: true, text: 'Bitrate (Mbps)' }, beginAtZero: true, grid: { drawOnChartArea: true } },
                        yRtt: { type: 'linear', display: true, position: 'right', title: { display: true, text: 'RTT (ms)' }, beginAtZero: true, grid: { drawOnChartArea: false } },
                        yLoss: { type: 'linear', display: true, position: 'right', title: { display: true, text: 'Loss (%)' }, beginAtZero: true, suggestedMax: 5, grid: { drawOnChartArea: false } }
                    },
                    animation: false,
                    plugins: { legend: { display: true, position: 'top'} }
                }
            });
        } catch (e) {
            console.error("Failed to initialize Chart.js:", e);
            if (ctx) { ctx.font = "16px Arial"; ctx.fillStyle = "red"; ctx.textAlign = "center"; ctx.fillText("Error loading chart.", ctx.canvas.width / 2, 50); }
        }
    }

    // --- Stats Update Function ---
    async function updateStats() {
        if (!streamKey) return;
        try {
            const response = await fetch(`/ui/stats/${streamKey}`); // Use UI endpoint

            if (!response.ok) {
                let errorMsg = `Error fetching stats (${response.status})`;
                try { const errData = await response.json(); if (errData && errData.error) errorMsg = errData.error; } catch (e) {}
                console.error("Stats fetch failed:", errorMsg);
                setText('status', `Error (${response.status})`);
                $('#status').removeClass().addClass('badge bg-danger');
                if (response.status === 404) { clearInterval(statsIntervalId); }
                return;
            }

            const data = await response.json();

            if (!data || (data.error && response.status !== 404)) {
                console.error("Error in stats data:", data?.error);
                setText('status', data?.error || 'Error');
                $('#status').removeClass().addClass('badge bg-danger');
                return;
            }

            // --- Update UI Elements ---
            const statusElem = document.getElementById('status');
            if (statusElem) {
                statusElem.textContent = data.connection_status || 'Unknown';
                let sClass = 'bg-secondary';
                if (data.connection_status === 'Connected') sClass = 'bg-success';
                else if (['Waiting for connection', 'Connecting...', 'Timeout / Reconnecting', 'Broken / Reconnecting'].includes(data.connection_status)) sClass = 'bg-info';
                else if (['Connection Failed', 'Disconnected', 'Rejected', 'Error', 'Bind Error', 'Start Error', 'Auth Error', 'Stopped'].includes(data.connection_status)) sClass = 'bg-danger';
                statusElem.className = `badge ${sClass}`;
                 if (sClass === 'bg-danger' || sClass === 'bg-secondary' || data.connection_status?.includes('Stopped')) {
                    clearInterval(statsIntervalId);
                    console.log("Stopping stats polling due to stream state:", data.connection_status);
                 }
            }
            setText('client-ip', data.connected_client || 'None Connected');
            setText('uptime', data.uptime || '0s');
            setText('stats-last-updated', data.timestamp_api ? new Date(data.timestamp_api * 1000).toLocaleTimeString() : '-');

            setText('negotiated-latency', data.negotiated_latency_ms ?? 'N/A');

            // Stat Cards
            const bitrate = data.bitrate_mbps !== undefined ? parseFloat(data.bitrate_mbps) : 0;
            const rtt = data.rtt_ms !== undefined ? parseInt(data.rtt_ms) : 0;
            const lossPercent = data.packet_loss_percent !== undefined ? parseFloat(data.packet_loss_percent) : 0.0;
            setText('bitrate-value', bitrate.toFixed(2)); setWidth('bitrate-bar', Math.min(100,(bitrate/50)*100));
            setText('rtt-value', rtt.toFixed(0)); setWidth('rtt-bar', Math.min(100,(rtt/500)*100));
            setText('loss-value', lossPercent.toFixed(2)); setWidth('loss-bar', Math.min(100,(lossPercent/5)*100));

            // Corrected Packet Counters
            const packetsSent = data.packets_sent !== undefined ? data.packets_sent : (data.packetsent_total || 0);
            const packetsReceived = data.packets_received_total !== undefined ? data.packets_received_total : (data.packets_received || 0);
            const packetsLost = data.packets_lost_total !== undefined ? data.packets_lost_total : 0;
            const packetsRetransmitted = data.packets_retransmitted_total !== undefined ? data.packets_retransmitted_total : (data.packets_retransmitted || 0);
            const bytesSent = data.bytesent_total !== undefined ? data.bytesent_total : (data.bytesent || 0);

            setText('loss-detail', `${(packetsLost || 0).toLocaleString()} / ${(packetsSent || 0).toLocaleString()}`);
            setText('packets-sent', (packetsSent || 0).toLocaleString());
            setText('packets-received', (packetsReceived || 0).toLocaleString());
            setText('packets-lost', (packetsLost || 0).toLocaleString());
            setText('packets-retransmitted', (packetsRetransmitted || 0).toLocaleString());
            setText('bytes-sent', formatBytes(bytesSent || 0)); // Assumes formatBytes is global

            // Update Chart
            if (statsChart) {
                const nowLabel = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit'});
                if (chartData.labels.length >= maxChartPoints) { chartData.labels.shift(); chartData.datasets.forEach(ds => ds.data.shift()); }
                chartData.labels.push(nowLabel);
                chartData.datasets[0].data.push(bitrate);
                chartData.datasets[1].data.push(rtt);
                chartData.datasets[2].data.push(lossPercent);
                statsChart.update('none');
            }

        } catch (error) {
            console.error("Error processing stats update:", error);
            setText('status', 'Update Error');
            $('#status').removeClass().addClass('badge bg-danger');
        }
    }

    // --- Debug Info Button Logic ---
    const debugButton = document.getElementById('show-debug-info');
    const debugInfoDiv = document.getElementById('debug-info');
    const debugContentPre = document.getElementById('debug-content');
    if (debugButton && debugInfoDiv && debugContentPre) {
        debugButton.addEventListener('click', async () => {
            if (debugInfoDiv.style.display === 'none') {
                debugInfoDiv.style.display = 'block';
                debugButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';
                debugButton.disabled = true;
                debugContentPre.textContent = 'Loading...';
                try {
                    const response = await fetch(`/ui/debug/${streamKey}`); // Use UI endpoint
                    const data = await response.json();
                    if (!response.ok) { throw new Error(data.error || `HTTP error ${response.status}`); }
                    debugContentPre.textContent = JSON.stringify(data, null, 2);
                    debugButton.innerHTML = '<i class="fas fa-minus-circle"></i> Hide Raw Stats';
                } catch (error) {
                    debugContentPre.textContent = 'Error fetching debug info: ' + error.message;
                    console.error("Debug fetch error:", error);
                    debugButton.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Error';
                } finally { debugButton.disabled = false; }
            } else {
                debugInfoDiv.style.display = 'none';
                debugButton.innerHTML = '<i class="fas fa-code"></i> Toggle Raw Stats';
            }
        });
    } else { console.warn("Debug info elements not found."); }

    // --- Initialize ---
    initChart();
    updateStats(); // Initial fetch
    const statsIntervalTime = 2000; // Update every 2 seconds
    let statsIntervalId = setInterval(updateStats, statsIntervalTime); // Store interval ID

}); // End DOMContentLoaded
