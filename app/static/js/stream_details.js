// /opt/mcr-srt-streamer/app/static/js/stream_details.js
// v3: Added JS-based Start Time (UTC) formatting and Uptime calculation.

// --- NEW HELPER FUNCTION for formatting seconds to D H:M:S ---
function formatDuration(totalSeconds) {
  if (isNaN(totalSeconds) || totalSeconds < 0) {
    return "0s";
  }

  totalSeconds = Math.floor(totalSeconds); // Work with whole seconds

  const days = Math.floor(totalSeconds / (3600 * 24));
  const hours = Math.floor((totalSeconds % (3600 * 24)) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  let parts = [];
  if (days > 0) {
    parts.push(`${days}d`);
  }
  if (hours > 0 || days > 0) {
    // Show hours if days are shown or if hours > 0
    parts.push(`${String(hours).padStart(2, "0")}h`);
  }
  if (minutes > 0 || hours > 0 || days > 0) {
    // Show minutes if hours/days are shown or minutes > 0
    parts.push(`${String(minutes).padStart(2, "0")}m`);
  }
  // Always show seconds unless it's exactly 0 and other parts exist
  if (seconds > 0 || parts.length === 0) {
    parts.push(`${String(seconds).padStart(2, "0")}s`);
  }

  return parts.join(" ") || "0s";
}
// --- END NEW HELPER FUNCTION ---

document.addEventListener("DOMContentLoaded", function () {
  const streamInfoDiv = document.getElementById("stream-info");
  const streamKey = streamInfoDiv ? streamInfoDiv.dataset.streamKey : null;
  const refreshIndicator = document.getElementById("refresh-indicator-details"); // Get refresh indicator for details

  if (!streamKey) {
    console.error("Stream key not found in data-stream-key attribute.");
    const body = document.querySelector(".container");
    if (body) {
      const errorDiv = document.createElement("div");
      errorDiv.className = "alert alert-danger";
      errorDiv.textContent =
        "Error: Could not identify stream key for fetching details.";
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
      {
        label: "Bitrate (Mbps)",
        data: [],
        yAxisID: "yBitrate",
        borderColor: "rgba(40, 167, 69, 1)",
        backgroundColor: "rgba(40, 167, 69, 0.1)",
        borderWidth: 1.5,
        tension: 0.1,
        pointRadius: 1,
        fill: true,
      },
      {
        label: "RTT (ms)",
        data: [],
        yAxisID: "yRtt",
        borderColor: "rgba(23, 162, 184, 1)",
        backgroundColor: "rgba(23, 162, 184, 0.1)",
        borderWidth: 1.5,
        tension: 0.1,
        pointRadius: 1,
        fill: false,
      },
      {
        label: "Loss (%)",
        data: [],
        yAxisID: "yLoss",
        borderColor: "rgba(220, 53, 69, 1)",
        backgroundColor: "rgba(220, 53, 69, 0.1)",
        borderWidth: 1.5,
        tension: 0.1,
        pointRadius: 1,
        fill: false,
      },
    ],
  };

  // --- Helper Functions ---
  function setText(id, text) {
    const elem = document.getElementById(id);
    if (elem) elem.textContent = text ?? "N/A"; // Use nullish coalescing for default
  }
  function setWidth(id, percentage) {
    const elem = document.getElementById(id);
    if (elem)
      elem.style.width = `${Math.max(0, Math.min(100, percentage || 0))}%`; // Handle null/undefined percentage
  }
  // formatBytes definition (remains the same)
  if (typeof formatBytes !== "function") {
    console.warn(
      "formatBytes function not found, defining basic fallback for bytes display.",
    );
    window.formatBytes = function (bytes, decimals = 2) {
      if (bytes === 0 || !bytes || isNaN(bytes)) return "0 B";
      const k = 1024;
      const dm = decimals < 0 ? 0 : decimals;
      const sizes = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
      const i = Math.min(
        Math.floor(Math.log(bytes) / Math.log(k)),
        sizes.length - 1,
      );
      if (i < 0 || isNaN(i)) return "0 B";
      return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
    };
  }

  // --- Chart Initialization ---
  // ... (initChart function remains the same) ...
  function initChart() {
    const ctx = document.getElementById("stats-chart")?.getContext("2d");
    if (!ctx) {
      console.error("Chart canvas not found.");
      return;
    }
    try {
      statsChart = new Chart(ctx, {
        type: "line",
        data: chartData,
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { mode: "index", intersect: false },
          scales: {
            x: { ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 10 } },
            yBitrate: {
              type: "linear",
              display: true,
              position: "left",
              title: { display: true, text: "Bitrate (Mbps)" },
              beginAtZero: true,
              grid: { drawOnChartArea: true },
            },
            yRtt: {
              type: "linear",
              display: true,
              position: "right",
              title: { display: true, text: "RTT (ms)" },
              beginAtZero: true,
              grid: { drawOnChartArea: false },
            },
            yLoss: {
              type: "linear",
              display: true,
              position: "right",
              title: { display: true, text: "Loss (%)" },
              beginAtZero: true,
              suggestedMax: 5,
              grid: { drawOnChartArea: false },
            },
          },
          animation: false,
          plugins: { legend: { display: true, position: "top" } },
        },
      });
    } catch (e) {
      console.error("Failed to initialize Chart.js:", e);
      if (ctx) {
        ctx.font = "16px Arial";
        ctx.fillStyle = "red";
        ctx.textAlign = "center";
        ctx.fillText("Error loading chart.", ctx.canvas.width / 2, 50);
      }
    }
  }

  async function updateStats() {
    if (!streamKey) return;
    if (refreshIndicator) refreshIndicator.classList.remove("d-none");

    try {
      // Fetching from debug endpoint
      const response = await fetch(`/ui/debug/${streamKey}`);

      if (!response.ok) {
        let errorMsg = `Error fetching debug info (${response.status})`;
        try {
          const errData = await response.json();
          if (errData && errData.error) errorMsg = errData.error;
        } catch (e) {}
        console.error("Debug info fetch failed:", errorMsg);
        setText("status", `Error (${response.status})`);
        $("#status").removeClass().addClass("badge bg-danger");
        if (response.status === 404) {
          clearInterval(statsIntervalId);
          console.log("Stopping polling: Stream not found (404).");
        }
        return;
      }

      const data = await response.json(); // data is the full debug_info object

      if (!data || (data.error && response.status !== 404)) {
        console.error("Error in debug data:", data?.error);
        setText("status", data?.error || "Data Error");
        $("#status").removeClass().addClass("badge bg-danger");
        if (data?.error && !data.error.toLowerCase().includes("not found")) {
          clearInterval(statsIntervalId);
          console.log("Stopping polling due to backend error:", data.error);
        }
        return;
      }

      // --- Update UI Elements ---

      // Status update
      const statusText = data.status || "Unknown";
      const statusElem = document.getElementById("status");
      if (statusElem) {
        statusElem.textContent = statusText;
        let sClass = "bg-secondary";
        if (statusText === "Connected") sClass = "bg-success";
        else if (
          [
            "Waiting for connection",
            "Connecting...",
            "Timeout / Reconnecting",
            "Broken / Reconnecting",
            "Running",
            "Ready",
            "Paused",
          ].includes(statusText)
        )
          sClass = "bg-info";
        else if (
          [
            "Connection Failed",
            "Disconnected",
            "Rejected",
            "Error",
            "Bind Error",
            "Start Error",
            "Auth Error",
            "Stopped",
            "Ended (EOS)",
          ].includes(statusText) ||
          statusText?.startsWith("Error")
        )
          sClass = "bg-danger";
        statusElem.className = `badge ${sClass}`;
        if (
          sClass === "bg-danger" ||
          sClass === "bg-secondary" ||
          statusText?.includes("Stopped") ||
          statusText?.includes("Ended")
        ) {
          clearInterval(statsIntervalId);
          console.log(
            "Stopping stats polling due to stream state:",
            statusText,
          );
        }
      }

      // *** START: Update Start Time and Uptime using JS ***
      const startTimeEpoch = data.start_time;
      if (startTimeEpoch && !isNaN(startTimeEpoch)) {
        // Format Start Time to UTC
        const startDate = new Date(startTimeEpoch * 1000); // JS Date needs milliseconds
        // Pad month, day, hours, minutes, seconds
        const year = startDate.getUTCFullYear();
        const month = String(startDate.getUTCMonth() + 1).padStart(2, "0"); // Month is 0-indexed
        const day = String(startDate.getUTCDate()).padStart(2, "0");
        const hours = String(startDate.getUTCHours()).padStart(2, "0");
        const minutes = String(startDate.getUTCMinutes()).padStart(2, "0");
        const seconds = String(startDate.getUTCSeconds()).padStart(2, "0");
        const startedUTCString = `${year}-${month}-${day} ${hours}:${minutes}:${seconds} UTC`;
        // Assumes your HTML has <span id="start-time-display">...</span>
        setText("start-time-display", startedUTCString);

        // Calculate and Format Uptime
        const nowSeconds = Date.now() / 1000;
        const durationSeconds = nowSeconds - startTimeEpoch;
        const uptimeString = formatDuration(durationSeconds); // Use the helper function
        setText("uptime", uptimeString); // Update the #uptime span
      } else {
        // Handle cases where start time is missing from backend data
        setText("start-time-display", "N/A");
        setText("uptime", "N/A");
      }
      // *** END: Update Start Time / Uptime Update ***

      setText("client-ip", data.connected_client || "None Connected");
      // Remove the old uptime update line if it existed: setText('uptime', data.uptime || '0s');
      setText(
        "stats-last-updated",
        data.timestamp_api
          ? new Date(data.timestamp_api * 1000).toLocaleTimeString()
          : data.stats?.timestamp
            ? new Date(data.stats.timestamp * 1000).toLocaleTimeString()
            : "-",
      );

      // Access nested stats object
      const stats = data.stats || {};
      setText("negotiated-latency", stats.negotiated_latency_ms ?? "N/A");

      // Update Stat Cards, Counters, Chart using stats.* (remains the same)
      const bitrate =
        stats.send_rate_mbps !== undefined
          ? parseFloat(stats.send_rate_mbps)
          : 0.0;
      const rtt = stats.rtt_ms !== undefined ? parseFloat(stats.rtt_ms) : 0.0;
      const lossPercent =
        stats.packet_loss_percent !== undefined
          ? parseFloat(stats.packet_loss_percent)
          : 0.0;

      setText("bitrate-value", bitrate.toFixed(2));
      setWidth("bitrate-bar", Math.min(100, (bitrate / 50) * 100));
      setText("rtt-value", rtt.toFixed(0));
      setWidth("rtt-bar", Math.min(100, (rtt / 500) * 100));
      setText("loss-value", lossPercent.toFixed(2));
      setWidth("loss-bar", Math.min(100, (lossPercent / 5) * 100));

      const packetsSent = stats.packets_sent || 0;
      const packetsReceived = stats.packets_received || 0;
      const packetsLost = stats.packets_sent_lost || 0;
      const packetsRetransmitted = stats.packets_retransmitted || 0;
      const bytesSent = stats.bytes_sent || 0;

      setText(
        "loss-detail",
        `${packetsLost.toLocaleString()} / ${packetsSent.toLocaleString()}`,
      );
      setText("packets-sent", packetsSent.toLocaleString());
      setText("packets-received", packetsReceived.toLocaleString());
      setText("packets-lost", packetsLost.toLocaleString());
      setText("packets-retransmitted", packetsRetransmitted.toLocaleString());
      setText("bytes-sent", formatBytes(bytesSent));

      if (statsChart) {
        const nowLabel = new Date().toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        });
        if (chartData.labels.length >= maxChartPoints) {
          chartData.labels.shift();
          chartData.datasets.forEach((ds) => ds.data.shift());
        }
        chartData.labels.push(nowLabel);
        chartData.datasets[0].data.push(bitrate);
        chartData.datasets[1].data.push(rtt);
        chartData.datasets[2].data.push(lossPercent);
        try {
          statsChart.update("none");
        } catch (chartError) {
          console.error("Error updating chart:", chartError);
        }
      }
    } catch (error) {
      console.error("Error processing stats update:", error);
      setText("status", "Fetch/Parse Error");
      $("#status").removeClass().addClass("badge bg-danger");
      clearInterval(statsIntervalId); // Stop polling on major error
    } finally {
      if (refreshIndicator)
        setTimeout(function () {
          refreshIndicator.classList.add("d-none");
        }, 300);
    }
  }

  // --- Debug Info Button Logic ---
  // ... (debug button logic remains the same) ...
  const debugButton = document.getElementById("show-debug-info");
  const debugInfoDiv = document.getElementById("debug-info");
  const debugContentPre = document.getElementById("debug-content");
  if (debugButton && debugInfoDiv && debugContentPre) {
    debugButton.addEventListener("click", async () => {
      if (debugInfoDiv.style.display === "none") {
        debugInfoDiv.style.display = "block";
        debugButton.innerHTML =
          '<i class="fas fa-spinner fa-spin"></i> Loading...';
        debugButton.disabled = true;
        debugContentPre.textContent = "Loading...";
        try {
          const response = await fetch(`/ui/debug/${streamKey}`);
          const data = await response.json();
          if (!response.ok) {
            throw new Error(data.error || `HTTP error ${response.status}`);
          }
          debugContentPre.textContent = JSON.stringify(data, null, 2);
          debugButton.innerHTML =
            '<i class="fas fa-minus-circle"></i> Hide Raw Stats';
        } catch (error) {
          debugContentPre.textContent =
            "Error fetching or parsing debug info: " + error.message;
          console.error("Debug fetch/parse error:", error);
          debugButton.innerHTML =
            '<i class="fas fa-exclamation-triangle"></i> Error';
        } finally {
          debugButton.disabled = false;
        }
      } else {
        debugInfoDiv.style.display = "none";
        debugButton.innerHTML = '<i class="fas fa-code"></i> Toggle Raw Stats';
      }
    });
  } else {
    console.warn("Debug info elements not found.");
  }

  // --- Initialize ---
  initChart();
  updateStats(); // Initial fetch
  const statsIntervalTime = 2000; // Update every 2 seconds
  // Make sure intervalId is declared correctly if it wasn't before
  let statsIntervalId = setInterval(updateStats, statsIntervalTime);
}); // End DOMContentLoaded
