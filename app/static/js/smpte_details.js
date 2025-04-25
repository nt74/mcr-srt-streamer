// /opt/mcr-srt-streamer/app/static/js/smpte_details.js
// v2: Updated fetch logic, per-leg error handling, chart updates.

// --- Helper function to update UI text safely ---
// (Ensure this or similar is defined, perhaps in app.js or here)
function setText(id, text) {
  const elem = document.getElementById(id);
  // Use '--' as default for null/undefined in this context
  if (elem)
    elem.textContent = text !== null && text !== undefined ? text : "--";
}

// --- Helper function to update the UI for one leg ---
function updateLegStatsDisplay(legPrefix, legStats) {
  const stats = legStats || {}; // Use empty object if legStats is null/undefined
  const error = stats.error; // Check for error within this leg's stats

  // Determine display values, showing '--' or 'Error' on error
  const rttDisp =
    !error && stats.rtt_ms !== null && stats.rtt_ms !== undefined
      ? `${stats.rtt_ms.toFixed(1)} ms`
      : error
        ? `Err`
        : "--";
  // *** ADDED: Get Negotiated Latency ***
  const negLatencyDisp =
    !error &&
    stats.negotiated_latency_ms !== null &&
    stats.negotiated_latency_ms !== undefined
      ? `${stats.negotiated_latency_ms} ms`
      : error
        ? "--"
        : "--";
  const lossRaw = stats.packet_loss_percent;
  const lossDisp =
    !error && lossRaw !== null && lossRaw !== undefined
      ? `${lossRaw.toFixed(2)} %`
      : error
        ? "--"
        : "--";
  const bitrateDisp =
    !error &&
    stats.send_rate_mbps !== null &&
    stats.send_rate_mbps !== undefined
      ? `${stats.send_rate_mbps.toFixed(2)} Mbps`
      : error
        ? "--"
        : "--";
  const recvRateDisp =
    !error &&
    stats.recv_rate_mbps !== null &&
    stats.recv_rate_mbps !== undefined
      ? `${stats.recv_rate_mbps.toFixed(2)} Mbps`
      : error
        ? "--"
        : "--";
  const pktsSentDisp =
    !error && stats.packets_sent !== null && stats.packets_sent !== undefined
      ? stats.packets_sent.toLocaleString()
      : "--";
  const pktsLostDisp =
    !error &&
    stats.packets_sent_lost !== null &&
    stats.packets_sent_lost !== undefined
      ? stats.packets_sent_lost.toLocaleString()
      : "--";
  const pktsRetransDisp =
    !error &&
    stats.packets_retransmitted !== null &&
    stats.packets_retransmitted !== undefined
      ? stats.packets_retransmitted.toLocaleString()
      : "--";

  // Update table cells using their specific IDs
  setText(`${legPrefix}-rtt`, rttDisp);
  // *** ADDED: Update Negotiated Latency element ***
  setText(`${legPrefix}-negLatency`, negLatencyDisp); // Assumes id="legX-negLatency"
  setText(`${legPrefix}-pktLoss`, lossDisp);
  setText(`${legPrefix}-sendRate`, bitrateDisp);
  setText(`${legPrefix}-recvRate`, recvRateDisp);
  setText(`${legPrefix}-pktsSent`, pktsSentDisp);
  setText(`${legPrefix}-pktsLost`, pktsLostDisp);
  setText(`${legPrefix}-pktRetrans`, pktsRetransDisp);

  // Add error class if loss > 1% (remains same)
  const lossCell = document.getElementById(`${legPrefix}-pktLoss`);
  if (lossCell) {
    if (!error && lossRaw > 1) {
      lossCell.classList.add("text-danger", "fw-bold");
    } else {
      lossCell.classList.remove("text-danger", "fw-bold");
    }
  }
  // Add error class to RTT if error occurred (remains same)
  const rttCell = document.getElementById(`${legPrefix}-rtt`);
  if (rttCell) {
    if (error) {
      rttCell.classList.add("text-warning");
      rttCell.textContent = `Stats Err`;
    } else {
      rttCell.classList.remove("text-warning");
    }
  }
}

// --- Document Ready ---
$(document).ready(function () {
  // --- Configuration ---
  const MAX_CHART_POINTS = 60; // Number of data points to show on charts
  const REFRESH_INTERVAL_MS = 2500; // How often to refresh stats (e.g., 2.5 seconds)

  // --- Get Pair ID ---
  // Get from data attribute on a known element OR fallback to URL parsing
  const pairIdElement = document.getElementById("smpte-pair-info"); // Needs <div id="smpte-pair-info" data-pair-id="{{ pair_id }}"> in HTML
  let pairId = pairIdElement ? pairIdElement.dataset.pairId : null;
  if (!pairId) {
    // Fallback: Try to get from URL path
    const pathParts = window.location.pathname.split("/");
    const potentialId = pathParts[pathParts.length - 1];
    if (potentialId && !isNaN(parseInt(potentialId))) {
      pairId = potentialId;
      console.warn(
        "Could not find pair ID from data attribute, using URL path.",
      );
    }
  }

  // --- Chart Variables & Initialization ---
  let leg1RttChart, leg1LossChart, leg1RateChart;
  let leg2RttChart, leg2LossChart, leg2RateChart;
  let statsIntervalId = null; // Declare interval ID variable

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      x: { ticks: { display: false }, grid: { display: false } },
      y: {
        beginAtZero: true,
        ticks: { font: { size: 10 } },
        grid: { color: "rgba(200, 200, 200, 0.2)" },
      },
    },
    plugins: { legend: { display: false }, tooltip: { enabled: true } },
    elements: {
      point: { radius: 1, hitRadius: 5 },
      line: { tension: 0.1, borderWidth: 2 },
    },
    animation: { duration: 0 },
  };

  function createStatChart(canvasId, label, borderColor, yAxisLabel = "") {
    const ctx = document.getElementById(canvasId);
    if (!ctx) {
      console.error(`Canvas element with ID ${canvasId} not found.`);
      return null;
    }
    const scalesOptions = JSON.parse(JSON.stringify(chartOptions.scales));
    if (yAxisLabel) {
      scalesOptions.y.title = {
        display: true,
        text: yAxisLabel,
        font: { size: 10 },
      };
    }
    // Ensure y-axis for Loss % starts at 0 and suggest max like 5% or 10%
    if (yAxisLabel === "%") {
      scalesOptions.y.suggestedMax = 5;
      // scalesOptions.y.max = 100; // Uncomment if you want scale to always go to 100%
    }
    // Ensure y-axis for Mbps starts at 0
    if (yAxisLabel === "Mbps") {
      scalesOptions.y.beginAtZero = true;
    }

    return new Chart(ctx, {
      type: "line",
      data: {
        labels: [],
        datasets: [
          { label: label, data: [], borderColor: borderColor, fill: false },
        ],
      },
      options: { ...chartOptions, scales: scalesOptions },
    });
  }

  function initCharts() {
    // Leg 1 Charts
    leg1RttChart = createStatChart(
      "leg1-rtt-chart",
      "RTT",
      "rgb(255, 99, 132)",
      "ms",
    );
    leg1LossChart = createStatChart(
      "leg1-loss-chart",
      "Pkt Loss",
      "rgb(255, 159, 64)",
      "%",
    );
    leg1RateChart = createStatChart(
      "leg1-rate-chart",
      "Send Rate",
      "rgb(75, 192, 192)",
      "Mbps",
    );
    // Leg 2 Charts
    leg2RttChart = createStatChart(
      "leg2-rtt-chart",
      "RTT",
      "rgb(255, 99, 132)",
      "ms",
    );
    leg2LossChart = createStatChart(
      "leg2-loss-chart",
      "Pkt Loss",
      "rgb(255, 159, 64)",
      "%",
    );
    leg2RateChart = createStatChart(
      "leg2-rate-chart",
      "Send Rate",
      "rgb(75, 192, 192)",
      "Mbps",
    );
  }

  function updateChart(chart, newDataPoint) {
    if (!chart) return;
    const data = chart.data.datasets[0].data;
    const labels = chart.data.labels;
    // Use a simple counter for labels instead of time
    const nextLabel =
      labels.length > 0 ? parseInt(labels[labels.length - 1]) + 1 : 1;

    // Ensure null is pushed if data is missing/invalid for chart continuity
    // Use isNaN as well to catch non-numeric values if stats errored partially
    data.push(
      typeof newDataPoint === "number" && !isNaN(newDataPoint)
        ? newDataPoint
        : null,
    );
    labels.push(nextLabel.toString());

    if (data.length > MAX_CHART_POINTS) {
      data.shift();
      labels.shift();
    }
    try {
      chart.update("none");
    } catch (e) {
      // Use 'none' to disable animation
      console.error("Chart update error:", e, chart.canvas.id);
    }
  }

  // --- Main Stats Update Function ---
  async function updateStats() {
    if (!pairId) return; // Don't run if ID is missing

    const refreshIndicator = document.getElementById("refresh-indicator-smpte"); // Check ID in HTML
    if (refreshIndicator) refreshIndicator.classList.remove("d-none");

    try {
      const statsApiUrl = `/smpte2022_7/api/stats/${pairId}`;
      const response = await fetch(statsApiUrl);

      if (!response.ok) {
        let errorMsg = `API Error (${response.status})`;
        try {
          const errData = await response.json();
          if (errData && errData.error) errorMsg = errData.error;
        } catch (e) {
          /* Ignore */
        }
        console.error(
          `Failed to fetch SMPTE stats from ${statsApiUrl}: ${errorMsg}`,
        );
        updateLegStatsDisplay("leg1", { error: "API Err" });
        updateLegStatsDisplay("leg2", { error: "API Err" });
        if (response.status === 404) {
          if (statsIntervalId) clearInterval(statsIntervalId);
          setText("pair-status", "Not Found");
          $("#pair-status").removeClass().addClass("badge bg-danger"); // Assumes jQuery for class manipulation
        }
        return; // Exit on HTTP error
      }

      const data = await response.json();

      if (data.error && !data.error.toLowerCase().includes("not found")) {
        console.warn("Received top-level warning from backend:", data.error);
        // Example: $('#pair-error-warning').text(data.error).show(); // Requires element with this ID
      }

      // Update Pair Status
      const pairStatusText = data.status || data.pair_status || "Unknown";
      setText("pair-status", pairStatusText); // Assumes element with id="pair-status"
      let pairStatusClass = "bg-secondary";
      if (
        pairStatusText === "Running" ||
        pairStatusText === "Started" ||
        pairStatusText === "Connected"
      ) {
        pairStatusClass = "bg-success";
      } else if (
        pairStatusText.includes("Starting") ||
        pairStatusText.includes("Async")
      ) {
        pairStatusClass = "bg-info";
      } else if (
        pairStatusText.includes("Error") ||
        pairStatusText.includes("Failed") ||
        pairStatusText.includes("Stopped")
      ) {
        pairStatusClass = "bg-danger";
      }
      $("#pair-status").removeClass().addClass(`badge ${pairStatusClass}`); // Assumes jQuery

      // Update stats for each leg using the helper
      updateLegStatsDisplay("leg1", data.leg1_stats);
      updateLegStatsDisplay("leg2", data.leg2_stats);

      // --- Update Charts ---
      const leg1Stats = data.leg1_stats || {};
      const leg2Stats = data.leg2_stats || {};
      updateChart(leg1RttChart, !leg1Stats.error ? leg1Stats.rtt_ms : null);
      updateChart(
        leg1LossChart,
        !leg1Stats.error ? leg1Stats.packet_loss_percent : null,
      );
      updateChart(
        leg1RateChart,
        !leg1Stats.error ? leg1Stats.send_rate_mbps : null,
      );
      updateChart(leg2RttChart, !leg2Stats.error ? leg2Stats.rtt_ms : null);
      updateChart(
        leg2LossChart,
        !leg2Stats.error ? leg2Stats.packet_loss_percent : null,
      );
      updateChart(
        leg2RateChart,
        !leg2Stats.error ? leg2Stats.send_rate_mbps : null,
      );

      // Update Last Updated timestamp
      const timestamp =
        leg1Stats.timestamp || leg2Stats.timestamp || Date.now() / 1000;
      // Assumes element with id="stats-last-updated-smpte" exists in HTML
      setText(
        "stats-last-updated-smpte",
        new Date(timestamp * 1000).toLocaleTimeString(),
      );
    } catch (error) {
      console.error("Error processing SMPTE stats update:", error);
      updateLegStatsDisplay("leg1", { error: "JS Err" });
      updateLegStatsDisplay("leg2", { error: "JS Err" });
      if (statsIntervalId) clearInterval(statsIntervalId);
    } finally {
      if (refreshIndicator)
        setTimeout(() => {
          refreshIndicator.classList.add("d-none");
        }, 300);
    }
  } // End updateStats

  // --- Initializations Call ---
  if (!pairId || isNaN(parseInt(pairId))) {
    console.error("Invalid or missing Pair ID.");
    $(".container").prepend(
      '<div class="alert alert-danger">Invalid Pair ID found. Cannot load details.</div>',
    );
  } else {
    console.log(`Initializing details page for SMPTE Pair ID: ${pairId}`);
    initCharts(); // Call chart initialization
    updateStats(); // Initial fetch
    statsIntervalId = setInterval(updateStats, REFRESH_INTERVAL_MS); // Start interval
  }

  // --- Stop Button Logic ---
  $("#stop-pair-button").on("click", function (e) {
    // Make sure button has id="stop-pair-button"
    e.preventDefault();
    // Use the currentPairId established earlier
    if (confirm(`Are you sure you want to stop SMPTE Pair ${pairId}?`)) {
      $("#stop-pair-form").submit(); // Assumes a form with id="stop-pair-form" exists
    }
  });

  // --- Debug Toggle Logic (Optional - Add if needed) ---
  const debugButton = document.getElementById("show-smpte-debug-info"); // Needs this button ID in HTML
  const debugInfoDiv = document.getElementById("smpte-debug-info"); // Needs this div ID in HTML
  const debugContentPre = document.getElementById("smpte-debug-content"); // Needs this pre ID in HTML

  if (debugButton && debugInfoDiv && debugContentPre) {
    debugButton.addEventListener("click", async () => {
      if (debugInfoDiv.style.display === "none") {
        debugInfoDiv.style.display = "block";
        debugButton.innerHTML =
          '<i class="fas fa-spinner fa-spin"></i> Loading...';
        debugButton.disabled = true;
        debugContentPre.textContent = "Loading...";
        try {
          // Fetch from the correct SMPTE debug endpoint
          const response = await fetch(`/smpte2022_7/api/debug/${pairId}`);
          const data = await response.json();
          if (!response.ok) {
            throw new Error(data.error || `HTTP error ${response.status}`);
          }
          debugContentPre.textContent = JSON.stringify(data, null, 2); // Pretty print JSON
          debugButton.innerHTML =
            '<i class="fas fa-minus-circle"></i> Hide Raw Debug';
        } catch (error) {
          debugContentPre.textContent =
            "Error fetching debug info: " + error.message;
          debugButton.innerHTML =
            '<i class="fas fa-exclamation-triangle"></i> Error';
          console.error("SMPTE Debug fetch error:", error);
        } finally {
          debugButton.disabled = false;
        }
      } else {
        debugInfoDiv.style.display = "none";
        debugButton.innerHTML = '<i class="fas fa-code"></i> Show Raw Debug';
      }
    });
  } else {
    console.warn("SMPTE Debug info elements not found.");
  }
}); // End document.ready
