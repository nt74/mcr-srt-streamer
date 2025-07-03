// /opt/mcr-srt-streamer/app/static/js/dashboard.js

$(document).ready(function () {
  // --- Store active listener ports for overwrite confirmation ---
  let activeListenerPorts = new Set();

  // System Info Update Logic
  function updateSystemInfo() {
    $.getJSON("/api/system/status", function (d) {
      if (!d) return;
      const n = new Date(),
        t = n.toTimeString().split(" ")[0];
      $("#sys-refresh-time").text("Upd: " + t);
      $("#cpu-value").text((d.cpu_usage || 0).toFixed(1) + "%");
      $("#cpu-bar")
        .css("width", (d.cpu_usage || 0) + "%")
        .attr("aria-valuenow", d.cpu_usage || 0);
      $("#memory-value").text((d.memory_percent || 0).toFixed(1) + "%");
      $("#memory-bar")
        .css("width", (d.memory_percent || 0) + "%")
        .attr("aria-valuenow", d.memory_percent || 0);
      $("#memory-details").text(
        (d.memory_used || "N/A") + " / " + (d.memory_total || "N/A"),
      );
      $("#disk-value").text((d.disk_percent || 0).toFixed(1) + "%");
      $("#disk-bar")
        .css("width", (d.disk_percent || 0) + "%")
        .attr("aria-valuenow", d.disk_percent || 0);
      $("#disk-details").text(
        (d.disk_used || "N/A") + " / " + (d.disk_total || "N/A") + " (Root)",
      );
      $("#external-ip").text(d.external_ip || "?");
      $("#utc-time").text(d.utc_time || "N/A");
      $("#current-user").text(d.current_user || "?");
      // Note: System uptime is displayed here, stream uptime is on card/details
      $("#uptime").text(d.uptime || "N/A");
    }).fail(function (jqXHR) {
      console.error(
        "Failed to fetch system info:",
        jqXHR.status,
        jqXHR.responseText,
      );
      $("#sys-refresh-time").text("Update Failed");
    });
  }

  // Active Streams Update Logic
  function updateActiveStreams() {
    $("#refresh-indicator").removeClass("d-none");
    // Use the unprotected UI endpoint (assumes it now serves combined data with stats)
    $.getJSON("/ui/active_streams_data", function (response) {
      const streams = response.data || {};
      const container = $("#active-streams-container");
      // --- Reset active listener ports set before rebuilding cards ---
      const newListenerPorts = new Set();

      container.empty(); // Clear previous cards

      if (!streams || Object.keys(streams).length === 0) {
        if (response.error) {
          // Display error from backend if present
          container.html(
            `<div class="col-12"><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> Error loading stream list: ${escapeHtml(response.error)} Please check server logs.</div></div>`,
          );
        } else {
          container.html(
            '<div class="col-12"><div class="alert alert-secondary"><i class="fas fa-info-circle"></i> No active streams or pairs detected.</div></div>',
          );
        }
        return;
      }

      // Sort keys maybe based on type then original key? Example: standard_10001, smpte_10201
      const sortedKeys = Object.keys(streams).sort();
      const csrfTokenValue = $("input[name=csrf_token]").val() || ""; // Get CSRF token

      for (const key of sortedKeys) {
        // key might be "standard_10001" or "smpte_10201"
        const stream = streams[key];
        if (!stream) continue;

        // Check for stream_type
        if (stream.stream_type === "smpte_pair") {
          // --- Render SMPTE Pair Card ---
          const pair_id = stream.pair_id;
          const leg1 = stream.leg1 || {};
          const leg2 = stream.leg2 || {};
          let pairHeaderClass = "bg-secondary text-white"; // Default Grey Header
          let pairStatusClass = "bg-secondary"; // Default Grey Badge
          let pairStatusIcon = "fa-hourglass-start"; // Default Icon
          let pairStatusText = stream.status || "?";

          // *** CORRECTED SMPTE Status Logic (Grey until Running/Connected) ***
          if (
            pairStatusText === "Running" ||
            pairStatusText === "Connected" ||
            pairStatusText === "Started"
          ) {
            // Use green only when actively running/connected/started
            pairStatusClass = "bg-success";
            pairStatusIcon = "fa-check-circle";
            // Keep header distinct for caller vs listener based on *any* leg being caller
            const isCaller = leg1.mode === "caller" || leg2.mode === "caller";
            pairHeaderClass = isCaller
              ? "bg-warning text-dark"
              : "bg-success text-white";
          } else if (
            pairStatusText.includes("Starting") ||
            pairStatusText.includes("Async")
          ) {
            // Use info blue for starting states
            pairHeaderClass = "bg-info text-dark";
            pairStatusClass = "bg-info";
            pairStatusIcon = "fa-spinner fa-spin";
          } else if (
            pairStatusText === "Ready" ||
            pairStatusText === "Paused"
          ) {
            // Keep grey/secondary for Ready/Paused
            pairHeaderClass = "bg-secondary text-white";
            pairStatusClass = "bg-secondary";
            pairStatusIcon = "fa-pause-circle"; // Specific icon for these states
          } else if (
            // Error or stopped states
            pairStatusText.includes("Error") ||
            pairStatusText.includes("Failed") ||
            pairStatusText.includes("Stopped") ||
            pairStatusText.includes("Ended")
          ) {
            pairHeaderClass = "bg-danger text-white";
            pairStatusClass = "bg-danger";
            pairStatusIcon = "fa-exclamation-triangle";
          }
          // *** END CORRECTED SMPTE Status Logic ***

          const encDisp = (stream.encryption || "none")
            .toUpperCase()
            .replace("_", "-");
          const passDisp =
            stream.encryption === "none"
              ? '<span class="text-muted fst-italic">N/A</span>'
              : '<span class="badge bg-success">Set</span>'; // Assuming pass check isn't available here
          const qosDisp = stream.qos
            ? '<span class="badge bg-success">Enabled</span>'
            : '<span class="badge bg-secondary">Disabled</span>';
          const ssrc_display = stream.ssrc
            ? `<code>${escapeHtml(stream.ssrc)}</code>`
            : "N/A";
          const input_display = stream.input_detail
            ? ` (Input: ${escapeHtml(stream.input_detail)})`
            : "";
          const detailsLink = `<a href="/smpte2022_7/${pair_id}" class="btn btn-info btn-sm me-2" title="View Detailed Statistics for Pair ${pair_id}"><i class="fas fa-chart-line"></i> Details</a>`;
          const debugLink = `<a href="/smpte2022_7/api/debug/${pair_id}" class="btn btn-secondary btn-sm" target="_blank" title="View Raw Debug Info for Pair ${pair_id} (JSON)"><i class="fas fa-bug"></i> Debug</a>`;

          // Ensure template literal uses backticks and variables are escaped if needed
          const card = `
                        <div class="col-lg-6 mb-4">
                            <div class="card stream-card h-100 border-info">
                                <div class="card-header ${pairHeaderClass}">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <span class="fw-bold text-break"><i class="fas fa-project-diagram me-2"></i>SMPTE Pair: ${escapeHtml(String(pair_id))}${input_display}</span>
                                        <form method="POST" action="/smpte2022_7/stop/${pair_id}" onsubmit="return confirm('Stop SMPTE Pair ${pair_id}?');" style="display:inline;">
                                            <input type="hidden" name="csrf_token" value="${csrfTokenValue}">
                                            <button type="submit" class="btn btn-sm btn-danger" title="Stop SMPTE Pair ${pair_id}"><i class="fas fa-stop-circle"></i></button>
                                        </form>
                                    </div>
                                </div>
                                <div class="card-body d-flex flex-column">
                                    <table class="table table-sm table-borderless small mb-2">
                                        <tbody>
                                            <tr><td width="110"><i class="fas fa-wifi fa-fw text-muted"></i> Status</td><td><span class="badge ${pairStatusClass}"><i class="fas ${pairStatusIcon} me-1"></i>${escapeHtml(pairStatusText)}</span></td></tr>
                                            <tr><td><i class="fas fa-hourglass-start fa-fw text-muted"></i> Started</td><td>${escapeHtml(stream.start_time_str || "?")}</td></tr>
                                            <tr><td><i class="fas fa-fingerprint fa-fw text-muted"></i> SSRC</td><td>${ssrc_display}</td></tr>
                                            <tr><td><i class="fas fa-history fa-fw text-muted"></i> Latency</td><td>${escapeHtml(String(stream.latency || "?"))} ms</td></tr>
                                            <tr><td><i class="fas fa-network-wired fa-fw text-muted"></i> Overhead</td><td>${escapeHtml(String(stream.overhead || "?"))}%</td></tr>
                                            <tr><td><i class="fas fa-lock fa-fw text-muted"></i> Encryption</td><td>${encDisp} (${passDisp})</td></tr>
                                            <tr><td><i class="fas fa-check-circle fa-fw text-muted"></i> QoS</td><td>${qosDisp}</td></tr>
                                        </tbody>
                                    </table>
                                    <hr class="my-2">
                                    <div class="row">
                                        <div class="col-md-6 mb-2 mb-md-0">
                                            <strong>Leg 1 (${escapeHtml(leg1.mode || "?")})</strong>
                                            <ul class="list-unstyled small mb-0 ms-2">
                                                <li><i class="fas fa-ethernet fa-fw text-muted"></i> NIC: ${escapeHtml(leg1.interface || "Auto")}</li>
                                                <li><i class="fas fa-network-wired fa-fw text-muted"></i> Port: ${escapeHtml(String(leg1.port || "?"))}</li>
                                                ${leg1.mode === "caller" ? `<li><i class="fas fa-map-marker-alt fa-fw text-muted"></i> Target: ${escapeHtml(leg1.target || "?")}</li>` : ""}
                                            </ul>
                                        </div>
                                        <div class="col-md-6">
                                            <strong>Leg 2 (${escapeHtml(leg2.mode || "?")})</strong>
                                             <ul class="list-unstyled small mb-0 ms-2">
                                                <li><i class="fas fa-ethernet fa-fw text-muted"></i> NIC: ${escapeHtml(leg2.interface || "Auto")}</li>
                                                <li><i class="fas fa-network-wired fa-fw text-muted"></i> Port: ${escapeHtml(String(leg2.port || "?"))}</li>
                                                ${leg2.mode === "caller" ? `<li><i class="fas fa-map-marker-alt fa-fw text-muted"></i> Target: ${escapeHtml(leg2.target || "?")}</li>` : ""}
                                            </ul>
                                        </div>
                                    </div>
                                    <div class="mt-auto pt-2 border-top d-flex">
                                        ${detailsLink} ${debugLink}
                                    </div>
                                </div>
                            </div>
                        </div>`;
          container.append(card);
        } else if (stream.stream_type === "standard") {
          // --- Render Standard Stream Card ---
          const stream_key = stream.key;

          // Determine status color/icon
          let headerClass = "bg-secondary text-white"; // Default Grey Header
          let statusClass = "bg-secondary"; // Default Grey Badge
          let statusIcon = "fa-question-circle"; // Default Icon (changed from hourglass)
          let statusText = stream.connection_status || "?"; // Default Status Text

          // *** CORRECTED STATUS LOGIC for Standard Streams (Grey until Running/Connected) ***
          if (
            stream.connection_status === "Connected" ||
            stream.connection_status === "Running"
          ) {
            // Use green only when actively running/connected
            statusClass = "bg-success";
            statusIcon = "fa-check-circle";
            // Keep header distinct for caller vs listener
            headerClass =
              stream.mode === "caller"
                ? "bg-warning text-dark"
                : "bg-success text-white";
          } else if (
            // States indicating activity or waiting but not fully connected/running yet
            [
              "Connecting...",
              "Waiting for connection",
              "Timeout / Reconnecting",
              "Broken / Reconnecting",
            ].includes(stream.connection_status)
          ) {
            // Use info blue for these transitional/waiting states
            headerClass = "bg-info text-dark";
            statusClass = "bg-info";
            statusIcon = "fa-spinner fa-spin"; // Use spinner only for connecting/waiting states
          } else if (["Ready", "Paused"].includes(stream.connection_status)) {
            // Use grey for Ready/Paused
            headerClass = "bg-secondary text-white";
            statusClass = "bg-secondary";
            statusIcon = "fa-pause-circle"; // Specific icon for these states
          } else if (
            // Error or stopped states
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
            ].includes(stream.connection_status) ||
            stream.connection_status?.startsWith("Error")
          ) {
            headerClass = "bg-danger text-white";
            statusClass = "bg-danger";
            statusIcon = "fa-exclamation-triangle";
            // Truncate long error messages for display
            if (statusText.startsWith("Error:") && statusText.length > 40) {
              statusText = statusText.substring(0, 37) + "...";
            }
          }
          // *** END CORRECTED STATUS LOGIC ***

          // Format other display values
          const encDisp = (stream.encryption || "none")
            .toUpperCase()
            .replace("_", "-");
          const passDisp =
            stream.encryption === "none"
              ? '<span class="text-muted fst-italic">N/A</span>'
              : stream.passphrase_set
                ? '<span class="badge bg-success">Set</span>'
                : '<span class="badge bg-danger">Missing</span>';
          const rtpDisp =
            stream.config && stream.config.rtp_encapsulation
              ? '<span class="badge bg-primary ms-1" title="RTP Encapsulation Enabled">RTP</span>'
              : "";
          const title =
            stream.mode === "caller"
              ? `<i class="fas fa-paper-plane"></i> Caller to ${escapeHtml(stream.target || "?")}`
              : `<i class="fas fa-satellite-dish"></i> Listener:${escapeHtml(String(stream.key))}`;
          const clientLabel = stream.mode === "caller" ? "Target" : "Client IP";
          const clientVal =
            stream.mode === "caller"
              ? escapeHtml(stream.target || "N/A")
              : escapeHtml(stream.client_ip || "None Connected");
          let inputTypeDisp = (stream.input_type || "?")
            .replace("_", " ")
            .replace(/\b\w/g, (l) => l.toUpperCase());
          let srcDisp = escapeHtml(stream.source_detail || "N/A");

          // Stats display logic (depends on backend providing stream.stats)
          const stats = stream.stats || {};
          const statsAvailable =
            (stream.connection_status === "Connected" ||
              stream.connection_status === "Running") &&
            stats &&
            !stats.error;
          const bitrateDisp =
            statsAvailable &&
            stats.send_rate_mbps !== null &&
            stats.send_rate_mbps !== undefined
              ? `${parseFloat(stats.send_rate_mbps).toFixed(2)} Mbps`
              : statsAvailable
                ? "..."
                : "N/A";
          const rttDisp =
            statsAvailable &&
            stats.rtt_ms !== null &&
            stats.rtt_ms !== undefined
              ? `${parseFloat(stats.rtt_ms).toFixed(0)} ms`
              : statsAvailable
                ? "..."
                : "N/A";
          const lossRaw = statsAvailable ? stats.packet_loss_percent : null;
          const lossDisp =
            statsAvailable && lossRaw !== null && lossRaw !== undefined
              ? `${parseFloat(lossRaw).toFixed(2)} %`
              : statsAvailable
                ? "..."
                : "N/A";
          const lossClass =
            statsAvailable &&
            lossRaw !== null &&
            lossRaw !== undefined &&
            parseFloat(lossRaw) > 1
              ? "text-danger fw-bold"
              : "";

          // Card HTML Generation
          const card = `
                <div class="col-lg-6 mb-4"> <div class="card stream-card h-100">
                    <div class="card-header ${headerClass}"> <div class="d-flex justify-content-between align-items-center"> <span class="fw-bold text-break">${title}</span> <form method="POST" action="/stop_stream/${stream_key}" onsubmit="return confirm('Stop stream ${stream_key}?');" style="display:inline;"> <input type="hidden" name="csrf_token" value="${csrfTokenValue}"> <button type="submit" class="btn btn-sm btn-danger" title="Stop Stream ${stream_key}"><i class="fas fa-stop-circle"></i></button> </form> </div> </div>
                    <div class="card-body d-flex flex-column">
                        <table class="table table-sm table-borderless small mb-2"> <tbody>
                            <tr><td width="110"><i class="fas fa-sign-in-alt fa-fw text-muted"></i> <strong>Input</strong></td><td class="text-break"><b>${escapeHtml(inputTypeDisp)}:</b> ${srcDisp} ${rtpDisp}</td></tr>
                            <tr><td><i class="fas fa-map-marker-alt fa-fw text-muted"></i> <strong>${escapeHtml(clientLabel)}</strong></td><td>${clientVal}</td></tr>
                            <tr><td><i class="fas fa-wifi fa-fw text-muted"></i> <strong>Status</strong></td><td><span class="badge ${statusClass}" title="${escapeHtml(stream.connection_status || "?")}"><i class="fas ${statusIcon} me-1"></i>${escapeHtml(statusText)}</span></td></tr>
                            <tr><td><i class="fas fa-hourglass-half fa-fw text-muted"></i> <strong>Uptime</strong></td><td>${escapeHtml(stream.uptime || "?")}</td></tr>
                            <tr><td><i class="fas fa-tachometer-alt fa-fw text-muted"></i> <strong>Bitrate</strong></td><td>${bitrateDisp}</td></tr>
                            <tr><td><i class="fas fa-exchange-alt fa-fw text-muted"></i> <strong>RTT</strong></td><td>${rttDisp}</td></tr>
                            <tr><td><i class="fas fa-exclamation-triangle fa-fw text-muted"></i> <strong>Loss</strong></td><td class="${lossClass}">${lossDisp}</td></tr>
                            <tr><td><i class="fas fa-history fa-fw text-muted"></i> <strong>Latency</strong></td><td>${escapeHtml(String(stream.latency || "?"))} ms</td></tr>
                            <tr><td><i class="fas fa-network-wired fa-fw text-muted"></i> <strong>Overhead</strong></td><td>${escapeHtml(String(stream.overhead_bandwidth || "?"))}%</td></tr>
                            <tr><td><i class="fas fa-lock fa-fw text-muted"></i> <strong>Encryption</strong></td><td>${encDisp} (${passDisp})</td></tr>
                        </tbody> </table>
                        <div class="mt-auto pt-2 border-top d-flex">
                            <a href="/stream/${stream_key}" class="btn btn-info btn-sm me-2" title="View Detailed Statistics"><i class="fas fa-chart-line"></i> Details</a>
                            <a href="/ui/debug/${stream_key}" class="btn btn-secondary btn-sm" target="_blank" title="View Raw Debug Info (JSON)"><i class="fas fa-bug"></i> Debug</a>
                        </div>
                    </div>
                </div>
              </div>`;
          // Add listener port to the set for overwrite check
          if (stream.mode === 'listener') {
              newListenerPorts.add(String(stream.key));
          }
          container.append(card);
        } else {
          console.warn("Unknown stream type found in data:", stream.stream_type, stream);
          container.append(`<div class="col-12"><div class="alert alert-warning">Received unknown stream type: ${escapeHtml(stream.stream_type || "Undefined")}</div></div>`);
        }
      }
      // --- Update the global set of active listener ports ---
      activeListenerPorts = newListenerPorts;
    })
      .fail(function (jqXHR, textStatus, errorThrown) {
        console.error(
          "Failed to fetch active streams from /ui/active_streams_data:",
          textStatus,
          errorThrown,
          jqXHR.status,
          jqXHR.responseText,
        );
        const container = $("#active-streams-container");
        let errorMsg = "Error loading stream list.";
        if (jqXHR.status === 503) {
          errorMsg = "Stream manager service unavailable.";
        } else if (jqXHR.responseJSON && jqXHR.responseJSON.error) {
          errorMsg = jqXHR.responseJSON.error;
        } else if (textStatus === "timeout") {
          errorMsg = "Request timed out.";
        }
        container.html(
          `<div class="col-12"><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> ${escapeHtml(errorMsg)} Please check server logs.</div></div>`,
        );
      })
      .always(function () {
        setTimeout(function () {
          $("#refresh-indicator").addClass("d-none");
        }, 300);
      });

    // Update system info too
    updateSystemInfo();
  } // End updateActiveStreams function

  // --- New Feature: Confirmation for Overwriting Listener Stream ---
  // Handle submission of the listener form
  $("#stream-form").submit(function (e) {
    const selectedPort = $("#port").val(); // Get value from listener port dropdown
    // Check if the selected port is in our set of active listener ports
    if (activeListenerPorts.has(selectedPort)) {
      if (
        !confirm(
          `A stream is already active on port ${selectedPort}. Do you want to stop the existing stream and start a new one?`
        )
      ) {
        e.preventDefault(); // Stop the form submission if user clicks 'Cancel'
      }
    }
    // If port is not in use, or if user confirms, the form will submit normally.
  }); // End of stream-form submit handler

  // Helper function for escaping HTML (basic version)
  function escapeHtml(unsafe) {
    if (typeof unsafe !== "string") {
      if (unsafe === null || unsafe === undefined) {
        return "";
      }
      try {
        unsafe = String(unsafe);
      } catch (e) {
        return "";
      }
    }
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Apply network test results from URL parameters
  function applyNetworkTestResults() {
    const p = new URLSearchParams(window.location.search);
    if (p.has("apply_network_test")) {
      const l = p.get("latency"),
        o = p.get("overhead");
      if (l && $("#latency").length) $("#latency").val(l);
      if (o && $("#overhead_bandwidth").length) {
        const v = parseInt(o);
        if (v >= 1 && v <= 99) $("#overhead_bandwidth").val(v);
      }
      if (window.history.replaceState) {
        const u = `${window.location.protocol}//${window.location.host}${window.location.pathname}`;
        window.history.replaceState({ path: u }, "", u);
      }
    }
  }

  // --- Initializations ---
  // Initialize listener form specific JS
  $("#encryption_listener")
    .change(function () {
      $(".listener-encryption-options").toggle($(this).val() !== "none");
    })
    .trigger("change");

  if (typeof initializeFormInputToggle === "function") {
    initializeFormInputToggle(
      "#input_type_listener",
      "#file-input-group-listener",
      "#multicast-input-group-listener",
    );
  } else {
    console.error(
      "initializeFormInputToggle function not found (forms.js missing or failed?)",
    );
  }

  if (typeof initializeMediaBrowser === "function") {
    initializeMediaBrowser(
      "#browse-media-listener",
      "#file_path_listener",
      "#mediaBrowserModal",
      "#refresh-media-listener",
      "#media-loading-listener",
      "#media-error-listener",
      "#media-files-listener tbody",
    );
  } else {
    console.error(
      "initializeMediaBrowser function not found (forms.js missing or failed?)",
    );
  }

  // Initial call and interval setup
  updateActiveStreams();
  const refreshInterval = 5000;
  setInterval(updateActiveStreams, refreshInterval);

  // Apply results if redirected from network test
  applyNetworkTestResults();
}); // End document.ready

