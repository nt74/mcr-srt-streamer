// /opt/mcr-srt-streamer/app/static/js/dashboard.js

$(document).ready(function() {

    // System Info Update Logic
    function updateSystemInfo() {
        $.getJSON('/api/system/status', function(d) {
            if (!d) return;
            const n = new Date(), t = n.toTimeString().split(' ')[0];
            $('#sys-refresh-time').text('Upd: ' + t);
            $('#cpu-value').text((d.cpu_usage || 0).toFixed(1) + '%');
            $('#cpu-bar').css('width', (d.cpu_usage || 0) + '%').attr('aria-valuenow', d.cpu_usage || 0);
            $('#memory-value').text((d.memory_percent || 0).toFixed(1) + '%');
            $('#memory-bar').css('width', (d.memory_percent || 0) + '%').attr('aria-valuenow', d.memory_percent || 0);
            $('#memory-details').text((d.memory_used || 'N/A') + ' / ' + (d.memory_total || 'N/A'));
            $('#disk-value').text((d.disk_percent || 0).toFixed(1) + '%');
            $('#disk-bar').css('width', (d.disk_percent || 0) + '%').attr('aria-valuenow', d.disk_percent || 0);
            $('#disk-details').text((d.disk_used || 'N/A') + ' / ' + (d.disk_total || 'N/A') + ' (Root)');
            $('#external-ip').text(d.external_ip || '?');
            $('#utc-time').text(d.utc_time || 'N/A');
            $('#current-user').text(d.current_user || '?');
            $('#uptime').text(d.uptime || 'N/A');
        }).fail(function(jqXHR) {
            console.error("Failed to fetch system info:", jqXHR.status, jqXHR.responseText);
            $('#sys-refresh-time').text('Update Failed');
        });
    }

    // Active Streams Update Logic
    function updateActiveStreams() {
        $('#refresh-indicator').removeClass('d-none');
        // Use the unprotected UI endpoint (now serves combined data)
        $.getJSON('/ui/active_streams_data', function(response) {
            const streams = response.data || {};
            const container = $('#active-streams-container');
            container.empty(); // Clear previous cards

            if (!streams || Object.keys(streams).length === 0) {
                if (response.error) { // Display error from backend if present
                     container.html(`<div class="col-12"><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> Error loading stream list: ${response.error} Please check server logs.</div></div>`);
                } else {
                     container.html('<div class="col-12"><div class="alert alert-secondary"><i class="fas fa-info-circle"></i> No active streams or pairs detected.</div></div>');
                }
                return;
            }

            // Sort keys maybe based on type then original key? Example: standard_10001, smpte_10201
            const sortedKeys = Object.keys(streams).sort();
            const csrfTokenValue = $('input[name=csrf_token]').val() || ''; // Get CSRF token

            for (const key of sortedKeys) { // key might be "standard_10001" or "smpte_10201"
                const stream = streams[key];
                if (!stream) continue;

                // Check for stream_type
                if (stream.stream_type === 'smpte_pair') {
                    // --- Render SMPTE Pair Card ---
                    const pair_id = stream.pair_id; // The key used to manage the pair
                    const leg1 = stream.leg1 || {};
                    const leg2 = stream.leg2 || {};
                    // Consistent naming for status variables
                    let pairHeaderClass = 'bg-info text-dark'; // Default for pairs
                    let pairStatusClass = 'bg-secondary';
                    let pairStatusIcon = 'fa-question-circle';
                    let pairStatusText = stream.status || '?';

                    if (pairStatusText === 'Running' || pairStatusText === 'Started' || pairStatusText === 'Connected') { // Treat 'Connected' as 'Running' visually
                         pairStatusClass = 'bg-success'; pairStatusIcon = 'fa-check-circle';
                    } else if (pairStatusText.includes('Starting') || pairStatusText.includes('Async')) {
                         pairStatusClass = 'bg-info'; pairStatusIcon = 'fa-spinner fa-spin';
                    } else if (pairStatusText.includes('Error') || pairStatusText.includes('Failed') || pairStatusText.includes('Stopped')) {
                         pairHeaderClass = 'bg-danger text-white'; // Use danger header for errors/stopped
                         pairStatusClass = 'bg-danger'; pairStatusIcon = 'fa-exclamation-triangle';
                    }

                    const encDisp = (stream.encryption || 'none').toUpperCase().replace('_', '-');
                    // Assume passphrase is set if encryption is not none (backend should ensure this)
                    const passDisp = stream.encryption === 'none' ? '<span class="text-muted fst-italic">N/A</span>' : ('<span class="badge bg-success">Set</span>');
                    const qosDisp = stream.qos ? '<span class="badge bg-success">Enabled</span>' : '<span class="badge bg-secondary">Disabled</span>';
                    const ssrc_display = stream.ssrc ? `<code>${stream.ssrc}</code>` : 'N/A'; // Display SSRC in code tags
                    const input_display = stream.input_detail ? ` (Input: ${stream.input_detail})` : ''; // Add input detail if available

                    // Generate links with corrected URLs
                    const detailsLink = `<a href="/smpte2022_7/${pair_id}" class="btn btn-info btn-sm me-2" title="View Detailed Statistics for Pair ${pair_id}"><i class="fas fa-chart-line"></i> Details</a>`;
                    const debugLink = `<a href="/smpte2022_7/api/debug/${pair_id}" class="btn btn-secondary btn-sm" target="_blank" title="View Raw Debug Info for Pair ${pair_id} (JSON)"><i class="fas fa-bug"></i> Debug</a>`;


                    const card = `
                    <div class="col-lg-6 mb-4">
                        <div class="card stream-card h-100 border-info">
                            <div class="card-header ${pairHeaderClass}">
                                <div class="d-flex justify-content-between align-items-center">
                                    <span class="fw-bold text-break"><i class="fas fa-project-diagram me-2"></i>SMPTE Pair: ${pair_id}${input_display}</span>
                                    <form method="POST" action="/smpte2022_7/stop/${pair_id}" onsubmit="return confirm('Stop SMPTE Pair ${pair_id}?');" style="display:inline;">
                                        <input type="hidden" name="csrf_token" value="${csrfTokenValue}">
                                        <button type="submit" class="btn btn-sm btn-danger" title="Stop SMPTE Pair ${pair_id}"><i class="fas fa-stop-circle"></i></button>
                                    </form>
                                </div>
                            </div>
                            <div class="card-body d-flex flex-column">
                                <table class="table table-sm table-borderless small mb-2">
                                    <tbody>
                                        <tr><td width="110"><i class="fas fa-wifi fa-fw text-muted"></i> Status</td><td><span class="badge ${pairStatusClass}"><i class="fas ${pairStatusIcon} me-1"></i>${pairStatusText}</span></td></tr>
                                        <tr><td><i class="fas fa-hourglass-start fa-fw text-muted"></i> Started</td><td>${stream.start_time_str || '?'}</td></tr>
                                        <tr><td><i class="fas fa-fingerprint fa-fw text-muted"></i> SSRC</td><td>${ssrc_display}</td></tr>
                                        <tr><td><i class="fas fa-history fa-fw text-muted"></i> Latency</td><td>${stream.latency || '?'} ms</td></tr>
                                        <tr><td><i class="fas fa-network-wired fa-fw text-muted"></i> Overhead</td><td>${stream.overhead || '?'}%</td></tr>
                                         <tr><td><i class="fas fa-lock fa-fw text-muted"></i> Encryption</td><td>${encDisp} (${passDisp})</td></tr>
                                         <tr><td><i class="fas fa-check-circle fa-fw text-muted"></i> QoS</td><td>${qosDisp}</td></tr>
                                    </tbody>
                                </table>
                                 <hr class="my-2">
                                 <div class="row">
                                     <div class="col-md-6 mb-2 mb-md-0">
                                         <strong>Leg 1 (${leg1.mode || '?'})</strong>
                                         <ul class="list-unstyled small mb-0 ms-2">
                                             <li><i class="fas fa-ethernet fa-fw text-muted"></i> NIC: ${leg1.interface || 'Auto'}</li>
                                             <li><i class="fas fa-network-wired fa-fw text-muted"></i> Port: ${leg1.port || '?'}</li>
                                             ${leg1.mode === 'caller' ? `<li><i class="fas fa-map-marker-alt fa-fw text-muted"></i> Target: ${leg1.target || '?'}</li>` : ''}
                                         </ul>
                                     </div>
                                     <div class="col-md-6">
                                         <strong>Leg 2 (${leg2.mode || '?'})</strong>
                                          <ul class="list-unstyled small mb-0 ms-2">
                                             <li><i class="fas fa-ethernet fa-fw text-muted"></i> NIC: ${leg2.interface || 'Auto'}</li>
                                             <li><i class="fas fa-network-wired fa-fw text-muted"></i> Port: ${leg2.port || '?'}</li>
                                             ${leg2.mode === 'caller' ? `<li><i class="fas fa-map-marker-alt fa-fw text-muted"></i> Target: ${leg2.target || '?'}</li>` : ''}
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

                } else if (stream.stream_type === 'standard') {
                    // --- Render Standard Stream Card (User's Existing Logic) ---
                    const stream_key = stream.key;
                    let headerClass='bg-secondary text-white', statusClass='bg-secondary', statusIcon='fa-question-circle';
                     if(stream.connection_status==='Connected'){headerClass = stream.mode === 'caller'?'bg-warning text-dark':'bg-success text-white';statusClass = 'bg-success'; statusIcon = 'fa-check-circle';}
                     else if(['Waiting for connection','Connecting...','Timeout / Reconnecting','Broken / Reconnecting'].includes(stream.connection_status)){headerClass='bg-info text-dark'; statusClass='bg-info'; statusIcon='fa-spinner fa-spin';}
                     else if(['Connection Failed','Disconnected','Rejected','Error','Bind Error','Start Error','Auth Error', 'Stopped'].includes(stream.connection_status)){headerClass='bg-danger text-white';statusClass = 'bg-danger'; statusIcon = 'fa-exclamation-triangle';}

                    const encDisp=(stream.encryption||'none').toUpperCase().replace('_','-'); const passDisp=stream.encryption==='none'?'<span class="text-muted fst-italic">N/A</span>':(stream.passphrase_set?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Missing</span>');
                    const qosDisp=stream.qos_enabled?'<span class="badge bg-success">Enabled</span>':'<span class="badge bg-secondary">Disabled</span>';
                    const rtpDisp = stream.config && stream.config.rtp_encapsulation ? '<span class="badge bg-primary ms-1" title="RTP Encapsulation Enabled">RTP</span>' : '';
                    const title=stream.mode==='caller'?`<i class="fas fa-paper-plane"></i> Caller to ${stream.target||'?'}`:`<i class="fas fa-satellite-dish"></i> Listener:${stream.key}`;
                    const clientLabel=stream.mode==='caller'?'Target':'Client IP'; const clientVal = stream.mode === 'caller' ? (stream.target || 'N/A') : (stream.client_ip || 'None Connected');
                    let inputTypeDisp = (stream.input_type||'?').replace('_',' ').replace(/\b\w/g,l=>l.toUpperCase());
                    let srcDisp = stream.source_detail||'N/A';
                    const smoothDisp = stream.smoothing_latency_ms ? `${stream.smoothing_latency_ms} ms` : 'N/A';

                    const card = `
                        <div class="col-lg-6 mb-4"> <div class="card stream-card h-100">
                            <div class="card-header ${headerClass}"> <div class="d-flex justify-content-between align-items-center"> <span class="fw-bold text-break">${title}</span> <form method="POST" action="/stop_stream/${stream_key}" onsubmit="return confirm('Stop stream ${stream_key}?');" style="display:inline;"> <input type="hidden" name="csrf_token" value="${csrfTokenValue}"> <button type="submit" class="btn btn-sm btn-danger" title="Stop Stream ${stream_key}"><i class="fas fa-stop-circle"></i></button> </ form> </div> </div>
                            <div class="card-body d-flex flex-column">
                                <table class="table table-sm table-borderless small mb-2"> <tbody>
                                        <tr><td width="110"><i class="fas fa-sign-in-alt fa-fw text-muted"></i> <strong>Input</strong></td><td class="text-break"><b>${inputTypeDisp}:</b> ${srcDisp} ${rtpDisp}</td></tr>
                                        <tr><td><i class="fas fa-map-marker-alt fa-fw text-muted"></i> <strong>${clientLabel}</strong></td><td>${clientVal}</td></tr>
                                        <tr><td><i class="fas fa-history fa-fw text-muted"></i> <strong>SRT Latency</strong></td><td>${stream.latency || '?'} ms</td></tr>
                                        <tr><td><i class="fas fa-network-wired fa-fw text-muted"></i> <strong>Overhead</strong></td><td>${stream.overhead_bandwidth || '?'}%</td></tr>
                                        <tr><td><i class="fas fa-sliders-h fa-fw text-muted"></i> <strong>Smoothing</strong></td><td>${smoothDisp}</td></tr>
                                        <tr><td><i class="fas fa-lock fa-fw text-muted"></i> <strong>Encryption</strong></td><td>${encDisp} (${passDisp})</td></tr>
                                        <tr><td><i class="fas fa-check-circle fa-fw text-muted"></i> <strong>QoS</strong></td><td>${qosDisp}</td></tr>
                                        <tr><td><i class="fas fa-wifi fa-fw text-muted"></i> <strong>Status</strong></td><td><span class="badge ${statusClass}"><i class="fas ${statusIcon} me-1"></i>${stream.connection_status || '?'}</span></td></tr>
                                        <tr><td><i class="fas fa-hourglass-start fa-fw text-muted"></i> <strong>Started</strong></td><td>${stream.start_time || '?'}</td></tr>
                                    </tbody> </table>
                                <div class="mt-auto pt-2 border-top d-flex"> <a href="/stream/${stream_key}" class="btn btn-info btn-sm me-2" title="View Detailed Statistics"><i class="fas fa-chart-line"></i> Details</a> <a href="/ui/debug/${stream_key}" class="btn btn-secondary btn-sm" target="_blank" title="View Raw Debug Info (JSON)"><i class="fas fa-bug"></i> Debug</a> </div>
                            </div> </div> </div>`;
                    container.append(card);
                } else {
                     console.warn("Unknown stream type found in data:", stream.stream_type, stream);
                     container.append(`<div class="col-12"><div class="alert alert-warning">Received unknown stream type: ${stream.stream_type || 'Undefined'}</div></div>`);
                }
            } // End for loop

        }).fail(function(jqXHR, textStatus, errorThrown) {
            console.error("Failed to fetch active streams from /ui/active_streams_data:", textStatus, errorThrown, jqXHR.status, jqXHR.responseText);
            const container = $('#active-streams-container');
            let errorMsg = "Error loading stream list.";
            if (jqXHR.status === 503) { errorMsg = "Stream manager service unavailable."; }
            else if (jqXHR.responseJSON && jqXHR.responseJSON.error) { errorMsg = jqXHR.responseJSON.error; }
            else if (textStatus === 'timeout') { errorMsg = "Request timed out."; }
            container.html(`<div class="col-12"><div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> ${errorMsg} Please check server logs.</div></div>`);
        }).always(function() {
            setTimeout(function() { $('#refresh-indicator').addClass('d-none'); }, 300);
        });

        // Update system info too
        updateSystemInfo();
    } // End updateActiveStreams function

    // Apply network test results from URL parameters
    function applyNetworkTestResults() {
        const p = new URLSearchParams(window.location.search);
        if (p.has('apply_network_test')) {
            const l = p.get('latency'), o = p.get('overhead');
            if (l && $('#latency').length) $('#latency').val(l);
            if (o && $('#overhead_bandwidth').length) {
                const v = parseInt(o);
                if (v >= 1 && v <= 99) $('#overhead_bandwidth').val(v);
            }
            if (window.history.replaceState) {
                const u = `${window.location.protocol}//${window.location.host}${window.location.pathname}`;
                window.history.replaceState({ path: u }, '', u);
            }
        }
    }

    // --- Initializations ---
    $('#encryption_listener').change(function() { $('.listener-encryption-options').toggle($(this).val() !== 'none'); }).trigger('change');

    if (typeof initializeFormInputToggle === 'function') {
        initializeFormInputToggle('#input_type_listener', '#file-input-group-listener', '#multicast-input-group-listener');
    } else { console.error("initializeFormInputToggle function not found (forms.js missing or failed?)"); }

    if (typeof initializeMediaBrowser === 'function') {
        initializeMediaBrowser(
            '#browse-media-listener',
            '#file_path_listener',
            '#mediaBrowserModal',
            '#refresh-media-listener',
            '#media-loading-listener',
            '#media-error-listener',
            '#media-files-listener tbody'
        );
    } else { console.error("initializeMediaBrowser function not found (forms.js missing or failed?)"); }

    // Initial call and interval setup
    updateActiveStreams();
    const refreshInterval = 5000;
    setInterval(updateActiveStreams, refreshInterval);

    // Apply results if redirected from network test
    applyNetworkTestResults();

}); // End document.ready

