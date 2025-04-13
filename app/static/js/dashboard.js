// /opt/mcr-srt-streamer/app/static/js/dashboard.js

$(document).ready(function() {

    // System Info Update Logic
    function updateSystemInfo() {
        // Assumes /api/system/status doesn't require X-API-Key
        // If it does, this needs headers added or the endpoint changed
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
        // Use the unprotected UI endpoint
        $.getJSON('/ui/active_streams_data', function(response) {
            const streams = response.data || {};
            const container = $('#active-streams-container');
            container.empty();

            if (!streams || Object.keys(streams).length === 0) {
                container.html('<div class="col-12"><div class="alert alert-secondary"><i class="fas fa-info-circle"></i> No active streams detected.</div></div>');
                return;
            }

            const sortedKeys = Object.keys(streams).sort((a, b) => parseInt(a) - parseInt(b));
            for (const key of sortedKeys) {
                const stream = streams[key]; if (!stream) continue;
                let headerClass='bg-secondary', statusClass='bg-secondary', statusIcon='fa-question-circle';
                if(stream.connection_status==='Connected'){headerClass = stream.mode === 'caller'?'bg-warning text-dark':'bg-success';statusClass = 'bg-success'; statusIcon = 'fa-check-circle';}
                else if(['Waiting for connection','Connecting...','Timeout / Reconnecting','Broken / Reconnecting'].includes(stream.connection_status)){headerClass='bg-info'; statusClass='bg-info'; statusIcon='fa-spinner fa-spin';}
                else if(['Connection Failed','Disconnected','Rejected','Error','Bind Error','Start Error','Auth Error', 'Stopped'].includes(stream.connection_status)){headerClass='bg-danger';statusClass = 'bg-danger'; statusIcon = 'fa-exclamation-triangle';}
                const encDisp=(stream.encryption||'none').toUpperCase().replace('_','-'); const passDisp=stream.encryption==='none'?'<span class="text-muted fst-italic">N/A</span>':(stream.passphrase_set?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Missing</span>');
                const qosDisp=stream.qos_enabled?'<span class="badge bg-success">Enabled</span>':'<span class="badge bg-secondary">Disabled</span>';
                const rtpDisp = stream.config && stream.config.rtp_encapsulation ? '<span class="badge bg-primary ms-1" title="RTP Encapsulation Enabled">RTP</span>' : '';
                const title=stream.mode==='caller'?`<i class="fas fa-paper-plane"></i> Caller to ${stream.target||'?'}`:`<i class="fas fa-satellite-dish"></i> Listener:${stream.key}`;
                const clientLabel=stream.mode==='caller'?'Target':'Client IP'; const clientVal = stream.mode === 'caller' ? (stream.target || 'N/A') : (stream.client_ip || 'None Connected');
                let inputTypeDisp = (stream.input_type||'?').replace('_',' ').replace(/\b\w/g,l=>l.toUpperCase());
                let srcDisp = stream.source_detail||'N/A';
                const smoothDisp = stream.smoothing_latency_ms ? `${stream.smoothing_latency_ms} ms` : 'N/A';
                const csrfTokenValue = $('input[name=csrf_token]').val() || ''; // Get CSRF token from form

                const card = `
                    <div class="col-lg-6 mb-4"> <div class="card stream-card h-100">
                        <div class="card-header ${headerClass} text-white"> <div class="d-flex justify-content-between align-items-center"> <span class="fw-bold text-break">${title}</span> <form method="POST" action="/stop_stream/${stream.key}" onsubmit="return confirm('Stop stream ${stream.key}?');" style="display:inline;"> <input type="hidden" name="csrf_token" value="${csrfTokenValue}"> <button type="submit" class="btn btn-sm btn-danger" title="Stop Stream ${stream.key}"><i class="fas fa-stop-circle"></i></button> </form> </div> </div>
                        <div class="card-body d-flex flex-column">
                            <table class="table table-sm table-borderless small mb-2"> <tbody>
                                    <tr><td width="110"><i class="fas fa-sign-in-alt fa-fw"></i> <strong>Input</strong></td><td class="text-break"><b>${inputTypeDisp}:</b> ${srcDisp} ${rtpDisp}</td></tr>
                                    <tr><td><i class="fas fa-map-marker-alt fa-fw"></i> <strong>${clientLabel}</strong></td><td>${clientVal}</td></tr>
                                    <tr><td><i class="fas fa-history fa-fw"></i> <strong>SRT Latency</strong></td><td>${stream.latency||'?'} ms</td></tr>
                                    <tr><td><i class="fas fa-network-wired fa-fw"></i> <strong>Overhead</strong></td><td>${stream.overhead_bandwidth||'?'}%</td></tr>
                                    <tr><td><i class="fas fa-sliders-h fa-fw"></i> <strong>Smoothing</strong></td><td>${smoothDisp}</td></tr>
                                    <tr><td><i class="fas fa-lock fa-fw"></i> <strong>Encryption</strong></td><td>${encDisp} (${passDisp})</td></tr>
                                    <tr><td><i class="fas fa-check-circle fa-fw"></i> <strong>QoS</strong></td><td>${qosDisp}</td></tr>
                                    <tr><td><i class="fas fa-wifi fa-fw"></i> <strong>Status</strong></td><td><span class="badge ${statusClass}"><i class="fas ${statusIcon} me-1"></i>${stream.connection_status||'?'}</span></td></tr>
                                    <tr><td><i class="fas fa-hourglass-start fa-fw"></i> <strong>Started</strong></td><td>${stream.start_time||'?'}</td></tr>
                                </tbody> </table>
                            <div class="mt-auto pt-2 border-top d-flex"> <a href="/stream/${stream.key}" class="btn btn-info btn-sm me-2" title="View Detailed Statistics"><i class="fas fa-chart-line"></i> Details</a> <a href="/api/debug/${stream.key}" class="btn btn-secondary btn-sm" target="_blank" title="View Raw Debug Info (JSON)"><i class="fas fa-bug"></i> Debug</a> </div>
                        </div> </div> </div>`;
                container.append(card);
             }
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
    }

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
            // Clean URL parameters after applying
            if (window.history.replaceState) {
                const u = `${window.location.protocol}//${window.location.host}${window.location.pathname}`;
                window.history.replaceState({ path: u }, '', u);
            }
        }
    }

    // --- Initializations ---
    $('#encryption_listener').change(function() { $('.listener-encryption-options').toggle($(this).val() !== 'none'); }).trigger('change');

    // Use shared form helpers
    if (typeof initializeFormInputToggle === 'function') {
        initializeFormInputToggle('#input_type_listener', '#file-input-group-listener', '#multicast-input-group-listener');
    } else { console.error("initializeFormInputToggle function not found (forms.js missing or failed?)"); }

    if (typeof initializeMediaBrowser === 'function') {
        initializeMediaBrowser(
            '#browse-media-listener',
            '#file_path_listener', // Target input for listener form
            '#mediaBrowserModal',
            '#refresh-media-listener',
            '#media-loading-listener',
            '#media-error-listener',
            '#media-files-listener tbody' // Use tbody selector
        );
    } else { console.error("initializeMediaBrowser function not found (forms.js missing or failed?)"); }

    // Initial call and interval setup
    updateActiveStreams();
    const refreshInterval = 5000;
    setInterval(updateActiveStreams, refreshInterval);

    // Apply results if redirected from network test
    applyNetworkTestResults();

}); // End document.ready
