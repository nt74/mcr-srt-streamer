// /opt/mcr-srt-streamer/app/static/js/network_test.js

$(document).ready(function() {
    // Tooltips (can rely on global init in app.js, but explicit doesn't hurt)
    // const tooltipTriggerList = [...document.querySelectorAll('[data-bs-toggle="tooltip"]')];
    // tooltipTriggerList.map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));

    // --- Form Mode Switching Logic ---
    const form = $('#network-test-form');
    const regionalOptions = $('#regional-options');
    const manualOptions = $('#manual-options');
    const manualProtocolGroup = $('#manual-protocol-group');
    const bitrateGroup = $('#bitrate-group');

    function toggleOptions() {
        const selectedMode = form.find('input[name="mode"]:checked').val();
        const isManual = selectedMode === 'manual';
        regionalOptions.toggleClass('hidden', selectedMode !== 'regional');
        manualOptions.toggleClass('hidden', !isManual);
        manualProtocolGroup.toggleClass('hidden', !isManual); // Show/hide based on manual mode
        bitrateGroup.toggleClass('hidden', !isManual); // Show/hide based on manual mode
    }
    form.find('input[name="mode"]').on('change', toggleOptions);
    toggleOptions(); // Initial call

    // --- AJAX Form Submission ---
    form.submit(function(e) {
        e.preventDefault();
        $('#test-progress').removeClass('d-none');
        $('#run-test-btn').prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> Testing...');
        $('#test-results').addClass('d-none');
        $('#test-error-alert').addClass('d-none');
        const formData = $(this).serialize();

        // Use the API endpoint defined in routes.py
        $.ajax({
            url: '/api/network_test', // This endpoint must exist and handle the form data
            type: 'POST',
            data: formData,
            dataType: 'json',
            success: function(data) {
                if (data.error && data.rtt_ms === null) { // Check for fallback/total failure case
                    showError('Test failed: ' + data.error);
                } else {
                    displayResults(data);
                    // Update recommendation note based on status/error message from results
                    $('#recommendation-note').text(data.error || 'Recommendations based on Haivision SRT Guide for measured conditions.')
                        .removeClass('text-danger text-warning text-muted')
                        .addClass(data.error && !data.error.toLowerCase().includes("estimated") ? 'text-warning' : 'text-muted'); // Warning if non-estimated error msg exists
                }
            },
            error: function(xhr) {
                console.error("AJAX error:", xhr.status, xhr.responseText);
                let errorMsg = 'Request failed.';
                if (xhr.responseJSON) {
                    if (xhr.responseJSON.error && xhr.responseJSON.details) {
                        let detailMsg = typeof xhr.responseJSON.details==='object'?Object.entries(xhr.responseJSON.details).map(([f,m])=>`${f}: ${m}`).join('; '):String(xhr.responseJSON.details);
                        errorMsg=`${xhr.responseJSON.error}: ${detailMsg}`;
                    } else if(xhr.responseJSON.error){
                        errorMsg=xhr.responseJSON.error;
                    }
                } else if (xhr.responseText){
                    errorMsg=`Server error: ${xhr.status} ${xhr.statusText||''}`;
                }
                showError(errorMsg);
            },
            complete: function() {
                $('#test-progress').addClass('d-none');
                $('#run-test-btn').prop('disabled', false).html('<i class="fas fa-play-circle"></i> Run Network Test');
            }
        });
    });

    // --- Result Display Functions ---
    function showError(message) {
        $('#test-error-message').text(message);
        $('#test-error-alert').removeClass('d-none');
        $('#test-results').addClass('d-none');
    }

    function displayResults(data){
        $('#test-results').removeClass('d-none');
        $('#test-error-alert').addClass('d-none');

        $('#result-server-label').text(data.server || 'N/A');
        $('#result-server-location').text(data.server_location || '');
        $('#result-rtt').text(data.rtt_ms ? data.rtt_ms.toFixed(1) + ' ms' : 'N/A');
        // Handle null loss specifically for TCP/Ping only
        let lossDisplay = 'N/A';
        if (data.loss_percent !== null) {
            lossDisplay = data.loss_percent.toFixed(2) + '%';
        } else if (data.bandwidth_type === 'TCP' || data.bandwidth_type === 'N/A' || data.bandwidth_type === null) {
            lossDisplay = 'N/A (TCP/Ping)';
        }
        $('#result-loss').text(lossDisplay);

        // Handle null jitter specifically for TCP/Ping only
        let jitterDisplay = 'N/A';
         if (data.jitter_ms !== null) {
            jitterDisplay = data.jitter_ms.toFixed(2) + ' ms';
        } else if (data.bandwidth_type === 'TCP' || data.bandwidth_type === 'N/A' || data.bandwidth_type === null) {
            jitterDisplay = 'N/A (TCP/Ping)';
        }
        $('#result-jitter').text(jitterDisplay);

        $('#result-bandwidth').text(data.bandwidth_mbps ? data.bandwidth_mbps + ' Mbps' : 'N/A');
        const bwElem = $('#result-bandwidth-type');
        if(data.bandwidth_type && data.bandwidth_type !== 'N/A'){
            bwElem.text(data.bandwidth_type).removeClass('d-none bg-secondary bg-info bg-warning').addClass(data.bandwidth_type === 'TCP' ? 'bg-info' : 'bg-warning'); // Orange for UDP, Blue for TCP
        } else {
            bwElem.addClass('d-none');
        }
        $('#result-latency').text(data.latency_recommendation !== null ? data.latency_recommendation : '-');
        $('#result-multiplier-inline').text(data.rtt_multiplier ? data.rtt_multiplier + 'x' : '-');
        $('#result-overhead').text(data.overhead_recommendation !== null ? data.overhead_recommendation : '-');
        $('#loss-percent-inline').text(data.loss_percent !== null ? data.loss_percent.toFixed(2) : '-');

        updateProgressBars(data);
        setQualityIndicators(data);
        // Smooth scroll to results
        $('html, body').animate({scrollTop: $("#test-results").offset().top - 20}, 500);
    }

    function updateProgressBars(data){
        const latP = data.latency_recommendation !== null ? Math.min(100, (data.latency_recommendation / 1000) * 100) : 0; // Example scaling
        $('#latency-bar').css('width', latP + '%').removeClass('bg-success bg-warning bg-danger bg-info').addClass('bg-info');
        const ovP = data.overhead_recommendation !== null ? Math.min(100, data.overhead_recommendation) : 0; // Overhead is already %
        $('#overhead-bar').css('width', ovP + '%').removeClass('bg-success bg-warning bg-danger bg-info').addClass('bg-success');
    }

    function setQualityIndicators(data){
        $('#result-rtt, #result-loss, #result-jitter, #result-latency, #result-overhead').removeClass('good-value moderate-value poor-value');
        let rttC = 'good-value';
        if(data.rtt_ms > 250) rttC = 'poor-value';
        else if(data.rtt_ms > 100) rttC = 'moderate-value';
        $('#result-rtt').addClass(rttC);

        let lossC = 'good-value';
        if(data.loss_percent === null || data.bandwidth_type === 'TCP' || data.bandwidth_type === 'N/A' || data.bandwidth_type === null) lossC = '';
        else if(data.loss_percent > 7.0) lossC = 'poor-value';
        else if(data.loss_percent > 1.0) lossC = 'moderate-value';
        $('#result-loss').addClass(lossC);
        $('#loss-percent-inline').parent().removeClass('good-value moderate-value poor-value').addClass(lossC);

        let jitC = 'good-value';
        if(data.jitter_ms === null || data.bandwidth_type === 'TCP' || data.bandwidth_type === 'N/A' || data.bandwidth_type === null) jitC = '';
        else if(data.jitter_ms > 50) jitC = 'poor-value';
        else if(data.jitter_ms > 20) jitC = 'moderate-value';
        $('#result-jitter').addClass(jitC);

        $('#result-latency').addClass(rttC); // Latency mirrors RTT
        $('#result-overhead').addClass(lossC); // Overhead mirrors Loss
        $('#result-multiplier-inline').parent().removeClass('good-value moderate-value poor-value').addClass(lossC);
    }

    // Apply Settings Button Logic
    $('#apply-settings-btn').click(function(){
        const l = $('#result-latency').text();
        const o = $('#result-overhead').text();
        if(l !== '-' && o !== '-' && !isNaN(parseInt(l)) && !isNaN(parseInt(o))){
            // Redirect to index page with parameters
            window.location.href = `${window.location.origin}/?apply_network_test=true&latency=${l}&overhead=${o}`;
        } else {
            alert('Cannot apply settings, invalid results.');
        }
    });

}); // End document.ready
