// /opt/mcr-srt-streamer/app/static/js/caller.js

$(document).ready(function() {
    // Initialize tooltips (can also be done globally in app.js)
    // const tooltipTriggerList = [...document.querySelectorAll('[data-bs-toggle="tooltip"]')];
    // tooltipTriggerList.map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));

    // --- Caller Form Specific Logic ---

    // Encryption Toggle
    $('#encryption_caller').change(function() {
        $('.caller-encryption-options').toggle($(this).val() !== 'none');
    }).trigger('change'); // Trigger on load to set initial state

    // Initialize Input Type Visibility Toggle (Using shared function from forms.js)
    if (typeof initializeFormInputToggle === 'function') {
        initializeFormInputToggle(
            '#input_type_caller',
            '#file-input-group-caller',
            '#multicast-input-group-caller'
        );
    } else {
        console.error("initializeFormInputToggle function not found (forms.js missing or failed?)");
    }

    // Initialize Media Browser (Using shared function from forms.js)
     if (typeof initializeMediaBrowser === 'function' && typeof formatBytes === 'function') {
        // Make sure formatBytes from app.js is available
        initializeMediaBrowser(
            '#browse-media-caller', // Button that triggers the modal
            '#file_path_caller',    // Input field to update
            '#mediaBrowserModal',   // The modal element
            '#refresh-media-caller-modal', // Refresh button inside modal
            '#media-loading-caller-modal', // Loading indicator inside modal
            '#media-error-caller-modal',   // Error display inside modal
            '#media-files-caller-modal tbody' // Table body inside modal
            // Optional 7th arg: '/media' (default)
        );
    } else {
        console.error("initializeMediaBrowser or formatBytes function not found (forms.js/app.js missing or failed?)");
    }

}); // End document.ready
