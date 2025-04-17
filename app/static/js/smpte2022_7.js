// Create app/static/js/smpte2022_7.js

$(document).ready(function() {
    // --- Initialize tooltips (using shared function likely from app.js) ---
    if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
        const tooltipTriggerList = [...document.querySelectorAll('[data-bs-toggle="tooltip"]')];
        tooltipTriggerList.map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
    } else {
        console.warn("Bootstrap Tooltip function not available for initialization.");
    }

    // --- Conditional Input Display Logic ---
    const inputTypeSelect = $('#input_type'); // Assuming the ID is 'input_type' in the new form
    const multicastGroup = $('#smpte-multicast-group'); // Unique ID for the multicast section

    function toggleInputFields() {
        const selectedType = inputTypeSelect.val();
        // Use toggleClass for cleaner show/hide based on condition
        multicastGroup.toggleClass('hidden-input', selectedType !== 'multicast');
    }

    inputTypeSelect.on('change', toggleInputFields);
    toggleInputFields(); // Set initial state on page load

    // --- Encryption Options Toggle ---
    const encryptionSelect = $('#encryption_smpte'); // Unique ID for encryption select
    const encryptionOptions = $('.smpte-encryption-options'); // Unique class for options div

    encryptionSelect.on('change', function() {
        encryptionOptions.toggle($(this).val() !== 'none');
    }).trigger('change'); // Set initial state

    // --- Caller Options Toggle ---
    const modeSelect1 = $('#mode_1');
    const callerOptions1 = $('#caller-options-1'); // ID for Leg 1 caller options div
    const modeSelect2 = $('#mode_2');
    const callerOptions2 = $('#caller-options-2'); // ID for Leg 2 caller options div

    modeSelect1.on('change', function() {
        // Show/hide based on whether 'caller' is selected for Leg 1
        callerOptions1.toggle($(this).val() === 'caller');
    }).trigger('change'); // Initialize state for Leg 1

    modeSelect2.on('change', function() {
        // Show/hide based on whether 'caller' is selected for Leg 2
        callerOptions2.toggle($(this).val() === 'caller');
    }).trigger('change'); // Initialize state for Leg 2

    // --- SSRC Mirroring/Validation (Optional Enhancement) ---
    // Could add JS here to ensure SSRC Leg 2 matches Leg 1 if desired,
    // or simply rely on backend validation/logic for now.

    console.log("SMPTE 2022-7 page JS loaded.");

}); // End document.ready
