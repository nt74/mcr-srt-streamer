// /opt/mcr-srt-streamer/app/static/js/forms.js

/**
 * Initializes the logic to show/hide form input groups based on a select dropdown.
 * @param {string} selectId - The ID of the select element (e.g., '#input_type_listener').
 * @param {string} fileGroupId - The ID of the file input group.
 * @param {string} multicastGroupId - The ID of the multicast input group.
 */
function initializeFormInputToggle(selectId, fileGroupId, multicastGroupId) {
    const inputTypeSelect = $(selectId);
    const fileGroup = $(fileGroupId);
    const multicastGroup = $(multicastGroupId);

    function toggleFields() {
        const selectedType = inputTypeSelect.val();
        // Hide all conditional groups first
        fileGroup.addClass('hidden-input');
        multicastGroup.addClass('hidden-input');
        // Show the relevant group
        if (selectedType === 'file') {
            fileGroup.removeClass('hidden-input');
        } else if (selectedType === 'multicast') {
            multicastGroup.removeClass('hidden-input');
        }
    }
    inputTypeSelect.on('change', toggleFields);
    toggleFields(); // Set initial state
}

/**
 * Handles loading media files via AJAX for the media browser modal.
 * Assumes formatBytes function is globally available.
 * @param {string} mediaUrl - The URL to fetch media files from (e.g., '/media').
 * @param {string} tbodySelector - jQuery selector for the table body to populate (e.g., '#media-files-listener tbody').
 * @param {string} loadingSelector - jQuery selector for the loading indicator.
 * @param {string} errorSelector - jQuery selector for the error message display.
 * @param {function(string)} selectCallback - Function to call when a file is selected, passing the filename.
 */
function loadMediaFiles(mediaUrl, tbodySelector, loadingSelector, errorSelector, selectCallback) {
    const targetTbody = $(tbodySelector); targetTbody.empty();
    $(loadingSelector).show(); $(errorSelector).hide();
    $.ajax({
        url: mediaUrl, type: 'GET', dataType: 'json',
        success: function(data) {
            $(loadingSelector).hide();
            if (!data || data.length === 0) {
                targetTbody.append('<tr><td colspan="3" class="text-center text-muted">No .ts media files found.</td></tr>');
                return;
            }
            data.forEach(function(file) {
                // Assume formatBytes is available globally (from app.js)
                const row = `<tr><td class="text-break">${file.name}</td><td>${formatBytes(file.size)}</td><td><button class="btn btn-sm btn-primary select-media-file" data-file="${file.name}"><i class="fas fa-check"></i> Select</button> <a href="/media_info/${encodeURIComponent(file.name)}" target="_blank" class="btn btn-sm btn-info ms-1" title="View Info"><i class="fas fa-info-circle"></i> Info</a></td></tr>`;
                targetTbody.append(row);
            });
            // Use event delegation for dynamically added buttons
            targetTbody.off('click', '.select-media-file').on('click', '.select-media-file', function() {
                const fileName = $(this).data('file');
                if (selectCallback && typeof selectCallback === 'function') {
                    selectCallback(fileName);
                }
            });
        },
        error: function(xhr) {
            $(loadingSelector).hide();
            $(errorSelector).show().text('Error fetching media: ' + (xhr.responseJSON?.error || xhr.statusText || 'Unknown error'));
        }
    });
}

/**
 * Initializes the media browser functionality for a specific form.
 * @param {string} browseButtonSelector - jQuery selector for the 'Browse' button.
 * @param {string} targetInputSelector - jQuery selector for the input field to populate with the filename.
 * @param {string} modalSelector - jQuery selector for the modal element.
 * @param {string} refreshButtonSelector - jQuery selector for the refresh button inside the modal.
 * @param {string} loadingSelector - jQuery selector for the loading indicator inside the modal.
 * @param {string} errorSelector - jQuery selector for the error display inside the modal.
 * @param {string} tbodySelector - jQuery selector for the table body inside the modal.
 * @param {string} mediaUrl - The URL to fetch media files from.
 */
function initializeMediaBrowser(browseButtonSelector, targetInputSelector, modalSelector, refreshButtonSelector, loadingSelector, errorSelector, tbodySelector, mediaUrl = '/media') {
    const modalElement = new bootstrap.Modal($(modalSelector)[0]); // Get Bootstrap modal instance

    // Action when "Browse" is clicked
    $(browseButtonSelector).click(function() {
        // Define the callback for when a file is selected inside the modal
        const selectCallback = function(fileName) {
             $(targetInputSelector).val(fileName); // Populate the input field
             modalElement.hide(); // Hide the modal
        };
        // Load files and show modal
        loadMediaFiles(mediaUrl, tbodySelector, loadingSelector, errorSelector, selectCallback);
        modalElement.show();
    });

    // Action for the refresh button inside the modal
    $(refreshButtonSelector).click(function() {
         // Redefine the callback for the refresh action
         const selectCallback = function(fileName) {
             $(targetInputSelector).val(fileName);
             modalElement.hide();
         };
        loadMediaFiles(mediaUrl, tbodySelector, loadingSelector, errorSelector, selectCallback);
    });
}
