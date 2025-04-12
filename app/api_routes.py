# /opt/mcr-srt-streamer/app/api_routes.py
from flask import Blueprint, jsonify, request, current_app as app
import logging
import re # For parsing multicast if needed again
import os # For file path validation if implementing file source via API

# Assuming your forms might be useful for constants or basic structure,
# but direct validation might be simpler here for JSON.
# from app.forms import StreamForm, CallerForm

logger = logging.getLogger(__name__)
api_bp = Blueprint('api', __name__, url_prefix='/api')

# --- IMPORTANT: API Authentication ---
# You MUST add an authentication mechanism here to protect these endpoints.
# Examples: Check for a specific header (X-API-Key), use tokens (JWT), etc.
# This is a placeholder function - replace with real authentication.
def require_api_auth():
    # Example: Check for a hypothetical API key in headers
    # api_key = request.headers.get('X-API-Key')
    # if not api_key or api_key != app.config.get('EXPECTED_API_KEY'):
    #     return jsonify({"error": "Unauthorized"}), 401
    # Return None if authentication passes, or a response tuple if it fails
    logger.warning("API Authentication not implemented! Endpoints are unprotected.")
    return None

# Apply authentication check to all API routes using before_request
@api_bp.before_request
def before_api_request():
    auth_error = require_api_auth()
    if auth_error:
        return auth_error # Return the error response immediately

# --- API Routes ---

@api_bp.route('/streams', methods=['GET'])
def api_get_streams():
    """ Returns a list of active streams. """
    try:
        # Ensure stream_manager exists
        if not hasattr(app, 'stream_manager') or not app.stream_manager:
             return jsonify({"error": "Stream manager not available"}), 503

        streams = app.stream_manager.get_active_streams()
        # The stream manager already sanitizes the output mostly
        return jsonify({"data": streams if isinstance(streams, dict) else {}})
    except Exception as e:
        logger.error(f"API GET /streams error: {e}", exc_info=True)
        return jsonify({"error": "Failed to retrieve streams"}), 500

@api_bp.route('/streams/<stream_key>', methods=['GET'])
def api_get_stream_detail(stream_key):
    """ Returns details/stats for a specific stream. """
    try:
        key = int(stream_key)
        if not (0 < key < 65536):
            raise ValueError("Invalid key range")

        # Ensure stream_manager exists
        if not hasattr(app, 'stream_manager') or not app.stream_manager:
             return jsonify({"error": "Stream manager not available"}), 503

        # Using get_stream_statistics as it includes live SRT stats
        stats = app.stream_manager.get_stream_statistics(key)

        if isinstance(stats, dict) and "error" in stats:
            status_code = 404 if "not found" in stats["error"].lower() else 500
            return jsonify(stats), status_code
        elif stats is None: # Should be caught by the error dict check generally
            return jsonify({"error": f"Stream {key} not found or stats unavailable"}), 404
        else:
            return jsonify({"data": stats}) # stats are already sanitized
    except ValueError:
        return jsonify({"error": "Invalid stream key format or value"}), 400
    except Exception as e:
        logger.error(f"API GET /streams/{stream_key} error: {e}", exc_info=True)
        return jsonify({"error": "Failed to retrieve stream details"}), 500

@api_bp.route('/streams', methods=['POST'])
def api_start_stream():
    """ Starts a new stream (listener or caller) based on JSON payload. """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 415 # Unsupported Media Type

    config_data = request.get_json()
    if not config_data:
         return jsonify({"error": "No JSON data provided"}), 400

    logger.info(f"API request received to start stream: {config_data}")

    # --- Basic Payload Validation ---
    errors = {}
    mode = config_data.get('mode', 'listener').lower()
    if mode not in ['listener', 'caller']:
        errors['mode'] = "Mode must be 'listener' or 'caller'."

    input_type = config_data.get('input_type')
    # Updated: Check against allowed values including colorbars
    allowed_inputs = ['multicast', 'file', 'colorbar_720p50', 'colorbar_1080i25']
    if not input_type or input_type not in allowed_inputs:
        errors['input_type'] = f"Missing or invalid input_type. Allowed: {', '.join(allowed_inputs)}"

    # Port/Target Validation based on mode
    if mode == 'listener':
        port = config_data.get('port')
        if not port or not isinstance(port, int) or not (10001 <= port <= 10010):
             errors['port'] = "Listener requires a 'port' between 10001 and 10010."
    else: # caller
        target_address = config_data.get('target_address')
        target_port = config_data.get('target_port')
        if not target_address or not isinstance(target_address, str) or len(target_address) > 255:
             errors['target_address'] = "Caller requires a valid 'target_address' (string, max 255)."
        # Basic validation - might need refinement (DNS vs IP)
        elif not re.match(r"^[a-zA-Z0-9\.\-]+$", target_address) or '.' not in target_address:
             errors['target_address'] = "Invalid target address format."

        if not target_port or not isinstance(target_port, int) or not (1 <= target_port <= 65535):
            errors['target_port'] = "Caller requires a 'target_port' between 1 and 65535."

    # Input source specific validation
    if input_type == 'file':
        file_path = config_data.get('file_path')
        if not file_path or not isinstance(file_path, str):
            errors['file_path'] = "File input requires a 'file_path' (string)."
        # Add checks if file exists within MEDIA_FOLDER if needed (requires access to app config)
        elif ".." in file_path or file_path.startswith("/"):
             errors['file_path'] = "Invalid file path format."
        elif not file_path.lower().endswith(".ts"):
             errors['file_path'] = "Only .ts files are supported."
        else:
             # Security check: ensure path is relative and within media folder
             media_dir = os.path.abspath(app.config['MEDIA_FOLDER'])
             abs_path = os.path.abspath(os.path.join(media_dir, os.path.basename(file_path)))
             if not abs_path.startswith(media_dir + os.sep):
                  errors['file_path'] = "File path is outside the allowed media directory."
             elif not os.path.isfile(abs_path):
                  errors['file_path'] = f"File does not exist: {os.path.basename(file_path)}"


    elif input_type == 'multicast':
         # For API, expect separate address & port, not combined channel string
         mc_address = config_data.get('multicast_address')
         mc_port = config_data.get('multicast_port')
         mc_interface = config_data.get('multicast_interface') # Optional

         if not mc_address or not isinstance(mc_address, str):
             errors['multicast_address'] = "Multicast input requires 'multicast_address'."
         # Basic IP validation - could be more robust
         elif not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", mc_address):
              errors['multicast_address'] = "Invalid multicast address format."

         if not mc_port or not isinstance(mc_port, int) or not (1 <= mc_port <= 65535):
             errors['multicast_port'] = "Multicast input requires 'multicast_port' (1-65535)."

         if mc_interface and not isinstance(mc_interface, str):
              errors['multicast_interface'] = "Multicast interface must be a string if provided."

    # SRT Parameter Validation (add more as needed)
    latency = config_data.get('latency', 300) # Default if missing
    overhead = config_data.get('overhead_bandwidth', 2) # Default if missing
    if not isinstance(latency, int) or not (20 <= latency <= 8000):
         errors['latency'] = "SRT Latency must be an integer between 20 and 8000."
    if not isinstance(overhead, int) or not (1 <= overhead <= 99):
        errors['overhead_bandwidth'] = "Overhead bandwidth must be an integer between 1 and 99."

    # Encryption Validation
    encryption = config_data.get('encryption', 'none').lower()
    passphrase = config_data.get('passphrase')
    if encryption not in ['none', 'aes-128', 'aes-256']:
        errors['encryption'] = "Invalid encryption type. Allowed: none, aes-128, aes-256."
    elif encryption != 'none':
        if not passphrase:
            errors['passphrase'] = "Passphrase is required when encryption is enabled."
        elif not isinstance(passphrase, str) or not (10 <= len(passphrase) <= 79):
            errors['passphrase'] = "Passphrase must be a string between 10 and 79 characters."

    # Return validation errors if any
    if errors:
        logger.warning(f"API stream config validation failed: {errors}")
        return jsonify({"error": "Validation failed", "details": errors}), 400
    # --- End Validation ---

    # Prepare config for StreamManager (ensure defaults are set if not provided)
    final_config = {
        "mode": mode,
        "latency": latency,
        "overhead_bandwidth": overhead,
        "encryption": encryption,
        "passphrase": passphrase if encryption != 'none' else "",
        "qos": config_data.get('qos', False),
        "smoothing_latency_ms": config_data.get('smoothing_latency_ms', 30), # Default
    }

    # Add mode-specific port/target
    if mode == 'listener':
        final_config['port'] = config_data['port']
    else: # caller
        final_config['target_address'] = config_data['target_address']
        final_config['target_port'] = config_data['target_port']

    # Add input-specific details
    if input_type == 'file':
        final_config['input_type'] = 'file'
        final_config['file_path'] = os.path.basename(config_data['file_path']) # Use only filename
    elif input_type == 'multicast':
        final_config['input_type'] = 'multicast'
        final_config['multicast_address'] = config_data['multicast_address']
        final_config['multicast_port'] = config_data['multicast_port']
        final_config['protocol'] = 'udp' # Assuming UDP for now
        final_config['multicast_interface'] = config_data.get('multicast_interface') # Pass if provided
    elif input_type.startswith('colorbar_'):
        final_config['input_type'] = 'colorbar'
        final_config['colorbar_resolution'] = input_type.split("_", 1)[1]

    # --- Start Stream ---
    logger.info(f"API validated config, attempting start_stream: {final_config}")
    try:
        # Ensure stream_manager exists
        if not hasattr(app, 'stream_manager') or not app.stream_manager:
             return jsonify({"error": "Stream manager not available"}), 503

        use_target_key = (mode == 'caller')
        success, message = app.stream_manager.start_stream(
            config=final_config,
            use_target_port_as_key=use_target_key
        )

        if success:
            started_key = final_config.get('target_port') if use_target_key else final_config.get('port')
            logger.info(f"API successfully initiated stream start for key {started_key}")
            # Return 201 Created status with message and key
            return jsonify({"message": message, "stream_key": started_key, "status": "starting"}), 201
        else:
            logger.error(f"API start_stream failed: {message}")
            return jsonify({"error": message}), 400 # Bad Request likely indicates config issue
    except Exception as e:
        logger.error(f"API POST /streams internal error: {e}", exc_info=True)
        return jsonify({"error": f"Internal server error starting stream: {str(e)}"}), 500

@api_bp.route('/streams/<stream_key>', methods=['DELETE'])
def api_stop_stream(stream_key):
    """ Stops a specific stream. """
    logger.info(f"API request received to stop stream {stream_key}")
    try:
        # Validate key format
        key_int = int(stream_key)
        if not (0 < key_int < 65536):
            raise ValueError("Invalid port range")

        # Ensure stream_manager exists
        if not hasattr(app, 'stream_manager') or not app.stream_manager:
             return jsonify({"error": "Stream manager not available"}), 503

        success, message = app.stream_manager.stop_stream(stream_key)

        if success:
            logger.info(f"API stop request for stream {stream_key} successful: {message}")
            return jsonify({"message": message, "status": "stopping"}), 200 # Or 202 Accepted
        else:
            logger.warning(f"API stop request failed for stream {stream_key}: {message}")
            status_code = 404 if "not found" in message.lower() else 400 # 400 for other failures
            return jsonify({"error": message}), status_code
    except ValueError:
         logger.warning(f"API stop request received invalid stream key: {stream_key}")
         return jsonify({"error": "Invalid stream key format or value"}), 400
    except Exception as e:
        logger.error(f"API DELETE /streams/{stream_key} internal error: {e}", exc_info=True)
        return jsonify({"error": f"Internal server error stopping stream: {str(e)}"}), 500

# --- Add other API endpoints as needed ---
# Example: System Status
@api_bp.route('/system/status', methods=['GET'])
def api_get_system_status():
    try:
        # Assuming get_system_info is imported or available
        from app.utils import get_system_info
        info = get_system_info()
        return jsonify(info)
    except Exception as e:
        logger.error(f"API GET /system/status error: {e}", exc_info=True)
        return jsonify({"error": "Failed to retrieve system status"}), 500

# Example: Network Test (Adapt based on network_test.py capabilities)
# @api_bp.route('/network-test', methods=['POST'])
# def api_run_network_test():
#     # 1. Get JSON data from request
#     # 2. Validate data (mode, target, etc.)
#     # 3. Call network_tester.run_network_test(...)
#     # 4. Return results or error via jsonify
#     return jsonify({"error": "Network test API not fully implemented"}), 501
