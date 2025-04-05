# /opt/mcr-srt-streamer/app/routes.py
# Added logic to populate and handle multicast interface selection

from flask import (
    render_template, request, jsonify, send_from_directory,
    redirect, url_for, flash, current_app as app, session
)
# Import ALL needed forms from the updated app/forms.py
from app.forms import (
    StreamForm, CallerForm, NetworkTestForm, MediaUploadForm, SettingsForm
)
# *** IMPORT new function from utils ***
from app.utils import get_system_info, get_network_interfaces # Added get_network_interfaces
from app.network_test import NetworkTester
import os
import logging
from datetime import datetime
import json # For loading channel list and handling JSON errors
import re   # For parsing multicast value

logger = logging.getLogger(__name__)

# Initialize network tester (remains the same)
try:
    network_tester = NetworkTester()
    logger.info("NetworkTester initialized successfully.")
except Exception as e:
    logger.error(f"Failed to initialize NetworkTester: {e}", exc_info=True)
    network_tester = None

# --- Helper Function to Load IPTV Channels ---
def load_iptv_channels():
    """Loads channel data from the JSON file."""
    iptv_channels = []
    data_dir = os.path.join(os.path.dirname(__file__), 'data')
    json_path = os.path.join(data_dir, 'iptv_channels.json')
    try:
        if os.path.exists(json_path):
            with open(json_path, 'r', encoding='utf-8') as f: iptv_channels = json.load(f)
            logger.info(f"Loaded {len(iptv_channels)} channels from {json_path}")
        else: logger.warning(f"IPTV channel file not found: {json_path}")
    except Exception as e: logger.error(f"Error loading IPTV channels from {json_path}: {e}", exc_info=True)
    return iptv_channels

# --- Helper Function to Populate Multicast Choices ---
def populate_multicast_choices(form_field):
    """Populates the choices for a SelectField from the loaded channels."""
    channels = load_iptv_channels()
    choices = [('', '-- Select Multicast Channel --')]
    for channel in channels:
        if 'name' in channel and 'address' in channel and 'port' in channel:
             value = f"{channel['address']}:{channel['port']}"; label = channel['name']
             choices.append((value, label))
        else: logger.warning(f"Skipping invalid channel entry: {channel}")
    form_field.choices = choices
    return choices

# *** NEW HELPER: Populate Network Interface Choices ***
def populate_interface_choices(form_field):
    """Populates the choices for the network interface SelectField."""
    interfaces = get_network_interfaces() # Call the function from utils.py
    # Start with 'Auto' option, value is empty string
    choices = [('', '-- Auto --')]
    for interface_name in interfaces:
        choices.append((interface_name, interface_name)) # Value and Label are the same
    form_field.choices = choices
    logger.debug(f"Populated interface choices: {choices}")
    return choices
# *** END NEW HELPER ***

# Wrap route definitions in a function called by __init__
def register_routes(app_instance):

    # --- Main Dashboard ---
    @app_instance.route('/')
    def index():
        """ Renders the main dashboard page with listener form and active streams. """
        form = StreamForm()
        populate_multicast_choices(form.multicast_channel)
        populate_interface_choices(form.multicast_interface) # Populate interfaces
        error_message = request.args.get('error')
        if request.args.get('apply_network_test'):
             try: # Apply Network Test settings logic remains the same
                 latency_arg=request.args.get('latency'); overhead_arg=request.args.get('overhead'); applied=False
                 if latency_arg is not None: form.latency.data = min(max(int(latency_arg), 20), 8000); applied = True
                 if overhead_arg is not None: form.overhead_bandwidth.data = min(max(int(overhead_arg), 1), 99); applied = True
                 if applied: flash(f"Net test settings applied: Latency={form.latency.data}ms, Overhead={form.overhead_bandwidth.data}%", 'success')
             except: flash("Error applying network settings.", 'danger')
        system_info = get_system_info()
        active_streams = app_instance.stream_manager.get_active_streams()
        return render_template('index.html', form=form, system_info=system_info, active_streams=active_streams, error=error_message, current_year=datetime.utcnow().year)

    @app_instance.route("/start_listener_stream", methods=["POST"])
    def start_listener_stream():
        """ Handles submission of the Listener stream form from the index page. """
        form = StreamForm()
        populate_multicast_choices(form.multicast_channel)
        populate_interface_choices(form.multicast_interface) # Repopulate choices before validation
        system_info = get_system_info()
        active_streams = app_instance.stream_manager.get_active_streams()

        if form.validate_on_submit():
            config = { 'port': form.port.data, 'latency': form.latency.data, 'overhead_bandwidth': form.overhead_bandwidth.data, 'mode': 'listener', 'encryption': form.encryption.data, 'passphrase': form.passphrase.data, 'qos': form.qos.data, 'input_type': form.input_type.data, 'smoothing_latency_ms': form.smoothing_latency_ms.data }
            input_type = config['input_type']; media_source_detail = "N/A"

            if input_type == 'file':
                try: # File handling remains the same
                    file_to_check=form.file_path.data; media_dir=os.path.abspath(app_instance.config['MEDIA_FOLDER']); file_path=os.path.abspath(os.path.join(media_dir, file_to_check))
                    if not file_path.startswith(media_dir+os.sep) or not os.path.isfile(file_path): raise ValueError("Invalid file path/not found.")
                    config['file_path']=file_path; media_source_detail=file_to_check
                except Exception as e: flash(f"Invalid media file: {e}",'danger'); logger.error(f"Listener file fail: {e}"); populate_multicast_choices(form.multicast_channel); populate_interface_choices(form.multicast_interface); return render_template('index.html',form=form,system_info=system_info,active_streams=active_streams,error=str(e),current_year=datetime.utcnow().year)
            elif input_type == 'multicast':
                selected_channel_value = form.multicast_channel.data
                match = re.match(r"(.+):(\d+)$", selected_channel_value)
                if match:
                    config['multicast_address'] = match.group(1); config['multicast_port'] = int(match.group(2)); config['protocol'] = 'udp';
                    media_source_detail = f"{config['multicast_address']}:{config['multicast_port']}"
                    # *** ADD Multicast Interface to Config ***
                    config['multicast_interface'] = form.multicast_interface.data # Store selected interface ('', 'vlan2', etc.)
                else: flash("Invalid multicast channel selection.",'danger'); logger.error(f"Listener mcast fail: {selected_channel_value}"); populate_multicast_choices(form.multicast_channel); populate_interface_choices(form.multicast_interface); return render_template('index.html',form=form,system_info=system_info,active_streams=active_streams,error="Invalid channel value.",current_year=datetime.utcnow().year)

            # Update log message to include interface if selected
            interface_log = f", Interface: {config.get('multicast_interface') or 'Auto'}" if input_type == 'multicast' else ""
            logger.info(f"Attempting to start LISTENER stream (port {config.get('port')}) with config: {config}")
            success, message = app_instance.stream_manager.start_stream(config=config)
            if success:
                logger.info(f"Listener stream start initiated (Port: {config.get('port')}, Input: {input_type} [{media_source_detail}]{interface_log}, Smoothing: {config.get('smoothing_latency_ms')}ms): {message}")
                flash(f"Listener stream started on port {config.get('port')}.", 'success')
                return redirect(url_for('index'))
            else:
                logger.error(f"Listener stream start failed: {message}"); flash(f"Failed start: {message}", 'danger');
                populate_multicast_choices(form.multicast_channel); populate_interface_choices(form.multicast_interface); # Repopulate for render
                return render_template('index.html',form=form,system_info=system_info,active_streams=active_streams,error=message,current_year=datetime.utcnow().year)
        else: # Validation failed
            populate_multicast_choices(form.multicast_channel); populate_interface_choices(form.multicast_interface); # Repopulate for render
            flash('Please correct the errors in the listener form.', 'warning')
            return render_template('index.html', form=form, system_info=system_info, active_streams=active_streams, error=None, current_year=datetime.utcnow().year)

    # --- Caller Page ---
    @app_instance.route('/caller', methods=['GET', 'POST'])
    def caller_page():
        """ Renders the Caller stream configuration page and handles form submission. """
        form = CallerForm()
        populate_multicast_choices(form.multicast_channel)
        populate_interface_choices(form.multicast_interface) # Populate interfaces
        error_message = None

        if form.validate_on_submit(): # Handles POST
            config = { 'mode': 'caller', 'target_address': form.target_address.data, 'target_port': form.target_port.data, 'latency': form.latency.data, 'overhead_bandwidth': form.overhead_bandwidth.data, 'encryption': form.encryption.data, 'passphrase': form.passphrase.data, 'qos': form.qos.data, 'input_type': form.input_type.data, 'smoothing_latency_ms': form.smoothing_latency_ms.data }
            input_type = config['input_type']; media_source_detail = "N/A"

            if input_type == 'file':
                try: # File handling remains the same
                     file_to_check=form.file_path.data; media_dir=os.path.abspath(app_instance.config['MEDIA_FOLDER']); file_path=os.path.abspath(os.path.join(media_dir, file_to_check))
                     if not file_path.startswith(media_dir+os.sep) or not os.path.isfile(file_path): raise ValueError("Invalid file path/not found.")
                     config['file_path']=file_path; media_source_detail=file_to_check
                except Exception as e: error_message=f"Invalid file: {e}"; logger.error(f"Caller file fail: {e}"); populate_multicast_choices(form.multicast_channel); populate_interface_choices(form.multicast_interface); return render_template('caller.html',form=form,error=error_message,current_year=datetime.utcnow().year)
            elif input_type == 'multicast':
                selected_channel_value = form.multicast_channel.data
                match = re.match(r"(.+):(\d+)$", selected_channel_value)
                if match:
                    config['multicast_address'] = match.group(1); config['multicast_port'] = int(match.group(2)); config['protocol'] = 'udp';
                    media_source_detail = f"{config['multicast_address']}:{config['multicast_port']}"
                    # *** ADD Multicast Interface to Config ***
                    config['multicast_interface'] = form.multicast_interface.data # Store selected interface
                else: error_message="Invalid multicast channel."; logger.error(f"Caller mcast fail: {selected_channel_value}"); populate_multicast_choices(form.multicast_channel); populate_interface_choices(form.multicast_interface); return render_template('caller.html',form=form,error=error_message,current_year=datetime.utcnow().year)

            # Update log message
            interface_log = f", Interface: {config.get('multicast_interface') or 'Auto'}" if input_type == 'multicast' else ""
            logger.info(f"Attempting to start CALLER stream to {config['target_address']}:{config['target_port']} with config: {config}")
            success, message = app_instance.stream_manager.start_stream(config=config, use_target_port_as_key=True)
            if success:
                logger.info(f"Caller stream start initiated (Target: {config['target_address']}:{config['target_port']}, Input: {input_type} [{media_source_detail}]{interface_log}, Smoothing: {config.get('smoothing_latency_ms')}ms): {message}")
                flash(f"Caller stream to {config.get('target_address')}:{config.get('target_port')} started.", 'success')
                return redirect(url_for('index'))
            else: logger.error(f"Caller stream start failed: {message}"); error_message = f"Failed start: {message}"
            # Fall through to render template with error (choices populated)

        # Handles GET or POST failure
        return render_template('caller.html', form=form, error=error_message, current_year=datetime.utcnow().year)

    # --- Other Routes (Stop, Media List, Info, Stats, Debug, Health, Network Test) ---
    # Only need to add populate_interface_choices if forms are directly rendered
    # on these pages (which they aren't directly, only passed for base template maybe)

    @app_instance.route("/stop_stream/<stream_key>", methods=["POST"])
    def stop_stream(stream_key):
        # ... (keep existing implementation) ...
        try: key_int = int(stream_key); assert 0 < key_int < 65536
        except: flash("Invalid stream identifier.", 'danger'); return redirect(url_for('index'))
        success, message = app_instance.stream_manager.stop_stream(stream_key)
        if success: logger.info(f"Stream stopped via UI: {message}"); flash(f"Stream ({stream_key}) stopped.", 'success')
        else: logger.error(f"Stream stop fail UI: {message}"); flash(f"Failed stop ({stream_key}): {message}", 'danger')
        referrer = request.referrer; return redirect(referrer) if referrer and request.host_url in referrer else redirect(url_for('index'))

    @app_instance.route("/media")
    def list_media():
        # ... (corrected implementation) ...
        media_files = []
        media_dir = app_instance.config.get('MEDIA_FOLDER', '/opt/mcr-srt-streamer/media')
        try:
            if not os.path.isdir(media_dir):
                raise FileNotFoundError("Media dir missing")
            for f in os.listdir(media_dir):
                if f.startswith('.') or not f.lower().endswith('.ts'):
                    continue
                try:
                    fp = os.path.join(media_dir, f)
                    if os.path.isfile(fp):
                        media_files.append({'name': f, 'size': os.path.getsize(fp)})
                except Exception as fe:
                    logger.warning(f"Err stat file '{f}': {fe}")
            media_files.sort(key=lambda x: x['name'])
        except Exception as e:
            logger.error(f"Failed list media: {e}")
            return jsonify({"error": "Failed list media"}), 500
        return jsonify(media_files)

    @app_instance.route("/media_info/<path:filename>")
    def media_info(filename):
        # Pass dummy form for base template, populate dropdowns just in case base needs them
        if '..' in filename or filename.startswith('/') or not filename.lower().endswith('.ts'): flash("Invalid filename.", 'danger'); return redirect(url_for('index'))
        try:
            media_dir=os.path.abspath(app_instance.config['MEDIA_FOLDER']); file_path=os.path.abspath(os.path.join(media_dir, filename))
            if not file_path.startswith(media_dir + os.sep) or not os.path.isfile(file_path): raise FileNotFoundError("Access error.")
        except Exception as e: flash(f"Cannot access '{filename}': {e}", 'danger'); return redirect(url_for('index'))
        info = app_instance.stream_manager.get_file_info(file_path)
        dummy_form = StreamForm()
        populate_multicast_choices(dummy_form.multicast_channel)
        populate_interface_choices(dummy_form.multicast_interface) # Populate interfaces
        return render_template('media_info.html', filename=filename, info=info, form=dummy_form, current_year=datetime.utcnow().year)

    @app_instance.route("/stream/<stream_key>")
    def stream_details(stream_key):
        # Pass dummy form for base template, populate dropdowns just in case base needs them
        try: key = int(stream_key); assert 0 < key < 65536
        except: flash("Invalid stream identifier.", 'danger'); return redirect(url_for('index'))
        stream_data = app_instance.stream_manager.get_active_streams().get(key)
        if not stream_data: flash(f"Stream ({key}) not found.", 'warning'); return redirect(url_for('index'))
        form = StreamForm() # For base template context - might not be needed
        populate_multicast_choices(form.multicast_channel)
        populate_interface_choices(form.multicast_interface) # Populate interfaces
        return render_template('stream_details.html', stream_key=key, stream=stream_data, form=form, current_year=datetime.utcnow().year)

    # --- API Endpoints (remain the same) ---
    @app_instance.route("/get_active_streams")
    def get_active_streams():
        try: streams = app_instance.stream_manager.get_active_streams(); return jsonify(streams)
        except Exception as e: logger.error(f"API Error get_active_streams: {e}"); return jsonify({"error": "Could not retrieve stream list"}), 500

    @app_instance.route("/api/stats/<stream_key>")
    def get_stats(stream_key):
        try: key = int(stream_key); assert 0 < key < 65536
        except: return jsonify({'error': f'Invalid key: {stream_key}'}), 400
        stats = app_instance.stream_manager.get_stream_statistics(stream_key)
        return jsonify(stats) if stats else (jsonify({'error': f'Stream ({stream_key}) not found'}), 404)

    @app_instance.route('/api/debug/<stream_key>')
    def get_debug_info(stream_key):
        try: key = int(stream_key); assert 0 < key < 65536
        except: return jsonify({'error': f'Invalid key: {stream_key}'}), 400
        debug_info = app_instance.stream_manager.get_debug_info(stream_key)
        if debug_info is None: return jsonify({'error': f'Error fetching info for {stream_key}'}), 500
        if 'error' in debug_info: status_code = 404 if 'not found' in debug_info['error'].lower() else 500; return jsonify(debug_info), status_code
        try: return jsonify(debug_info)
        except TypeError as e: logger.error(f"Serialization error debug info {stream_key}: {e}"); return jsonify({"error": f"Serialization error"}), 500

    @app_instance.route("/system_info")
    def system_info():
        try: info = get_system_info(); return jsonify(info)
        except Exception as e: logger.error(f"API Error system_info: {e}"); return jsonify({"error": "Could not retrieve system info"}), 500

    @app_instance.route('/health')
    def health_check():
        return "OK", 200

    # --- Network Test Routes (corrected network_test_api) ---
    @app_instance.route('/network_test')
    def network_test_page():
        form = NetworkTestForm(); location_info = None; regions = []
        if network_tester:
            try: location_info=network_tester.get_external_ip_and_location(); regions=network_tester.get_server_regions(); form.region.choices = [('','-- Select Region --')] + [(r,r) for r in regions if r]
            except Exception as e: logger.error(f"Error prep network test: {e}")
        else: flash("Network testing service unavailable.","warning")
        dummy_form = StreamForm() # For base template context
        populate_multicast_choices(dummy_form.multicast_channel)
        populate_interface_choices(dummy_form.multicast_interface) # Populate interfaces
        return render_template('network_test.html', form=form, base_form=dummy_form, location_info=location_info, regions=regions, current_year=datetime.utcnow().year)

    @app_instance.route('/api/network_test', methods=['POST'])
    def network_test_api():
        form = NetworkTestForm(request.form)
        if network_tester:
            try:
                form.region.choices = [('', '-- Select Region --')] + [(r, r) for r in network_tester.get_server_regions() if r]
            except Exception as e:
                logger.error(f"Fail populate region API: {e}")
        if form.validate():
            try:
                if not network_tester:
                    return jsonify({"error": "Network test service unavailable."}), 503
                location_info = network_tester.get_external_ip_and_location()
                result = network_tester.run_network_test(
                    mode=form.mode.data,
                    region=form.region.data,
                    manual_host=form.manual_host.data or None,
                    manual_port=form.manual_port.data,
                    manual_protocol=form.manual_protocol.data,
                    duration=form.duration.data,
                    bitrate=form.bitrate.data,
                    location_info=location_info
                )
                return jsonify(result or network_tester.get_fallback_results("Test returned None."))
            except Exception as e:
                logger.error(f"Net test API err: {e}", exc_info=True)
                return jsonify({"error": f"Test fail: {e}"}), 500
        else:
            errors = {f: e[0] for f, e in form.errors.items() if f != 'csrf_token'}
            msg = next(iter(errors.values()), "Invalid input")
            logger.warning(f"Net test validation fail: {errors}")
            return jsonify({"error": f"Validation failed: {msg}", "details": errors}), 400

    # --- End of register_routes function ---
