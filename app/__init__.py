# /opt/srt-streamer-enhanced/app/__init__.py
# Initializes the Flask application, configures logging, CSRF, and registers routes.

from flask import Flask
import os
import logging
from logging.handlers import RotatingFileHandler
from app.stream_manager import StreamManager
# Import CSRFProtect
from flask_wtf.csrf import CSRFProtect

# Configure logging
log_dir_standard = '/var/log/srt-streamer' # Standard log directory
logging.basicConfig(level=logging.INFO) # Basic config for root logger
logger = logging.getLogger() # Get root logger

# --- File Handler using standard path ---
try:
    # Create log directory if it doesn't exist
    if not os.path.exists(log_dir_standard):
        try:
            # Set permissions appropriate for the directory
            os.makedirs(log_dir_standard, mode=0o755, exist_ok=True)
            logger.info(f"Created log directory: {log_dir_standard}")
            # Optional: Set ownership if running as non-root and need specific user access
            # import pwd, grp
            # uid = pwd.getpwnam('your_run_user').pw_uid
            # gid = grp.getgrnam('your_run_group').gr_gid
            # os.chown(log_dir_standard, uid, gid)
        except Exception as dir_e:
            logger.error(f"Failed to create log directory {log_dir_standard}: {dir_e}. Logging to file might fail.")

    log_file_path = os.path.join(log_dir_standard, 'srt_streamer.log')

    # Use RotatingFileHandler for log rotation
    file_handler = RotatingFileHandler(
        log_file_path,
        maxBytes=10*1024*1024,  # 10MB per file
        backupCount=5          # Keep 5 backup files
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO) # Set level for file handler
    logger.addHandler(file_handler) # Add handler to the root logger
    logger.info(f"Logging to file: {log_file_path}")

except Exception as log_e:
    logger.error(f"Failed to set up file logging to {log_dir_standard}: {log_e}")
    logger.warning("File logging setup failed. Check permissions and path.")

# --- Initialize Flask App ---
app = Flask(__name__)

# ** IMPORTANT: Load SECRET_KEY from environment variable for production **
# Example for systemd service file: Environment="SECRET_KEY=your_very_strong_random_secret_key"
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    logger.critical("FATAL ERROR: SECRET_KEY environment variable is not set. Application will not start securely.")
    # Optionally, provide a default for development ONLY, but raise error/exit in production
    # app.config['SECRET_KEY'] = 'dev-secret-key-only-not-for-production'
    # logger.warning("SECURITY WARNING: Using insecure default SECRET_KEY for development.")
    raise ValueError("SECRET_KEY environment variable must be set for the application to run.")
elif app.config['SECRET_KEY'] == 'a5458bf94a5181014e17836e8af327ec479b236bf393d089': # Check against the example default in service file
    logger.warning("SECURITY WARNING: Using the example default SECRET_KEY. Generate a new strong key and set it via environment variable.")


# Load Media Folder from environment variable
app.config['MEDIA_FOLDER'] = os.environ.get('MEDIA_FOLDER', '/opt/srt-streamer-enhanced/media') # Default if not set
if not os.path.isdir(app.config['MEDIA_FOLDER']):
     logger.warning(f"Media folder '{app.config['MEDIA_FOLDER']}' does not exist or is not a directory.")
     # Decide if this is fatal or not. Maybe create it? For now, just warn.

# --- Initialize CSRF Protection ---
csrf = CSRFProtect(app)
logger.info("CSRF protection initialized.")

# --- Initialize Managers ---
# Ensure StreamManager is initialized *after* app config is set
# This line correctly passes the media folder path to the StreamManager constructor
# The TypeError previously observed originates from the StreamManager.__init__ definition itself
app.stream_manager = StreamManager(app.config['MEDIA_FOLDER'])

# --- Register Routes ---
# Import the function and call it, passing the app instance
from app.routes import register_routes
register_routes(app)
logger.info("Application routes registered.")

# --- Application Initialization Complete ---
# Use app.logger for Flask-specific logging if preferred after initialization
app.logger.info('SRT Streamer Enhanced Application initialized successfully.')

# --- REMOVED DUPLICATE HEALTH CHECK ---
# The health check route is now defined within app/routes.py
# @app.route('/health')
# def health_check():
#    return "OK", 200
# --- END REMOVED DUPLICATE ---

# Add any other application-level setup here if needed
