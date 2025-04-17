# /opt/srt-streamer-enhanced/app/__init__.py

from flask import Flask
import os
import logging
from logging.handlers import RotatingFileHandler
from app.stream_manager import StreamManager

# Import CSRFProtect
from flask_wtf.csrf import CSRFProtect

# Import SMPTE2022-7 components
from app.smpte_routes import smpte_bp
from app.smpte_manager import SMPTEManager

# Configure logging
log_dir_standard = "/var/log/srt-streamer"  # Standard log directory
logging.basicConfig(level=logging.INFO)  # Basic config for root logger
logger = logging.getLogger()  # Get root logger

# --- File Handler using standard path ---
try:
    # Create log directory if it doesn't exist
    if not os.path.exists(log_dir_standard):
        try:
            # Set permissions appropriate for the directory
            os.makedirs(log_dir_standard, mode=0o755, exist_ok=True)
            logger.info(f"Created log directory: {log_dir_standard}")
        except Exception as dir_e:
            logger.error(
                f"Failed to create log directory {log_dir_standard}: {dir_e}. Logging to file might fail."
            )

    log_file_path = os.path.join(log_dir_standard, "srt_streamer.log")

    # Use RotatingFileHandler for log rotation
    file_handler = RotatingFileHandler(
        log_file_path,
        maxBytes=10 * 1024 * 1024,  # 10MB per file
        backupCount=5,  # Keep 5 backup files
    )
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
        )
    )
    file_handler.setLevel(logging.INFO)  # Set level for file handler
    logger.addHandler(file_handler)  # Add handler to the root logger
    logger.info(f"Logging to file: {log_file_path}")

except Exception as log_e:
    logger.error(f"Failed to set up file logging to {log_dir_standard}: {log_e}")
    logger.warning("File logging setup failed. Check permissions and path.")

# --- Initialize Flask App ---
app = Flask(__name__)

# ** IMPORTANT: Load SECRET_KEY from environment variable for production **
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    logger.critical(
        "FATAL ERROR: SECRET_KEY environment variable is not set. Application will not start securely."
    )
    raise ValueError(
        "SECRET_KEY environment variable must be set for the application to run."
    )
elif (
    app.config["SECRET_KEY"] == "a5458bf94a5181014e17836e8af327ec479b236bf393d089"
):  # Check against example
    logger.warning(
        "SECURITY WARNING: Using the example default SECRET_KEY. Generate a new strong key and set it via environment variable."
    )


# Load Media Folder from environment variable
app.config["MEDIA_FOLDER"] = os.environ.get(
    "MEDIA_FOLDER",
    "/opt/mcr-srt-streamer/media",  # Adjusted default to match structure shown previously
)
if not os.path.isdir(app.config["MEDIA_FOLDER"]):
    logger.warning(
        f"Media folder '{app.config['MEDIA_FOLDER']}' does not exist or is not a directory."
    )

# --- Initialize Managers ---
# Ensure StreamManager is initialized *after* app config is set
app.stream_manager = StreamManager(app.config["MEDIA_FOLDER"])

app.smpte_manager = SMPTEManager(main_stream_manager_ref=app.stream_manager)
logger.info("Initialized SMPTEManager.")
# ------------------------------------------------------

# --- Register Blueprints ---
# Import and register blueprints BEFORE initializing CSRF fully
from app.routes import register_routes
from app.api_routes import api_bp  # <--- Import the API blueprint

register_routes(app)  # Register your standard web routes
app.register_blueprint(
    api_bp
)  # <--- Register the API blueprint (default prefix is /api)
logger.info("Registered web routes and API blueprint under /api")

app.register_blueprint(smpte_bp)  # Register the SMPTE blueprint
logger.info("Registered SMPTE 2022-7 blueprint under /smpte2022_7")
# csrf.exempt(smpte_bp) # Uncomment if API endpoints are added to smpte_bp later

# --- Initialize CSRF Protection AFTER blueprints ---
csrf = CSRFProtect()
# Exclude the API blueprint from CSRF protection by name
csrf.exempt(api_bp)
csrf.init_app(app)  # Initialize CSRF protection for the rest of the app
logger.info("CSRF protection initialized, API blueprint exempted.")


# --- Application Initialization Complete ---
app.logger.info(
    "SRT Streamer Enhanced Application initialized successfully (with API and SMPTE)."
)

# Add any other application-level setup here if needed
