# wsgi.py - Should look something like this
from app import app
from waitress import serve
import os
import logging

# Configure logging if not already done in app/__init__.py
# logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s') # Example

if __name__ == "__main__":
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', 5000))
    threads = int(os.environ.get('THREADS', 4))
    flask_env = os.environ.get('FLASK_ENV', 'production')

    # Use Flask's logger or configure Waitress logger
    logger = logging.getLogger('waitress')
    logger.setLevel(logging.INFO)

    logger.info(f"Starting Waitress WSGI Server for SRT Streamer Enhanced ({flask_env} mode)")
    logger.info(f"Listening on http://{host}:{port}")
    logger.info(f"Using {threads} worker threads.")

    # Call waitress.serve
    serve(app, host=host, port=port, threads=threads)
