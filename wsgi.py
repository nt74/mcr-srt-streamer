# /opt/mcr-srt-streamer/wsgi.py

# IMPORTANT: gevent monkey-patching must happen before any other modules are imported.
# This makes standard libraries (like threading, socket) compatible with gevent.
try:
    import gevent.monkey

    gevent.monkey.patch_all()
    print("Gevent monkey-patch applied.")
except ImportError:
    print("Gevent not found, skipping monkey-patching. Functionality may be affected.")


from app import app

# This code block will run when Gunicorn loads this file as a module.
# It accesses the manager instances from the created 'app' object and
# starts their non-blocking background loops in separate greenlets.
# Since we use --workers 1, this will only happen once.
if __name__ != "__main__":
    if hasattr(app, "stream_manager") and hasattr(
        app.stream_manager, "start_glib_loop"
    ):
        print("Starting StreamManager GLib loop...")
        app.stream_manager.start_glib_loop()
    if hasattr(app, "smpte_manager") and hasattr(app.smpte_manager, "start_glib_loop"):
        print("Starting SMPTEManager GLib loop...")
        app.smpte_manager.start_glib_loop()
