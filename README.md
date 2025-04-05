# MCR SRT Streamer

## Description

`mcr-srt-streamer` is a tool for testing SRT (Secure Reliable Transport) listeners and callers, optimized for professional broadcast workflows (e.g., DVB transport streams). Built with Python, Flask, GStreamer, and Bootstrap 5 (with SVT color theme), it provides a web interface to manage and monitor multiple SRT streams originating from local Transport Stream (`.ts`) files or UDP multicast inputs.

The core functionality uses GStreamer pipelines (e.g., `filesrc ! tsparse ! srtsink` or `udpsrc ! tsparse ! srtsink`) configured for stable TS-over-SRT streaming. It includes network testing tools (`ping`, `iperf3`) to provide SRT configuration recommendations (Latency, Overhead) based on the Haivision SRT Deployment Guide. The web interface uses Bootstrap 5 (local assets), jQuery (local), and Chart.js (local) for a responsive experience suitable for standalone/firewalled environments.

## Features

* **Multi-Stream Hosting:** Host multiple simultaneous SRT streams (default limit configurable).
* **Listener & Caller Modes:** Start streams in Listener (server) or Caller (client) mode via dedicated web UI forms.
* **Multiple Input Sources:**
    * **File:** Stream from local `.ts` files located in the `media/` directory.
    * **Multicast:** Stream from UDP multicast sources defined in `app/data/iptv_channels.json`.
        * Selectable network interface for receiving multicast (`Auto` uses OS default).
* **GStreamer Pipeline (`... ! tsparse ! srtsink`):**
    * Reads from `filesrc` or `udpsrc`.
    * Parses Transport Streams using `tsparse` with timestamping (`set-timestamps=true`), 7-packet alignment (`alignment=7`), and configurable smoothing latency (`smoothing-latency=...`) to reduce PCR jitter.
    * Transmits using `srtsink` configured with user-defined latency, overhead, encryption, Quality of Service (QoS) flag, and specific DVB/SRT parameters (large buffers, `tlpktdrop`, NAK reports) via `app/dvb_config.py`.
* **DVB Compliance Focus:** Applies specific SRT parameters (`dvb_config.py`) and `tsparse` settings suitable for DVB transport stream carriage.
* **Configurable Stream Parameters (UI):**
    * **Listener Port:** Select from predefined range (10001-10010).
    * **Target Host/Port:** Specify for Caller mode.
    * **TSParse Smoothing Latency:** Selectable (e.g., 20ms, 30ms).
    * **SRT Latency:** 20-8000ms.
    * **SRT Overhead:** 1-99%.
    * **Encryption:** None, AES-128, AES-256 (requires 10-79 char passphrase).
    * **QoS Flag:** Enable/disable `qos=true|false` in SRT URI.
* **Accurate Stats Parsing:** Parses detailed SRT statistics from `srtsink` for both Listener and Caller modes.
* **Integrated Network Testing:**
    * Measures RTT using `ping`.
    * Measures Bandwidth using `iperf3` (TCP for Auto modes, selectable TCP/UDP for Manual). Loss/Jitter only reliably measured via UDP.
    * **Modes:** Auto (Closest server via GeoIP, TCP), Auto (Regional via GeoIP, TCP), Manual (User-specified server, TCP or UDP).
    * **Haivision-Based Recommendations:** Recommends SRT Latency/Overhead based on measured RTT and Loss (Loss % is estimated when using TCP, potentially leading to higher recommendations). Derived from Haivision SRT Deployment Guide principles.
    * **Apply Settings:** Button to pre-fill Listener form with recommendations.
* **Real-time Monitoring & Statistics:**
    * Dashboard with system info and active stream overview.
    * Detailed stream view with live-updating charts (Chart.js) for Bitrate/RTT/Loss history, packet counters, connection status (incl. client IP for listeners), and debug info API.
* **Media Management:**
    * AJAX media browser modal lists `.ts` files from the `media/` folder.
    * Media Info page uses `ffprobe` or `mediainfo` for file details.
* **Web Interface:**
    * Built with Bootstrap 5, jQuery, Chart.js (served locally).
    * Uses custom SVT color theme defined in `app/static/css/style.css`.
    * AJAX updates for system info & streams.
* **Secure Access & Operations:**
    * Recommended NGINX frontend for Basic Authentication.
    * Flask-WTF CSRF Protection enabled.
    * Requires a strong `SECRET_KEY` environment variable.
* **Health Check:** Endpoint at `/health`.
* **Standalone Operation:** Designed to run without external CDN dependencies (CSS, JS, Fonts served locally).

## Technology Stack

* **Backend:** Python 3, Flask, Flask-WTF, Waitress, GStreamer 1.0 (via PyGObject), `requests`, `psutil`.
* **Frontend:** Bootstrap 5, jQuery, Chart.js, Font Awesome (all served locally from `app/static/`), Jinja2, Custom JS.
* **Supporting:** NGINX (recommended for proxy & auth), `ffmpeg` (for ffprobe), `mediainfo`, `iperf3`, `ping` (iputils-ping), `curl`, `dig` (dnsutils/bind-utils), Systemd (recommended for service management).

## Architecture Overview

1.  **Backend (`app/`):** Python/Flask application.
    * `StreamManager` (`stream_manager.py`): Controls GStreamer pipelines.
    * `NetworkTester` (`network_test.py`): Runs ping/iperf3 tests.
    * `utils.py`: Provides system info & network interface detection.
    * `forms.py`: Defines web forms (Listener, Caller, Network Test).
    * `routes.py`: Handles web requests and UI logic.
    * `dvb_config.py`: Stores DVB-specific SRT parameters.
    * Logging: Configured in `__init__.py`, logs to `/var/log/srt-streamer/srt_streamer.log` (standard path).
    * Data/Cache: Uses `app/data/` for IPTV channels, iperf3 server list cache, external IP cache.
2.  **Frontend (NGINX):** Recommended setup.
    * Acts as a reverse proxy for the Waitress server (`http://127.0.0.1:5000`).
    * Provides Basic Authentication via `.htpasswd`.
    * Serves static files (`css`, `js`, `fonts`, `images`) from `app/static/`.
3.  **Service Management (Systemd):** Recommended setup uses two systemd units:
    * `network-tuning.service`: Runs `network-tuning.sh` at boot to apply network `sysctl` optimizations (optional but recommended).
    * `srt-streamer.service`: Manages the main application process (Waitress via `wsgi.py`), activating the Python virtual environment. Depends on `network-tuning.service`.
4.  **GStreamer Pipeline Structure (Example):**
    * **File Input:**
        ```gst-pipeline
        filesrc location="..." ! tsparse name="tsparse_F..." ... smoothing-latency=30000 ... ! srtsink name="srtsink_F..." uri="srt://..." ...
        ```
    * **Multicast Input:**
        ```gst-pipeline
        udpsrc uri="udp://..." multicast-iface="..." ... ! tsparse name="tsparse_M..." ... smoothing-latency=30000 ... ! srtsink name="srtsink_M..." uri="srt://..." ...
        ```
    * `tsparse` options include `set-timestamps=true`, `alignment=7`, `parse-private-sections=true`, and the selected `smoothing-latency`.
    * `srtsink` URI includes `mode`, `latency`, `overheadbandwidth`, `passphrase`, `pbkeylen`, `qos`, and DVB parameters from `dvb_config.py`.

## System Requirements

* **Operating System:** Debian/Ubuntu or Rocky Linux/RHEL (or similar Linux distributions with GStreamer 1.0+ support).
* **RAM:** Recommend ~1 GB per simultaneous stream (e.g., >= 10 GB for 10 streams).
* **CPU/GPU:** Low CPU usage expected. GPU is not used.
* **Network:** Stable connection with sufficient bandwidth (stream bitrate + SRT overhead). Network tuning (`network-tuning.sh`) is recommended for optimal performance.

## Installation Guide

*(Assumes default installation path `/opt/mcr-srt-streamer`. Adapt if using a different path.)*

1.  **Get the Code:**
    * Clone repository or download source to `/opt/mcr-srt-streamer`.
        ```bash
        # Example using git (replace URL with your actual repo URL)
        sudo git clone https://your-github-repo/mcr-srt-streamer.git /opt/mcr-srt-streamer
        cd /opt/mcr-srt-streamer
        ```

2.  **Install System Dependencies:**
    * Install required system packages.
    * **Debian / Ubuntu Example:**
        ```bash
        sudo apt update && sudo apt install -y \
            python3 python3-pip python3-venv python3-gi gir1.2-gobject-2.0 \
            gir1.2-glib-2.0 libgirepository1.0-dev \
            gcc libcairo2-dev pkg-config python3-dev \
            gir1.2-gstreamer-1.0 gir1.2-gst-plugins-base-1.0 \
            gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
            gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly \
            gstreamer1.0-tools gstreamer1.0-libav \
            nginx curl iperf3 iputils-ping dnsutils ffmpeg mediainfo apache2-utils
        ```
    * **RHEL / Rocky / Fedora Example:**
        ```bash
        sudo dnf update && sudo dnf install -y \
            python3 python3-pip python3-gobject gobject-introspection-devel \
            cairo-gobject-devel python3-devel pkgconf-pkg-config gcc \
            gstreamer1 gstreamer1-plugins-base gstreamer1-plugins-good \
            gstreamer1-plugins-bad-free gstreamer1-plugins-ugly-free gstreamer1-libav \
            nginx curl iperf3 iputils bind-utils ffmpeg mediainfo httpd-tools
        ```
        *(Use `yum` on older RHEL/CentOS)*

3.  **Set Up Python Environment:**
    * Create and activate a Python virtual environment (e.g., `/opt/venv`).
        ```bash
        sudo python3 -m venv /opt/venv
        source /opt/venv/bin/activate
        ```
    * Install Python packages:
        ```bash
        # Navigate to the app directory first
        cd /opt/mcr-srt-streamer
        pip install -r requirements.txt
        ```
    * Deactivate:
        ```bash
        deactivate
        ```

4.  **Configure Application:**
    * **Media Files:** Place `.ts` files into `/opt/mcr-srt-streamer/media/`.
        ```bash
        sudo mkdir -p /opt/mcr-srt-streamer/media
        # Copy your .ts files here
        sudo chown -R root:root /opt/mcr-srt-streamer/media # Adjust owner if service runs non-root
        sudo chmod 755 /opt/mcr-srt-streamer/media
        sudo chmod 644 /opt/mcr-srt-streamer/media/*.ts
        ```
    * **Multicast Channels:** Edit `app/data/iptv_channels.json` to define your multicast sources if using that input type.
    * **Log/Data Directories:** Ensure writable by the service user (default: root).
        ```bash
        sudo mkdir -p /var/log/srt-streamer /opt/mcr-srt-streamer/app/data
        sudo chown root:root /var/log/srt-streamer /opt/mcr-srt-streamer/app/data
        # Ensure data files are present/writable if needed by utils.py/network_test.py
        sudo touch /opt/mcr-srt-streamer/app/data/external_ip.txt
        sudo touch /opt/mcr-srt-streamer/app/data/external_ip_cache.json
        # Adjust ownership if service user is not root
        # sudo chown your_user:your_group /opt/mcr-srt-streamer/app/data/*
        ```
    * **NGINX:**
        * Configure Nginx as a reverse proxy (see example `nginx.conf` if provided).
        * Create Basic Auth password file (e.g., `/etc/nginx/.htpasswd`). **Use a strong password and change the user `admin`.**
            ```bash
            sudo htpasswd -c /etc/nginx/.htpasswd admin
            # Secure permissions (adjust NGINX_USER if needed)
            NGINX_USER=$(ps aux | grep '[n]ginx: worker process' | head -n 1 | awk '{print $1}')
            [ -z "$NGINX_USER" ] && NGINX_USER=nginx # Default fallback
            sudo chown $NGINX_USER:$NGINX_USER /etc/nginx/.htpasswd
            sudo chmod 640 /etc/nginx/.htpasswd
            ```
        * Enable the Nginx site config and restart Nginx.
            ```bash
            # Example: sudo ln -s /opt/mcr-srt-streamer/nginx.conf /etc/nginx/sites-enabled/mcr-srt-streamer
            sudo nginx -t
            sudo systemctl restart nginx
            ```
    * **Flask Secret Key:** Generate a strong key and **copy it**.
        ```bash
        openssl rand -hex 32
        ```

5.  **Set Up Systemd Services (Recommended):**
    * Ensure `network-tuning.sh` is executable:
        ```bash
        sudo chmod +x /opt/mcr-srt-streamer/network-tuning.sh
        ```
    * Create `/etc/systemd/system/network-tuning.service` (as shown in original README).
    * Create/Edit `/etc/systemd/system/srt-streamer.service` (as shown in original README):
        * **PASTE your generated `SECRET_KEY`** into the `Environment="SECRET_KEY=..."` line.
        * Ensure `WorkingDirectory`, `Environment="MEDIA_FOLDER"`, and `ExecStart` paths are correct.
    * Reload systemd and enable/start the main service:
        ```bash
        sudo systemctl daemon-reload
        sudo systemctl enable srt-streamer.service
        sudo systemctl start srt-streamer.service
        ```

6.  **Verify:**
    * Check service status: `systemctl status srt-streamer.service network-tuning.service`
    * Check logs: `journalctl -u srt-streamer.service`, `/var/log/srt-streamer/srt_streamer.log`
    * Access the web UI via the Nginx address and log in.

## Usage Workflow

1.  **Access & Login:** Open the app URL, log in via NGINX Basic Auth.
2.  **Dashboard (`/`):**
    * View system info and active streams.
    * Start **Listener** streams: Select input (Multicast/File), specify source details (channel/interface or file path via Browse modal), select port (10001-10010), set smoothing, latency (20-8000ms), overhead (1-99%), encryption, and QoS flag.
3.  **Start Caller (`/caller`):**
    * Start **Caller** streams: Specify target Host/IP and Port, select input (Multicast/File) & source details, set smoothing, latency (20-8000ms), overhead (1-99%), encryption, and QoS flag.
4.  **Network Test (`/network_test`):**
    * Select mode (Closest [TCP], Regional [TCP], Manual [TCP/UDP]).
    * Run test, view RTT, Bandwidth, Loss/Jitter (UDP only), and Haivision-based recommendations.
    * Click "Apply..." to pre-fill Listener form on the dashboard.
5.  **View Details (`/stream/<key>`):**
    * Click "Details" on the dashboard.
    * Monitor live stats (Bitrate, RTT, Loss %, Packet Counters, etc.) via text and charts.
    * View connection status (e.g., Waiting, Connected [Client IP], Error).
    * Access raw debug info via Debug button.
6.  **Stop Streams:** Use "Stop" buttons on the dashboard or details page.

## Configuration & Tuning Tips

* **SRT Latency:** Buffer for jitter/retransmissions. Set based on RTT (e.g., 4x RTT) & loss. [cite: 383] Higher value used if Sender/Receiver differ[cite: 386].
* **Bandwidth Overhead:** Reserve extra bandwidth (1-99%) for recovery[cite: 362]. Higher loss needs more overhead[cite: 366]. Start ~25% and adjust based on stats[cite: 384].
* **TSParse Smoothing Latency:** Adjusts internal buffer in `tsparse` to stabilize PCR timing, crucial for professional decoders. 20-30ms recommended.
* **Quality of Service (QoS):** `qos=true` flag attempts to set DSCP bits; effectiveness depends on network support[cite: 458].
* **Monitoring (Stream Details Page):**
    * High *Send* buffer levels may indicate bitrate too high or overhead too low. Spikes might need more Latency[cite: 474, 467].
    * Frequent drops to zero in *Receive* buffer suggest bitrate too high. Occasional drops might need more Latency[cite: 471, 472].
    * Monitor Lost/Skipped Packets. Increase Latency for slow/jitter issues. Lower Bitrate or increase Overhead for large bursts/jumps[cite: 455, 456].

## License

This project is licensed under the **BSD 2-Clause License**. See the `LICENSE` file for details.

## References

* Haivision SRT Protocol Deployment Guide v1.5.x (Included in `/docs`) [cite: 2]
* [SRT Alliance](https://www.srtalliance.org/)
* [SRT GitHub Repository](https://github.com/Haivision/srt)
* [GStreamer Documentation](https://gstreamer.freedesktop.org/documentation/)

---
