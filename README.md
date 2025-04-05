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
    * Dashboard with system info (CPU, Mem, Disk, IP, Uptime, Running User) and active stream overview.
    * Detailed stream view with live-updating charts (Chart.js) for Bitrate/RTT/Loss history, packet counters, connection status (incl. client IP for listeners), and debug info API.
* **Media Management:**
    * AJAX media browser modal lists `.ts` files from the `media/` folder.
    * Media Info page uses `ffprobe` or `mediainfo` for file details.
* **Web Interface:**
    * Built with Bootstrap 5, jQuery, Chart.js, Font Awesome (all served locally from `app/static/`).
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
    * `mcr-srt-streamer.service`: Manages the main application process (Waitress via `wsgi.py`), activating the Python virtual environment. Depends on `network-tuning.service`.
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

* **Operating System:** Debian/Ubuntu or Rocky Linux/RHEL 9+ (or similar Linux distributions with GStreamer 1.0+ support).
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
    * Install required system packages. **Choose the command block appropriate for your distribution.**
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
    * **RHEL / Rocky / Fedora 9+ Example:**
        ```bash
        # Ensure EPEL repository is enabled for iperf3 if needed
        # sudo dnf install epel-release
        sudo dnf update && sudo dnf install -y \
            python3 python3-pip python3-gobject gobject-introspection-devel \
            cairo-gobject-devel python3-devel pkgconf-pkg-config gcc \
            gstreamer1 gstreamer1-plugins-base gstreamer1-plugins-good \
            gstreamer1-plugins-bad-free gstreamer1-plugins-ugly-free gstreamer1-libav \
            nginx curl iperf3 iputils bind-utils ffmpeg mediainfo httpd-tools
        ```
        *(Use `yum` instead of `dnf` on older RHEL/CentOS 7)*

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
        # Set permissions (adjust user/group if service runs non-root)
        sudo chown -R root:root /opt/mcr-srt-streamer/media
        sudo chmod 755 /opt/mcr-srt-streamer/media
        sudo chmod 644 /opt/mcr-srt-streamer/media/*.ts
        ```
    * **Multicast Channels (`app/data/iptv_channels.json`):** Edit this file to define your multicast sources. It should be a JSON list of objects. The `name`, `address`, and `port` fields are used to populate the dropdown menu. The `source_ip` field is optional and currently *not* used by the pipeline but can be included for reference. Example structure:
        ```json
        [
          {
            "name": "Channel Name 1 HD",
            "address": "239.1.1.1",
            "port": 1234,
            "protocol": "udp",
            "source_ip": "10.0.0.1"
          },
          {
            "name": "Another Channel SD",
            "address": "239.1.1.2",
            "port": 1234,
            "protocol": "udp"
            // source_ip is optional
          }
        ]
        ```
    * **Log/Data Directories:** Create directories and ensure they are writable by the user the service will run as (e.g., `nginx` or `root`).
        ```bash
        sudo mkdir -p /var/log/srt-streamer /opt/mcr-srt-streamer/app/data
        # If running service as nginx:
        sudo chown -R nginx:nginx /var/log/srt-streamer /opt/mcr-srt-streamer/app/data
        # If running service as root (less secure):
        # sudo chown -R root:root /var/log/srt-streamer /opt/mcr-srt-streamer/app/data

        # Ensure necessary cache files exist (adjust owner if needed)
        sudo touch /opt/mcr-srt-streamer/app/data/external_ip_cache.json
        sudo touch /opt/mcr-srt-streamer/app/data/iperf3_export_servers.json
        sudo touch /opt/mcr-srt-streamer/app/data/iptv_channels.json # Create if not present
        # sudo chown your_user:your_group /opt/mcr-srt-streamer/app/data/*
        ```
    * **NGINX:**
        * Configure Nginx as a reverse proxy. Create a configuration file in `/etc/nginx/conf.d/` (e.g., `/etc/nginx/conf.d/mcr-srt-streamer.conf`) or `/etc/nginx/sites-available/` (and link to `sites-enabled`) with content similar to:
          ```nginx
          server {
              listen 80; # Or your desired port
              server_name your_server_domain_or_ip; # Replace with your server's name/IP

              # Basic Auth Settings
              auth_basic "Restricted Content";
              auth_basic_user_file /etc/nginx/.htpasswd; # Path to password file

              location / {
                  proxy_pass [http://127.0.0.1:5000](http://127.0.0.1:5000); # Forward to Waitress
                  proxy_set_header Host $host;
                  proxy_set_header X-Real-IP $remote_addr;
                  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                  proxy_set_header X-Forwarded-Proto $scheme;
                  proxy_connect_timeout 600s; # Increase timeouts if needed
                  proxy_send_timeout 600s;
                  proxy_read_timeout 600s;
              }

              # Optional: Serve static files directly via Nginx for performance
              location /static {
                  alias /opt/mcr-srt-streamer/app/static;
                  expires 7d;
                  add_header Cache-Control "public";
              }
          }
          ```
        * Create the Basic Auth password file. **Use a strong password and change the example user `admin`.**
            ```bash
            # Install httpd-tools/apache2-utils if not already done
            sudo htpasswd -c /etc/nginx/.htpasswd admin # Follow prompts for password
            # Secure permissions (find Nginx user, often nginx or www-data)
            NGINX_USER=$(ps aux | grep '[n]ginx: worker process' | head -n 1 | awk '{print $1}')
            [ -z "$NGINX_USER" ] && NGINX_USER=nginx # Default fallback
            sudo chown $NGINX_USER:$NGINX_USER /etc/nginx/.htpasswd
            sudo chmod 640 /etc/nginx/.htpasswd
            ```
        * Test Nginx configuration and restart:
            ```bash
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
    * **Network Tuning Service (`/etc/systemd/system/network-tuning.service`):** Create this file with the following content:
        ```ini
        [Unit]
        Description=Apply Network Settings for MCR SRT Streamer
        After=network.target
        # Ensure it runs before the main app service
        Before=mcr-srt-streamer.service
        ConditionFileIsExecutable=/opt/mcr-srt-streamer/network-tuning.sh

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        User=root
        Group=root
        ExecStart=/opt/mcr-srt-streamer/network-tuning.sh
        StandardOutput=journal
        StandardError=journal

        [Install]
        # This service is typically WantedBy the main service, not enabled directly
        ```
    * **Application Service (`/etc/systemd/system/mcr-srt-streamer.service`):** Create/Edit this file. **It is recommended to run as the `nginx` user for better integration and simpler permissions.**
        ```ini
        [Unit]
        Description=MCR SRT Streamer - Application Server (Waitress)
        After=network.target network-online.target network-tuning.service nginx.service
        # Ensure network tuning runs first if present
        Wants=network-tuning.service
        Requires=network-online.target

        [Service]
        Type=simple
        # Recommended: Run as nginx user. Ensure log/data dirs are owned by nginx (see step 4).
        User=nginx
        Group=nginx
        # Alternative: Run as root (less secure, easier permissions)
        # User=root
        # Group=root
        WorkingDirectory=/opt/mcr-srt-streamer
        # --- IMPORTANT: Paste your generated SECRET_KEY here ---
        Environment="SECRET_KEY=PASTE_YOUR_GENERATED_32_BYTE_HEX_KEY_HERE"
        # --- Other Environment Variables ---
        Environment="HOST=127.0.0.1"
        Environment="PORT=5000"
        Environment="THREADS=8" # Adjust based on server cores/load
        Environment="MEDIA_FOLDER=/opt/mcr-srt-streamer/media"
        Environment="FLASK_ENV=production"
        # --- Execution ---
        # Ensure the python3 in the venv is used
        ExecStart=/opt/venv/bin/python3 /opt/mcr-srt-streamer/wsgi.py
        Restart=on-failure
        RestartSec=5s
        TimeoutStopSec=30s
        KillMode=mixed
        StandardOutput=journal
        StandardError=journal

        # --- Security Hardening (Optional - Review paths carefully) ---
        # PrivateTmp=true
        # ProtectSystem=strict
        # ProtectHome=true
        # NoNewPrivileges=true
        # CapabilityBoundingSet=CAP_NET_BIND_SERVICE # Only needed if binding low ports as non-root
        # ReadWritePaths=/opt/mcr-srt-streamer/app/data /var/log/srt-streamer /opt/mcr-srt-streamer/media # Ensure service user can write here

        [Install]
        WantedBy=multi-user.target
        ```
    * **PASTE your generated `SECRET_KEY`** into the `Environment="SECRET_KEY=..."` line in `/etc/systemd/system/mcr-srt-streamer.service`.
    * **Set Permissions:** If you set `User=nginx`, ensure the `nginx` user owns the necessary directories:
        ```bash
        sudo chown -R nginx:nginx /opt/mcr-srt-streamer/app/data /var/log/srt-streamer /opt/mcr-srt-streamer/media
        ```
    * **Reload systemd, enable and start the main service:**
        ```bash
        sudo systemctl daemon-reload
        sudo systemctl enable mcr-srt-streamer.service # Service name matches file
        sudo systemctl start mcr-srt-streamer.service
        ```

6.  **SELinux (Rocky/RHEL/Fedora):** If Nginx gives 502 errors and `ausearch -m avc -ts recent` shows denials for nginx connecting to port 5000, allow the connection:
    ```bash
    sudo setsebool -P httpd_can_network_connect 1
    sudo systemctl restart nginx
    ```

7.  **Verify:**
    * Check service status: `systemctl status mcr-srt-streamer.service network-tuning.service`
    * Check logs: `journalctl -u mcr-srt-streamer.service`, `/var/log/srt-streamer/srt_streamer.log`
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

* **SRT Latency:** Buffer for jitter/retransmissions. Set based on RTT (e.g., 4x RTT) & loss. Higher value used if Sender/Receiver differ.
* **Bandwidth Overhead:** Reserve extra bandwidth (1-99%) for recovery. Higher loss needs more overhead. Start ~25% and adjust based on stats.
* **TSParse Smoothing Latency:** Adjusts internal buffer in `tsparse` to stabilize PCR timing, crucial for professional decoders. 20-30ms recommended.
* **Quality of Service (QoS):** `qos=true` flag attempts to set DSCP bits; effectiveness depends on network support.
* **Monitoring (Stream Details Page):** Use stats like buffer levels and packet loss/retransmits to fine-tune Latency and Overhead settings based on Haivision guide principles.

## License

This project is licensed under the **BSD 2-Clause License**. See the `LICENSE` file for details.

## References

* Haivision SRT Protocol Deployment Guide v1.5.x (Included in `/docs`)
* [SRT Alliance](https://www.srtalliance.org/)
* [SRT GitHub Repository](https://github.com/Haivision/srt)
* [GStreamer Documentation](https://gstreamer.freedesktop.org/documentation/)

---
