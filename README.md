# MCR SRT Streamer

## Description

`mcr-srt-streamer` is a tool for testing SRT (Secure Reliable Transport) listeners and callers, optimized for professional broadcast workflows (e.g., DVB transport streams). Built with Python, Flask, GStreamer, and Bootstrap 5 (with SVT color theme), it provides a web interface to manage and monitor multiple SRT streams originating from local Transport Stream (`.ts`) files or UDP multicast inputs.

The core functionality uses GStreamer pipelines (e.g., `filesrc ! tsparse ! srtsink` or `udpsrc ! tsparse ! srtsink`) configured for stable TS-over-SRT streaming. It includes network testing tools (`ping`, optional `iperf3`) to provide SRT configuration recommendations (Latency, Overhead) based on the Haivision SRT Deployment Guide. The web interface uses Bootstrap 5 (local assets), jQuery (local), and Chart.js (local) for a responsive experience suitable for standalone/firewalled environments.

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
* **Integrated Network Testing (Configurable Mechanism):**
    * **Mechanism Selection:** Controlled via `NETWORK_TEST_MECHANISM` environment variable (`ping_only` or `iperf`).
    * **`ping_only` Mode (Default):**
        * Uses the full public iperf3 server list (`app/data/iperf3_export_servers.json`).
        * Performs **only** `ping` tests to measure RTT. Finds closest/regional servers based on RTT.
        * Calculates SRT recommendations using measured RTT and a predefined assumed loss percentage (`ASSUMED_LOSS_FOR_TCP_FALLBACK` in `network_test.py`, default 7.0%).
        * Does **not** require `iperf3` to be installed or accessible. Suitable for firewall-restricted environments.
    * **`iperf` Mode:**
        * Requires the `iperf-server-check` background job (systemd timer/service) to be configured and running periodically to generate `app/data/udp_safe_servers.json`.
        * Prioritizes using the filtered `udp_safe_servers.json` list for tests (falls back to the full list if the safe list is missing or outdated).
        * Performs `ping` tests for RTT.
        * Performs `iperf3` tests:
            * **Auto (Closest/Regional):** UDP client test (fixed parameters) against selected server(s) from the chosen list.
            * **Manual:** User-selected TCP or UDP test against the specified server.
        * Calculates SRT recommendations using measured RTT and iperf3 metrics (Loss/Jitter from UDP, Bandwidth from UDP/TCP). Falls back to RTT + assumed loss if `iperf3` fails.
        * Requires `iperf3` command to be installed and accessible.
    * **Common Features:**
        * GeoIP lookup to determine local region.
        * User selection of test mode (Closest, Regional, Manual).
        * Haivision-Based Recommendations: Uses derived principles from Haivision SRT Deployment Guide.
        * Apply Settings: Button to pre-fill Listener form with recommendations.
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
    * `NetworkTester` (`network_test.py`): Runs ping/iperf3 tests based on configured mechanism.
    * `utils.py`: Provides system info & network interface detection.
    * `forms.py`: Defines web forms (Listener, Caller, Network Test).
    * `routes.py`: Handles web requests and UI logic. Reads `NETWORK_TEST_MECHANISM`.
    * `dvb_config.py`: Stores DVB-specific SRT parameters.
    * `test_iperf_servers.py`: Standalone script (run by background job) to test UDP servers and generate safe list.
    * Logging: Configured in `__init__.py`, logs to `/var/log/srt-streamer/srt_streamer.log`.
    * Data/Cache: Uses `app/data/` for IPTV channels, full iperf3 server list cache, UDP safe server list, external IP cache.
2.  **Frontend (NGINX):** Recommended setup (same as before).
3.  **Service Management (Systemd):** Recommended setup uses up to three systemd units:
    * `network-tuning.service`: Runs `network-tuning.sh` at boot (optional).
    * `mcr-srt-streamer.service`: Manages the main application process. Reads `NETWORK_TEST_MECHANISM` env var.
    * `iperf-server-check.timer` & `.service`: Periodically runs `test_iperf_servers.py` to generate the UDP safe list (required *only* if using `NETWORK_TEST_MECHANISM="iperf"`).
4.  **GStreamer Pipeline Structure (Example):** (Same as before).

## System Requirements

* **Operating System:** Debian/Ubuntu or Rocky Linux/RHEL 9+ (or similar).
* **RAM:** Recommend ~1 GB per simultaneous stream.
* **CPU/GPU:** Low CPU usage expected.
* **Network:** Stable connection. Network tuning (`network-tuning.sh`) recommended.
* **Dependencies:** Ensure all tools listed in "Technology Stack" (`ping`, `iperf3`, `ffmpeg`, `mediainfo` etc.) are installed if using features that rely on them. `iperf3` is only needed if `NETWORK_TEST_MECHANISM="iperf"`.

## Installation Guide

*(Assumes default path `/opt/mcr-srt-streamer`.)*

1.  **Get the Code:** (Same as before).
2.  **Install System Dependencies:** (Same as before, ensure `iperf3` is installed if planning to use `iperf` mechanism).
3.  **Set Up Python Environment:** (Same as before).
4.  **Configure Application:**
    * **Media Files:** (Same as before).
    * **Multicast Channels (`app/data/iptv_channels.json`):** (Same as before).
    * **Log/Data Directories:** (Same as before).
    * **NGINX:** (Same as before).
    * **Flask Secret Key:** (Same as before).
    * **Network Test Mechanism (Environment Variable):** Decide which mechanism to use:
        * `ping_only` (Default): Only uses ping, safer in restricted environments.
        * `iperf`: Uses ping and iperf3 (requires background job and `iperf3` installation).
        * Set this in the main application's systemd service file (see Step 5).

5.  **Set Up Systemd Services (Recommended):**
    * Ensure scripts are executable:
        ```bash
        sudo chmod +x /opt/mcr-srt-streamer/network-tuning.sh
        sudo chmod +x /opt/mcr-srt-streamer/test_iperf_servers.py # Needed for iperf mechanism
        ```
    * **Network Tuning Service (`/etc/systemd/system/network-tuning.service`):** (Same content as before).
    * **Application Service (`/etc/systemd/system/mcr-srt-streamer.service`):** Create/Edit this file. **Add the `NETWORK_TEST_MECHANISM` environment variable.**
        ```ini
        [Unit]
        Description=MCR SRT Streamer - Application Server (Waitress)
        After=network.target network-online.target network-tuning.service nginx.service
        Wants=network-tuning.service
        Requires=network-online.target

        [Service]
        Type=simple
        User=nginx # Or root
        Group=nginx # Or root
        WorkingDirectory=/opt/mcr-srt-streamer
        Environment="SECRET_KEY=PASTE_YOUR_GENERATED_32_BYTE_HEX_KEY_HERE"
        Environment="HOST=127.0.0.1"
        Environment="PORT=5000"
        Environment="THREADS=8"
        Environment="MEDIA_FOLDER=/opt/mcr-srt-streamer/media"
        Environment="FLASK_ENV=production"
        # *** Choose and set the Network Test Mechanism ***
        # Option 1: Ping Only (Default, safer) - No iperf3 needed, no background job needed
        Environment="NETWORK_TEST_MECHANISM=ping_only"
        # Option 2: Enable iperf3 (Requires iperf3 install & background job below)
        # Environment="NETWORK_TEST_MECHANISM=iperf"

        ExecStart=/opt/venv/bin/python3 /opt/mcr-srt-streamer/wsgi.py
        Restart=on-failure
        RestartSec=5s
        TimeoutStopSec=30s
        KillMode=mixed
        StandardOutput=journal
        StandardError=journal
        # Optional security hardening...

        [Install]
        WantedBy=multi-user.target
        ```
    * **PASTE your `SECRET_KEY`**. **CHOOSE the desired `NETWORK_TEST_MECHANISM`**. Set user permissions if needed.
    * **UDP Server Check Background Job (Optional - ONLY needed if `NETWORK_TEST_MECHANISM="iperf"`):**
        * Create `/etc/systemd/system/iperf-server-check.service`:
            ```ini
            [Unit]
            Description=Periodically check iperf3 UDP servers for MCR SRT Streamer
            Wants=network-online.target
            After=network-online.target

            [Service]
            Type=oneshot
            User=root # Or same user as main app service if permissions allow
            Group=root
            WorkingDirectory=/opt/mcr-srt-streamer
            ExecStart=/opt/venv/bin/python3 /opt/mcr-srt-streamer/test_iperf_servers.py
            StandardOutput=journal+console
            StandardError=journal+console

            [Install]
            WantedBy=multi-user.target
            ```
        * Create `/etc/systemd/system/iperf-server-check.timer`:
            ```ini
            [Unit]
            Description=Run iperf-server-check daily

            [Timer]
            OnCalendar=*-*-* 03:00:00 # Daily at 3 AM
            RandomizedDelaySec=1h
            Persistent=true
            Unit=iperf-server-check.service

            [Install]
            WantedBy=timers.target
            ```
        * Enable the timer *only if using `iperf` mechanism*:
            ```bash
            # Only run these if NETWORK_TEST_MECHANISM is set to "iperf"
            sudo systemctl daemon-reload
            sudo systemctl enable --now iperf-server-check.timer
            # Run once manually to generate initial list:
            # sudo systemctl start iperf-server-check.service
            ```
    * **Reload systemd, enable and start the main service:**
        ```bash
        sudo systemctl daemon-reload
        sudo systemctl enable mcr-srt-streamer.service
        sudo systemctl restart mcr-srt-streamer.service # Use restart to apply env var changes
        ```
6.  **SELinux (Rocky/RHEL/Fedora):** (Same as before).
7.  **Verify:** (Same as before).

## Usage Workflow

1.  **Access & Login:** (Same as before).
2.  **Dashboard (`/`):** (Same as before).
3.  **Start Caller (`/caller`):** (Same as before).
4.  **Network Test (`/network_test`):**
    * View the active mechanism (Ping Only or iperf Enabled).
    * Select mode (Closest, Regional, Manual).
    * Run test. Results (RTT, Loss, Jitter, Bandwidth) depend on the active mechanism. `ping_only` will show RTT and use assumed loss; `iperf` will attempt full tests using the safe list.
    * Click "Apply..." to pre-fill Listener form.
5.  **View Details (`/stream/<key>`):** (Same as before).
6.  **Stop Streams:** (Same as before).

## Configuration & Tuning Tips

* **Network Test Mechanism:** Choose `ping_only` via `NETWORK_TEST_MECHANISM` env var if `iperf3` is blocked or unreliable. Choose `iperf` for potentially more accurate UDP metrics, but ensure the background job (`iperf-server-check`) is set up and running.
* **SRT Latency:** (Same as before).
* **Bandwidth Overhead:** (Same as before).
* **TSParse Smoothing Latency:** (Same as before).
* **Quality of Service (QoS):** (Same as before).
* **Monitoring (Stream Details Page):** (Same as before).

## License

This project is licensed under the **BSD 2-Clause License**. See the `LICENSE` file for details.

## References

* Haivision SRT Protocol Deployment Guide v1.5.x (Included in `/docs`)
* [SRT Alliance](https://www.srtalliance.org/)
* [SRT GitHub Repository](https://github.com/Haivision/srt)
* [GStreamer Documentation](https://gstreamer.freedesktop.org/documentation/)

---
