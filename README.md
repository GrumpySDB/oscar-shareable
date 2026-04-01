# OSCAR Shareable

OSCAR Shareable is a web-based, secure uploader and viewer for **OSCAR (Open Source CPAP Analysis Reporter)** data. It allows users to securely upload their CPAP and oximetry data to a private, isolated environment where they can then use OSCAR to analyze their results directly in their browser.

## 🚀 Key Features

- **Secure Sharing**: Generate tokenized, read-only sharing links to allow clinicians or peers to view specific OSCAR profiles.
- **Secure Data Upload**: Easy drag-and-drop or folder selection for CPAP SD card and oximetry data via the web UI.
- **Third-Party API Support**: Integrated API for hardware devices (like ESP32/CPAP-AutoSync) to perform incremental data synchronization.
- **Isolated User Sessions**: Each user session runs in its own dedicated, transient Docker container, ensuring maximum privacy and data isolation.
- **Full OSCAR Interface**: Access the complete OSCAR application via high-performance remote desktop (Selkies VNC) without installing anything locally.
- **Privacy First**: Designed for security with optional "Tinfoil Hat Mode" (client-side encryption) and strictly isolated storage.
- **Admin Management**: Built-in panel for managing users, invite codes, and system audit logs.

## 🏗️ Architecture Overview

OSCAR Shareable is composed of three primary layers:

1.  **Frontend**: A modern, responsive web interface built with Vite and vanilla JavaScript.
2.  **Backend (Secure Uploader)**: A high-performance Rust service built with **Axum**. It handles authentication, file synchronization, API requests, and dynamically manages the lifecycle of OSCAR Docker containers.
3.  **Visualization Layer**: Isolated Docker containers running the OSCAR desktop application, streamed to the browser using the [linuxserver.io Selkies VNC](https://docs.linuxserver.io/images/docker-baseimage-selkies/) base.

## 📂 Documentation

Detailed guides and specifications are available in the [docs/](docs/) directory:

- 📖 **[API Documentation](docs/API_DOCUMENTATION.md)**: Details on the Third-Party Upload API for hardware developers.
- 🛠️ **[Self-Hosting Guide](docs/SELF_HOSTING.md)**: Instructions for deploying OSCAR Shareable using Docker.
- 🔐 **[Privacy and Security](docs/SECURITY_PRIVACY.md)**: Information on our data handling and security posture.

## 🛠️ Tech Stack

- **Backend**: Rust (Axum, Tokio, SQLx, Bollard)
- **Frontend**: Vite, JavaScript, CSS3
- **Containerization**: Docker, Docker Compose
- **Database**: SQLite3
- **Proxy/Web Server**: Nginx (Internal)
- **Remote Desktop**: Selkies / WebRTC / WebGL

## 📜 Licensing and Attribution

This project is distributed under the **GNU GPL v3 License**.

### Significant Attributions

- **OSCAR**: Released under the GNU GPL v3 License.
- **Qt SDK**: Built using Qt SDK (Open Source Edition).
- **linuxserver.io**: The VNC infrastructure is powered by the [docker-baseimage-selkies](https://docs.linuxserver.io/images/docker-baseimage-selkies/) container.

### AI-Generated Content

Portions of this software and its documentation were created using **generative AI tools**. As such, the application may exhibit unexpected behavior in certain edge cases. Extensive testing has been performed to ensure it functions as designed.

## ⚠️ Disclaimer

This software is provided as-is. Users are responsible for their own data and compliance with local health data regulations. Please use responsibly.
