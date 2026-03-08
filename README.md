# OSCAR Shareable

OSCAR Shareable is a web-based, secure uploader and viewer for OSCAR (Open Source CPAP Analysis Reporter) data. It allows users to securely upload their CPAP and oximetry data to a private, isolated environment where they can then use OSCAR to analyze their results.

## Purpose

The project's primary goal is to provide a user-friendly and secure way for CPAP users to share their data with clinicians or peers for analysis, without the need for manual file transfers or compromising privacy. It leverages modern web technologies and containerization to ensure each user session is isolated and secure.

## Features

- **Secure Data Upload**: Easy drag-and-drop or folder selection for CPAP SD card and oximetry data.
- **Isolated Environments**: Each user session runs in a dedicated, isolated Docker container.
- **OSCAR Integration**: Seamless transition from upload to the full OSCAR interface.
- **Privacy First**: No personal data is stored beyond what is necessary for the session.
- **Tinfoil Hat Mode**: Optional additional encryption for users who want extra security.
- **Discord Integration**: Support for authentication via Discord.
- **Sharing Links**: Generate secure, time-limited read-only sharing links for OSCAR profiles.
- **VNC Access**: High-performance remote desktop access to the OSCAR application via Selkies.

## Tech Stack

- **Frontend**: Vanilla HTML/JavaScript/CSS (developed with Vite).
- **Backend (Uploader)**: Rust (using `axum` and `tokio`).
- **Containerization**: Docker and Docker Compose.
- **Remote Desktop**: [linuxserver.io's docker-baseimage-selkies](https://docs.linuxserver.io/images/docker-baseimage-selkies/) for the VNC portion.
- **Tunneling**: Cloudflare Tunnels (optional).

## Licensing and Attribution

This project is distributed under the **GNU GPL v3 License**.

### Significant Attributions

- **OSCAR**: Released under the GNU GPL v3 License.
- **Qt SDK**: Built using Qt SDK (Open Source Edition), available from [qt.io](https://qt.io).
- **SleepyHead**: Portions of this software are based on SleepyHead, developed and copyright by Mark Watkins (C) 2011-2018.
- **linuxserver.io**: The VNC portion of the application is built using the [docker-baseimage-selkies](https://docs.linuxserver.io/images/docker-baseimage-selkies/) container.
- **Generative AI**: Portions of this application were created using generative AI tools.

## Disclaimer

This software is provided as-is, and users are responsible for their own data. Please use responsibly.
