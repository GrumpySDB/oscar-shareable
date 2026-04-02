# Self-Hosting OSCAR Shareable

> [!CAUTION]
> **EXPERIMENTAL AND UNTESTED**
> This project is designed for a specific development environment. Self-hosting OSCAR Shareable in other environments (different Linux distros, cloud providers, or home labs) is **entirely untested**. 
> - **No Plug-and-Play Guarantee**: This is NOT a drop-in or plug-and-play service. 
> - **Experimentation Required**: You MUST be comfortable with Docker, networking, and security troubleshooting to make this work in your specific environment.

---

## 🛠️ Modular Deployment Options

You can host OSCAR Shareable in two ways, depending on your needs.

### Option A: Full OSCAR Shareable Stack
This includes the Rust `uploader` backend, the web UI, and the dynamic container management system. 

**Requirements**:
- A Linux host with Docker and Docker Compose.
- A public domain (with SSL/TLS terminate at Nginx).
- **Docker Socket Access**: The uploader service requires access to the host's Docker socket (via a secure proxy) to spawn transient OSCAR containers.

### Option B: Standalone OSCAR VNC (No Uploader)
If you just want a web-accessible OSCAR environment for manual analysis of existing files on your server, you can run the `oscar` service directly.

**Requirements**:
- Docker and Docker Compose.

---

## 🚀 Setup Instructions (Option A: Full Stack)

### 1. Clone the Repository
```bash
git clone https://github.com/grumpysdb/oscar-shareable.git
cd oscar-shareable
```

### 2. Configure Secrets
Create the following files in the `secrets/` directory:

```bash
mkdir -p secrets
openssl rand -base64 32 > secrets/jwt_secret.txt
echo "admin" > secrets/app_username.txt
echo "MyComplexPassword123" > secrets/app_password.txt
```

### 3. Environment Variables
Copy `.env.example` to `.env` and update `BASE_HOSTNAME`, `DOCKER_GID`, and `STORAGE_PATH`.

### 4. Deploy
```bash
sudo docker compose up -d
```

---

## 📦 Standalone Deployment (Option B: OSCAR VNC Only)

For a simplified, persistent OSCAR instance without the backend uploader, use the following `docker-compose.yml` template:

```yaml
services:
  oscar:
    image: ghcr.io/grumpysdb/oscar-shareable-oscar:latest
    container_name: oscar-standalone
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      # These folders should lead to your local OSCAR data and SD card backups
      - ./data/profiles:/config/Documents/OSCAR_Data:rw
      - ./data/uploads:/config/Documents/SDCARD:rw
      - ./data/app_config:/config/.config/OSCAR_Team:rw
    environment:
      - PUID=1000            # Your host user ID
      - PGID=1000            # Your host group ID
      - TZ=America/Chicago    # Your timezone
      - MAX_RES=2560x1440
      - TITLE=OSCAR Standalone
      - START_DOCKER=false
      - DISABLE_IPV6=true
      - NO_DECOR=false
      - NO_GAMEPAD=true
      - HARDEN_DESKTOP=true
      - HARDEN_OPENBOX=true
      - SELKIES_ENABLE_CURSORS=true
      - SELKIES_AUDIO_ENABLED=true
      - SELKIES_GAMEPAD_ENABLED=false
      - SELKIES_MICROPHONE_ENABLED=false
      - SELKIES_CLIPBOARD_IN_ENABLED=true
      - SELKIES_CLIPBOARD_OUT_ENABLED=true
      - SELKIES_ENABLE_SHARING=true
      - SELKIES_UI_SIDEBAR_SHOW_GAMEPADS=false
      - SELKIES_UI_SIDEBAR_SHOW_CLIPBOARD=true
      - SELKIES_UI_SIDEBAR_SHOW_AUDIO_SETTINGS=true
      - SELKIES_UI_SIDEBAR_SHOW_SHARING=true
      - SELKIES_UI_SHOW_CORE_BUTTONS=true
      - SELKIES_USE_BROWSER_CURSORS=true
```

1. Save the above as `docker-compose.yml`.
2. Run `docker compose up -d`.
3. Access OSCAR at `http://<your-ip>:3000`.

---

## 🔍 Troubleshooting

- **Check Logs**: `sudo docker compose logs -f`
- **Volume Permissions**: OSCAR runs as UID 911 internally by default. If your volume mounts are not readable, adjust `PUID`/`PGID` to match your host user.
- **Docker Socket**: If using Option A, ensure the `docker-socket-proxy` can reach `/var/run/docker.sock`.
