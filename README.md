# JellyLooter 🍇

A web-based tool for downloading media from remote Jellyfin and Emby servers.

![JellyLooter Screenshot](https://raw.githubusercontent.com/jlightner86/jellylooter/main/screenshots/browse.png)

## Features

- 📁 **Browse Remote Libraries** - Visual browsing with poster artwork
- ⬇️ **Multi-Select Downloads** - Ctrl+click or right-click to select multiple items
- 🔄 **Auto-Sync** - Schedule automatic library syncing
- ✓ **Duplicate Detection** - Skip content you already have locally
- 🎨 **Dark/Light Themes** - Easy on the eyes, day or night
- 🔒 **User Authentication** - Secure login with password protection
- ⏱️ **Speed Limiting** - Control bandwidth usage
- 📊 **Real-Time Progress** - Live download speed and progress tracking

## Installation

### Unraid (Community Apps)

1. Go to **Apps** tab in Unraid
2. Search for "JellyLooter"
3. Click **Install**
4. Configure the paths and port
5. Click **Apply**

### Docker

```bash
docker run -d \
  --name jellylooter \
  -p 5000:5000 \
  -v /path/to/config:/config \
  -v /path/to/media:/storage \
  -e TZ=America/New_York \
  jlightner86/jellylooter:latest
```

### Docker Compose

```yaml
version: '3.8'
services:
  jellylooter:
    image: jlightner86/jellylooter:latest
    container_name: jellylooter
    ports:
      - "5000:5000"
    volumes:
      - ./config:/config
      - /path/to/media:/storage
    environment:
      - TZ=America/New_York
      - PUID=1000
      - PGID=1000
    restart: unless-stopped
```

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/jlightner86/jellylooter.git
cd jellylooter

# Install dependencies
pip install flask requests schedule

# Run
python app.py
```

## First-Time Setup

1. Navigate to `http://your-server:5000`
2. Create your admin account (username + password)
3. Log in with your new credentials
4. Go to **Settings** and add your remote Jellyfin/Emby servers

## Configuration

### Adding Remote Servers

1. Go to **Settings** tab
2. Click **+ Add Remote Server**
3. Enter server details:
   - **Name**: Friendly name (e.g., "Friend's Server")
   - **URL**: Server address (e.g., `http://192.168.1.100:8096`)
   - **API Key** or **Username/Password**
4. Click **Test Connection** to verify
5. Click **Add Server**

### Getting an API Key

On the remote Jellyfin/Emby server:
1. Go to **Dashboard** → **Advanced** → **API Keys**
2. Click **+** to create a new key
3. Name it "JellyLooter"
4. Copy the generated key

### Setting Up Duplicate Detection

1. Go to **Settings** tab
2. Under "Local Server", click **Configure Local Server**
3. Enter your local Jellyfin/Emby server URL and API key
4. Click **Save & Scan**

This will scan your local library and mark items you already have when browsing remote servers.

### Auto-Sync

1. Go to **Sync** tab
2. Click **+ Add Mapping**
3. Select remote server and library
4. Enter local destination path
5. Enable **Auto-Sync** toggle
6. Set sync time in **Settings** → **Advanced**

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TZ` | `America/New_York` | Timezone for scheduled tasks |
| `PUID` | `99` | User ID for file permissions |
| `PGID` | `100` | Group ID for file permissions |
| `SECRET_KEY` | (auto-generated) | Session encryption key |

## Volumes

| Path | Description |
|------|-------------|
| `/config` | Configuration files, auth data, cache |
| `/storage` | Root directory for downloads |

## Ports

| Port | Description |
|------|-------------|
| `5000` | Web interface |

## Screenshots

### Browse Libraries
![Browse](https://raw.githubusercontent.com/jlightner86/jellylooter/main/screenshots/browse.png)

### Downloads Queue
![Downloads](https://raw.githubusercontent.com/jlightner86/jellylooter/main/screenshots/downloads.png)

### Settings
![Settings](https://raw.githubusercontent.com/jlightner86/jellylooter/main/screenshots/settings.png)

## FAQ

**Q: Does this work with Plex?**  
A: No, only Jellyfin and Emby are supported.

**Q: Is this legal?**  
A: JellyLooter is a tool. Downloading content you have rights to is fine. Piracy is not.

**Q: How do I reset my password?**  
A: Delete `/config/auth.json` and restart the container. You'll be prompted to create a new account.

**Q: Can I add multiple users?**  
A: Currently only a single admin account is supported.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) or visit `/changelog` in the web interface.

## Contributing

Pull requests welcome! Please open an issue first to discuss major changes.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is for personal use. Respect copyright laws and only download content you have permission to access. The developers are not responsible for misuse.
