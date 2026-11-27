# JellyLooter v4.0.0 Release Notes

**A complete redesign with a faster, crash-safe download engine.**

Upgrading from v3.x? Just update the container — servers, logins, sync mappings, settings and your Pro license carry over automatically (the old config is backed up as `looter_config.json.v3-backup.json`).

---

## 🆕 Highlights

### 🖼️ New interface
- Two layouts: **Clean Grid** (default) and **Dashboard**, switchable in Settings
- Posters with quality badges (4K / 1080p / HDR / Dolby Vision), ratings and the size of each movie or show
- Page navigation (Previous / Next / Page x of y / jump), 25–100 items per page, 3–8 posters per row
- Download panel and sidebar stay in place while you scroll
- Settings split into **General / Pro / Advanced** with your license status on top
- English, Spanish and German

### ✅ Never download the same thing twice
- Your local server is matched by IMDb, TMDB, TVDB, AniDB and other IDs **plus** title and year
- Owned items show a green ✓ and hide the download button; finished downloads are marked instantly
- The local server is browse-only

### 📁 Downloads land in the right place
- Visual folder picker with breadcrumbs, subfolder tiles and "New Folder"
- Shows always go into `Season NN` folders; specials are offered separately and saved in `Specials`

### 🧩 Missing episodes & airing status
- Owned shows display "−N" when episodes are missing; the show page offers "Download N missing" into your existing folder
- Shows display Continuing or Ended; for a show that's still airing, the download window asks whether Sonarr should watch for new episodes
- Browser Back / Forward work inside JellyLooter

### 🔄 Sync
- Library mappings with an editable destination, **Sync Media** and **Sync Duplicate Media**
- Never-sync list (🚫 on any poster)
- Sync fills in missing episodes of shows you already own (setting: "Fill In Missing Episodes")
- Adding a server automatically finds its libraries

## ⭐ New Pro features
- **Multi-connection downloads** — large files download in parallel parts (about 2× faster)
- **Crash-safe resume** — parts resume after an outage; files are size-checked and verified with ffprobe; the queue comes back after a restart or power cut
- **Download when a server blocks downloads** — downloads the original-quality stream instead (switch in Settings → Pro)
- **Built-in WireGuard VPN** — Proton, PIA (built-in login + regions), Mullvad, IVPN, AirVPN, Windscribe, Surfshark or any WireGuard config, with an optional **kill switch**. Needs `--cap-add=NET_ADMIN`
- **Sonarr / Radarr / Lidarr** — the show, movie or artist is added the moment you click Download (monitored, no indexer search), with automatic path detection
- **Detailed download statistics** — per day, type, server, hour and weekday, top titles, largest and fastest files (Download Analytics in the left sidebar of both layouts)
- **Better quality available** — titles the remote has in higher resolution are marked ⬆; "Download & replace" swaps them in only after each new file is verified
- Lowering download/transcode workers pauses the extra one mid-file and resumes it later

## 🚀 Fixes & improvements
- Much faster downloads — the license was being re-checked on every 64 KB chunk
- Posters load through JellyLooter, so they work even if your browser can't reach the remote server
- Saved server keys could be encrypted twice and stop working — fixed, and affected configs repair themselves
- The local library scan now uses your account and only your local server(s)
- Sonarr now receives the show's IDs (shows were not being added)
- TVDB works without a subscriber PIN (only needed for subscriber keys); OMDb has a Test button
- "Stop after current" now really pauses the queue
- Every Test button shows its result on the button
- Free plan allows 1 local + 2 remote servers (previously local and remote shared one limit)

## 🔒 Security
- Server tokens, *arr keys, VPN keys and passwords are never sent to the browser or included in config exports
- License backup endpoints require login
- New license keys must be confirmed by Gumroad when activated

## 📦 Installation
See the [README](https://github.com/jlightner86/jellylooter#installation) for Unraid, Docker, Docker Compose and Docker Desktop instructions, plus GPU and VPN setup.

```bash
docker pull ghcr.io/jlightner86/jellylooter:latest
```

## 🔗 Links
- **Pro license:** https://lightwave43.gumroad.com/l/rmtmrr
- **Issues:** https://github.com/jlightner86/jellylooter/issues
