# JellyLooter v3.1.0 Release Notes

**Release Date:** December 2024

This release adds library search, time format options, AVI encoding, improved *arr integration, transcode cache drive support, download retry logic, and numerous bug fixes.

---

## 🆕 New Features

### 🔍 Library Search
- **Search within any library** - Find movies/shows by name without scrolling through pages
- **Server-side search** - Returns up to 100 results instantly
- **Smart UI** - Search box appears when inside a library, hidden at root level
- **Clear search** - One-click return to normal browsing with pagination

### ⏰ Time Format Options
- **12-hour format** - Display times as "1:30:45 PM" (default, standard time)
- **24-hour format** - Display times as "13:30:45" (military time)
- **Proper timezone support** - 30+ timezone options with accurate log timestamps
- **Startup verification** - Logs timezone status on container start

### 🎬 AVI Encoding Preset (Pro)
- **Legacy-compatible encoding** - MPEG-4 video + MP3 audio in AVI container
- **Broad device support** - Works with older media players and devices
- **Software encoding** - Uses mpeg4 codec (no GPU acceleration needed)

### 📡 Enhanced *arr Integration (Pro)
- **Auto-add series to Sonarr** - Automatically adds new series when downloading episodes
- **Smart root folder detection** - Matches download path to Sonarr/Radarr root folders
- **Intelligent path mapping** - Scans filesystem to auto-detect path mappings
- **Multiple fallback strategies** - TVDB → IMDB → Title search
- **Detailed logging** - See exactly what's happening at each step

### 💾 Transcode Cache Drive (Pro)
- **Transcode to fast storage first** - Use an SSD or local drive for transcoding, then move to final destination
- **Reduces NAS/network storage load** - All the small I/O happens on fast local storage
- **Keeps partial files separate** - Failed transcodes stay in cache, not cluttering your media folders
- **Cache status indicator** - Shows file count and total size in cache
- **Clear cache button** - Remove partial/failed transcode files with one click

### 🔄 Auto-Retry Failed Downloads
- **Automatic retry on connection errors** - Retries on timeout, connection reset, server errors (502/503/504)
- **Configurable attempts** - Set retry count from 1-10 (default: 3)
- **Configurable delay** - Set delay between retries from 5-300 seconds (default: 30)
- **Visual countdown** - Shows retry status in download queue (e.g., "Retry in 25s (2/3)")

### ⚡ Download Limit Override (Pro)
- **Allow >10 concurrent downloads** - Override the safety limit up to 50 downloads
- **Prominent warnings** - Clear warnings about server overload, rate limiting, and bandwidth impact
- **Use responsibly** - Can affect other users on shared servers

### 📋 Copy Logs Button
- **One-click copy** - Copy entire activity log to clipboard
- **HTTP support** - Works over HTTP (not just HTTPS) using execCommand fallback
- **Easy sharing** - Share logs for troubleshooting or bug reports

---

## 🐛 Bug Fixes

### Transcoding Fixes
- **Fixed "return code None" errors** - Now properly waits for ffmpeg to finish with `process.wait()`
- **Output validation** - If ffmpeg exits abnormally, validates output with ffprobe before discarding
- **Salvages 90%+ complete transcodes** - Files that are substantially complete are kept if valid
- **Filtered error logging** - FFmpeg progress output no longer appears as errors
- **Better error logging** - Detailed diagnostics for transcode failures

### *arr Integration Fixes
- **Fixed Sonarr API format** - Uses proper `params` instead of URL concatenation
- **IMDB fallback** - If TVDB lookup fails, tries IMDB
- **Title search fallback** - Extracts series name from folder path if ID lookups fail

### Other Fixes
- **Timezone support** - Added tzdata package to Docker images
- **Search endpoint** - Fixed `get_auth_headers` error
- **Clipboard API** - Works over HTTP using execCommand fallback
- Episode folders now use series-level IDs instead of episode IDs
- Episode folders use show name only when series IDs unavailable (no duplicate folders)
- Transcode now runs for Pro users (previously only worked in test mode)
- Rebuild Cache now supports multi-local-server configurations
- Download statistics no longer reset to 0 during active downloads
- Download stats persist across container restarts

---

## ⚡ Improvements

- **Transcode validates output with ffprobe** - Checks file integrity before replacing original
- **Enhanced retry logic** - Handles chunked encoding errors, broken pipes, connection refused
- **Activity log controls** - Icon-only buttons save space
- **Enhanced metadata logging** - Shows API lookup results and failures
- **Enhanced transcode logging** - Detailed error output for debugging
- **Transcode worker management** - Workers start/stop when settings change (no restart needed)

---

## 📦 Installation

### Docker
```bash
docker pull ghcr.io/jlightner86/jellylooter:3.1.0
```

### Upgrade from v3.0.x
1. Pull the new image
2. Restart the container
3. Your config will be migrated automatically
4. New settings have sensible defaults

---

## ⚙️ New Configuration Options

| Setting | Default | Description |
|---------|---------|-------------|
| `time_format` | `12h` | Time display format (12h or 24h) |
| `transcode_cache_enabled` | `false` | Use cache drive for transcoding |
| `transcode_cache_path` | `/tmp/transcode_cache` | Path to cache drive |
| `download_auto_retry` | `true` | Auto-retry failed downloads |
| `download_retry_count` | `3` | Number of retry attempts |
| `download_retry_delay` | `30` | Seconds between retries |
| `override_download_limit` | `false` | Allow >10 concurrent downloads |

### Transcode Presets
| Preset | Codec | Container | Use Case |
|--------|-------|-----------|----------|
| Original | - | - | No transcoding |
| H.264 | libx264/h264_nvenc | .mp4 | Compatible with most devices |
| H.265/HEVC | libx265/hevc_nvenc | .mkv | Smaller files, modern devices |
| AVI | mpeg4 | .avi | Legacy device compatibility |
| Mobile | libx264 | .mp4 | 720p for phones/tablets |
| 4K Optimized | libx265/hevc_nvenc | .mkv | High quality 4K content |

---

## 🙏 Special Thanks

A huge thank you to our beta testers and contributors:

- **[vwidmer](https://github.com/vwidmer)** - Beta testing, bug reports, and feature suggestions for transcoding, *arr integration, and download improvements

---

## 📋 Full Changelog

### New Features
- 🔍 Library search functionality
- ⏰ Time format option (12h/24h)
- 🎬 AVI encoding preset (Pro)
- 📡 Auto-add series to Sonarr (Pro)
- 📡 Intelligent path mapping auto-detection (Pro)
- 💾 Transcode cache drive support (Pro)
- 🗑️ Clear transcode cache button (Pro)
- 🔄 Auto-retry failed downloads with configurable attempts/delay
- ⚡ Download limit override - up to 50 concurrent (Pro)
- 📋 Copy logs button in Activity Log

### Bug Fixes
- Fixed transcode "return code None" with proper process.wait()
- Fixed transcode output validation with ffprobe
- Fixed transcode error logging (filters progress output)
- Fixed Sonarr API lookup format
- Fixed timezone support (added tzdata)
- Fixed clipboard copy over HTTP
- Fixed episode folder naming (uses series IDs, not episode IDs)
- Fixed download stats persistence
- Fixed multi-local-server cache rebuild

### Improvements
- Enhanced transcode error handling and logging
- Enhanced *arr integration logging
- Improved retry logic for connection failures
- Transcode workers start when settings change
- Activity log UI improvements

---

## 🔗 Links

- **GitHub:** [github.com/jlightner86/jellylooter](https://github.com/jlightner86/jellylooter)
- **Pro License:** [lightwave43.gumroad.com/l/rmtmrr](https://lightwave43.gumroad.com/l/rmtmrr)
- **Donations:** [Ko-fi](https://ko-fi.com/jellyloot)

Thank you for using JellyLooter!
