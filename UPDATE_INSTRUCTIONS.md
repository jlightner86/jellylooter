# JellyLooter v2.1.0 - GitHub Update Instructions

## Your Current Repo Structure:
```
jellylooter/
├── .github/workflows/
├── templates/
├── .gitignore
├── LICENSE
├── README.md
├── Dockerfile
├── icon.png
├── jellylooter.xml
├── looter_app.py
└── looter_config.json
```

## Files to UPDATE (replace existing):

### 1. `looter_app.py` → rename to `app.py` (or update Dockerfile)
Replace with the new `app.py` from the package.

### 2. `templates/` folder
Replace ALL files in templates/ with:
- `index.html` (updated with themes, auth, help link)
- `login.html` (NEW)
- `setup.html` (NEW)  
- `changelog.html` (updated)
- `help.html` (NEW)

### 3. `jellylooter.xml`
Replace with the new XML template.

### 4. `Dockerfile`
Replace with the new Dockerfile.

### 5. `README.md`
Replace with the new README.

## Files to ADD (new):

### 6. `CHANGELOG.md` (NEW)
Add to repo root.

### 7. `docker-compose.yml` (NEW)
Add to repo root.

### 8. `screenshots/` folder (NEW - recommended)
Create folder and add screenshots for CA listing.

## Files to KEEP as-is:
- `.github/workflows/` (your CI/CD)
- `.gitignore`
- `LICENSE`
- `icon.png`
- `looter_config.json` (example config)

---

## Step-by-Step Commands:

```bash
# 1. Clone your repo (if not already)
git clone https://github.com/jlightner86/jellylooter.git
cd jellylooter

# 2. Download the new files from Claude's output
# (Copy them from the downloaded jellylooter folder)

# 3. Rename the app file (or update Dockerfile to use looter_app.py)
# OPTION A: Rename app file
mv looter_app.py looter_app.py.backup
cp /path/to/new/app.py ./app.py

# OPTION B: Keep looter_app.py name, just replace contents
cp /path/to/new/app.py ./looter_app.py

# 4. Replace templates
rm templates/*.html
cp /path/to/new/templates/*.html ./templates/

# 5. Replace other files
cp /path/to/new/Dockerfile ./Dockerfile
cp /path/to/new/jellylooter.xml ./jellylooter.xml
cp /path/to/new/README.md ./README.md

# 6. Add new files
cp /path/to/new/CHANGELOG.md ./CHANGELOG.md
cp /path/to/new/docker-compose.yml ./docker-compose.yml

# 7. Create screenshots folder (optional but recommended)
mkdir -p screenshots

# 8. Stage all changes
git add -A

# 9. Commit
git commit -m "v2.1.0: Add authentication, themes, help page"

# 10. Tag the release
git tag -a v2.1.0 -m "Version 2.1.0 - Authentication & Themes"

# 11. Push
git push origin main
git push origin v2.1.0
```

---

## Final Repo Structure Should Be:

```
jellylooter/
├── .github/
│   └── workflows/
│       └── main.yml
├── templates/
│   ├── index.html      ← UPDATED
│   ├── login.html      ← NEW
│   ├── setup.html      ← NEW
│   ├── changelog.html  ← UPDATED
│   └── help.html       ← NEW
├── screenshots/        ← NEW (optional)
│   ├── browse.png
│   ├── downloads.png
│   └── settings.png
├── .gitignore
├── LICENSE
├── README.md           ← UPDATED
├── CHANGELOG.md        ← NEW
├── Dockerfile          ← UPDATED
├── docker-compose.yml  ← NEW
├── icon.png
├── jellylooter.xml     ← UPDATED
├── app.py              ← RENAMED/UPDATED (was looter_app.py)
└── looter_config.json
```

---

## Dockerfile Note:

Your current Dockerfile probably references `looter_app.py`. You have two options:

**Option A:** Rename `looter_app.py` to `app.py` and use my new Dockerfile as-is.

**Option B:** Keep `looter_app.py` name and update the Dockerfile's last line:
```dockerfile
CMD ["python", "looter_app.py"]
```

---

## Creating a GitHub Release:

1. Go to https://github.com/jlightner86/jellylooter/releases
2. Click "Create a new release"
3. Choose tag: `v2.1.0`
4. Release title: `v2.1.0 - Authentication & Themes`
5. Description:

```markdown
## What's New in v2.1.0

### 🔒 Security
- Added user authentication with secure login system
- First-time setup wizard for creating admin account
- Password hashing with salt

### 🎨 New Features
- Light and dark theme support with toggle
- User session management with "remember me" option
- Password change functionality
- Toast notifications
- Comprehensive help/instructions page

### ⚙️ Settings Improvements
- Connection timeout setting
- Chunk size setting for download tuning
- "Confirm before downloading" option
- Notification preferences
- Better organized settings sections

### 🐛 Fixes
- Theme persists across sessions
- Various UI improvements

## Upgrade Notes

After updating, you'll be prompted to create an admin account on first access. Your existing server configurations will be preserved.

## Docker

```bash
docker pull jlightner86/jellylooter:latest
```
```

6. Click "Publish release"
