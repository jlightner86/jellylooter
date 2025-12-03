import os
import json
import time
import requests
import threading
import schedule
import re
import random
import string
import queue
import datetime
import hashlib
import secrets
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, make_response

CONFIG_FILE = '/config/looter_config.json'
CACHE_FILE = '/config/local_cache.json'
AUTH_FILE = '/config/auth.json'

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Thread-safe state management
task_queue = queue.Queue()
active_downloads = {}
pending_display = []
cancelled_tasks = set()
download_lock = threading.Lock()
is_paused = False
log_buffer = []
local_id_cache = set()
cache_timestamp = "Never"
scan_progress = {
    "running": False,
    "percent": 0,
    "current": 0,
    "total": 0,
    "status": "Idle"
}

# --- Authentication Helpers ---

def hash_password(password, salt=None):
    """Hash password with salt using SHA-256"""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{hashed}"


def verify_password(password, stored_hash):
    """Verify password against stored hash"""
    try:
        salt, hashed = stored_hash.split(':')
        return hash_password(password, salt) == stored_hash
    except ValueError:
        return False


def load_auth():
    """Load authentication data"""
    if not os.path.exists(AUTH_FILE):
        return None
    try:
        with open(AUTH_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return None


def save_auth(auth_data):
    """Save authentication data"""
    os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
    with open(AUTH_FILE, 'w') as f:
        json.dump(auth_data, f, indent=4)


def is_setup_complete():
    """Check if initial setup has been completed"""
    auth = load_auth()
    return auth is not None and 'users' in auth and len(auth['users']) > 0


def login_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for session token
        if 'user' not in session:
            # Check for remember token in cookie
            remember_token = request.cookies.get('remember_token')
            if remember_token:
                auth = load_auth()
                if auth and 'tokens' in auth:
                    for username, token in auth['tokens'].items():
                        if token == remember_token:
                            session['user'] = username
                            break
            
            if 'user' not in session:
                if request.path.startswith('/api/'):
                    return jsonify({"status": "error", "message": "Unauthorized"}), 401
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# --- Utility Functions ---

def log(msg):
    """Thread-safe logging with timestamp"""
    print(msg)
    with download_lock:
        log_buffer.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
        if len(log_buffer) > 200:
            log_buffer.pop(0)


def clean_name(name):
    """Remove invalid filesystem characters"""
    return re.sub(r'[\\/*?:"<>|]', "", name)


def generate_id():
    """Generate random task ID"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))


def format_bytes(size):
    """Format bytes to human readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def get_auth_header(token=None):
    """Generate Jellyfin/Emby auth header"""
    return {
        'X-Emby-Authorization': f'MediaBrowser Client="JellyLooter", Device="Unraid", DeviceId="JellyLooterId", Version="2.1.0", Token="{token or ""}"'
    }


# --- Config Management ---

def get_default_config():
    """Return default configuration"""
    return {
        "servers": [],
        "mappings": [],
        "sync_time": "04:00",
        "speed_limit_kbs": 0,
        "local_server_url": "",
        "local_server_key": "",
        "auto_sync_enabled": True,
        "theme": "dark",
        "max_concurrent_downloads": 2,
        "retry_attempts": 3,
        "advanced_mode": False,
        "show_notifications": True,
        "confirm_downloads": False,
        "auto_start_downloads": True,
        "log_retention_days": 7,
        "connection_timeout": 30,
        "chunk_size_kb": 64
    }


def load_config():
    """Load config with defaults"""
    default = get_default_config()
    if not os.path.exists(CONFIG_FILE):
        return default
    try:
        with open(CONFIG_FILE, 'r') as f:
            return {**default, **json.load(f)}
    except Exception:
        return default


def save_config(data):
    """Save config and refresh schedule"""
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(data, f, indent=4)
    setup_schedule()


# --- Cache Management ---

def load_cache_from_disk():
    """Load local ID cache from disk"""
    global local_id_cache, cache_timestamp
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                data = json.load(f)
                local_id_cache = set(data.get('ids', []))
                cache_timestamp = data.get('timestamp', 'Unknown')
        except Exception:
            pass


def cache_worker():
    """Scan local server and build ID cache"""
    global local_id_cache, cache_timestamp, scan_progress
    
    cfg = load_config()
    url = cfg.get('local_server_url')
    key = cfg.get('local_server_key')
    
    if not url or not key:
        log("Scan Skipped: No Local Server configured")
        return
    
    if scan_progress['running']:
        log("Scan already in progress")
        return

    log("Starting Local Library Scan...")
    scan_progress = {
        "running": True,
        "percent": 0,
        "current": 0,
        "total": 0,
        "status": "Connecting..."
    }

    try:
        headers = get_auth_header(key)
        timeout = cfg.get('connection_timeout', 30)
        
        # Get user ID
        u_res = requests.get(f"{url}/Users", headers=headers, timeout=timeout)
        if not u_res.ok:
            raise Exception("Authentication Failed")
        uid = u_res.json()[0]['Id']

        # Get total count
        params = {
            'Recursive': 'true',
            'IncludeItemTypes': 'Movie,Series',
            'Fields': 'ProviderIds',
            'Limit': 0
        }
        total_res = requests.get(
            f"{url}/Users/{uid}/Items",
            headers=headers,
            params=params
        ).json()
        total_count = total_res.get('TotalRecordCount', 0)

        scan_progress.update({
            'total': total_count,
            'status': f"Found {total_count} items. Fetching..."
        })

        # Fetch in batches
        new_cache = set()
        limit = 100
        offset = 0

        while offset < total_count:
            params.update({'StartIndex': offset, 'Limit': limit})
            items = requests.get(
                f"{url}/Users/{uid}/Items",
                headers=headers,
                params=params
            ).json().get('Items', [])

            for item in items:
                providers = item.get('ProviderIds', {})
                if 'Imdb' in providers:
                    new_cache.add(f"imdb_{providers['Imdb']}")
                if 'Tmdb' in providers:
                    new_cache.add(f"tmdb_{providers['Tmdb']}")

            offset += len(items)
            scan_progress.update({
                'current': offset,
                'percent': int((offset / total_count) * 100) if total_count > 0 else 0
            })

        # Save cache
        local_id_cache = new_cache
        cache_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, 'w') as f:
            json.dump({
                'timestamp': cache_timestamp,
                'ids': list(local_id_cache)
            }, f)

        log(f"Scan Complete. Cached {len(local_id_cache)} provider IDs.")
        scan_progress = {
            "running": False,
            "percent": 100,
            "current": total_count,
            "total": total_count,
            "status": "Complete"
        }

    except Exception as e:
        log(f"Scan Failed: {e}")
        scan_progress = {
            "running": False,
            "percent": 0,
            "current": 0,
            "total": 0,
            "status": f"Error: {str(e)}"
        }


def get_existing_ids():
    """Get cached local IDs, loading from disk if needed"""
    if not local_id_cache:
        load_cache_from_disk()
    return local_id_cache


# --- Schedule Management ---

def setup_schedule():
    """Configure scheduled tasks"""
    schedule.clear()
    cfg = load_config()
    
    # Daily cache rebuild at 3 AM
    schedule.every().day.at("03:00").do(
        lambda: threading.Thread(target=cache_worker, daemon=True).start()
    )
    
    # Sync at configured time
    if cfg.get('auto_sync_enabled', True):
        sync_time = cfg.get('sync_time', "04:00")
        try:
            schedule.every().day.at(sync_time).do(sync_job)
            log(f"Scheduled: Cache rebuild 03:00, Sync {sync_time}")
        except Exception:
            schedule.every().day.at("04:00").do(sync_job)
            log("Scheduled: Cache rebuild 03:00, Sync 04:00 (default)")


def schedule_runner():
    """Background thread for running scheduled tasks"""
    while True:
        schedule.run_pending()
        time.sleep(60)


# --- Download Management ---

def worker():
    """Download worker thread"""
    while True:
        task = task_queue.get()
        if task is None:
            break
        
        tid = task['task_id']
        
        # Remove from pending
        with download_lock:
            global pending_display
            pending_display = [x for x in pending_display if x['id'] != tid]
        
        # Check if cancelled before starting
        if tid in cancelled_tasks:
            cancelled_tasks.discard(tid)
            task_queue.task_done()
            continue
        
        try:
            download_file(task)
        except Exception as e:
            log(f"Worker Error: {e}")
        
        task_queue.task_done()


def download_file(task):
    """Download a single file with speed limiting and pause support"""
    global is_paused
    
    tid = task['task_id']
    filepath = task['filepath']
    filename = os.path.basename(filepath)
    speed_limit = task.get('limit', 0)
    cfg = load_config()
    chunk_size = cfg.get('chunk_size_kb', 64) * 1024
    
    try:
        with download_lock:
            active_downloads[tid] = {
                'id': tid,
                'filename': filename,
                'total': 0,
                'current': 0,
                'speed': '0 B/s',
                'percent': 0,
                'status': 'Starting'
            }
        
        timeout = cfg.get('connection_timeout', 30)
        with requests.get(task['url'], stream=True, timeout=timeout) as response:
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            with download_lock:
                active_downloads[tid]['total'] = total_size
            
            downloaded = 0
            speed_window = []
            last_speed_update = time.time()
            
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if tid in cancelled_tasks:
                        raise InterruptedError("Download cancelled")
                    
                    while is_paused:
                        with download_lock:
                            if tid in active_downloads:
                                active_downloads[tid].update({
                                    'status': 'Paused',
                                    'speed': '0 B/s'
                                })
                        time.sleep(0.5)
                        
                        if tid in cancelled_tasks:
                            raise InterruptedError("Download cancelled")
                    
                    if not chunk:
                        continue
                    
                    chunk_start = time.time()
                    f.write(chunk)
                    chunk_len = len(chunk)
                    downloaded += chunk_len
                    
                    if speed_limit > 0:
                        target_time = chunk_len / (speed_limit * 1024)
                        elapsed = time.time() - chunk_start
                        if elapsed < target_time:
                            time.sleep(target_time - elapsed)
                    
                    now = time.time()
                    speed_window.append((now, chunk_len))
                    speed_window = [(t, s) for t, s in speed_window if now - t < 2]
                    
                    if now - last_speed_update >= 0.5:
                        if speed_window:
                            window_time = now - speed_window[0][0]
                            window_bytes = sum(s for _, s in speed_window)
                            speed = window_bytes / window_time if window_time > 0 else 0
                        else:
                            speed = 0
                        
                        with download_lock:
                            if tid in active_downloads:
                                active_downloads[tid].update({
                                    'current': downloaded,
                                    'speed': f"{format_bytes(speed)}/s",
                                    'status': 'Downloading',
                                    'percent': int((downloaded / total_size) * 100) if total_size > 0 else 0
                                })
                        last_speed_update = now
        
        with download_lock:
            if tid in active_downloads:
                del active_downloads[tid]
        log(f"✓ Completed: {filename}")
        
    except InterruptedError:
        log(f"✗ Cancelled: {filename}")
        _cleanup_download(tid, filepath)
        
    except Exception as e:
        log(f"✗ Failed {filename}: {e}")
        _cleanup_download(tid, filepath)


def _cleanup_download(tid, filepath):
    """Clean up after failed/cancelled download"""
    with download_lock:
        if tid in active_downloads:
            del active_downloads[tid]
    cancelled_tasks.discard(tid)
    
    if os.path.exists(filepath):
        try:
            os.remove(filepath)
        except Exception:
            pass


# --- API Authentication ---

def login_with_creds(url, username, password):
    """Authenticate with username/password and return token"""
    try:
        response = requests.post(
            f"{url}/Users/AuthenticateByName",
            json={"Username": username, "Pw": password},
            headers=get_auth_header(),
            timeout=10
        )
        if response.status_code == 200:
            return response.json().get("AccessToken")
        return None
    except Exception:
        return None


# --- Flask Routes: Authentication ---

@app.route('/setup')
def setup_page():
    """Initial setup page"""
    if is_setup_complete():
        return redirect(url_for('login'))
    return render_template('setup.html')


@app.route('/login')
def login():
    """Login page"""
    if not is_setup_complete():
        return redirect(url_for('setup_page'))
    if 'user' in session:
        return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.pop('user', None)
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('remember_token')
    return response


@app.route('/api/setup', methods=['POST'])
def api_setup():
    """Handle initial setup"""
    if is_setup_complete():
        return jsonify({"status": "error", "message": "Setup already completed"})
    
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    # Validation
    if len(username) < 3:
        return jsonify({"status": "error", "message": "Username too short"})
    if len(password) < 8:
        return jsonify({"status": "error", "message": "Password too short"})
    
    # Create auth data
    auth_data = {
        "users": {
            username: {
                "password_hash": hash_password(password),
                "created": datetime.datetime.now().isoformat(),
                "role": "admin"
            }
        },
        "tokens": {}
    }
    
    save_auth(auth_data)
    log(f"Setup complete. Admin user '{username}' created.")
    
    return jsonify({"status": "ok"})


@app.route('/api/login', methods=['POST'])
def api_login():
    """Handle login"""
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    remember = data.get('remember', False)
    
    auth = load_auth()
    if not auth or 'users' not in auth:
        return jsonify({"status": "error", "message": "No users configured"})
    
    user = auth['users'].get(username)
    if not user or not verify_password(password, user['password_hash']):
        return jsonify({"status": "error", "message": "Invalid credentials"})
    
    session['user'] = username
    
    response_data = {"status": "ok"}
    response = make_response(jsonify(response_data))
    
    if remember:
        token = secrets.token_hex(32)
        if 'tokens' not in auth:
            auth['tokens'] = {}
        auth['tokens'][username] = token
        save_auth(auth)
        response.set_cookie('remember_token', token, max_age=30*24*60*60, httponly=True)
    
    log(f"User '{username}' logged in")
    return response


@app.route('/api/change_password', methods=['POST'])
@login_required
def api_change_password():
    """Change user password"""
    data = request.json
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    if len(new_password) < 8:
        return jsonify({"status": "error", "message": "New password too short"})
    
    auth = load_auth()
    username = session.get('user')
    user = auth['users'].get(username)
    
    if not verify_password(current_password, user['password_hash']):
        return jsonify({"status": "error", "message": "Current password incorrect"})
    
    auth['users'][username]['password_hash'] = hash_password(new_password)
    save_auth(auth)
    
    log(f"User '{username}' changed password")
    return jsonify({"status": "ok"})


# --- Flask Routes: Main Application ---

@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/changelog')
def changelog():
    return render_template('changelog.html')


@app.route('/help')
def help_page():
    return render_template('help.html')


@app.route('/api/user')
@login_required
def api_user():
    """Get current user info"""
    return jsonify({
        "username": session.get('user'),
        "logged_in": True
    })


@app.route('/api/config', methods=['GET', 'POST'])
@login_required
def config_api():
    if request.method == 'POST':
        save_config(request.json)
        return jsonify({"status": "ok"})
    return jsonify(load_config())


@app.route('/api/status')
@login_required
def status():
    with download_lock:
        return jsonify({
            "active": dict(active_downloads),
            "pending": list(pending_display),
            "paused": is_paused,
            "cache_time": cache_timestamp,
            "cache_count": len(local_id_cache),
            "scan_progress": dict(scan_progress),
            "queue_size": task_queue.qsize()
        })


@app.route('/api/logs')
@login_required
def get_logs():
    with download_lock:
        return "\n".join(reversed(log_buffer))


@app.route('/api/pause', methods=['POST'])
@login_required
def pause_dl():
    global is_paused
    is_paused = True
    log("Downloads paused")
    return jsonify({"paused": True})


@app.route('/api/resume', methods=['POST'])
@login_required
def resume_dl():
    global is_paused
    is_paused = False
    log("Downloads resumed")
    return jsonify({"paused": False})


@app.route('/api/cancel', methods=['POST'])
@login_required
@app.route('/api/cancel', methods=['POST'])
@login_required
def cancel_dl():
    global pending_display  # <--- FIXED: Moved to the top so it works everywhere
    """Cancel a specific download or all downloads"""
    data = request.json or {}
    task_id = data.get('task_id')
    cancel_all = data.get('all', False)
    
    if cancel_all:
        with download_lock:
            for tid in active_downloads:
                cancelled_tasks.add(tid)
            for item in pending_display:
                cancelled_tasks.add(item['id'])
            pending_display.clear()
        
        while not task_queue.empty():
            try:
                task = task_queue.get_nowait()
                task_queue.task_done()
            except queue.Empty:
                break
        
        log("All downloads cancelled")
        return jsonify({"status": "all_cancelled"})
    
    elif task_id:
        cancelled_tasks.add(task_id)
        with download_lock:
            # global pending_display <--- REMOVED from here (it's at the top now)
            pending_display = [x for x in pending_display if x['id'] != task_id]
        log(f"Cancelled task: {task_id}")
        return jsonify({"status": "cancelled", "task_id": task_id})
    
    return jsonify({"status": "error", "message": "No task_id provided"})
@app.route('/api/test_connection', methods=['POST'])
@login_required
def test_connection():
    data = request.json
    cfg = load_config()
    timeout = cfg.get('connection_timeout', 30)
    
    try:
        if data.get('username'):
            token = login_with_creds(
                data['url'],
                data.get('username'),
                data.get('password')
            )
            if token:
                return jsonify({"status": "ok", "key": token})
            return jsonify({"status": "error", "error": "Invalid credentials"})
        else:
            response = requests.get(
                f"{data['url']}/Users",
                headers=get_auth_header(data.get('key')),
                timeout=timeout
            )
            if response.ok:
                return jsonify({"status": "ok", "key": data.get('key')})
            return jsonify({"status": "error", "error": "Invalid API Key"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


@app.route('/api/rebuild_cache', methods=['POST'])
@login_required
def rebuild_cache():
    threading.Thread(target=cache_worker, daemon=True).start()
    return jsonify({"status": "started"})


@app.route('/api/remove_local', methods=['POST'])
@login_required
def remove_local():
    cfg = load_config()
    cfg['local_server_url'] = ""
    cfg['local_server_key'] = ""
    save_config(cfg)
    return jsonify({"status": "ok"})


@app.route('/api/scan_libs')
@login_required
def scan_libs():
    cfg = load_config()
    results = []
    
    for server in cfg['servers']:
        try:
            headers = get_auth_header(server['key'])
            user_id = requests.get(
                f"{server['url']}/Users",
                headers=headers
            ).json()[0]['Id']
            
            libs = requests.get(
                f"{server['url']}/Users/{user_id}/Views",
                headers=headers
            ).json().get('Items', [])
            
            results.append({
                "server_id": server['id'],
                "server_name": server['name'],
                "libs": libs
            })
        except Exception:
            pass
    
    return jsonify(results)


@app.route('/api/browse_remote', methods=['POST'])
@login_required
def browse_remote():
    data = request.json
    cfg = load_config()
    
    server = next(
        (s for s in cfg['servers'] if s['id'] == data['server_id']),
        None
    )
    if not server:
        return jsonify({"items": [], "total": 0})
    
    try:
        headers = get_auth_header(server['key'])
        user_id = requests.get(
            f"{server['url']}/Users",
            headers=headers
        ).json()[0]['Id']
        
        local_ids = get_existing_ids()
        
        if data['parent_id'] == 'root':
            items = requests.get(
                f"{server['url']}/Users/{user_id}/Views",
                headers=headers
            ).json().get('Items', [])
            
            clean_items = [{
                "Id": item['Id'],
                "Name": item['Name'],
                "IsFolder": True,
                "HasImage": True
            } for item in items]
            
            return jsonify({
                "items": clean_items,
                "base_url": server['url'],
                "total": len(items)
            })
        else:
            params = {
                'ParentId': data['parent_id'],
                'SortBy': 'SortName',
                'Fields': 'ImageTags,ProviderIds',
                'StartIndex': data.get('skip', 0),
                'Limit': data.get('limit', 50)
            }
            
            response = requests.get(
                f"{server['url']}/Users/{user_id}/Items",
                headers=headers,
                params=params
            ).json()
            
            clean_items = []
            for item in response.get('Items', []):
                is_folder = item['Type'] in [
                    'Folder', 'CollectionFolder', 'Series',
                    'Season', 'BoxSet'
                ]
                
                exists = False
                if not is_folder and local_ids:
                    providers = item.get('ProviderIds', {})
                    imdb_key = f"imdb_{providers.get('Imdb')}"
                    tmdb_key = f"tmdb_{providers.get('Tmdb')}"
                    exists = imdb_key in local_ids or tmdb_key in local_ids
                
                clean_items.append({
                    "Id": item['Id'],
                    "Name": item['Name'],
                    "IsFolder": is_folder,
                    "HasImage": 'Primary' in item.get('ImageTags', {}),
                    "ExistsLocally": exists,
                    "Type": item.get('Type', 'Unknown')
                })
            
            return jsonify({
                "items": clean_items,
                "base_url": server['url'],
                "total": response.get('TotalRecordCount', 0)
            })
            
    except Exception as e:
        log(f"Browse Error: {e}")
        return jsonify({"items": [], "total": 0})


@app.route('/api/batch_download', methods=['POST'])
@login_required
def batch_download():
    data = request.json
    cfg = load_config()
    
    server = next(
        (s for s in cfg['servers'] if s['id'] == data['server_id']),
        None
    )
    if not server:
        return jsonify({"status": "error", "message": "Server not found"})
    
    for item_id in data['item_ids']:
        tid = generate_id()
        with download_lock:
            pending_display.append({"name": "Resolving...", "id": tid})
        
        threading.Thread(
            target=recursive_resolve,
            args=(server, item_id, data['path'], tid, cfg.get('speed_limit_kbs', 0)),
            daemon=True
        ).start()
    
    return jsonify({"status": "queued", "count": len(data['item_ids'])})


def recursive_resolve(server, item_id, base_path, tid, limit):
    """Resolve item and queue downloads (handles series/seasons)"""
    global pending_display
    
    try:
        headers = get_auth_header(server['key'])
        user_id = requests.get(
            f"{server['url']}/Users",
            headers=headers
        ).json()[0]['Id']
        
        item = requests.get(
            f"{server['url']}/Users/{user_id}/Items/{item_id}",
            headers=headers
        ).json()
        
        container_types = ['Series', 'Season', 'BoxSet', 'Folder', 'CollectionFolder']
        
        if item['Type'] in container_types:
            children = requests.get(
                f"{server['url']}/Users/{user_id}/Items",
                headers=headers,
                params={
                    'ParentId': item_id,
                    'Recursive': 'true',
                    'IncludeItemTypes': 'Movie,Episode'
                }
            ).json().get('Items', [])
            
            with download_lock:
                pending_display = [x for x in pending_display if x['id'] != tid]
            
            for child in children:
                sub_tid = generate_id()
                queue_item(server, child, base_path, sub_tid, limit)
        else:
            queue_item(server, item, base_path, tid, limit)
            
    except Exception as e:
        log(f"Resolve Error: {e}")
        with download_lock:
            pending_display = [x for x in pending_display if x['id'] != tid]


def queue_item(server, item, base_path, tid, limit):
    """Queue a single item for download"""
    try:
        safe_name = clean_name(item['Name'])
        ext = item.get('Container', 'mkv')
        
        if item['Type'] == 'Episode':
            series = clean_name(item.get('SeriesName', 'Unknown'))
            season_num = item.get('ParentIndexNumber', 1)
            episode_num = item.get('IndexNumber', 0)
            
            rel_path = os.path.join(series, f"Season {season_num}")
            filename = f"{series} - S{season_num:02}E{episode_num:02} - {safe_name}.{ext}"
        else:
            rel_path = ""
            filename = f"{safe_name}.{ext}"
        
        full_dir = os.path.join(base_path, rel_path)
        os.makedirs(full_dir, exist_ok=True)
        
        filepath = os.path.join(full_dir, filename)
        
        if os.path.exists(filepath):
            log(f"Skipped (exists): {filename}")
            with download_lock:
                global pending_display
                pending_display = [x for x in pending_display if x['id'] != tid]
            return
        
        with download_lock:
            if any(p['name'] == filename for p in pending_display):
                return
            if any(d['filename'] == filename for d in active_downloads.values()):
                return
            
            for p in pending_display:
                if p['id'] == tid:
                    p['name'] = filename
                    break
            else:
                pending_display.append({"name": filename, "id": tid})
        
        task_queue.put({
            'url': f"{server['url']}/Items/{item['Id']}/Download?api_key={server['key']}",
            'filepath': filepath,
            'task_id': tid,
            'limit': limit
        })
        
    except Exception as e:
        log(f"Queue Error: {e}")


@app.route('/api/browse_local', methods=['POST'])
@login_required
def browse_local():
    """Browse local filesystem for destination selection"""
    path = request.json.get('path', '/storage')
    
    if not path.startswith('/storage'):
        path = '/storage'
    
    try:
        folders = sorted([
            entry.name for entry in os.scandir(path)
            if entry.is_dir() and not entry.name.startswith('.')
        ])
        
        return jsonify({
            "current": path,
            "folders": folders,
            "parent": os.path.dirname(path) if path != '/storage' else None
        })
    except Exception as e:
        return jsonify({
            "error": str(e),
            "folders": [],
            "current": path
        })


@app.route('/api/sync', methods=['POST'])
@login_required
def trigger_sync():
    threading.Thread(target=sync_job, daemon=True).start()
    return jsonify({"status": "started"})


def sync_job():
    """Run sync for all configured mappings"""
    cfg = load_config()
    
    if not cfg.get('auto_sync_enabled', True):
        log("Sync skipped: Auto-sync disabled")
        return
    
    log("─── Sync Started ───")
    load_cache_from_disk()
    
    for mapping in cfg['mappings']:
        server = next(
            (s for s in cfg['servers'] if s['id'] == mapping['server_id']),
            None
        )
        if not server:
            continue
        
        try:
            headers = get_auth_header(server['key'])
            user_id = requests.get(
                f"{server['url']}/Users",
                headers=headers
            ).json()[0]['Id']
            
            items = requests.get(
                f"{server['url']}/Users/{user_id}/Items",
                headers=headers,
                params={
                    'ParentId': mapping['lib_id'],
                    'Recursive': 'true',
                    'IncludeItemTypes': 'Movie,Episode',
                    'Fields': 'ProviderIds'
                }
            ).json().get('Items', [])
            
            queued = 0
            for item in items:
                if local_id_cache:
                    providers = item.get('ProviderIds', {})
                    imdb_key = f"imdb_{providers.get('Imdb')}"
                    tmdb_key = f"tmdb_{providers.get('Tmdb')}"
                    if imdb_key in local_id_cache or tmdb_key in local_id_cache:
                        continue
                
                tid = generate_id()
                queue_item(server, item, mapping['local_path'], tid, cfg.get('speed_limit_kbs', 0))
                queued += 1
            
            log(f"Sync: Queued {queued} items from {server['name']}")
            
        except Exception as e:
            log(f"Sync Error ({server['name']}): {e}")
    
    log("─── Sync Finished ───")


# --- Application Startup ---

if __name__ == '__main__':
    # Load cache
    load_cache_from_disk()
    
    # Start worker threads
    num_workers = load_config().get('max_concurrent_downloads', 2)
    for _ in range(num_workers):
        threading.Thread(target=worker, daemon=True).start()
    
    # Setup and start scheduler
    setup_schedule()
    threading.Thread(target=schedule_runner, daemon=True).start()
    
    log("JellyLooter v2.1.0 started")
    app.run(host='0.0.0.0', port=5000, threaded=True)
