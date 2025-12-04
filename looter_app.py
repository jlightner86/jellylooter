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
import shutil
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, make_response, send_from_directory

CONFIG_FILE = '/config/looter_config.json'
CACHE_FILE = '/config/local_cache.json'
AUTH_FILE = '/config/auth.json'

VERSION = "2.3.0"

app = Flask(__name__, static_folder='static')

# Thread-safe state management
task_queue = queue.Queue()
active_downloads = {}
pending_display = []
cancelled_tasks = set()
download_lock = threading.Lock()
worker_lock = threading.Lock()
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

# Worker management
active_workers = 0
target_workers = 2
worker_shutdown = threading.Event()

# --- Translations ---
TRANSLATIONS = {
    'en': {
        'app_name': 'JellyLooter',
        'sign_in': 'Sign In',
        'sign_out': 'Sign Out',
        'username': 'Username',
        'password': 'Password',
        'remember_me': 'Remember me',
        'settings': 'Settings',
        'browse': 'Browse',
        'downloads': 'Downloads',
        'help': 'Help',
        'changelog': 'Changelog',
        'remote_servers': 'Remote Servers',
        'local_server': 'Local Server',
        'add_server': 'Add Server',
        'remove': 'Remove',
        'save': 'Save',
        'cancel': 'Cancel',
        'download': 'Download',
        'pause': 'Pause',
        'resume': 'Resume',
        'cancel_all': 'Cancel All',
        'speed_limit': 'Speed Limit',
        'max_downloads': 'Max Downloads',
        'no_servers': 'No servers configured',
        'select_server': 'Select Server',
        'select_destination': 'Select Destination',
        'items_selected': 'items selected',
        'download_complete': 'Download complete',
        'download_failed': 'Download failed',
        'connection_error': 'Connection error',
        'invalid_credentials': 'Invalid credentials',
        'sync': 'Sync',
        'rebuild_cache': 'Rebuild Cache',
        'cache_info': 'Cache Info',
        'last_scan': 'Last Scan',
        'items_cached': 'Items Cached',
        'general': 'General',
        'advanced': 'Advanced',
        'authentication': 'Authentication',
        'enable_auth': 'Enable Authentication',
        'auth_description': 'Require login to access JellyLooter',
        'language': 'Language',
        'items_per_page': 'Items Per Page',
        'view_mode': 'View Mode',
        'grid_view': 'Grid',
        'list_view': 'List',
        'download_order': 'Download Order',
        'order_library': 'Library Order',
        'order_show_complete': 'Complete Shows First',
        'order_season_round': 'Season Round Robin',
        'order_episode_round': 'Episode Round Robin',
        'order_alphabetical': 'Alphabetical',
        'order_random': 'Random',
        'confirmed_working': 'Confirmed working on Unraid 7.2.0',
        'support_project': 'Support the Project',
        'buy_coffee': 'Buy Me a Coffee',
        'loading': 'Loading...',
        'error': 'Error',
        'success': 'Success',
        'warning': 'Warning',
        'free_space': 'Free Space',
        'total_space': 'Total Space',
        'refresh': 'Refresh',
        'back': 'Back',
        'home': 'Home',
        'page': 'Page',
        'of': 'of',
        'previous': 'Previous',
        'next': 'Next',
        'search': 'Search',
        'filter': 'Filter',
        'all': 'All',
        'movies': 'Movies',
        'shows': 'Shows',
        'exists_locally': 'Exists Locally',
        'queued': 'Queued',
        'downloading': 'Downloading',
        'completed': 'Completed',
        'failed': 'Failed',
        'paused': 'Paused',
        'starting': 'Starting',
    },
    'es': {
        'app_name': 'JellyLooter',
        'sign_in': 'Iniciar Sesión',
        'sign_out': 'Cerrar Sesión',
        'username': 'Usuario',
        'password': 'Contraseña',
        'remember_me': 'Recordarme',
        'settings': 'Configuración',
        'browse': 'Explorar',
        'downloads': 'Descargas',
        'help': 'Ayuda',
        'changelog': 'Cambios',
        'remote_servers': 'Servidores Remotos',
        'local_server': 'Servidor Local',
        'add_server': 'Agregar Servidor',
        'remove': 'Eliminar',
        'save': 'Guardar',
        'cancel': 'Cancelar',
        'download': 'Descargar',
        'pause': 'Pausar',
        'resume': 'Reanudar',
        'cancel_all': 'Cancelar Todo',
        'speed_limit': 'Límite de Velocidad',
        'max_downloads': 'Descargas Máximas',
        'no_servers': 'No hay servidores configurados',
        'select_server': 'Seleccionar Servidor',
        'select_destination': 'Seleccionar Destino',
        'items_selected': 'elementos seleccionados',
        'download_complete': 'Descarga completa',
        'download_failed': 'Descarga fallida',
        'connection_error': 'Error de conexión',
        'invalid_credentials': 'Credenciales inválidas',
        'sync': 'Sincronizar',
        'rebuild_cache': 'Reconstruir Caché',
        'cache_info': 'Info de Caché',
        'last_scan': 'Último Escaneo',
        'items_cached': 'Elementos en Caché',
        'general': 'General',
        'advanced': 'Avanzado',
        'authentication': 'Autenticación',
        'enable_auth': 'Habilitar Autenticación',
        'auth_description': 'Requerir inicio de sesión para acceder',
        'language': 'Idioma',
        'items_per_page': 'Elementos por Página',
        'view_mode': 'Modo de Vista',
        'grid_view': 'Cuadrícula',
        'list_view': 'Lista',
        'download_order': 'Orden de Descarga',
        'order_library': 'Orden de Biblioteca',
        'order_show_complete': 'Series Completas Primero',
        'order_season_round': 'Rotación por Temporada',
        'order_episode_round': 'Rotación por Episodio',
        'order_alphabetical': 'Alfabético',
        'order_random': 'Aleatorio',
        'confirmed_working': 'Confirmado funcionando en Unraid 7.2.0',
        'support_project': 'Apoya el Proyecto',
        'buy_coffee': 'Invítame un Café',
        'loading': 'Cargando...',
        'error': 'Error',
        'success': 'Éxito',
        'warning': 'Advertencia',
        'free_space': 'Espacio Libre',
        'total_space': 'Espacio Total',
        'refresh': 'Actualizar',
        'back': 'Atrás',
        'home': 'Inicio',
        'page': 'Página',
        'of': 'de',
        'previous': 'Anterior',
        'next': 'Siguiente',
        'search': 'Buscar',
        'filter': 'Filtrar',
        'all': 'Todo',
        'movies': 'Películas',
        'shows': 'Series',
        'exists_locally': 'Existe Localmente',
        'queued': 'En Cola',
        'downloading': 'Descargando',
        'completed': 'Completado',
        'failed': 'Fallido',
        'paused': 'Pausado',
        'starting': 'Iniciando',
    },
    'de': {
        'app_name': 'JellyLooter',
        'sign_in': 'Anmelden',
        'sign_out': 'Abmelden',
        'username': 'Benutzername',
        'password': 'Passwort',
        'remember_me': 'Angemeldet bleiben',
        'settings': 'Einstellungen',
        'browse': 'Durchsuchen',
        'downloads': 'Downloads',
        'help': 'Hilfe',
        'changelog': 'Änderungen',
        'remote_servers': 'Remote-Server',
        'local_server': 'Lokaler Server',
        'add_server': 'Server hinzufügen',
        'remove': 'Entfernen',
        'save': 'Speichern',
        'cancel': 'Abbrechen',
        'download': 'Herunterladen',
        'pause': 'Pause',
        'resume': 'Fortsetzen',
        'cancel_all': 'Alle abbrechen',
        'speed_limit': 'Geschwindigkeitslimit',
        'max_downloads': 'Max. Downloads',
        'no_servers': 'Keine Server konfiguriert',
        'select_server': 'Server auswählen',
        'select_destination': 'Ziel auswählen',
        'items_selected': 'Elemente ausgewählt',
        'download_complete': 'Download abgeschlossen',
        'download_failed': 'Download fehlgeschlagen',
        'connection_error': 'Verbindungsfehler',
        'invalid_credentials': 'Ungültige Anmeldedaten',
        'sync': 'Synchronisieren',
        'rebuild_cache': 'Cache neu aufbauen',
        'cache_info': 'Cache-Info',
        'last_scan': 'Letzter Scan',
        'items_cached': 'Zwischengespeicherte Elemente',
        'general': 'Allgemein',
        'advanced': 'Erweitert',
        'authentication': 'Authentifizierung',
        'enable_auth': 'Authentifizierung aktivieren',
        'auth_description': 'Anmeldung für Zugriff erforderlich',
        'language': 'Sprache',
        'items_per_page': 'Elemente pro Seite',
        'view_mode': 'Ansichtsmodus',
        'grid_view': 'Raster',
        'list_view': 'Liste',
        'download_order': 'Download-Reihenfolge',
        'order_library': 'Bibliotheksreihenfolge',
        'order_show_complete': 'Komplette Serien zuerst',
        'order_season_round': 'Staffel-Rotation',
        'order_episode_round': 'Episoden-Rotation',
        'order_alphabetical': 'Alphabetisch',
        'order_random': 'Zufällig',
        'confirmed_working': 'Bestätigt funktionierend auf Unraid 7.2.0',
        'support_project': 'Projekt unterstützen',
        'buy_coffee': 'Kauf mir einen Kaffee',
        'loading': 'Laden...',
        'error': 'Fehler',
        'success': 'Erfolg',
        'warning': 'Warnung',
        'free_space': 'Freier Speicher',
        'total_space': 'Gesamtspeicher',
        'refresh': 'Aktualisieren',
        'back': 'Zurück',
        'home': 'Start',
        'page': 'Seite',
        'of': 'von',
        'previous': 'Zurück',
        'next': 'Weiter',
        'search': 'Suchen',
        'filter': 'Filter',
        'all': 'Alle',
        'movies': 'Filme',
        'shows': 'Serien',
        'exists_locally': 'Lokal vorhanden',
        'queued': 'In Warteschlange',
        'downloading': 'Wird heruntergeladen',
        'completed': 'Abgeschlossen',
        'failed': 'Fehlgeschlagen',
        'paused': 'Pausiert',
        'starting': 'Startet',
    }
}


def get_translation(key, lang='en'):
    """Get translation for a key"""
    return TRANSLATIONS.get(lang, TRANSLATIONS['en']).get(key, TRANSLATIONS['en'].get(key, key))


def get_all_translations(lang='en'):
    """Get all translations for a language"""
    return TRANSLATIONS.get(lang, TRANSLATIONS['en'])


# --- Authentication Helpers ---

def init_secret_key():
    """Initialize or load secret key for Flask sessions"""
    auth = load_auth()
    if auth and 'secret_key' in auth:
        return auth['secret_key']
    
    # Generate new secret key
    secret = secrets.token_hex(32)
    
    # Save it if auth is enabled
    if auth:
        auth['secret_key'] = secret
        save_auth(auth)
    
    return secret


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


def is_auth_enabled():
    """Check if authentication is enabled"""
    cfg = load_config()
    return cfg.get('auth_enabled', False)


def is_setup_complete():
    """Check if initial setup has been completed (only matters if auth is enabled)"""
    if not is_auth_enabled():
        return True
    auth = load_auth()
    return auth is not None and 'users' in auth and len(auth['users']) > 0


def login_required(f):
    """Decorator to require authentication (only if auth is enabled)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If auth is disabled, allow access
        if not is_auth_enabled():
            return f(*args, **kwargs)
        
        if 'user' not in session:
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
    headers = {
        'X-Emby-Authorization': f'MediaBrowser Client="JellyLooter", Device="Unraid", DeviceId="JellyLooterId", Version="{VERSION}"'
    }
    if token:
        headers['X-Emby-Authorization'] += f', Token="{token}"'
        headers['X-Emby-Token'] = token
        headers['X-MediaBrowser-Token'] = token
        headers['Authorization'] = f'MediaBrowser Token="{token}"'
    return headers


def check_disk_space(path, required_bytes=0):
    """Check if there's enough disk space at the given path"""
    try:
        stat = shutil.disk_usage(path)
        free_bytes = stat.free
        
        if required_bytes > 0 and free_bytes < required_bytes:
            return False, f"Not enough space. Free: {format_bytes(free_bytes)}, Need: {format_bytes(required_bytes)}"
        
        if free_bytes < 1024 * 1024 * 1024:
            log(f"⚠️ Warning: Low disk space on {path} - {format_bytes(free_bytes)} free")
        
        return True, f"Free: {format_bytes(free_bytes)}"
    except Exception as e:
        return False, f"Cannot check disk space: {e}"


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
        "chunk_size_kb": 64,
        "auth_enabled": False,
        "language": "en",
        "items_per_page": 50,
        "view_mode": "grid",
        "download_order": "library"
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
    adjust_workers(data.get('max_concurrent_downloads', 2))
    
    # Handle auth state changes
    if data.get('auth_enabled', False):
        auth = load_auth()
        if not auth:
            # Initialize auth file with secret key
            auth = {'secret_key': secrets.token_hex(32), 'users': {}, 'tokens': {}}
            save_auth(auth)
        elif 'secret_key' not in auth:
            auth['secret_key'] = secrets.token_hex(32)
            save_auth(auth)
        app.secret_key = auth['secret_key']


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
        
        u_res = requests.get(f"{url}/Users", headers=headers, timeout=timeout)
        if not u_res.ok:
            raise Exception("Authentication Failed")
        uid = u_res.json()[0]['Id']

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
    
    schedule.every().day.at("03:00").do(
        lambda: threading.Thread(target=cache_worker, daemon=True).start()
    )
    
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


# --- Worker Management ---

def adjust_workers(new_count):
    """Dynamically adjust the number of worker threads"""
    global active_workers, target_workers
    
    with worker_lock:
        target_workers = max(1, min(new_count, 10))
        
        while active_workers < target_workers:
            threading.Thread(target=worker, daemon=True).start()
            active_workers += 1
            log(f"Started worker (total: {active_workers})")


def worker():
    """Download worker thread"""
    global active_workers, pending_display
    
    while True:
        with worker_lock:
            if active_workers > target_workers:
                active_workers -= 1
                log(f"Stopped worker (total: {active_workers})")
                return
        
        try:
            task = task_queue.get(timeout=5)
        except queue.Empty:
            continue
        
        if task is None:
            task_queue.task_done()
            break
        
        tid = task['task_id']
        
        with download_lock:
            pending_display = [x for x in pending_display if x['id'] != tid]
        
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
    
    cfg = load_config()
    speed_limit = cfg.get('speed_limit_kbs', 0)
    chunk_size = cfg.get('chunk_size_kb', 64) * 1024
    timeout = cfg.get('connection_timeout', 30)
    
    try:
        dir_path = os.path.dirname(filepath)
        
        if not os.path.exists(dir_path):
            try:
                os.makedirs(dir_path, exist_ok=True)
                log(f"Created directory: {dir_path}")
            except OSError as e:
                raise Exception(f"Cannot create directory {dir_path}: {e}")
        
        test_file = os.path.join(dir_path, '.write_test')
        try:
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
        except OSError as e:
            raise Exception(f"Cannot write to {dir_path}: {e}")
        
        space_ok, space_msg = check_disk_space(dir_path)
        if not space_ok:
            raise Exception(space_msg)
        
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
        
        with requests.get(task['url'], stream=True, timeout=timeout, headers=task.get('headers', {})) as response:
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            
            if total_size > 0:
                space_ok, space_msg = check_disk_space(dir_path, total_size)
                if not space_ok:
                    raise Exception(space_msg)
            
            with download_lock:
                active_downloads[tid]['total'] = total_size
            
            downloaded = 0
            speed_window = []
            last_speed_update = time.time()
            last_config_check = time.time()
            
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
                    
                    try:
                        f.write(chunk)
                    except OSError as e:
                        if e.errno == 28:
                            raise Exception(f"Disk full while writing to {dir_path}")
                        raise
                    
                    chunk_len = len(chunk)
                    downloaded += chunk_len
                    
                    now = time.time()
                    if now - last_config_check > 10:
                        cfg = load_config()
                        speed_limit = cfg.get('speed_limit_kbs', 0)
                        last_config_check = now
                    
                    if speed_limit > 0:
                        target_time = chunk_len / (speed_limit * 1024)
                        elapsed = time.time() - chunk_start
                        sleep_time = target_time - elapsed
                        if sleep_time > 0:
                            time.sleep(sleep_time)
                    
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


# --- Download Queue Ordering ---

def sort_download_queue(items, order='library'):
    """Sort items based on download order preference"""
    if order == 'random':
        random.shuffle(items)
        return items
    
    if order == 'alphabetical':
        return sorted(items, key=lambda x: x.get('sort_name', x.get('Name', '')).lower())
    
    if order == 'show_complete':
        # Group by series, download complete series before moving to next
        series_groups = {}
        movies = []
        for item in items:
            series_name = item.get('SeriesName')
            if series_name:
                if series_name not in series_groups:
                    series_groups[series_name] = []
                series_groups[series_name].append(item)
            else:
                movies.append(item)
        
        result = movies
        for series in sorted(series_groups.keys()):
            eps = series_groups[series]
            eps.sort(key=lambda x: (x.get('ParentIndexNumber', 0), x.get('IndexNumber', 0)))
            result.extend(eps)
        return result
    
    if order == 'season_round':
        # First season of each show, then second season of each, etc.
        series_seasons = {}
        movies = []
        for item in items:
            series_name = item.get('SeriesName')
            if series_name:
                season = item.get('ParentIndexNumber', 0)
                key = (series_name, season)
                if key not in series_seasons:
                    series_seasons[key] = []
                series_seasons[key].append(item)
            else:
                movies.append(item)
        
        # Sort episodes within each season
        for key in series_seasons:
            series_seasons[key].sort(key=lambda x: x.get('IndexNumber', 0))
        
        # Get max season number
        max_season = max([k[1] for k in series_seasons.keys()], default=0)
        
        result = movies
        for season_num in range(1, max_season + 2):
            for series_name in sorted(set(k[0] for k in series_seasons.keys())):
                key = (series_name, season_num)
                if key in series_seasons:
                    result.extend(series_seasons[key])
        return result
    
    if order == 'episode_round':
        # First episode of each show, then second episode of each, etc.
        series_episodes = {}
        movies = []
        for item in items:
            series_name = item.get('SeriesName')
            if series_name:
                if series_name not in series_episodes:
                    series_episodes[series_name] = []
                series_episodes[series_name].append(item)
            else:
                movies.append(item)
        
        # Sort by season then episode
        for series in series_episodes:
            series_episodes[series].sort(key=lambda x: (x.get('ParentIndexNumber', 0), x.get('IndexNumber', 0)))
        
        # Round robin through episodes
        result = movies
        max_len = max([len(eps) for eps in series_episodes.values()], default=0)
        for i in range(max_len):
            for series in sorted(series_episodes.keys()):
                if i < len(series_episodes[series]):
                    result.append(series_episodes[series][i])
        return result
    
    # Default: library order (as returned by server)
    return items


# --- API Authentication ---

def login_with_creds(url, username, password):
    """Authenticate with username/password and return token and user_id"""
    try:
        response = requests.post(
            f"{url}/Users/AuthenticateByName",
            json={"Username": username, "Pw": password},
            headers=get_auth_header(),
            timeout=10
        )
        log(f"Auth response status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            log(f"Auth response keys: {list(data.keys())}")
            
            # Try different token field names used by different Jellyfin versions
            token = data.get("AccessToken") or data.get("access_token") or data.get("Token")
            
            # Get user ID from the response
            user_id = None
            if "User" in data and isinstance(data["User"], dict):
                user_id = data["User"].get("Id")
            
            if token:
                log(f"Got access token: {token[:20]}... for user: {user_id}")
                return {"token": token, "user_id": user_id}
            else:
                log(f"No token found in response. Full response: {str(data)[:500]}")
                return None
        else:
            log(f"Auth failed: {response.status_code} - {response.text[:200]}")
            return None
    except requests.exceptions.Timeout:
        log("Auth failed: Connection timeout")
        return None
    except requests.exceptions.ConnectionError as e:
        log(f"Auth failed: Connection error - {e}")
        return None
    except Exception as e:
        log(f"Auth failed: {e}")
        return None


# --- Flask Routes: Static Files ---

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)


# --- Flask Routes: Authentication ---

@app.route('/setup')
def setup_page():
    """Initial setup page"""
    if not is_auth_enabled():
        return redirect(url_for('index'))
    if is_setup_complete():
        return redirect(url_for('login'))
    return render_template('setup.html')


@app.route('/login')
def login():
    """Login page"""
    if not is_auth_enabled():
        return redirect(url_for('index'))
    if not is_setup_complete():
        return redirect(url_for('setup_page'))
    if 'user' in session:
        return redirect(url_for('index'))
    cfg = load_config()
    return render_template('login.html', lang=cfg.get('language', 'en'), version=VERSION)


@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.pop('user', None)
    response = make_response(redirect(url_for('login') if is_auth_enabled() else url_for('index')))
    response.delete_cookie('remember_token')
    return response


@app.route('/api/setup', methods=['POST'])
def api_setup():
    """Handle initial setup"""
    if not is_auth_enabled():
        return jsonify({"status": "error", "message": "Authentication is disabled"})
    if is_setup_complete():
        return jsonify({"status": "error", "message": "Setup already completed"})
    
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password required"})
    
    if len(password) < 4:
        return jsonify({"status": "error", "message": "Password must be at least 4 characters"})
    
    auth = load_auth() or {}
    auth['users'] = {username: hash_password(password)}
    auth['tokens'] = {}
    if 'secret_key' not in auth:
        auth['secret_key'] = secrets.token_hex(32)
    save_auth(auth)
    app.secret_key = auth['secret_key']
    
    return jsonify({"status": "ok", "message": "Setup complete"})


@app.route('/api/login', methods=['POST'])
def api_login():
    """Handle login"""
    if not is_auth_enabled():
        return jsonify({"status": "error", "message": "Authentication is disabled"})
    
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    remember = data.get('remember', False)
    
    auth = load_auth()
    if not auth or 'users' not in auth:
        return jsonify({"status": "error", "message": "No users configured"})
    
    if username not in auth['users']:
        return jsonify({"status": "error", "message": "Invalid credentials"})
    
    if not verify_password(password, auth['users'][username]):
        return jsonify({"status": "error", "message": "Invalid credentials"})
    
    session['user'] = username
    
    response_data = {"status": "ok"}
    
    if remember:
        token = secrets.token_hex(32)
        if 'tokens' not in auth:
            auth['tokens'] = {}
        auth['tokens'][username] = token
        save_auth(auth)
        response_data['remember_token'] = token
    
    return jsonify(response_data)


# --- Flask Routes: Main ---

@app.route('/')
@login_required
def index():
    cfg = load_config()
    lang = cfg.get('language', 'en')
    return render_template('index.html', 
                           lang=lang, 
                           translations=get_all_translations(lang),
                           version=VERSION,
                           config=cfg)


@app.route('/changelog')
@login_required
def changelog():
    cfg = load_config()
    return render_template('changelog.html', 
                           lang=cfg.get('language', 'en'),
                           version=VERSION)


@app.route('/help')
@login_required
def help_page():
    cfg = load_config()
    return render_template('help.html', 
                           lang=cfg.get('language', 'en'),
                           version=VERSION)


@app.route('/api/config', methods=['GET', 'POST'])
@login_required
def config_api():
    if request.method == 'POST':
        save_config(request.json)
        return jsonify({"status": "ok"})
    return jsonify(load_config())


@app.route('/api/translations')
def get_translations():
    """Get translations for current language"""
    cfg = load_config()
    lang = request.args.get('lang', cfg.get('language', 'en'))
    return jsonify(get_all_translations(lang))


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
            "queue_size": task_queue.qsize(),
            "worker_count": active_workers,
            "version": VERSION
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
def cancel_dl():
    global pending_display
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
            pending_display = [x for x in pending_display if x['id'] != task_id]
        log(f"Cancelled task: {task_id}")
        return jsonify({"status": "cancelled", "task_id": task_id})
    
    return jsonify({"status": "error", "message": "No task_id provided"})


@app.route('/api/test_connection', methods=['POST'])
@login_required
def test_connection():
    data = request.json
    url = data.get('url', '').rstrip('/')
    
    if not url:
        return jsonify({"status": "error", "error": "URL is required"})
    
    try:
        if data.get('username'):
            # Username/password auth
            auth_result = login_with_creds(
                url,
                data.get('username'),
                data.get('password')
            )
            if auth_result and auth_result.get('token'):
                token = auth_result['token']
                user_id = auth_result.get('user_id')
                
                # Verify the token works by accessing the user's own data
                verify_response = requests.get(
                    f"{url}/Users/{user_id}" if user_id else f"{url}/Users",
                    headers=get_auth_header(token),
                    timeout=10
                )
                if verify_response.ok:
                    return jsonify({"status": "ok", "key": token, "user_id": user_id})
                else:
                    return jsonify({"status": "error", "error": "Token verification failed"})
            return jsonify({"status": "error", "error": "Invalid credentials"})
        else:
            # API key auth
            key = data.get('key')
            if not key:
                return jsonify({"status": "error", "error": "API key is required"})
            
            response = requests.get(
                f"{url}/Users",
                headers=get_auth_header(key),
                timeout=10
            )
            if response.ok:
                users = response.json()
                if users and len(users) > 0:
                    return jsonify({"status": "ok", "key": key})
                else:
                    return jsonify({"status": "error", "error": "No users found - invalid API key?"})
            return jsonify({"status": "error", "error": f"Server returned {response.status_code}"})
    except requests.exceptions.Timeout:
        return jsonify({"status": "error", "error": "Connection timeout"})
    except requests.exceptions.ConnectionError:
        return jsonify({"status": "error", "error": "Cannot connect to server"})
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
            
            # Use stored user_id if available (for username/password auth)
            user_id = server.get('user_id')
            
            if not user_id:
                user_id = requests.get(
                    f"{server['url']}/Users",
                    headers=headers,
                    timeout=10
                ).json()[0]['Id']
            
            libs = requests.get(
                f"{server['url']}/Users/{user_id}/Views",
                headers=headers,
                timeout=10
            ).json().get('Items', [])
            
            results.append({
                "server_id": server['id'],
                "server_name": server['name'],
                "libs": libs
            })
        except Exception as e:
            log(f"Scan libs error for {server.get('name', 'unknown')}: {e}")
    
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
        return jsonify({"items": [], "total": 0, "error": "Server not found"})
    
    try:
        log(f"Browsing server: {server['name']} with key: {server['key'][:20] if server.get('key') else 'None'}...")
        headers = get_auth_header(server['key'])
        log(f"Using headers: {list(headers.keys())}")
        
        # Use stored user_id if available (for username/password auth)
        # Otherwise, query /Users to get a user ID (for API key auth)
        user_id = server.get('user_id')
        
        if not user_id:
            users_response = requests.get(
                f"{server['url']}/Users",
                headers=headers,
                timeout=10
            )
            
            log(f"Users response: {users_response.status_code}")
            
            if not users_response.ok:
                log(f"Browse Error: Server returned {users_response.status_code} - {users_response.text[:200]}")
                return jsonify({"items": [], "total": 0, "error": f"Auth failed: {users_response.status_code}"})
            
            users_data = users_response.json()
            if not users_data or len(users_data) == 0:
                log("Browse Error: No users returned from server")
                return jsonify({"items": [], "total": 0, "error": "No users found - check API key"})
            
            user_id = users_data[0]['Id']
        
        log(f"Using user ID: {user_id}")
        
        local_ids = get_existing_ids()
        
        if data['parent_id'] == 'root':
            views_response = requests.get(
                f"{server['url']}/Users/{user_id}/Views",
                headers=headers,
                timeout=15
            )
            log(f"Views response: {views_response.status_code}")
            
            if not views_response.ok:
                log(f"Views Error: {views_response.status_code} - {views_response.text[:200]}")
                return jsonify({"items": [], "total": 0, "error": f"Failed to get libraries: {views_response.status_code}"})
            
            try:
                views_data = views_response.json()
                items = views_data.get('Items', [])
            except Exception as e:
                log(f"Views JSON Error: {e} - Response: {views_response.text[:200]}")
                return jsonify({"items": [], "total": 0, "error": "Invalid response from server"})
            
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
            # Get pagination params
            page = data.get('page', 1)
            items_per_page = data.get('items_per_page', cfg.get('items_per_page', 50))
            skip = (page - 1) * items_per_page
            
            params = {
                'ParentId': data['parent_id'],
                'SortBy': 'SortName',
                'Fields': 'ImageTags,ProviderIds',
                'StartIndex': skip,
                'Limit': items_per_page
            }
            
            items_response = requests.get(
                f"{server['url']}/Users/{user_id}/Items",
                headers=headers,
                params=params,
                timeout=30
            )
            log(f"Items response: {items_response.status_code}")
            
            if not items_response.ok:
                log(f"Items Error: {items_response.status_code} - {items_response.text[:200]}")
                return jsonify({"items": [], "total": 0, "error": f"Failed to get items: {items_response.status_code}"})
            
            try:
                response = items_response.json()
            except Exception as e:
                log(f"Items JSON Error: {e} - Response: {items_response.text[:200]}")
                return jsonify({"items": [], "total": 0, "error": "Invalid response from server"})
            
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
                    "Type": item.get('Type', 'Unknown'),
                    "SeriesName": item.get('SeriesName'),
                    "ParentIndexNumber": item.get('ParentIndexNumber'),
                    "IndexNumber": item.get('IndexNumber')
                })
            
            total = response.get('TotalRecordCount', 0)
            total_pages = (total + items_per_page - 1) // items_per_page
            
            return jsonify({
                "items": clean_items,
                "base_url": server['url'],
                "total": total,
                "page": page,
                "items_per_page": items_per_page,
                "total_pages": total_pages
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
    
    download_path = data['path']
    space_ok, space_msg = check_disk_space(download_path)
    if not space_ok:
        return jsonify({"status": "error", "message": space_msg})
    
    download_order = cfg.get('download_order', 'library')
    
    for item_id in data['item_ids']:
        tid = generate_id()
        with download_lock:
            pending_display.append({"name": "Resolving...", "id": tid})
        
        threading.Thread(
            target=recursive_resolve,
            args=(server, item_id, data['path'], tid, cfg.get('speed_limit_kbs', 0), download_order),
            daemon=True
        ).start()
    
    return jsonify({"status": "queued", "count": len(data['item_ids'])})


@app.route('/api/disk_space', methods=['POST'])
@login_required
def get_disk_space():
    """Get disk space info for a path"""
    path = request.json.get('path', '/storage')
    
    try:
        stat = shutil.disk_usage(path)
        return jsonify({
            "status": "ok",
            "path": path,
            "total": format_bytes(stat.total),
            "used": format_bytes(stat.used),
            "free": format_bytes(stat.free),
            "percent_used": int((stat.used / stat.total) * 100)
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        })


def recursive_resolve(server, item_id, base_path, tid, limit, download_order='library'):
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
                    'IncludeItemTypes': 'Movie,Episode',
                    'Fields': 'ProviderIds'
                }
            ).json().get('Items', [])
            
            with download_lock:
                pending_display = [x for x in pending_display if x['id'] != tid]
            
            # Sort children based on download order
            children = sort_download_queue(children, download_order)
            
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
    global pending_display
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
            'url': f"{server['url']}/Items/{item['Id']}/Download",
            'filepath': filepath,
            'task_id': tid,
            'limit': limit,
            'headers': get_auth_header(server['key'])
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
        
        try:
            stat = shutil.disk_usage(path)
            space_info = {
                "free": format_bytes(stat.free),
                "total": format_bytes(stat.total),
                "percent_used": int((stat.used / stat.total) * 100)
            }
        except Exception:
            space_info = None
        
        return jsonify({
            "current": path,
            "folders": folders,
            "parent": os.path.dirname(path) if path != '/storage' else None,
            "space": space_info
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
    
    download_order = cfg.get('download_order', 'library')
    
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
            
            # Filter out items we already have
            items_to_queue = []
            for item in items:
                if local_id_cache:
                    providers = item.get('ProviderIds', {})
                    imdb_key = f"imdb_{providers.get('Imdb')}"
                    tmdb_key = f"tmdb_{providers.get('Tmdb')}"
                    if imdb_key in local_id_cache or tmdb_key in local_id_cache:
                        continue
                items_to_queue.append(item)
            
            # Sort based on download order
            items_to_queue = sort_download_queue(items_to_queue, download_order)
            
            queued = 0
            for item in items_to_queue:
                tid = generate_id()
                queue_item(server, item, mapping['local_path'], tid, cfg.get('speed_limit_kbs', 0))
                queued += 1
            
            log(f"Sync: Queued {queued} items from {server['name']}")
            
        except Exception as e:
            log(f"Sync Error ({server['name']}): {e}")
    
    log("─── Sync Finished ───")


# --- Application Startup ---

def init_app():
    """Initialize application"""
    global app
    
    # Load or generate secret key
    cfg = load_config()
    if cfg.get('auth_enabled', False):
        auth = load_auth()
        if auth and 'secret_key' in auth:
            app.secret_key = auth['secret_key']
        else:
            secret = secrets.token_hex(32)
            if auth:
                auth['secret_key'] = secret
                save_auth(auth)
            app.secret_key = secret
    else:
        # Auth disabled - use a session secret anyway for flash messages etc
        app.secret_key = secrets.token_hex(32)


if __name__ == '__main__':
    init_app()
    load_cache_from_disk()
    
    cfg = load_config()
    num_workers = cfg.get('max_concurrent_downloads', 2)
    adjust_workers(num_workers)
    
    setup_schedule()
    threading.Thread(target=schedule_runner, daemon=True).start()
    
    log(f"JellyLooter v{VERSION} started")
    log(f"Workers: {active_workers}, Speed limit: {cfg.get('speed_limit_kbs', 0)} KB/s")
    log(f"Auth: {'Enabled' if cfg.get('auth_enabled', False) else 'Disabled'}")
    app.run(host='0.0.0.0', port=5000, threaded=True)
