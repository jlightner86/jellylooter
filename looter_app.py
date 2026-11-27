import os
import json
import time
import select
import fcntl
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
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
import glob
import hmac
import subprocess
import signal
import base64
from collections import deque
from functools import wraps, lru_cache
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, make_response, send_from_directory
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Timezone support
try:
    from zoneinfo import ZoneInfo
    TIMEZONE_SUPPORT = True
except ImportError:
    TIMEZONE_SUPPORT = False

# Create a session with connection pooling and retry logic
def create_http_session():
    """Create an optimized HTTP session with connection pooling and retries"""
    sess = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(
        pool_connections=10,
        pool_maxsize=20,
        max_retries=retry_strategy
    )
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    return sess

# Global HTTP session for reuse
http_session = create_http_session()

# Security imports
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False

try:
    from flask_wtf.csrf import CSRFProtect
    CSRF_AVAILABLE = True
except ImportError:
    CSRF_AVAILABLE = False

# Notifications
try:
    import apprise
    APPRISE_AVAILABLE = True
except ImportError:
    APPRISE_AVAILABLE = False

CONFIG_FILE = '/config/looter_config.json'
CACHE_FILE = '/config/local_cache.json'
AUTH_FILE = '/config/auth.json'
LICENSE_FILE = '/config/license.json'
ENCRYPTION_KEY_FILE = '/config/.encryption_key'
PARTIAL_DOWNLOADS_FILE = '/config/partial_downloads.json'
METADATA_CACHE_FILE = '/config/metadata_cache.json'  # Pro feature: cached metadata lookups

VERSION = "4.0.0"

# Developer-only switches (Pro test activation, transcode test mode). Never set in the public image.
DEV_MODE = os.environ.get('JELLYLOOTER_DEV') == '1'

# --- Encryption for API Keys at Rest ---

_encryption_key_cache = {'mtime': None, 'value': None}


def _get_encryption_key():
    """Fernet key, derived once per key-file version (PBKDF2 is deliberately slow, so cache it)."""
    try:
        mtime = os.path.getmtime(ENCRYPTION_KEY_FILE)
    except OSError:
        mtime = None
    if mtime is not None and _encryption_key_cache['mtime'] == mtime and _encryption_key_cache['value']:
        return _encryption_key_cache['value']
    value = _derive_encryption_key()
    try:
        _encryption_key_cache.update(mtime=os.path.getmtime(ENCRYPTION_KEY_FILE), value=value)
    except OSError:
        pass
    return value


def _derive_encryption_key():
    """Get or create machine-specific encryption key for Fernet"""
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, 'rb') as f:
            stored_key = f.read()
            # If old format (32 bytes raw), upgrade to Fernet key
            if len(stored_key) == 32:
                # Derive a Fernet-compatible key using PBKDF2
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b'jellylooter_salt_v2',
                    iterations=100000,
                )
                fernet_key = base64.urlsafe_b64encode(kdf.derive(stored_key))
                return fernet_key, stored_key  # Return both for backward compat
            return stored_key, None  # Already Fernet format
    # Generate new key
    raw_key = secrets.token_bytes(32)
    os.makedirs(os.path.dirname(ENCRYPTION_KEY_FILE), exist_ok=True)
    with open(ENCRYPTION_KEY_FILE, 'wb') as f:
        f.write(raw_key)
    os.chmod(ENCRYPTION_KEY_FILE, 0o600)  # Restrict permissions
    # Derive Fernet key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'jellylooter_salt_v2',
        iterations=100000,
    )
    fernet_key = base64.urlsafe_b64encode(kdf.derive(raw_key))
    return fernet_key, raw_key

def encrypt_sensitive(plaintext):
    """Encrypt sensitive data (API keys) using Fernet (AES-128-CBC + HMAC)"""
    if not plaintext:
        return ''
    try:
        fernet_key, _ = _get_encryption_key()
        f = Fernet(fernet_key)
        encrypted = f.encrypt(plaintext.encode('utf-8'))
        return f"ENC2:{encrypted.decode('ascii')}"
    except Exception as e:
        log(f"Encryption error: {e}")
        return plaintext  # Fallback to plaintext

def _decrypt_v1(ciphertext, raw_key):
    """Decrypt old XOR-encrypted data for migration"""
    try:
        data = base64.b64decode(ciphertext)
        iv = data[:16]
        encrypted = data[16:]
        working_key = hmac.new(raw_key, iv, hashlib.sha256).digest()
        decrypted = bytearray()
        for i, byte in enumerate(encrypted):
            key_byte = working_key[i % len(working_key)]
            decrypted.append(byte ^ key_byte)
        return decrypted.decode('utf-8')
    except:
        return ''

def decrypt_sensitive(ciphertext):
    """Decrypt sensitive data, unwrapping any nested layers.

    Older builds' is_encrypted() didn't recognise ENC2:, so save_config()
    re-encrypted already-encrypted keys on every save. Peel layers until
    we reach plaintext so those configs self-heal.
    """
    value = ciphertext
    for _ in range(20):
        if not value or not (value.startswith('ENC:') or value.startswith('ENC2:')):
            break
        value = _decrypt_one_layer(value)
    return value


def _decrypt_one_layer(ciphertext):
    """Decrypt one layer - supports both old (ENC:) and new (ENC2:) formats"""
    if not ciphertext:
        return ''
    if not ciphertext.startswith('ENC'):
        return ciphertext  # Not encrypted, return as-is (migration)
    try:
        fernet_key, raw_key = _get_encryption_key()

        if ciphertext.startswith('ENC2:'):
            # New Fernet format
            f = Fernet(fernet_key)
            decrypted = f.decrypt(ciphertext[5:].encode('ascii'))
            return decrypted.decode('utf-8')
        elif ciphertext.startswith('ENC:') and raw_key:
            # Old XOR format - decrypt for backward compatibility
            return _decrypt_v1(ciphertext[4:], raw_key)
        else:
            return ''
    except Exception as e:
        log(f"Decryption error: {e}")
        return ''  # Return empty on error

def is_encrypted(value):
    """Check if a value is encrypted"""
    return bool(value) and isinstance(value, str) and (value.startswith('ENC:') or value.startswith('ENC2:'))

def mask_key(key):
    """Mask an API key for display (show first 4 and last 4 chars)"""
    if not key or len(key) < 12:
        return '****'
    # Handle encrypted keys
    if is_encrypted(key):
        return 'ðŸ”’ ****-****'
    return f"{key[:4]}...{key[-4:]}"

app = Flask(__name__, static_folder='static')

# Security: Limit request body size (16MB max - enough for config but prevents abuse)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Session security settings
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JS access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 24 hours default

# Security headers middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    # Content Security Policy - allow inline styles/scripts for the app, but restrict sources
    # Note: 'unsafe-inline' needed for onclick handlers and inline styles
    # Note: http: added for users on internal networks without HTTPS
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: http: https: blob:; "
        "connect-src 'self' http: https: https://api.gumroad.com; "
        "frame-ancestors 'self'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    response.headers['Content-Security-Policy'] = csp
    
    # Prevent caching of sensitive pages
    if request.endpoint in ['login', 'settings', 'config_api']:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    return response

# Rate limiting (if available) - only for login, not general API
if LIMITER_AVAILABLE:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=[],  # No default limits - only apply to specific endpoints
        storage_uri="memory://"
    )
else:
    limiter = None

# API rate limiting - track failed attempts per IP
api_failed_attempts = {}  # {ip: {'count': int, 'last_attempt': timestamp}}
API_LOCKOUT_THRESHOLD = 10  # Lock out after 10 failed attempts
API_LOCKOUT_DURATION = 300  # 5 minutes lockout

# CSRF Protection (if available)
if CSRF_AVAILABLE:
    csrf = CSRFProtect()
else:
    csrf = None

# --- Licensing System ---

LICENSE_TIERS = {
    'free': {
        'max_remote_servers': 2,
        'max_local_servers': 1,
        'max_sync_mappings': 1,
        'max_items_per_page': 100,
        'max_concurrent_downloads': 2,
        'show_ads': True,
        'notifications': False,
        'custom_themes': False,
        'scheduling': False,
        'arr_integration': False,
        'analytics': False,
        'transcoding': False,
        'api_access': False,
        'vpn': False,
        'stream_downloads': False,
        'quality_upgrades': False,
        'metadata_cache': False
    },
    'trial': {
        'max_remote_servers': 999,
        'max_local_servers': 999,
        'max_sync_mappings': 999,
        'max_items_per_page': 999,
        'max_concurrent_downloads': 10,
        'show_ads': False,
        'notifications': True,
        'custom_themes': True,
        'scheduling': True,
        'arr_integration': True,
        'analytics': True,
        'transcoding': True,
        'api_access': True,
        'vpn': True,
        'stream_downloads': True,
        'quality_upgrades': True,
        'metadata_cache': True
    },
    'pro': {
        'max_remote_servers': 999,
        'max_local_servers': 999,
        'max_sync_mappings': 999,
        'max_items_per_page': 999,
        'max_concurrent_downloads': 10,
        'show_ads': False,
        'notifications': True,
        'custom_themes': True,
        'scheduling': True,
        'arr_integration': True,
        'analytics': True,
        'transcoding': True,
        'api_access': True,
        'vpn': True,
        'stream_downloads': True,
        'quality_upgrades': True,
        'metadata_cache': True
    }
}

TRIAL_DURATION_DAYS = 14
GUMROAD_PRODUCT_ID = "5jxZ3dk7Mc_egZqQ67FCCw=="

def load_license():
    """Load license information"""
    if not os.path.exists(LICENSE_FILE):
        return {'tier': 'free', 'key': None, 'trial_started': None}
    try:
        with open(LICENSE_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {'tier': 'free', 'key': None, 'trial_started': None}

def save_license(data):
    """Save license information"""
    os.makedirs(os.path.dirname(LICENSE_FILE), exist_ok=True)
    with open(LICENSE_FILE, 'w') as f:
        json.dump(data, f, indent=4)
    invalidate_license_cache()


# License tier is checked constantly (every API call, every download); verifying it means
# decrypting the key and checking backups, so cache the answer briefly.
_license_tier_cache = {'tier': None, 'at': 0.0, 'mtime': None}
_LICENSE_CACHE_SECONDS = 300


def invalidate_license_cache():
    _license_tier_cache.update(tier=None, at=0.0, mtime=None)

def _verify_license_integrity(license_data):
    """Verify license data hasn't been tampered with"""
    tier = license_data.get('tier', 'free')

    if tier == 'pro':
        key_hash = license_data.get('key_hash')

        # Developer test activation - only honoured when JELLYLOOTER_DEV=1
        if key_hash == 'test-mode':
            return DEV_MODE

        # Verify pro license has valid hash
        encrypted_key = license_data.get('key', '')
        if not key_hash or not encrypted_key:
            return False
        # Decrypt and verify hash matches
        try:
            decrypted = decrypt_sensitive(encrypted_key)
            if decrypted:
                computed_hash = hashlib.sha256(decrypted.encode()).hexdigest()[:16]
                return computed_hash == key_hash
        except:
            pass
        return False
    
    elif tier == 'trial':
        # Verify trial hash
        trial_started = license_data.get('trial_started')
        trial_hash = license_data.get('trial_hash')
        if not trial_started or not trial_hash:
            return False
        expected_hash = hashlib.sha256(
            (trial_started + 'jl_trial').encode()
        ).hexdigest()[:16]
        return trial_hash == expected_hash
    
    return True  # Free tier always valid

def get_license_tier():
    """Current license tier (cached; recomputed every few minutes or when license.json changes)."""
    try:
        mtime = os.path.getmtime(LICENSE_FILE)
    except OSError:
        mtime = None
    c = _license_tier_cache
    if c['tier'] is not None and c['mtime'] == mtime and time.time() - c['at'] < _LICENSE_CACHE_SECONDS:
        return c['tier']
    tier = _compute_license_tier()
    try:
        mtime = os.path.getmtime(LICENSE_FILE)
    except OSError:
        mtime = None
    c.update(tier=tier, at=time.time(), mtime=mtime)
    return tier


def _compute_license_tier():
    """Get current license tier with integrity and expiration check"""
    license_data = load_license()
    tier = license_data.get('tier', 'free')
    
    # Verify integrity (primary + backup for pro)
    if tier == 'pro':
        if not _verify_license_integrity(license_data):
            log("Primary license integrity check failed, checking backup...")
            # Try to restore from backup
            restore_result = restore_from_backup()
            if restore_result.get('success'):
                return 'pro'
            log("License integrity check failed, reverting to free")
            license_data['tier'] = 'free'
            save_license(license_data)
            return 'free'
        
        # Dual verification - check backup matches
        if not verify_dual_license():
            log("âš ï¸ License mismatch detected between primary and backup")
            # Don't immediately revoke, but log warning
    
    elif tier == 'trial':
        if not _verify_license_integrity(license_data):
            log("License integrity check failed, reverting to free")
            license_data['tier'] = 'free'
            save_license(license_data)
            return 'free'
    
    # Check if trial has expired
    if tier == 'trial':
        trial_started = license_data.get('trial_started')
        if trial_started:
            start_date = datetime.datetime.fromisoformat(trial_started)
            days_elapsed = (datetime.datetime.now() - start_date).days
            if days_elapsed >= TRIAL_DURATION_DAYS:
                # Trial expired, revert to free
                license_data['tier'] = 'free'
                save_license(license_data)
                return 'free'
    
    return tier

def get_trial_days_remaining():
    """Get number of days remaining in trial"""
    license_data = load_license()
    if license_data.get('tier') != 'trial':
        return 0
    trial_started = license_data.get('trial_started')
    if not trial_started:
        return 0
    start_date = datetime.datetime.fromisoformat(trial_started)
    days_elapsed = (datetime.datetime.now() - start_date).days
    return max(0, TRIAL_DURATION_DAYS - days_elapsed)

def get_tier_limits():
    """Get limits for current tier"""
    tier = get_license_tier()
    return LICENSE_TIERS.get(tier, LICENSE_TIERS['free'])

def is_pro():
    """Check if user has Pro license"""
    return get_license_tier() == 'pro'

def is_trial():
    """Check if user is in trial"""
    return get_license_tier() == 'trial'

def is_feature_available(feature):
    """Check if a feature is available in current tier"""
    limits = get_tier_limits()
    return limits.get(feature, False)

def get_feature_limit(limit_name):
    """Get a numeric limit for current tier"""
    limits = get_tier_limits()
    return limits.get(limit_name, 0)

def _compute_key_checksum(key):
    """Compute checksum for license key validation"""
    # Split key and compute weighted checksum
    parts = key.upper().replace('-', '')
    if len(parts) != 20:
        return 0
    total = 0
    for i, c in enumerate(parts):
        val = ord(c) - (48 if c.isdigit() else 55)  # 0-9 or A-Z
        total += val * (i + 1)
    return total % 97

def validate_license_key_format(key):
    """Validate license key format - accepts multiple Gumroad formats"""
    if not key:
        return False
    
    # Clean up the key - remove whitespace, normalize dashes
    key = key.strip().upper()
    # Replace various dash characters with standard hyphen
    key = key.replace('â€“', '-').replace('â€”', '-').replace('âˆ’', '-')
    # Remove any spaces
    key = key.replace(' ', '')
    
    if len(key) < 16:
        log(f"License key too short: {len(key)} chars")
        return False
    
    # Gumroad format 1: XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX (8-8-8-8)
    pattern1 = r'^[A-Z0-9]{8}-[A-Z0-9]{8}-[A-Z0-9]{8}-[A-Z0-9]{8}$'
    
    # Gumroad format 2: XXXXX-XXXXX-XXXXX-XXXXX (5-5-5-5)
    pattern2 = r'^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$'
    
    # Gumroad format 3: Any alphanumeric with dashes, 20+ chars
    pattern3 = r'^[A-Z0-9\-]{20,}$'
    
    if re.match(pattern1, key) or re.match(pattern2, key) or re.match(pattern3, key):
        return True
    
    log(f"License key format invalid: {key[:8]}...")
    return False

def _obfuscated_verify(k, pid):
    """Internal verification (obfuscated)"""
    try:
        # Build request dynamically to avoid simple string replacement
        ep = ''.join([chr(x) for x in [104,116,116,112,115,58,47,47,97,112,105,46,103,117,109,114,111,97,100,46,99,111,109,47,118,50,47,108,105,99,101,110,115,101,115,47,118,101,114,105,102,121]])
        r = requests.post(ep, data={'product_id': pid, 'license_key': k}, timeout=10)
        d = r.json()
        return d.get('success', False), d.get('purchase', {}).get('email'), d.get('message')
    except:
        return None, None, None  # Network error

def verify_license_key(key):
    """Verify license key with Gumroad API (with offline fallback)"""
    # Clean up the key
    key = key.strip().upper()
    key = key.replace('â€“', '-').replace('â€”', '-').replace('âˆ’', '-').replace(' ', '')
    
    if not validate_license_key_format(key):
        return {'valid': False, 'error': 'Invalid key format'}
    
    # Try online verification
    success, email, msg = _obfuscated_verify(key, GUMROAD_PRODUCT_ID)
    
    if success is True:
        return {'valid': True, 'email': email}
    elif success is False:
        return {'valid': False, 'error': msg or 'Invalid key'}
    else:
        # Offline fallback - trust format if checksum passes
        log("License verification offline, using format validation")
        return {'valid': True, 'offline': True}

def activate_license(key):
    """Activate a Pro license"""
    # Developer test activation (JELLYLOOTER_DEV=1 only)
    if key == 'TEST-PRO-ACTIVATION' and DEV_MODE:
        license_data = load_license()
        license_data['tier'] = 'pro'
        license_data['key'] = None
        license_data['key_hash'] = 'test-mode'
        license_data['activated_at'] = datetime.datetime.now().isoformat()
        save_license(license_data)
        return {'success': True}

    result = verify_license_key(key)
    if result.get('valid') and result.get('offline'):
        # A brand-new key must be confirmed by Gumroad - "looks like a key" is not enough
        return {'success': False, 'error': "Couldn't reach Gumroad to verify the key. Check the internet connection and try again."}
    if result.get('valid'):
        license_data = load_license()
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]

        # Store encrypted key
        license_data['tier'] = 'pro'
        license_data['key'] = encrypt_sensitive(key)
        license_data['key_hash'] = key_hash
        license_data['activated_at'] = datetime.datetime.now().isoformat()
        save_license(license_data)

        # Save backup to library folders
        save_backup_license(key, key_hash)

        return {'success': True}
    return {'success': False, 'error': result.get('error', 'Invalid key')}

def activate_trial():
    """Activate 14-day trial"""
    license_data = load_license()
    
    # Check if trial was already used
    if license_data.get('trial_started'):
        return {'success': False, 'error': 'Trial already used'}
    
    license_data['tier'] = 'trial'
    license_data['trial_started'] = datetime.datetime.now().isoformat()
    # Add integrity check
    license_data['trial_hash'] = hashlib.sha256(
        (license_data['trial_started'] + 'jl_trial').encode()
    ).hexdigest()[:16]
    save_license(license_data)
    return {'success': True, 'days': TRIAL_DURATION_DAYS}


# --- Backup License System ---
# Obscure folder/file names to avoid detection
_BKP_FOLDER = '.jlsys'  # Hidden folder
_BKP_FILE = 'metadata.db'  # Looks like a database file
_BKP_SALT = 'jl_bkp_v3_'

def _get_backup_paths():
    """Get all potential backup paths from library mappings"""
    config = load_config()
    paths = []
    
    # Check library mappings
    for mapping in config.get('mappings', []):
        local_path = mapping.get('local_path', '')
        if local_path and os.path.isdir(local_path):
            paths.append(local_path)
    
    # Check download base path
    base_path = config.get('download_path', '/downloads')
    if base_path and os.path.isdir(base_path):
        paths.append(base_path)
    
    return list(set(paths))  # Unique paths

def _encode_backup_data(key, key_hash):
    """Encode backup data with obfuscation"""
    # Format: base64(encrypted_key)|hash|timestamp_hash
    ts = datetime.datetime.now().strftime('%Y%m')  # Monthly rotation indicator
    ts_hash = hashlib.sha256((_BKP_SALT + ts).encode()).hexdigest()[:8]
    
    # XOR encrypt the key with a derived key
    derived = hashlib.sha256((_BKP_SALT + key_hash).encode()).digest()
    encrypted = ''.join(chr(ord(c) ^ derived[i % len(derived)]) for i, c in enumerate(key))
    encoded = base64.b64encode(encrypted.encode('latin-1')).decode()
    
    return f"{encoded}|{key_hash}|{ts_hash}"

def _decode_backup_data(data):
    """Decode backup data and verify"""
    try:
        parts = data.strip().split('|')
        if len(parts) != 3:
            return None, None
        
        encoded, key_hash, ts_hash = parts
        
        # Derive decryption key from hash
        derived = hashlib.sha256((_BKP_SALT + key_hash).encode()).digest()
        encrypted = base64.b64decode(encoded).decode('latin-1')
        decrypted = ''.join(chr(ord(c) ^ derived[i % len(derived)]) for i, c in enumerate(encrypted))
        
        # Verify the decrypted key matches the hash
        computed_hash = hashlib.sha256(decrypted.encode()).hexdigest()[:16]
        if computed_hash == key_hash:
            return decrypted, key_hash
        
        return None, None
    except Exception:
        return None, None

def save_backup_license(key, key_hash):
    """Save encrypted license backup to library folders"""
    paths = _get_backup_paths()
    if not paths:
        return False
    
    backup_data = _encode_backup_data(key, key_hash)
    saved_count = 0
    
    for path in paths:
        try:
            backup_dir = os.path.join(path, _BKP_FOLDER)
            backup_file = os.path.join(backup_dir, _BKP_FILE)
            
            # Create hidden directory
            os.makedirs(backup_dir, exist_ok=True)
            
            # Write backup file
            with open(backup_file, 'w') as f:
                f.write(backup_data)
            
            # Set restrictive permissions
            try:
                os.chmod(backup_dir, 0o700)
                os.chmod(backup_file, 0o600)
            except:
                pass
            
            saved_count += 1
        except Exception as e:
            log(f"Could not save backup to {path}: {e}")
    
    return saved_count > 0

def check_backup_license(verify_online=True):
    """Check for valid backup license in library folders.

    verify_online=False is used by the routine integrity check so it never waits on Gumroad.
    """
    paths = _get_backup_paths()
    
    for path in paths:
        try:
            backup_file = os.path.join(path, _BKP_FOLDER, _BKP_FILE)
            if os.path.exists(backup_file):
                with open(backup_file, 'r') as f:
                    data = f.read()
                
                key, key_hash = _decode_backup_data(data)
                if key and key_hash:
                    if not verify_online:
                        if hashlib.sha256(key.encode()).hexdigest()[:16] == key_hash:
                            return {'found': True, 'key': key, 'hash': key_hash}
                        continue
                    # Verify with Gumroad
                    result = verify_license_key(key)
                    if result.get('valid'):
                        return {'found': True, 'key': key, 'hash': key_hash}
        except Exception:
            pass
    
    return {'found': False}

def restore_from_backup():
    """Attempt to restore license from backup"""
    backup = check_backup_license()
    if backup.get('found'):
        key = backup['key']
        key_hash = backup['hash']
        
        # Activate the license
        license_data = load_license()
        license_data['tier'] = 'pro'
        license_data['key'] = encrypt_sensitive(key)
        license_data['key_hash'] = key_hash
        license_data['activated_at'] = datetime.datetime.now().isoformat()
        license_data['restored_from_backup'] = True
        save_license(license_data)
        
        log("âœ… License restored from backup")
        return {'success': True, 'message': 'License restored from backup'}
    
    return {'success': False, 'message': 'No valid backup found'}

def verify_dual_license():
    """Verify license exists in both primary and backup locations"""
    license_data = load_license()
    tier = license_data.get('tier', 'free')
    
    if tier != 'pro':
        return True  # Only check for pro licenses
    
    # Check primary license
    if not _verify_license_integrity(license_data):
        return False
    
    # Check backup license (local check only - never block on the network here)
    backup = check_backup_license(verify_online=False)
    if not backup.get('found'):
        # Backup missing - could be new install or tampering
        # Try to recreate backup
        encrypted_key = license_data.get('key', '')
        key_hash = license_data.get('key_hash', '')
        if encrypted_key and key_hash:
            try:
                decrypted = decrypt_sensitive(encrypted_key)
                if decrypted:
                    save_backup_license(decrypted, key_hash)
            except:
                pass
        return True  # Allow if primary is valid
    
    # Both exist - verify they match
    primary_hash = license_data.get('key_hash', '')
    backup_hash = backup.get('hash', '')
    
    return primary_hash == backup_hash


# Thread-safe state management
task_queue = queue.Queue()
transcode_queue = queue.Queue()  # Separate queue for transcoding
active_downloads = {}
active_transcodes = {}  # Track active transcode jobs
pending_display = []
pending_transcodes = []  # Track pending transcode jobs for display
cancelled_tasks = set()
download_lock = threading.Lock()
transcode_lock = threading.Lock()  # Separate lock for transcodes
worker_lock = threading.Lock()
is_paused = False
log_buffer = deque(maxlen=500)  # Ring buffer for performance
download_history = deque(maxlen=1000)  # Limited history
local_id_cache = set()
episode_id_cache = set()       # Episode-specific IDs for episode-level checking
series_episode_counts = {}     # series_id -> count of episodes locally
cache_timestamp = "Never"
scan_progress = {
    "running": False,
    "percent": 0,
    "current": 0,
    "total": 0,
    "status": "Idle"
}

# Config cache for performance
_config_cache = None
_config_mtime = 0

# Worker management
active_workers = 0
target_workers = 2
active_transcode_workers = 0
target_transcode_workers = 1
_transcode_order = []   # transcode task ids in start order (newest get frozen when workers are reduced)
worker_shutdown = threading.Event()
transcode_shutdown = threading.Event()

# Download history persistence
HISTORY_FILE = '/config/download_history.json'
TRANSCODE_STATS_FILE = '/config/transcode_stats.json'

# Transcode statistics
transcode_stats = {
    'files_transcoded': 0,
    'files_skipped_larger': 0,
    'total_original_bytes': 0,
    'total_transcoded_bytes': 0,
    'total_space_saved_bytes': 0
}
transcode_stats_lock = threading.Lock()

# Download statistics
DOWNLOAD_STATS_FILE = '/config/download_stats.json'
download_stats = {
    'total_files': 0,
    'total_bytes': 0,
    'session_files': 0,
    'session_bytes': 0,
    'by_server': {},  # server_id -> {files, bytes}
    'last_updated': None
}
download_stats_lock = threading.Lock()

# Per-server queue system (Pro feature)
server_queues = {}  # server_id -> queue.Queue()
server_workers = {}  # server_id -> worker thread
server_worker_lock = threading.Lock()

def save_transcode_stats():
    """Save transcode statistics to file"""
    try:
        with transcode_stats_lock:
            stats_copy = dict(transcode_stats)
        with open(TRANSCODE_STATS_FILE, 'w') as f:
            json.dump(stats_copy, f)
    except Exception as e:
        log(f"Failed to save transcode stats: {e}")

def load_transcode_stats():
    """Load transcode statistics from file"""
    global transcode_stats
    try:
        if os.path.exists(TRANSCODE_STATS_FILE):
            with open(TRANSCODE_STATS_FILE, 'r') as f:
                loaded = json.load(f)
            with transcode_stats_lock:
                transcode_stats.update(loaded)
            log(f"Loaded transcode stats: {transcode_stats['files_transcoded']} files, {format_bytes(transcode_stats['total_space_saved_bytes'])} saved")
    except Exception as e:
        log(f"Failed to load transcode stats: {e}")

def update_transcode_stats(original_size, new_size, kept_original=False):
    """Update transcode statistics"""
    global transcode_stats
    with transcode_stats_lock:
        if kept_original:
            transcode_stats['files_skipped_larger'] += 1
        else:
            transcode_stats['files_transcoded'] += 1
            transcode_stats['total_original_bytes'] += original_size
            transcode_stats['total_transcoded_bytes'] += new_size
            transcode_stats['total_space_saved_bytes'] += (original_size - new_size)
    # Save asynchronously
    threading.Thread(target=save_transcode_stats, daemon=True).start()


def save_download_stats():
    """Save download statistics to file"""
    try:
        with download_stats_lock:
            stats_copy = dict(download_stats)
            stats_copy['last_updated'] = datetime.datetime.now().isoformat()
        with open(DOWNLOAD_STATS_FILE, 'w') as f:
            json.dump(stats_copy, f, indent=2)
    except Exception as e:
        log(f"Failed to save download stats: {e}")


def load_download_stats():
    """Load download statistics from file"""
    global download_stats
    try:
        if os.path.exists(DOWNLOAD_STATS_FILE):
            with open(DOWNLOAD_STATS_FILE, 'r') as f:
                loaded = json.load(f)
            with download_stats_lock:
                download_stats.update(loaded)
                # Reset session counters on load
                download_stats['session_files'] = 0
                download_stats['session_bytes'] = 0
            log(f"ðŸ“Š Loaded download stats: {download_stats['total_files']} files, {format_bytes(download_stats['total_bytes'])}")
    except Exception as e:
        log(f"Failed to load download stats: {e}")


def update_download_stats(file_size, server_id=None, server_name=None):
    """Update download statistics when a download completes"""
    global download_stats
    with download_stats_lock:
        download_stats['total_files'] += 1
        download_stats['total_bytes'] += file_size
        download_stats['session_files'] += 1
        download_stats['session_bytes'] += file_size
        
        # Track per-server stats
        if server_id:
            if server_id not in download_stats['by_server']:
                download_stats['by_server'][server_id] = {
                    'name': server_name or server_id,
                    'files': 0,
                    'bytes': 0
                }
            download_stats['by_server'][server_id]['files'] += 1
            download_stats['by_server'][server_id]['bytes'] += file_size
    
    # Save asynchronously
    threading.Thread(target=save_download_stats, daemon=True).start()


def get_download_stats():
    """Get current download statistics"""
    with download_stats_lock:
        return dict(download_stats)


def reset_download_stats(session_only=False):
    """Reset download statistics"""
    global download_stats
    with download_stats_lock:
        if session_only:
            download_stats['session_files'] = 0
            download_stats['session_bytes'] = 0
        else:
            download_stats = {
                'total_files': 0,
                'total_bytes': 0,
                'session_files': 0,
                'session_bytes': 0,
                'by_server': {},
                'last_updated': None
            }
    threading.Thread(target=save_download_stats, daemon=True).start()


def save_download_history():
    """Save download history to file"""
    try:
        with download_lock:
            history_list = list(download_history)
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history_list, f)
    except Exception as e:
        log(f"Failed to save download history: {e}")

def load_download_history():
    """Load download history from file"""
    global download_history
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f:
                history_list = json.load(f)
            with download_lock:
                download_history = deque(history_list, maxlen=1000)
            log(f"Loaded {len(download_history)} items from download history")
    except Exception as e:
        log(f"Failed to load download history: {e}")

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
        'buy_coffee': 'Support on Ko-fi',
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
        'remote_browser': 'Remote Browser',
        'select_all': 'Select All',
        'deselect_all': 'Deselect All',
        'download_selected': 'Download Selected',
        'clear': 'Clear',
        'filter_items': 'ðŸ” Filter items...',
        'activity_log': 'Activity Log',
        'history': 'History',
        'download_queue': 'Download Queue',
        'active': 'Active',
        'pending': 'Pending',
        'cached': 'Cached',
        'appearance': 'Appearance',
        'dark_theme': 'Dark Theme',
        'library_mappings': 'Library Mappings',
        'add_mapping': 'Add Mapping',
        'save_settings': 'Save Settings',
        'test_connection': 'Test Connection',
        'connection_successful': 'Connection successful',
        'no_mappings': 'No Mappings',
        'no_mappings_desc': 'Create a mapping to automatically sync content from remote libraries.',
        'sync_now': 'Sync Now',
        'auto_sync': 'Auto-Sync',
        'configuration': 'Configuration',
        'theme_hint': 'Switch between dark and light themes',
        'language_hint': 'Interface language (page will refresh)',
        'add_remote_server': 'Add Remote Server',
        'duplicate_detection': 'Duplicate Detection',
        'no_local_server': 'No local server configured. Add one to detect existing content.',
        'configure_local': 'Configure Local Server',
        'advanced_settings': 'Advanced Settings',
        'speed_limit_hint': 'Set to 0 for unlimited speed',
        'sync_time': 'Sync Time',
        'timezone': 'Timezone',
        'timezone_hint': 'Affects log timestamps and scheduling',
        'connection_timeout': 'Connection Timeout (s)',
        'chunk_size': 'Chunk Size (KB)',
        'confirm_downloads': 'Confirm before downloading',
        'show_notifications': 'Show notifications',
        'select_server': 'Select Server...',
        'no_active_downloads': 'No active downloads',
        'last_scan': 'Last Scan',
        'scanning': 'Scanning local library...',
        'select_a_server': 'Select a Server',
        'select_server_desc': 'Choose a remote server from the dropdown to browse its library.',
        # Changelog translations
        'support_btn': 'Support',
        'back': 'Back',
        'enjoying_jellylooter': 'Enjoying JellyLooter?',
        'support_message': 'If this project saves you time, consider supporting on Ko-fi!',
        'december': 'December',
        'latest': 'Latest',
        'fix': 'Fix',
        'new': 'New',
        'improve': 'Improve',
        'ch_mobile_view': 'Mobile view now works correctly with hamburger menu',
        'ch_download_error': 'Fixed download errors with username/password auth',
        'ch_poster_aspect': 'Fixed poster image aspect ratio',
        'ch_language_selector': 'Language selector in settings with full UI translations',
        'ch_title_downloads': 'Download count shown in browser tab title',
        'ch_select_all': 'Select All / Deselect All button for bulk selection',
        'ch_filter': 'Filter/search box to find items in current view',
        'ch_history': 'Download history panel with timestamps',
        'ch_eta': 'Estimated time remaining on active downloads',
        'ch_quick_paths': 'Quick path selection from library mappings when downloading',
        'ch_auth_optional': 'Authentication now optional (off by default)',
        'ch_tooltip': 'Tooltip z-index fixed',
        'ch_pagination': 'All items now display with server-side pagination',
        'ch_responsive': 'Mobile-friendly responsive design',
        'ch_grid_list': 'Grid/List view toggle',
        'ch_items_page': 'Pagination with configurable items per page',
        'ch_queue_order': 'Download queue ordering options',
        'ch_multilang': 'Multi-language support (English, Spanish, German)',
        'ch_syntax': 'Python syntax errors fixed',
        'ch_favicon': 'Added favicon',
        'ch_kofi': 'Ko-fi support links',
        'ch_userpw': 'Username/password authentication support',
        'ch_queue_visible': 'Download queue visibility improvements',
        'ch_ux': 'User experience improvements',
        # Help translations
        'help_support': 'Help & Support',
        'support_jellylooter': 'Support JellyLooter',
        'verified': 'VERIFIED',
        'confirmed_working': 'Confirmed working on',
        'quick_tips': 'Quick Tips',
        'tip_multiselect': 'Multi-Select Items',
        'tip_multiselect_desc': 'Hold Ctrl/Cmd and click to select multiple items, or just click non-folder items to toggle selection.',
        'tip_speed': 'Speed Limit Updates Live',
        'tip_speed_desc': 'Change speed limit in settings and it applies to active downloads within 10 seconds.',
        'tip_order': 'Download Order',
        'tip_order_desc': 'Choose how items are queued: complete shows first, round-robin by season/episode, or alphabetically.',
        'tip_mappings': 'Library Mappings',
        'tip_mappings_desc': 'Set up mappings to sync entire libraries automatically. Maps remote libraries to local folders.',
        'tip_language': 'Change Language',
        'tip_language_desc': 'Go to Settings > Appearance > Language to switch between English, Spanish, and German.',
        'troubleshooting': 'Troubleshooting',
        'issue_auth': 'Authentication Issues',
        'issue_auth_desc': 'If using username/password auth, try deleting and re-adding the server. The user_id must be stored correctly.',
        'issue_slow': 'Slow Downloads',
        'issue_slow_desc': 'Check your speed limit setting. Set to 0 for unlimited. Also check network connection to remote server.',
        'issue_error': 'Download Errors',
        'issue_error_desc': 'Check the Activity Log for details. Common issues: disk full, permissions, network timeout.',
        'no_remote_servers': 'No remote servers configured yet.',
        'confirm_remove_local': 'Remove local server?',
        'local_server_removed': 'Local server removed',
        'unknown': 'Unknown',
        'library': 'Library',
        'server_name': 'Server Name',
        'server_url': 'Server URL',
        'auth_method': 'Authentication Method',
        'api_key': 'API Key',
        'username_password': 'Username/Password',
        'test_before_adding': 'âš ï¸ Test the connection before adding the server',
        'cancel': 'Cancel',
        'add_server': 'Add Server',
        'save_and_scan': 'Save & Scan',
        'select_download_location': 'Select Download Location',
        'or_browse': 'Or browse to a folder:',
        'download_here': 'Download Here',
        # v3.0.0 new translations
        'show_ratings': 'Show ratings on posters',
        'show_quality': 'Show quality badges (4K, HDR, etc)',
        'download_subtitles': 'Download subtitles automatically',
        'subtitle_languages': 'Subtitle Languages (ISO codes)',
        'subtitle_hint': 'Comma-separated language codes. Use "all" to download all available subtitles.',
        'security_settings': 'Security Settings',
        'enable_auth': 'Enable Authentication',
        'auth_hint': 'Require login to access JellyLooter',
        'session_timeout': 'Session Timeout (minutes)',
        'trust_proxy': 'Trust X-Forwarded headers',
        'trust_proxy_hint': 'Enable if using a reverse proxy (Nginx, Traefik, etc.) to get correct client IPs',
        'trusted_proxies': 'Trusted Proxy IPs',
        'trusted_proxies_hint': 'Comma-separated list of IP ranges allowed to set X-Forwarded headers',
        'save_security': 'Save Security Settings',
        'pro_features': 'Pro Features',
        'unlock_pro': 'Unlock Pro Features',
        'enter_license': 'Enter License Key',
        'go_pro': 'Go Pro',
        'trial_days': 'days left in trial',
        'thank_you_pro': 'Thank you for supporting JellyLooter!',
        'notifications': 'Notifications',
        'notification_urls': 'Notification URLs (Apprise)',
        'notification_hint': 'One URL per line. Supports Discord, Telegram, Email, and 80+ services.',
        'notify_complete': 'Notify on download complete',
        'notify_error': 'Notify on download error',
        'transcoding': 'Transcoding',
        'enable_transcoding': 'Enable transcoding',
        'transcode_preset': 'Preset',
        'encoder': 'Encoder',
        'scheduling': 'Scheduling',
        'enable_scheduling': 'Enable download scheduling',
        'schedule_start': 'Start time',
        'schedule_end': 'End time',
        'bandwidth_scheduling': 'Bandwidth Scheduling',
        'day_limit': 'Day limit (KB/s)',
        'night_limit': 'Night limit (KB/s)',
        'arr_integration': '*arr Integration',
        'arr_hint': 'Connect Sonarr/Radarr for automatic folder naming based on your *arr library.',
        'custom_themes': 'Custom Themes',
        'theme': 'Theme',
        'primary_color': 'Primary Color',
        'accent_color': 'Accent Color',
        'background': 'Background',
        'card_background': 'Card Background',
        'input_background': 'Input Background',
        'border_color': 'Border Color',
        'apply_theme': 'Apply Custom Theme',
        'multiple_servers': 'Multiple Local Servers',
        'multiple_servers_hint': 'Connect multiple local Jellyfin/Emby servers for unified duplicate detection across your network.',
        'add_local_server': 'Add Local Server',
        'save_pro': 'Save Pro Settings',
        'collapse_panel': 'Collapse',
        'expand_panel': 'Expand',
        'move_up': 'Move Up',
        'move_down': 'Move Down',
        'reset_layout': 'Reset Layout',
        'backup_restore': 'Backup & Restore',
        'export_config': 'Export Config',
        'import_config': 'Import Config',
        'export_hint': 'Export saves settings (API keys masked). Import restores settings while preserving existing API keys.',
    },
    'es': {
        'app_name': 'JellyLooter',
        'sign_in': 'Iniciar SesiÃ³n',
        'sign_out': 'Cerrar SesiÃ³n',
        'username': 'Usuario',
        'password': 'ContraseÃ±a',
        'remember_me': 'Recordarme',
        'settings': 'ConfiguraciÃ³n',
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
        'speed_limit': 'LÃ­mite de Velocidad',
        'max_downloads': 'Descargas MÃ¡ximas',
        'no_servers': 'No hay servidores configurados',
        'select_server': 'Seleccionar Servidor',
        'select_destination': 'Seleccionar Destino',
        'items_selected': 'elementos seleccionados',
        'download_complete': 'Descarga completa',
        'download_failed': 'Descarga fallida',
        'connection_error': 'Error de conexiÃ³n',
        'invalid_credentials': 'Credenciales invÃ¡lidas',
        'sync': 'Sincronizar',
        'rebuild_cache': 'Reconstruir CachÃ©',
        'cache_info': 'Info de CachÃ©',
        'last_scan': 'Ãšltimo Escaneo',
        'items_cached': 'Elementos en CachÃ©',
        'general': 'General',
        'advanced': 'Avanzado',
        'authentication': 'AutenticaciÃ³n',
        'enable_auth': 'Habilitar AutenticaciÃ³n',
        'auth_description': 'Requerir inicio de sesiÃ³n para acceder',
        'language': 'Idioma',
        'items_per_page': 'Elementos por PÃ¡gina',
        'view_mode': 'Modo de Vista',
        'grid_view': 'CuadrÃ­cula',
        'list_view': 'Lista',
        'download_order': 'Orden de Descarga',
        'order_library': 'Orden de Biblioteca',
        'order_show_complete': 'Series Completas Primero',
        'order_season_round': 'RotaciÃ³n por Temporada',
        'order_episode_round': 'RotaciÃ³n por Episodio',
        'order_alphabetical': 'AlfabÃ©tico',
        'order_random': 'Aleatorio',
        'confirmed_working': 'Confirmado funcionando en Unraid 7.2.0',
        'support_project': 'Apoya el Proyecto',
        'buy_coffee': 'Apoyar en Ko-fi',
        'loading': 'Cargando...',
        'error': 'Error',
        'success': 'Ã‰xito',
        'warning': 'Advertencia',
        'free_space': 'Espacio Libre',
        'total_space': 'Espacio Total',
        'refresh': 'Actualizar',
        'back': 'AtrÃ¡s',
        'home': 'Inicio',
        'page': 'PÃ¡gina',
        'of': 'de',
        'previous': 'Anterior',
        'next': 'Siguiente',
        'search': 'Buscar',
        'filter': 'Filtrar',
        'all': 'Todo',
        'movies': 'PelÃ­culas',
        'shows': 'Series',
        'exists_locally': 'Existe Localmente',
        'queued': 'En Cola',
        'downloading': 'Descargando',
        'completed': 'Completado',
        'failed': 'Fallido',
        'paused': 'Pausado',
        'starting': 'Iniciando',
        'remote_browser': 'Explorador Remoto',
        'select_all': 'Seleccionar Todo',
        'deselect_all': 'Deseleccionar Todo',
        'download_selected': 'Descargar Seleccionados',
        'clear': 'Limpiar',
        'filter_items': 'ðŸ” Filtrar elementos...',
        'activity_log': 'Registro de Actividad',
        'history': 'Historial',
        'download_queue': 'Cola de Descargas',
        'active': 'Activo',
        'pending': 'Pendiente',
        'cached': 'En CachÃ©',
        'appearance': 'Apariencia',
        'dark_theme': 'Tema Oscuro',
        'library_mappings': 'Mapeo de Bibliotecas',
        'add_mapping': 'Agregar Mapeo',
        'save_settings': 'Guardar ConfiguraciÃ³n',
        'test_connection': 'Probar ConexiÃ³n',
        'connection_successful': 'ConexiÃ³n exitosa',
        'no_mappings': 'Sin Mapeos',
        'no_mappings_desc': 'Crea un mapeo para sincronizar contenido automÃ¡ticamente.',
        'sync_now': 'Sincronizar Ahora',
        'auto_sync': 'Auto-SincronizaciÃ³n',
        'configuration': 'ConfiguraciÃ³n',
        'theme_hint': 'Cambiar entre tema oscuro y claro',
        'language_hint': 'Idioma de la interfaz (la pÃ¡gina se recargarÃ¡)',
        'add_remote_server': 'Agregar Servidor Remoto',
        'duplicate_detection': 'DetecciÃ³n de Duplicados',
        'no_local_server': 'No hay servidor local configurado. Agrega uno para detectar contenido existente.',
        'configure_local': 'Configurar Servidor Local',
        'advanced_settings': 'ConfiguraciÃ³n Avanzada',
        'speed_limit_hint': 'Establecer en 0 para velocidad ilimitada',
        'sync_time': 'Hora de SincronizaciÃ³n',
        'timezone': 'Zona Horaria',
        'timezone_hint': 'Afecta marcas de tiempo y programaciÃ³n',
        'connection_timeout': 'Tiempo de Espera (s)',
        'chunk_size': 'TamaÃ±o de Bloque (KB)',
        'confirm_downloads': 'Confirmar antes de descargar',
        'show_notifications': 'Mostrar notificaciones',
        'select_server': 'Seleccionar Servidor...',
        'no_active_downloads': 'No hay descargas activas',
        'last_scan': 'Ãšltimo Escaneo',
        'scanning': 'Escaneando biblioteca local...',
        'select_a_server': 'Seleccionar un Servidor',
        'select_server_desc': 'Elige un servidor remoto del menÃº desplegable para explorar su biblioteca.',
        # Changelog translations
        'support_btn': 'Apoyar',
        'back': 'Volver',
        'enjoying_jellylooter': 'Â¿Te gusta JellyLooter?',
        'support_message': 'Â¡Si este proyecto te ahorra tiempo, considera apoyar en Ko-fi!',
        'december': 'Diciembre',
        'latest': 'Ãšltima',
        'fix': 'Corr',
        'new': 'Nuevo',
        'improve': 'Mejor',
        'ch_mobile_view': 'Vista mÃ³vil ahora funciona correctamente con menÃº hamburguesa',
        'ch_download_error': 'Corregidos errores de descarga con autenticaciÃ³n usuario/contraseÃ±a',
        'ch_poster_aspect': 'Corregida proporciÃ³n de imÃ¡genes de pÃ³ster',
        'ch_language_selector': 'Selector de idioma en configuraciÃ³n con traducciones completas',
        'ch_title_downloads': 'Contador de descargas en la pestaÃ±a del navegador',
        'ch_select_all': 'BotÃ³n Seleccionar Todo / Deseleccionar Todo',
        'ch_filter': 'Cuadro de filtro/bÃºsqueda para encontrar elementos',
        'ch_history': 'Panel de historial de descargas con marcas de tiempo',
        'ch_eta': 'Tiempo estimado restante en descargas activas',
        'ch_quick_paths': 'SelecciÃ³n rÃ¡pida de ruta desde mapeos de biblioteca',
        'ch_auth_optional': 'AutenticaciÃ³n ahora opcional (desactivada por defecto)',
        'ch_tooltip': 'Corregido z-index de tooltip',
        'ch_pagination': 'Todos los elementos ahora se muestran con paginaciÃ³n',
        'ch_responsive': 'DiseÃ±o responsive para mÃ³viles',
        'ch_grid_list': 'Cambio entre vista de cuadrÃ­cula/lista',
        'ch_items_page': 'PaginaciÃ³n con elementos por pÃ¡gina configurables',
        'ch_queue_order': 'Opciones de orden de cola de descarga',
        'ch_multilang': 'Soporte multiidioma (inglÃ©s, espaÃ±ol, alemÃ¡n)',
        'ch_syntax': 'Errores de sintaxis Python corregidos',
        'ch_favicon': 'AÃ±adido favicon',
        'ch_kofi': 'Enlaces de soporte Ko-fi',
        'ch_userpw': 'Soporte de autenticaciÃ³n usuario/contraseÃ±a',
        'ch_queue_visible': 'Mejoras de visibilidad de cola de descarga',
        'ch_ux': 'Mejoras de experiencia de usuario',
        # Help translations
        'help_support': 'Ayuda y Soporte',
        'support_jellylooter': 'Apoyar JellyLooter',
        'verified': 'VERIFICADO',
        'confirmed_working': 'Confirmado funcionando en',
        'quick_tips': 'Consejos RÃ¡pidos',
        'tip_multiselect': 'SelecciÃ³n MÃºltiple',
        'tip_multiselect_desc': 'MantÃ©n Ctrl/Cmd y haz clic para seleccionar mÃºltiples elementos, o simplemente haz clic en elementos que no sean carpetas.',
        'tip_speed': 'LÃ­mite de Velocidad en Vivo',
        'tip_speed_desc': 'Cambia el lÃ­mite de velocidad en configuraciÃ³n y se aplica a las descargas activas en 10 segundos.',
        'tip_order': 'Orden de Descarga',
        'tip_order_desc': 'Elige cÃ³mo se ordenan los elementos: series completas primero, round-robin por temporada/episodio, o alfabÃ©ticamente.',
        'tip_mappings': 'Mapeos de Biblioteca',
        'tip_mappings_desc': 'Configura mapeos para sincronizar bibliotecas enteras automÃ¡ticamente.',
        'tip_language': 'Cambiar Idioma',
        'tip_language_desc': 'Ve a ConfiguraciÃ³n > Apariencia > Idioma para cambiar entre inglÃ©s, espaÃ±ol y alemÃ¡n.',
        'troubleshooting': 'SoluciÃ³n de Problemas',
        'issue_auth': 'Problemas de AutenticaciÃ³n',
        'issue_auth_desc': 'Si usas autenticaciÃ³n usuario/contraseÃ±a, intenta eliminar y volver a agregar el servidor.',
        'issue_slow': 'Descargas Lentas',
        'issue_slow_desc': 'Revisa tu lÃ­mite de velocidad. Establece en 0 para ilimitado. TambiÃ©n verifica la conexiÃ³n de red.',
        'issue_error': 'Errores de Descarga',
        'issue_error_desc': 'Revisa el Registro de Actividad para detalles. Problemas comunes: disco lleno, permisos, tiempo de espera.',
        'no_remote_servers': 'No hay servidores remotos configurados.',
        'confirm_remove_local': 'Â¿Eliminar servidor local?',
        'local_server_removed': 'Servidor local eliminado',
        'unknown': 'Desconocido',
        'library': 'Biblioteca',
        'server_name': 'Nombre del Servidor',
        'server_url': 'URL del Servidor',
        'auth_method': 'MÃ©todo de AutenticaciÃ³n',
        'api_key': 'Clave API',
        'username_password': 'Usuario/ContraseÃ±a',
        'test_before_adding': 'âš ï¸ Prueba la conexiÃ³n antes de agregar el servidor',
        'cancel': 'Cancelar',
        'add_server': 'Agregar Servidor',
        'save_and_scan': 'Guardar y Escanear',
        'select_download_location': 'Seleccionar UbicaciÃ³n de Descarga',
        'or_browse': 'O navegar a una carpeta:',
        'download_here': 'Descargar AquÃ­',
        # v3.0.0 new translations
        'show_ratings': 'Mostrar calificaciones en pÃ³sters',
        'show_quality': 'Mostrar insignias de calidad (4K, HDR, etc)',
        'download_subtitles': 'Descargar subtÃ­tulos automÃ¡ticamente',
        'subtitle_languages': 'Idiomas de SubtÃ­tulos (cÃ³digos ISO)',
        'subtitle_hint': 'CÃ³digos de idioma separados por comas. Usa "all" para descargar todos los subtÃ­tulos.',
        'security_settings': 'ConfiguraciÃ³n de Seguridad',
        'enable_auth': 'Habilitar AutenticaciÃ³n',
        'auth_hint': 'Requerir inicio de sesiÃ³n para acceder a JellyLooter',
        'session_timeout': 'Tiempo de SesiÃ³n (minutos)',
        'trust_proxy': 'Confiar en cabeceras X-Forwarded',
        'trust_proxy_hint': 'Habilitar si usas proxy inverso (Nginx, Traefik, etc.)',
        'trusted_proxies': 'IPs de Proxy Confiables',
        'trusted_proxies_hint': 'Lista de rangos IP separados por comas',
        'save_security': 'Guardar ConfiguraciÃ³n de Seguridad',
        'pro_features': 'Funciones Pro',
        'unlock_pro': 'Desbloquear Funciones Pro',
        'enter_license': 'Ingresar Clave de Licencia',
        'go_pro': 'Obtener Pro',
        'trial_days': 'dÃ­as de prueba restantes',
        'thank_you_pro': 'Â¡Gracias por apoyar JellyLooter!',
        'notifications': 'Notificaciones',
        'notification_urls': 'URLs de NotificaciÃ³n (Apprise)',
        'notification_hint': 'Una URL por lÃ­nea. Soporta Discord, Telegram, Email y mÃ¡s de 80 servicios.',
        'notify_complete': 'Notificar al completar descarga',
        'notify_error': 'Notificar en error de descarga',
        'transcoding': 'TranscodificaciÃ³n',
        'enable_transcoding': 'Habilitar transcodificaciÃ³n',
        'transcode_preset': 'Preajuste',
        'encoder': 'Codificador',
        'scheduling': 'ProgramaciÃ³n',
        'enable_scheduling': 'Habilitar programaciÃ³n de descargas',
        'schedule_start': 'Hora de inicio',
        'schedule_end': 'Hora de fin',
        'bandwidth_scheduling': 'ProgramaciÃ³n de Ancho de Banda',
        'day_limit': 'LÃ­mite diurno (KB/s)',
        'night_limit': 'LÃ­mite nocturno (KB/s)',
        'arr_integration': 'IntegraciÃ³n *arr',
        'arr_hint': 'Conecta Sonarr/Radarr para nombrado automÃ¡tico de carpetas.',
        'custom_themes': 'Temas Personalizados',
        'theme': 'Tema',
        'primary_color': 'Color Primario',
        'accent_color': 'Color de Acento',
        'background': 'Fondo',
        'card_background': 'Fondo de Tarjetas',
        'input_background': 'Fondo de Entradas',
        'border_color': 'Color de Borde',
        'apply_theme': 'Aplicar Tema Personalizado',
        'multiple_servers': 'MÃºltiples Servidores Locales',
        'multiple_servers_hint': 'Conecta mÃºltiples servidores locales para detecciÃ³n unificada de duplicados.',
        'add_local_server': 'Agregar Servidor Local',
        'save_pro': 'Guardar ConfiguraciÃ³n Pro',
        'collapse_panel': 'Colapsar',
        'expand_panel': 'Expandir',
        'move_up': 'Mover Arriba',
        'move_down': 'Mover Abajo',
        'reset_layout': 'Restablecer DiseÃ±o',
        'backup_restore': 'Copia de Seguridad',
        'export_config': 'Exportar Config',
        'import_config': 'Importar Config',
        'export_hint': 'Exportar guarda configuraciÃ³n (claves API ocultas). Importar restaura preservando claves existentes.',
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
        'changelog': 'Ã„nderungen',
        'remote_servers': 'Remote-Server',
        'local_server': 'Lokaler Server',
        'add_server': 'Server hinzufÃ¼gen',
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
        'select_server': 'Server auswÃ¤hlen',
        'select_destination': 'Ziel auswÃ¤hlen',
        'items_selected': 'Elemente ausgewÃ¤hlt',
        'download_complete': 'Download abgeschlossen',
        'download_failed': 'Download fehlgeschlagen',
        'connection_error': 'Verbindungsfehler',
        'invalid_credentials': 'UngÃ¼ltige Anmeldedaten',
        'sync': 'Synchronisieren',
        'rebuild_cache': 'Cache neu aufbauen',
        'cache_info': 'Cache-Info',
        'last_scan': 'Letzter Scan',
        'items_cached': 'Zwischengespeicherte Elemente',
        'general': 'Allgemein',
        'advanced': 'Erweitert',
        'authentication': 'Authentifizierung',
        'enable_auth': 'Authentifizierung aktivieren',
        'auth_description': 'Anmeldung fÃ¼r Zugriff erforderlich',
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
        'order_random': 'ZufÃ¤llig',
        'confirmed_working': 'BestÃ¤tigt funktionierend auf Unraid 7.2.0',
        'support_project': 'Projekt unterstÃ¼tzen',
        'buy_coffee': 'Auf Ko-fi unterstÃ¼tzen',
        'loading': 'Laden...',
        'error': 'Fehler',
        'success': 'Erfolg',
        'warning': 'Warnung',
        'free_space': 'Freier Speicher',
        'total_space': 'Gesamtspeicher',
        'refresh': 'Aktualisieren',
        'back': 'ZurÃ¼ck',
        'home': 'Start',
        'page': 'Seite',
        'of': 'von',
        'previous': 'ZurÃ¼ck',
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
        'remote_browser': 'Remote-Browser',
        'select_all': 'Alle auswÃ¤hlen',
        'deselect_all': 'Alle abwÃ¤hlen',
        'download_selected': 'AusgewÃ¤hlte herunterladen',
        'clear': 'Leeren',
        'filter_items': 'ðŸ” Elemente filtern...',
        'activity_log': 'AktivitÃ¤tsprotokoll',
        'history': 'Verlauf',
        'download_queue': 'Download-Warteschlange',
        'active': 'Aktiv',
        'pending': 'Ausstehend',
        'cached': 'Gecached',
        'appearance': 'Darstellung',
        'dark_theme': 'Dunkles Design',
        'library_mappings': 'Bibliothekszuordnungen',
        'add_mapping': 'Zuordnung hinzufÃ¼gen',
        'save_settings': 'Einstellungen speichern',
        'test_connection': 'Verbindung testen',
        'connection_successful': 'Verbindung erfolgreich',
        'no_mappings': 'Keine Zuordnungen',
        'no_mappings_desc': 'Erstellen Sie eine Zuordnung, um Inhalte automatisch zu synchronisieren.',
        'sync_now': 'Jetzt synchronisieren',
        'auto_sync': 'Auto-Sync',
        'configuration': 'Konfiguration',
        'theme_hint': 'Zwischen hellem und dunklem Design wechseln',
        'language_hint': 'Schnittstellensprache (Seite wird neu geladen)',
        'add_remote_server': 'Remote-Server hinzufÃ¼gen',
        'duplicate_detection': 'Duplikaterkennung',
        'no_local_server': 'Kein lokaler Server konfiguriert. FÃ¼gen Sie einen hinzu, um vorhandene Inhalte zu erkennen.',
        'configure_local': 'Lokalen Server konfigurieren',
        'advanced_settings': 'Erweiterte Einstellungen',
        'speed_limit_hint': 'Auf 0 setzen fÃ¼r unbegrenzte Geschwindigkeit',
        'sync_time': 'Sync-Zeit',
        'timezone': 'Zeitzone',
        'timezone_hint': 'Beeinflusst Protokoll-Zeitstempel und Planung',
        'connection_timeout': 'Verbindungs-Timeout (s)',
        'chunk_size': 'BlockgrÃ¶ÃŸe (KB)',
        'confirm_downloads': 'Vor dem Download bestÃ¤tigen',
        'show_notifications': 'Benachrichtigungen anzeigen',
        'select_server': 'Server auswÃ¤hlen...',
        'no_active_downloads': 'Keine aktiven Downloads',
        'last_scan': 'Letzter Scan',
        'scanning': 'Lokale Bibliothek wird gescannt...',
        'select_a_server': 'Server auswÃ¤hlen',
        'select_server_desc': 'WÃ¤hlen Sie einen Remote-Server aus der Dropdown-Liste, um seine Bibliothek zu durchsuchen.',
        # Changelog translations
        'support_btn': 'UnterstÃ¼tzen',
        'back': 'ZurÃ¼ck',
        'enjoying_jellylooter': 'GefÃ¤llt Ihnen JellyLooter?',
        'support_message': 'Wenn dieses Projekt Ihnen Zeit spart, unterstÃ¼tzen Sie es auf Ko-fi!',
        'december': 'Dezember',
        'latest': 'Neueste',
        'fix': 'Fix',
        'new': 'Neu',
        'improve': 'Besser',
        'ch_mobile_view': 'Mobile Ansicht funktioniert jetzt korrekt mit Hamburger-MenÃ¼',
        'ch_download_error': 'Download-Fehler mit Benutzername/Passwort-Auth behoben',
        'ch_poster_aspect': 'Poster-BildverhÃ¤ltnis korrigiert',
        'ch_language_selector': 'Sprachauswahl in Einstellungen mit vollstÃ¤ndigen Ãœbersetzungen',
        'ch_title_downloads': 'Download-ZÃ¤hler im Browser-Tab-Titel',
        'ch_select_all': 'Alle auswÃ¤hlen / AbwÃ¤hlen SchaltflÃ¤che',
        'ch_filter': 'Filter-/Suchfeld zum Finden von Elementen',
        'ch_history': 'Download-Verlauf mit Zeitstempeln',
        'ch_eta': 'GeschÃ¤tzte Restzeit bei aktiven Downloads',
        'ch_quick_paths': 'Schnelle Pfadauswahl aus Bibliothekszuordnungen',
        'ch_auth_optional': 'Authentifizierung jetzt optional (standardmÃ¤ÃŸig deaktiviert)',
        'ch_tooltip': 'Tooltip z-index behoben',
        'ch_pagination': 'Alle Elemente werden jetzt mit Paginierung angezeigt',
        'ch_responsive': 'Mobilfreundliches responsives Design',
        'ch_grid_list': 'Raster-/Listenansicht-Umschalter',
        'ch_items_page': 'Paginierung mit konfigurierbaren Elementen pro Seite',
        'ch_queue_order': 'Download-Warteschlangen-Sortieroptionen',
        'ch_multilang': 'Mehrsprachige UnterstÃ¼tzung (Englisch, Spanisch, Deutsch)',
        'ch_syntax': 'Python-Syntaxfehler behoben',
        'ch_favicon': 'Favicon hinzugefÃ¼gt',
        'ch_kofi': 'Ko-fi Support-Links',
        'ch_userpw': 'Benutzername/Passwort-Authentifizierung',
        'ch_queue_visible': 'Verbesserungen der Download-Warteschlangen-Sichtbarkeit',
        'ch_ux': 'Verbesserungen der Benutzererfahrung',
        # Help translations
        'help_support': 'Hilfe & Support',
        'support_jellylooter': 'JellyLooter unterstÃ¼tzen',
        'verified': 'VERIFIZIERT',
        'confirmed_working': 'BestÃ¤tigt funktionierend auf',
        'quick_tips': 'Schnelle Tipps',
        'tip_multiselect': 'Mehrfachauswahl',
        'tip_multiselect_desc': 'Halten Sie Strg/Cmd und klicken Sie, um mehrere Elemente auszuwÃ¤hlen.',
        'tip_speed': 'Geschwindigkeitslimit Live',
        'tip_speed_desc': 'Ã„ndern Sie das Geschwindigkeitslimit in den Einstellungen und es wird innerhalb von 10 Sekunden angewendet.',
        'tip_order': 'Download-Reihenfolge',
        'tip_order_desc': 'WÃ¤hlen Sie, wie Elemente eingereiht werden: komplette Serien zuerst, Round-Robin, oder alphabetisch.',
        'tip_mappings': 'Bibliothekszuordnungen',
        'tip_mappings_desc': 'Richten Sie Zuordnungen ein, um ganze Bibliotheken automatisch zu synchronisieren.',
        'tip_language': 'Sprache Ã¤ndern',
        'tip_language_desc': 'Gehen Sie zu Einstellungen > Darstellung > Sprache, um zwischen Englisch, Spanisch und Deutsch zu wechseln.',
        'troubleshooting': 'Fehlerbehebung',
        'issue_auth': 'Authentifizierungsprobleme',
        'issue_auth_desc': 'Bei Benutzername/Passwort-Auth versuchen Sie, den Server zu lÃ¶schen und neu hinzuzufÃ¼gen.',
        'issue_slow': 'Langsame Downloads',
        'issue_slow_desc': 'ÃœberprÃ¼fen Sie Ihr Geschwindigkeitslimit. Setzen Sie es auf 0 fÃ¼r unbegrenzt.',
        'issue_error': 'Download-Fehler',
        'issue_error_desc': 'ÃœberprÃ¼fen Sie das AktivitÃ¤tsprotokoll fÃ¼r Details. HÃ¤ufige Probleme: Festplatte voll, Berechtigungen, Timeout.',
        'no_remote_servers': 'Keine Remote-Server konfiguriert.',
        'confirm_remove_local': 'Lokalen Server entfernen?',
        'local_server_removed': 'Lokaler Server entfernt',
        'unknown': 'Unbekannt',
        'library': 'Bibliothek',
        'server_name': 'Servername',
        'server_url': 'Server-URL',
        'auth_method': 'Authentifizierungsmethode',
        'api_key': 'API-SchlÃ¼ssel',
        'username_password': 'Benutzername/Passwort',
        'test_before_adding': 'âš ï¸ Testen Sie die Verbindung bevor Sie den Server hinzufÃ¼gen',
        'cancel': 'Abbrechen',
        'add_server': 'Server hinzufÃ¼gen',
        'save_and_scan': 'Speichern & Scannen',
        'select_download_location': 'Download-Speicherort auswÃ¤hlen',
        'or_browse': 'Oder zu einem Ordner navigieren:',
        'download_here': 'Hier herunterladen',
        # v3.0.0 new translations
        'show_ratings': 'Bewertungen auf Postern anzeigen',
        'show_quality': 'QualitÃ¤tsabzeichen anzeigen (4K, HDR, etc)',
        'download_subtitles': 'Untertitel automatisch herunterladen',
        'subtitle_languages': 'Untertitelsprachen (ISO-Codes)',
        'subtitle_hint': 'Kommagetrennte Sprachcodes. Verwenden Sie "all" fÃ¼r alle verfÃ¼gbaren Untertitel.',
        'security_settings': 'Sicherheitseinstellungen',
        'enable_auth': 'Authentifizierung aktivieren',
        'auth_hint': 'Anmeldung fÃ¼r Zugriff auf JellyLooter erforderlich',
        'session_timeout': 'Sitzungs-Timeout (Minuten)',
        'trust_proxy': 'X-Forwarded-Header vertrauen',
        'trust_proxy_hint': 'Aktivieren bei Verwendung eines Reverse-Proxys (Nginx, Traefik, etc.)',
        'trusted_proxies': 'VertrauenswÃ¼rdige Proxy-IPs',
        'trusted_proxies_hint': 'Kommagetrennte Liste von IP-Bereichen',
        'save_security': 'Sicherheitseinstellungen speichern',
        'pro_features': 'Pro-Funktionen',
        'unlock_pro': 'Pro-Funktionen freischalten',
        'enter_license': 'LizenzschlÃ¼ssel eingeben',
        'go_pro': 'Pro kaufen',
        'trial_days': 'Testtage verbleibend',
        'thank_you_pro': 'Vielen Dank fÃ¼r Ihre UnterstÃ¼tzung von JellyLooter!',
        'notifications': 'Benachrichtigungen',
        'notification_urls': 'Benachrichtigungs-URLs (Apprise)',
        'notification_hint': 'Eine URL pro Zeile. UnterstÃ¼tzt Discord, Telegram, E-Mail und 80+ Dienste.',
        'notify_complete': 'Bei Download-Abschluss benachrichtigen',
        'notify_error': 'Bei Download-Fehler benachrichtigen',
        'transcoding': 'Transkodierung',
        'enable_transcoding': 'Transkodierung aktivieren',
        'transcode_preset': 'Voreinstellung',
        'encoder': 'Encoder',
        'scheduling': 'Zeitplanung',
        'enable_scheduling': 'Download-Zeitplanung aktivieren',
        'schedule_start': 'Startzeit',
        'schedule_end': 'Endzeit',
        'bandwidth_scheduling': 'Bandbreiten-Zeitplanung',
        'day_limit': 'Tageslimit (KB/s)',
        'night_limit': 'Nachtlimit (KB/s)',
        'arr_integration': '*arr-Integration',
        'arr_hint': 'Verbinden Sie Sonarr/Radarr fÃ¼r automatische Ordnerbenennung.',
        'custom_themes': 'Benutzerdefinierte Designs',
        'theme': 'Design',
        'primary_color': 'PrimÃ¤rfarbe',
        'accent_color': 'Akzentfarbe',
        'background': 'Hintergrund',
        'card_background': 'Karten-Hintergrund',
        'input_background': 'Eingabe-Hintergrund',
        'border_color': 'Randfarbe',
        'apply_theme': 'Design anwenden',
        'multiple_servers': 'Mehrere lokale Server',
        'multiple_servers_hint': 'Verbinden Sie mehrere lokale Server fÃ¼r einheitliche Duplikaterkennung.',
        'add_local_server': 'Lokalen Server hinzufÃ¼gen',
        'save_pro': 'Pro-Einstellungen speichern',
        'collapse_panel': 'Einklappen',
        'expand_panel': 'Ausklappen',
        'move_up': 'Nach oben',
        'move_down': 'Nach unten',
        'reset_layout': 'Layout zurÃ¼cksetzen',
        'backup_restore': 'Sichern & Wiederherstellen',
        'export_config': 'Config exportieren',
        'import_config': 'Config importieren',
        'export_hint': 'Export speichert Einstellungen (API-SchlÃ¼ssel maskiert). Import stellt wieder her und behÃ¤lt vorhandene SchlÃ¼ssel.',
    }
}


def get_translation(key, lang='en'):
    """Get translation for a key"""
    return TRANSLATIONS.get(lang, TRANSLATIONS['en']).get(key, TRANSLATIONS['en'].get(key, key))


@lru_cache(maxsize=8)
def get_all_translations(lang='en'):
    """Get all translations for a language (cached)"""
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
    """Hash password using bcrypt (preferred) or SHA-256 fallback"""
    if BCRYPT_AVAILABLE:
        # Use bcrypt for secure password hashing
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    else:
        # Fallback to SHA-256 with salt
        if salt is None:
            salt = secrets.token_hex(16)
        hashed = hashlib.sha256((password + salt).encode()).hexdigest()
        return f"sha256:{salt}:{hashed}"


def verify_password(password, stored_hash):
    """Verify password against stored hash"""
    try:
        if BCRYPT_AVAILABLE and stored_hash.startswith('$2'):
            # bcrypt hash
            return bcrypt.checkpw(password.encode(), stored_hash.encode())
        elif stored_hash.startswith('sha256:'):
            # SHA-256 fallback format
            _, salt, hashed = stored_hash.split(':')
            return hash_password(password, salt) == stored_hash
        else:
            # Legacy format (old SHA-256)
            salt, hashed = stored_hash.split(':')
            check_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            return f"{salt}:{check_hash}" == stored_hash
    except (ValueError, Exception):
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


def verify_api_key():
    """Check if request has valid API key with brute force protection"""
    global api_failed_attempts
    
    # Get client IP
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip and ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()
    
    # Check for lockout
    if client_ip in api_failed_attempts:
        attempt_info = api_failed_attempts[client_ip]
        if attempt_info['count'] >= API_LOCKOUT_THRESHOLD:
            time_since_last = time.time() - attempt_info['last_attempt']
            if time_since_last < API_LOCKOUT_DURATION:
                remaining = int(API_LOCKOUT_DURATION - time_since_last)
                return False, f"Too many failed attempts. Try again in {remaining} seconds"
            else:
                # Reset after lockout expires
                del api_failed_attempts[client_ip]
    
    cfg = load_config()
    
    # Check if API is enabled
    if not cfg.get('api_enabled', False):
        return False, "API access is disabled"
    
    stored_key = cfg.get('api_key', '')
    if not stored_key:
        return False, "No API key configured"
    
    # Check header first (preferred - doesn't appear in logs)
    provided_key = request.headers.get('X-Api-Key', '')
    
    # Fall back to query param (less secure - may appear in logs)
    if not provided_key:
        provided_key = request.args.get('apikey', '')
    
    if not provided_key:
        return False, "No API key provided"
    
    # Constant-time comparison to prevent timing attacks
    if hmac.compare_digest(stored_key, provided_key):
        # Reset failed attempts on success
        if client_ip in api_failed_attempts:
            del api_failed_attempts[client_ip]
        return True, None
    
    # Track failed attempt
    if client_ip not in api_failed_attempts:
        api_failed_attempts[client_ip] = {'count': 0, 'last_attempt': 0}
    api_failed_attempts[client_ip]['count'] += 1
    api_failed_attempts[client_ip]['last_attempt'] = time.time()
    
    # Log suspicious activity (without revealing the key)
    if api_failed_attempts[client_ip]['count'] >= 3:
        log(f"âš ï¸ [API] Multiple failed auth attempts from {client_ip} ({api_failed_attempts[client_ip]['count']} attempts)")
    
    return False, "Invalid API key"


def api_key_required(f):
    """Decorator to require API key authentication for external API endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        valid, error = verify_api_key()
        if not valid:
            # Determine if this is a rate limit issue
            status_code = 429 if "Too many failed attempts" in error else 401
            response = jsonify({
                "success": False,
                "error": error,
                "code": "RATE_LIMITED" if status_code == 429 else "UNAUTHORIZED"
            })
            return response, status_code
        return f(*args, **kwargs)
    return decorated_function


def api_key_or_login_required(f):
    """Decorator that accepts either API key or session login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First try API key
        valid, _ = verify_api_key()
        if valid:
            return f(*args, **kwargs)
        
        # Fall back to session auth
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
                return jsonify({
                    "success": False,
                    "error": "Authentication required",
                    "code": "UNAUTHORIZED"
                }), 401
        return f(*args, **kwargs)
    return decorated_function


def generate_api_key():
    """Generate a secure random API key"""
    # Format: jl_xxxxxxxxxxxxxxxxxxxxxxxxxxxx (32 chars after prefix)
    return 'jl_' + secrets.token_hex(16)


# --- Utility Functions ---

def get_local_time():
    """Get current time in configured timezone"""
    cfg = load_config()
    tz_name = cfg.get('timezone', 'UTC')
    
    # Handle empty or invalid timezone
    if not tz_name:
        tz_name = 'UTC'
    
    if TIMEZONE_SUPPORT:
        try:
            tz = ZoneInfo(tz_name)
            return datetime.datetime.now(tz)
        except Exception as e:
            # Log once on first failure
            if not hasattr(get_local_time, '_tz_error_logged'):
                print(f"âš ï¸ Timezone error for '{tz_name}': {e}")
                print(f"âš ï¸ Falling back to UTC. Install tzdata package for timezone support.")
                get_local_time._tz_error_logged = True
    
    # Fallback to UTC
    try:
        return datetime.datetime.now(datetime.timezone.utc)
    except:
        return datetime.datetime.now()


def check_timezone_support():
    """Check and log timezone support status at startup"""
    cfg = load_config()
    tz_name = cfg.get('timezone', 'UTC')
    
    if TIMEZONE_SUPPORT:
        try:
            tz = ZoneInfo(tz_name)
            test_time = datetime.datetime.now(tz)
            print(f"âœ… Timezone support: {tz_name} (current time: {test_time.strftime('%H:%M:%S %Z')})")
            return True
        except Exception as e:
            print(f"âš ï¸ Timezone '{tz_name}' not available: {e}")
            print(f"âš ï¸ Available timezones may require tzdata package")
    else:
        print(f"âš ï¸ ZoneInfo not available - timezone support disabled")
    return False


def log(msg):
    """Thread-safe logging with timestamp in configured timezone and format"""
    print(msg)
    with download_lock:
        try:
            cfg = load_config()
            local_time = get_local_time()
            time_format = cfg.get('time_format', '12h')
            
            if time_format == '24h':
                timestamp = local_time.strftime('%H:%M:%S')
            else:
                # 12-hour format with AM/PM
                timestamp = local_time.strftime('%I:%M:%S %p').lstrip('0')
        except:
            timestamp = time.strftime('%H:%M:%S')
        log_buffer.append(f"[{timestamp}] {msg}")
        # deque handles max size automatically via maxlen


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
    """Generate Jellyfin/Emby auth header - compatible with all versions"""
    # Base MediaBrowser auth string
    auth_string = f'MediaBrowser Client="JellyLooter", Device="Unraid", DeviceId="JellyLooterId", Version="{VERSION}"'

    if token:
        auth_string += f', Token="{token}"'

    headers = {
        'Content-Type': 'application/json',
        # Primary header for newer Jellyfin (10.9+)
        'Authorization': auth_string,
        # Legacy headers for older Jellyfin/Emby compatibility
        'X-Emby-Authorization': auth_string,
    }

    # Also add token as separate headers for maximum compatibility
    if token:
        headers['X-Emby-Token'] = token
        headers['X-MediaBrowser-Token'] = token

    return headers


def check_disk_space(path, required_bytes=0):
    """Check if there's enough disk space at the given path"""
    try:
        stat = shutil.disk_usage(path)
        free_bytes = stat.free
        
        if required_bytes > 0 and free_bytes < required_bytes:
            return False, f"Not enough space. Free: {format_bytes(free_bytes)}, Need: {format_bytes(required_bytes)}"
        
        if free_bytes < 1024 * 1024 * 1024:
            log(f"âš ï¸ Warning: Low disk space on {path} - {format_bytes(free_bytes)} free")
        
        return True, f"Free: {format_bytes(free_bytes)}"
    except Exception as e:
        return False, f"Cannot check disk space: {e}"


# --- Input Validation ---

def validate_url(url):
    """Validate URL format"""
    if not url:
        return False, "URL is required"
    
    url = url.strip()
    
    # Length check to prevent DoS
    if len(url) > 2048:
        return False, "URL is too long"
    
    # Check for valid protocol
    if not url.startswith(('http://', 'https://')):
        return False, "URL must start with http:// or https://"
    
    # Basic URL pattern check
    pattern = r'^https?://[a-zA-Z0-9\-\.]+(:[0-9]+)?(/.*)?$'
    if not re.match(pattern, url):
        return False, "Invalid URL format"
    
    # Block potentially dangerous URLs
    dangerous_patterns = ['localhost:22', '127.0.0.1:22', '/etc/', '/proc/', '..', 
                         'file://', 'ftp://', 'gopher://', 'javascript:']
    for dangerous in dangerous_patterns:
        if dangerous in url.lower():
            return False, "Invalid URL"
    
    return True, "Valid"


def validate_api_key(key):
    """Validate API key format"""
    if not key:
        return False, "API key is required"
    
    key = key.strip()
    
    # Jellyfin API keys are typically 32 hex characters
    if len(key) < 16:
        return False, "API key is too short"
    
    if len(key) > 128:
        return False, "API key is too long"
    
    # Check for valid characters
    if not re.match(r'^[a-zA-Z0-9\-_]+$', key):
        return False, "API key contains invalid characters"
    
    return True, "Valid"


def validate_server_input(url, api_key=None, username=None, password=None):
    """Validate server connection inputs"""
    url_valid, url_msg = validate_url(url)
    if not url_valid:
        return False, url_msg
    
    if api_key:
        key_valid, key_msg = validate_api_key(api_key)
        if not key_valid:
            return False, key_msg
    elif username and password:
        if len(username) < 1:
            return False, "Username is required"
        if len(password) < 1:
            return False, "Password is required"
    else:
        return False, "API key or username/password required"
    
    return True, "Valid"


# --- Partial Downloads Management (Pro Feature) ---

def load_partial_downloads():
    """Load partial downloads manifest"""
    try:
        if os.path.exists(PARTIAL_DOWNLOADS_FILE):
            with open(PARTIAL_DOWNLOADS_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}


def save_partial_downloads(partials):
    """Save partial downloads manifest"""
    try:
        with open(PARTIAL_DOWNLOADS_FILE, 'w') as f:
            json.dump(partials, f, indent=2)
    except Exception as e:
        log(f"Error saving partial downloads: {e}")


def save_partial_state(task_id, task, downloaded_bytes, total_bytes, queued=False):
    """Save state for a partial download (Pro feature)"""
    if not is_feature_available('transcoding'):  # Use transcoding as proxy for Pro
        return
    
    partials = load_partial_downloads()
    server = task.get('server', {}) or {}
    # Credentials are NOT stored here (headers/keys are rebuilt from the server config on resume)
    partials[task_id] = {
        'task_id': task_id,
        'url': task.get('url', ''),
        'filepath': task.get('filepath', ''),
        'filename': os.path.basename(task.get('filepath', '')),
        'server_id': server.get('id', ''),
        'server': {'id': server.get('id', ''), 'name': server.get('name', ''), 'url': server.get('url', '')},
        'item_id': task.get('item_id', ''),
        'item_type': task.get('item_type', ''),
        'provider_ids': task.get('provider_ids', {}),
        'series_provider_ids': task.get('series_provider_ids', {}),
        'downloaded': downloaded_bytes,
        'queued': bool(queued),
        'total': total_bytes or partials.get(task_id, {}).get('total', 0),
        'timestamp': datetime.datetime.now().isoformat(),
        'partial_file': task.get('filepath', '') + '.partial'
    }
    save_partial_downloads(partials)


def task_from_partial(task_id, info):
    """Rebuild a download task from saved partial state using the current server credentials."""
    cfg = load_config()
    sid = info.get('server_id') or (info.get('server') or {}).get('id')
    server = next((s for s in get_all_servers(cfg) if s.get('id') == sid), None)
    if not server:
        return None
    return {
        'task_id': task_id,
        'url': info.get('url', ''),
        'filepath': info.get('filepath', ''),
        'headers': get_auth_header(server.get('key', '')),
        'server': server,
        'item_id': info.get('item_id', ''),
        'item_type': info.get('item_type', ''),
        'provider_ids': info.get('provider_ids', {}),
        'series_provider_ids': info.get('series_provider_ids', {}),
        'resume': True
    }


def _partial_bytes(info):
    pf = info.get('partial_file', '')
    if pf and os.path.exists(pf):
        return os.path.getsize(pf)
    if pf and os.path.exists(pf + '.jlseg'):
        return sum(os.path.getsize(s) for s in glob.glob(pf + '.seg*'))
    return None


def auto_resume_partials():
    """After a restart / power cut, put unfinished downloads back in the queue (Pro)."""
    if not is_feature_available('transcoding') or not load_config().get('auto_resume_downloads', True):
        return
    resumed = 0
    for task_id, info in list(load_partial_downloads().items()):
        if os.path.exists(info.get('filepath', '')):
            clear_partial_state(task_id)  # finished before the restart
            continue
        if _partial_bytes(info) is None and not info.get('queued'):
            continue
        task = task_from_partial(task_id, info)
        if not task:
            continue
        with download_lock:
            pending_display.append({'id': task_id, 'name': f"🔄 {info.get('filename', 'Unknown')}"})
        server = task['server']
        queue_to_server_or_global(task, server.get('id') or server.get('url', 'unknown'), server.get('name'))
        resumed += 1
    if resumed:
        log(f"🔄 Auto-resumed {resumed} unfinished download(s) after restart")


def clear_partial_state(task_id):
    """Remove a partial download entry"""
    partials = load_partial_downloads()
    if task_id in partials:
        del partials[task_id]
        save_partial_downloads(partials)


def get_resumable_downloads():
    """Get list of downloads that can be resumed"""
    partials = load_partial_downloads()
    resumable = []
    
    for task_id, info in partials.items():
        actual_size = _partial_bytes(info)
        if actual_size is not None:
            resumable.append({
                'task_id': task_id,
                'filename': info.get('filename', 'Unknown'),
                'filepath': info.get('filepath', ''),
                'downloaded': actual_size,
                'downloaded_human': format_bytes(actual_size),
                'total': info.get('total', 0),
                'total_human': format_bytes(info.get('total', 0)),
                'percent': int((actual_size / info['total']) * 100) if info.get('total', 0) > 0 else 0,
                'timestamp': info.get('timestamp', ''),
                'age': _get_age_string(info.get('timestamp', ''))
            })
    
    return resumable


def _get_age_string(timestamp_str):
    """Get human-readable age from timestamp"""
    try:
        ts = datetime.datetime.fromisoformat(timestamp_str)
        age = datetime.datetime.now() - ts
        if age.days > 0:
            return f"{age.days}d ago"
        hours = age.seconds // 3600
        if hours > 0:
            return f"{hours}h ago"
        minutes = age.seconds // 60
        return f"{minutes}m ago"
    except:
        return "Unknown"


def cleanup_old_partials(max_age_days=7):
    """Remove partial downloads older than max_age_days"""
    partials = load_partial_downloads()
    now = datetime.datetime.now()
    removed = 0
    
    for task_id in list(partials.keys()):
        info = partials[task_id]
        try:
            ts = datetime.datetime.fromisoformat(info.get('timestamp', ''))
            if (now - ts).days > max_age_days:
                partial_file = info.get('partial_file', '')
                if partial_file and os.path.exists(partial_file):
                    os.remove(partial_file)
                del partials[task_id]
                removed += 1
        except:
            pass
    
    if removed > 0:
        save_partial_downloads(partials)
        log(f"Cleaned up {removed} old partial downloads")


# --- Config Management ---

def get_default_config():
    """Return default configuration"""
    return {
        "servers": [],
        "local_servers": [],  # New: multiple local servers (Pro)
        "mappings": [],
        "sync_time": "04:00",
        "speed_limit_kbs": 0,
        "local_server_url": "",
        "local_server_key": "",
        "auto_sync_enabled": True,
        "theme": "dark",
        "custom_theme": {},  # Pro: custom colors
        "max_concurrent_downloads": 2,
        "override_download_limit": False,  # Allow >10 concurrent downloads
        "download_auto_retry": True,  # Auto-retry failed connections
        "download_retry_count": 3,  # Number of retry attempts
        "download_retry_delay": 30,  # Seconds between retries
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
        "download_order": "library",
        # Folder naming settings
        "folder_naming_format": "standard",  # standard, ids_space, ids_braces, ids_brackets, tmdb_only, imdb_only
        # Metadata API settings (Free feature)
        "tmdb_api_key": "",
        "tvdb_api_key": "",  # TVDB v4 API key
        "tvdb_subscriber_pin": "",  # TVDB v4 subscriber PIN (required)
        "omdb_api_key": "",
        "imdb_lookup_enabled": True,  # IMDB direct lookup (no API key needed)
        "metadata_lookup_on_browse": False,  # True = lookup on browse (slower), False = lookup on download only (faster)
        # Display settings
        "show_ratings": True,
        "show_quality": True,
        # Subtitle settings (Free feature)
        "download_subtitles": True,
        "subtitle_languages": ["eng", "spa", "ger"],  # ISO 639-2 codes
        # New v3.0.0 settings
        "session_timeout_minutes": 30,
        "force_https": False,
        "trust_proxy_headers": False,
        "trusted_proxy_ips": "",
        # API Key for external integrations (NZB360, etc.)
        "api_key": "",  # Generated API key for external access
        "api_enabled": False,  # Enable/disable API access
        # Dashboard layout
        "dashboard_layout": "classic",  # classic, compact, cards, list, minimal
        # Resource Limits
        "resource_limits_enabled": False,  # Enable resource limiting
        "cpu_limit_threads": 0,  # 0 = auto, 1-32 = specific thread count for transcoding
        "cpu_priority": "normal",  # low, normal, high - process priority (nice)
        "io_priority": "normal",  # idle, low, normal - I/O priority (ionice)
        "memory_buffer_mb": 64,  # Download buffer size in MB (8-256)
        "transcode_memory_limit_mb": 0,  # 0 = unlimited, or specific limit for ffmpeg
        # Per-server workers (Pro feature)
        "per_server_workers": False,  # Enable dedicated worker per server
        "per_server_worker_count": 2,  # Workers per server (1-10)
        # Skip list for auto-sync
        "sync_skip_list": [],  # List of {id, name, type, server_id} items to skip during sync
        # Scheduling (Pro)
        "download_schedule_enabled": False,
        "download_schedule_start": "02:00",
        "download_schedule_end": "06:00",
        "bandwidth_schedule_enabled": False,
        "bandwidth_day_limit_kbs": 1000,
        "bandwidth_night_limit_kbs": 0,
        "bandwidth_night_start": "22:00",
        "bandwidth_night_end": "06:00",
        # Notifications (Pro)
        "notification_urls": [],  # Apprise URLs
        "notify_on_complete": True,
        "notify_on_error": True,
        # *arr integration (Pro)
        "sonarr_url": "",
        "sonarr_api_key": "",
        "radarr_url": "",
        "radarr_api_key": "",
        "lidarr_url": "",
        "lidarr_api_key": "",
        "arr_auto_import": True,  # Auto-add media to *arr and trigger scan after download
        "arr_path_mappings": [],  # Array of {name, from, to} path mappings
        # Transcoding (Pro)
        "transcode_enabled": False,
        "transcode_preset": "original",  # original, h265, mobile, custom
        "transcode_encoder": "software",  # software, nvenc, qsv, vaapi
        "transcode_custom_args": "",
        "transcode_cache_enabled": False,  # Use cache drive for transcoding
        "transcode_cache_path": "/tmp/transcode_cache",  # Path to cache drive
        # Analytics (Pro)
        "track_analytics": True,
        # Last visited locations per server
        "last_locations": {},
        # What's new tracking
        "last_seen_items": {}
    }


def _decrypt_config_keys(config):
    """Decrypt all API keys in config"""
    result = config.copy()
    
    # Decrypt server API keys
    if 'servers' in result:
        decrypted_servers = []
        for server in result['servers']:
            s = server.copy()
            if s.get('key') and is_encrypted(s['key']):
                s['key'] = decrypt_sensitive(s['key'])
            decrypted_servers.append(s)
        result['servers'] = decrypted_servers
    
    # Decrypt local server key
    if result.get('local_server_key') and is_encrypted(result['local_server_key']):
        result['local_server_key'] = decrypt_sensitive(result['local_server_key'])
    
    # Decrypt local_servers list
    if 'local_servers' in result:
        decrypted_local = []
        for server in result['local_servers']:
            s = server.copy()
            if s.get('key') and is_encrypted(s['key']):
                s['key'] = decrypt_sensitive(s['key'])
            decrypted_local.append(s)
        result['local_servers'] = decrypted_local
    
    # Decrypt *arr API keys
    for arr_key in ['sonarr_api_key', 'radarr_api_key', 'lidarr_api_key']:
        if result.get(arr_key) and is_encrypted(result[arr_key]):
            result[arr_key] = decrypt_sensitive(result[arr_key])
    
    # Decrypt metadata API keys
    for meta_key in ['tmdb_api_key', 'tvdb_api_key', 'tvdb_subscriber_pin', 'omdb_api_key']:
        if result.get(meta_key) and is_encrypted(result[meta_key]):
            result[meta_key] = decrypt_sensitive(result[meta_key])
    
    # Decrypt external API key
    if result.get('api_key') and is_encrypted(result['api_key']):
        result['api_key'] = decrypt_sensitive(result['api_key'])
    
    return result


def load_config(force_reload=False):
    """Load config with caching and automatic decryption"""
    global _config_cache, _config_mtime
    
    # Check if we can use cached config
    if not force_reload and _config_cache is not None:
        try:
            current_mtime = os.path.getmtime(CONFIG_FILE) if os.path.exists(CONFIG_FILE) else 0
            if current_mtime == _config_mtime:
                return _config_cache.copy()
        except Exception:
            pass
    
    default = get_default_config()
    if not os.path.exists(CONFIG_FILE):
        return default
    try:
        with open(CONFIG_FILE, 'r') as f:
            loaded = json.load(f)
            merged = {**default, **loaded}
            # Decrypt API keys for use
            _config_cache = _decrypt_config_keys(merged)
            _config_mtime = os.path.getmtime(CONFIG_FILE)
            return _config_cache.copy()
    except Exception:
        return default


def save_config(data):
    """Save config with encrypted API keys, invalidate cache, and refresh schedule"""
    global _config_cache, _config_mtime
    
    # Apply tier limits before saving
    limits = get_tier_limits()
    
    # Limit servers if over quota
    if len(data.get('servers', [])) > limits['max_remote_servers']:
        data['servers'] = data['servers'][:limits['max_remote_servers']]
        log(f"Server limit reached ({limits['max_remote_servers']} max for your tier)")
    
    if len(data.get('mappings', [])) > limits['max_sync_mappings']:
        data['mappings'] = data['mappings'][:limits['max_sync_mappings']]
        log(f"Mapping limit reached ({limits['max_sync_mappings']} max for your tier)")
    
    # Enforce max concurrent downloads limit
    max_downloads = data.get('max_concurrent_downloads', 2)
    max_allowed = limits.get('max_concurrent_downloads', 2)
    if max_downloads > max_allowed:
        data['max_concurrent_downloads'] = max_allowed
        log(f"Concurrent downloads limited to {max_allowed} for your tier")
    
    # Encrypt sensitive API keys before saving
    data_to_save = data.copy()
    
    # Encrypt server API keys
    if 'servers' in data_to_save:
        encrypted_servers = []
        for server in data_to_save['servers']:
            s = server.copy()
            if s.get('key') and not is_encrypted(s['key']):
                s['key'] = encrypt_sensitive(s['key'])
            encrypted_servers.append(s)
        data_to_save['servers'] = encrypted_servers
    
    # Encrypt local server key
    if data_to_save.get('local_server_key') and not is_encrypted(data_to_save['local_server_key']):
        data_to_save['local_server_key'] = encrypt_sensitive(data_to_save['local_server_key'])
    
    # Encrypt local_servers list
    if 'local_servers' in data_to_save:
        encrypted_local = []
        for server in data_to_save['local_servers']:
            s = server.copy()
            if s.get('key') and not is_encrypted(s['key']):
                s['key'] = encrypt_sensitive(s['key'])
            encrypted_local.append(s)
        data_to_save['local_servers'] = encrypted_local
    
    # Encrypt *arr API keys
    for arr_key in ['sonarr_api_key', 'radarr_api_key', 'lidarr_api_key']:
        if data_to_save.get(arr_key) and not is_encrypted(data_to_save[arr_key]):
            data_to_save[arr_key] = encrypt_sensitive(data_to_save[arr_key])
    
    # Encrypt metadata API keys
    for meta_key in ['tmdb_api_key', 'tvdb_api_key', 'tvdb_subscriber_pin', 'omdb_api_key']:
        if data_to_save.get(meta_key) and not is_encrypted(data_to_save[meta_key]):
            data_to_save[meta_key] = encrypt_sensitive(data_to_save[meta_key])
    
    # Encrypt external API key
    if data_to_save.get('api_key') and not is_encrypted(data_to_save['api_key']):
        data_to_save['api_key'] = encrypt_sensitive(data_to_save['api_key'])
    
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(data_to_save, f, indent=4)
    
    # Invalidate cache
    _config_cache = None
    _config_mtime = 0
    
    setup_schedule()
    adjust_workers(data.get('max_concurrent_downloads', 2))
    
    # Adjust transcode workers if Pro user OR test mode enabled
    test_mode = (DEV_MODE and data.get('_transcode_test_mode', False))
    transcode_enabled = data.get('transcode_enabled', False)
    if (transcode_enabled and is_feature_available('transcoding')) or test_mode:
        adjust_transcode_workers(data.get('max_concurrent_transcodes', 1), force=test_mode)
    
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
    global local_id_cache, episode_id_cache, series_episode_counts, cache_timestamp
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                data = json.load(f)
                local_id_cache = set(data.get('ids', []))
                episode_id_cache = set(data.get('episode_ids', []))
                series_episode_counts = data.get('series_episodes', {})
                cache_timestamp = data.get('timestamp', 'Unknown')
                m = data.get('match', {})
                local_match_index.update({
                    'movie_ids': set(m.get('movie_ids', [])),
                    'series_ids': set(m.get('series_ids', [])),
                    'movie_titles': m.get('movie_titles', {}),
                    'series_titles': m.get('series_titles', {}),
                    'episode_titles': set(m.get('episode_titles', [])),
                    'built': bool(m),
                })
        except Exception:
            pass


def cache_worker():
    """Scan local server(s) and build ID cache with episode counts"""
    global local_id_cache, episode_id_cache, series_episode_counts, cache_timestamp, scan_progress
    
    cfg = load_config()
    
    # Support both old single-server and new multi-server format
    local_servers = []
    
    # Check new multi-server format first
    if cfg.get('local_servers'):
        # v4 keeps remote servers in this list too - only index servers marked local
        local_servers = [s for s in cfg.get('local_servers', []) if s.get('type', 'local') == 'local']

    # Fall back to old single-server format
    if not local_servers and cfg.get('local_server_url') and cfg.get('local_server_key'):
        local_servers = [{
            'url': cfg.get('local_server_url'),
            'api_key': cfg.get('local_server_key'),
            'name': 'Local Server'
        }]
    
    if not local_servers:
        log("Scan Skipped: No Local Server configured")
        return
    
    if scan_progress['running']:
        log("Scan already in progress")
        return

    log(f"Starting Local Library Scan ({len(local_servers)} server(s))...")
    scan_progress = {
        "running": True,
        "percent": 0,
        "current": 0,
        "total": 0,
        "status": "Connecting..."
    }

    try:
        new_cache = {
            'ids': set(),              # All provider IDs
            'episode_ids': set(),      # Episode-specific IDs (for episode-level checking)
            'series_episodes': {},     # series_id -> count of episodes locally
            'match': {'movie_ids': set(), 'series_ids': set(), 'movie_titles': {}, 'series_titles': {},
                      'episode_titles': set(), 'series_counts': {}},
        }
        timeout = cfg.get('connection_timeout', 30)
        total_items_scanned = 0
        
        for server in local_servers:
            url = server.get('url', '').rstrip('/')
            # Support both 'api_key' (new format) and 'key' (might exist)
            key = server.get('api_key') or server.get('key', '')
            name = server.get('name', url)
            
            # Also support username/password auth
            username = server.get('username', '')
            password = server.get('password', '')
            
            if not url:
                continue
            
            if not key and not (username and password):
                log(f"Skipping {name}: No authentication configured")
                continue
            
            try:
                # Get auth header based on auth type
                if key:
                    headers = get_auth_header(key)
                else:
                    # Username/password auth - need to authenticate first
                    auth_res = requests.post(
                        f"{url}/Users/AuthenticateByName",
                        json={'Username': username, 'Pw': password},
                        headers={'Content-Type': 'application/json'},
                        timeout=timeout
                    )
                    if not auth_res.ok:
                        log(f"Scan Failed for {name}: Authentication failed")
                        continue
                    auth_data = auth_res.json()
                    access_token = auth_data.get('AccessToken', '')
                    headers = get_auth_header(access_token)
                
                log(f"Scanning {name}...")
                
                # Scan as the configured account (not just the first user on the server)
                uid = server.get('user_id')
                if not uid:
                    me_res = requests.get(f"{url}/Users/Me", headers=headers, timeout=timeout)
                    if me_res.ok:
                        uid = me_res.json().get('Id')
                if not uid:
                    u_res = requests.get(f"{url}/Users", headers=headers, timeout=timeout)
                    if not u_res.ok:
                        log(f"Scan Failed for {name}: Could not get users")
                        continue
                    uid = u_res.json()[0]['Id']

                params = {
                    'Recursive': 'true',
                    'IncludeItemTypes': 'Movie,Series,Episode',
                    'Fields': 'ProviderIds,SeriesProviderIds,OriginalTitle',
                    'Limit': 0
                }
                total_res = requests.get(
                    f"{url}/Users/{uid}/Items",
                    headers=headers,
                    params=params
                ).json()
                total_count = total_res.get('TotalRecordCount', 0)

                scan_progress.update({
                    'total': scan_progress.get('total', 0) + total_count,
                    'status': f"Scanning {name}: {total_count} items"
                })

                limit = 500
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
                        series_providers = item.get('SeriesProviderIds', {})
                        item_type = item.get('Type', '')

                        # Rich match index: every provider id + normalized titles
                        mi = new_cache['match']
                        pkeys = _provider_keys(providers)
                        year = item.get('ProductionYear') or 0
                        if item_type == 'Movie':
                            mi['movie_ids'] |= pkeys
                            for n in (item.get('Name'), item.get('OriginalTitle')):
                                if normalize_title(n):
                                    mi['movie_titles'].setdefault(normalize_title(n), set()).add(year)
                        elif item_type == 'Series':
                            mi['series_ids'] |= pkeys
                            for n in (item.get('Name'), item.get('OriginalTitle')):
                                if normalize_title(n):
                                    mi['series_titles'].setdefault(normalize_title(n), set()).add(year)
                        elif item_type == 'Episode':
                            new_cache['episode_ids'] |= pkeys
                            spkeys = _provider_keys(series_providers)
                            mi['series_ids'] |= spkeys
                            for k in spkeys:
                                mi['series_counts'][k] = mi['series_counts'].get(k, 0) + 1
                            sname = normalize_title(item.get('SeriesName'))
                            if sname:
                                mi['series_titles'].setdefault(sname, set()).add(0)
                                if item.get('IndexNumber') is not None:
                                    mi['episode_titles'].add(f"{sname}|{item.get('ParentIndexNumber')}|{item.get('IndexNumber')}")

                        # Store item's own provider IDs
                        if 'Imdb' in providers:
                            new_cache['ids'].add(f"imdb_{providers['Imdb']}")
                        if 'Tmdb' in providers:
                            new_cache['ids'].add(f"tmdb_{providers['Tmdb']}")
                        if 'Tvdb' in providers:
                            new_cache['ids'].add(f"tvdb_{providers['Tvdb']}")
                        
                        # For Episodes, track episode-specific IDs and count per series
                        if item_type == 'Episode':
                            # Store episode's own IDs
                            for key_type in ['Imdb', 'Tmdb', 'Tvdb']:
                                if key_type in providers:
                                    new_cache['episode_ids'].add(f"{key_type.lower()}_{providers[key_type]}")
                            
                            # Track episode count per series
                            if series_providers:
                                series_key = None
                                if 'Tvdb' in series_providers:
                                    series_key = f"tvdb_{series_providers['Tvdb']}"
                                elif 'Imdb' in series_providers:
                                    series_key = f"imdb_{series_providers['Imdb']}"
                                elif 'Tmdb' in series_providers:
                                    series_key = f"tmdb_{series_providers['Tmdb']}"
                                
                                if series_key:
                                    new_cache['series_episodes'][series_key] = new_cache['series_episodes'].get(series_key, 0) + 1
                                
                                # Also add series-level IDs
                                if 'Imdb' in series_providers:
                                    new_cache['ids'].add(f"imdb_{series_providers['Imdb']}")
                                if 'Tmdb' in series_providers:
                                    new_cache['ids'].add(f"tmdb_{series_providers['Tmdb']}")
                                if 'Tvdb' in series_providers:
                                    new_cache['ids'].add(f"tvdb_{series_providers['Tvdb']}")

                    offset += len(items)
                    total_items_scanned += len(items)
                    scan_progress.update({
                        'current': total_items_scanned,
                        'percent': int((total_items_scanned / scan_progress['total']) * 100) if scan_progress['total'] > 0 else 0
                    })
                
                log(f"Scanned {total_count} items from {name}")
                
            except Exception as server_error:
                log(f"Scan Failed for {name}: {server_error}")
                continue

        # Store new cache format - update global variables
        local_id_cache.clear()
        local_id_cache.update(new_cache['ids'])
        episode_id_cache.clear()
        episode_id_cache.update(new_cache['episode_ids'])
        mi = new_cache['match']
        # Count episodes under every series id (not just the first one found)
        for k, n in mi['series_counts'].items():
            new_cache['series_episodes'][k] = max(new_cache['series_episodes'].get(k, 0), n)
        series_episode_counts.clear()
        series_episode_counts.update(new_cache['series_episodes'])
        local_match_index.update({
            'movie_ids': mi['movie_ids'], 'series_ids': mi['series_ids'],
            'movie_titles': {k: sorted(v) for k, v in mi['movie_titles'].items()},
            'series_titles': {k: sorted(v) for k, v in mi['series_titles'].items()},
            'episode_titles': mi['episode_titles'],
            'built': True,
        })
        cache_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, 'w') as f:
            json.dump({
                'timestamp': cache_timestamp,
                'ids': list(new_cache['ids']),
                'episode_ids': list(new_cache['episode_ids']),
                'series_episodes': new_cache['series_episodes'],
                'match': {
                    'movie_ids': list(mi['movie_ids']), 'series_ids': list(mi['series_ids']),
                    'movie_titles': local_match_index['movie_titles'],
                    'series_titles': local_match_index['series_titles'],
                    'episode_titles': list(mi['episode_titles']),
                }
            }, f)

        log(f"Scan Complete. Cached {len(new_cache['ids'])} IDs, {len(new_cache['episode_ids'])} episode IDs, {len(new_cache['series_episodes'])} series episode counts.")
        scan_progress = {
            "running": False,
            "percent": 100,
            "current": total_items_scanned,
            "total": total_items_scanned,
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


import unicodedata

# Richer local index for duplicate detection (title + every provider id)
local_match_index = {'movie_ids': set(), 'series_ids': set(), 'movie_titles': {}, 'series_titles': {}, 'episode_titles': set(), 'built': False}


def normalize_title(name):
    """Lowercase, strip accents/punctuation/leading article/trailing (year) for title matching."""
    if not name:
        return ''
    s = unicodedata.normalize('NFKD', str(name))
    s = ''.join(c for c in s if not unicodedata.combining(c)).lower()
    s = re.sub(r'\(\s*\d{4}\s*\)\s*$', '', s).replace('&', ' and ')
    s = re.sub(r"['â€™`]", '', s)
    s = re.sub(r'[\W_]+', ' ', s).strip()
    return re.sub(r'^(the|a|an) ', '', s)


def _provider_keys(providers):
    return {f"{k.lower()}_{v}" for k, v in (providers or {}).items() if v}


def _title_hit(index, names, year):
    """True if any normalized name is in index with a compatible year (Â±1, or unknown)."""
    for name in names:
        years = index.get(normalize_title(name))
        if years is None:
            continue
        if not year or not years or 0 in years or any(abs(int(y) - int(year)) <= 1 for y in years):
            return True
    return False


def series_exists_locally(series_providers, series_names, year=None):
    idx = local_match_index
    keys = _provider_keys(series_providers)
    series_ids = idx['series_ids'] if idx.get('built') else (idx['series_ids'] | local_id_cache)  # no full index yet: legacy ids too
    if keys & series_ids or any(series_episode_counts.get(k, 0) > 0 for k in keys):
        return True
    return _title_hit(idx['series_titles'], [n for n in series_names if n], year)


def local_match_status(item):
    """'full', 'partial' or False for a remote Jellyfin item (ids, then title/year)."""
    get_existing_ids()
    idx = local_match_index
    t = item.get('Type', '')
    prov = _provider_keys(item.get('ProviderIds'))
    names = [item.get('Name'), item.get('OriginalTitle')]
    year = item.get('ProductionYear')
    movie_ids = idx['movie_ids'] if idx.get('built') else (idx['movie_ids'] | local_id_cache)  # no full index yet: legacy ids too
    if t == 'Episode':
        if prov & episode_id_cache:
            return 'full'
        if item.get('IndexNumber') is not None:
            key = f"{normalize_title(item.get('SeriesName'))}|{item.get('ParentIndexNumber')}|{item.get('IndexNumber')}"
            if key in idx['episode_titles']:
                return 'full'
        return False
    if t == 'Series':
        return 'full' if series_exists_locally(item.get('ProviderIds'), names, year) else False
    if t == 'Season':
        return 'partial' if series_exists_locally(item.get('SeriesProviderIds'), [item.get('SeriesName')]) else False
    if t in ('Movie', 'Video', 'MusicVideo'):
        if prov & movie_ids or _title_hit(idx['movie_titles'], [n for n in names if n], year):
            return 'full'
    return False


def local_series_episode_count(item):
    keys = _provider_keys(item.get('ProviderIds'))
    return max([series_episode_counts.get(k, 0) for k in keys] or [0])


def get_existing_ids():
    """Get cached local IDs, loading from disk if needed"""
    if not local_id_cache:
        load_cache_from_disk()
    return local_id_cache


def get_episode_cache():
    """Get episode-specific IDs and series episode counts"""
    if not local_id_cache:
        load_cache_from_disk()
    return episode_id_cache, series_episode_counts


def update_cache_for_download(provider_ids, series_provider_ids=None, item_type='Episode'):
    """
    Incrementally update the local cache when a download completes.
    Much faster than full rebuild - just adds the new item's IDs.
    """
    global local_id_cache, episode_id_cache, series_episode_counts, cache_timestamp
    
    # Ensure cache is loaded
    if not local_id_cache:
        load_cache_from_disk()
    
    updated = False
    
    # Add item's own provider IDs to main cache
    for key_type in ['Imdb', 'Tmdb', 'Tvdb']:
        if provider_ids.get(key_type):
            cache_key = f"{key_type.lower()}_{provider_ids[key_type]}"
            if cache_key not in local_id_cache:
                local_id_cache.add(cache_key)
                updated = True
    
    # For episodes, add to episode_id_cache and update series counts
    if item_type == 'Episode':
        # Add episode-specific IDs
        for key_type in ['Imdb', 'Tmdb', 'Tvdb']:
            if provider_ids.get(key_type):
                ep_key = f"{key_type.lower()}_{provider_ids[key_type]}"
                if ep_key not in episode_id_cache:
                    episode_id_cache.add(ep_key)
                    updated = True
        
        # Update series episode count
        if series_provider_ids:
            series_key = None
            if series_provider_ids.get('Tvdb'):
                series_key = f"tvdb_{series_provider_ids['Tvdb']}"
            elif series_provider_ids.get('Imdb'):
                series_key = f"imdb_{series_provider_ids['Imdb']}"
            elif series_provider_ids.get('Tmdb'):
                series_key = f"tmdb_{series_provider_ids['Tmdb']}"
            
            if series_key:
                series_episode_counts[series_key] = series_episode_counts.get(series_key, 0) + 1
                updated = True
                log(f"ðŸ“Š Cache updated: {series_key} now has {series_episode_counts[series_key]} episodes")
            
            # Also add series-level IDs to main cache
            for key_type in ['Imdb', 'Tmdb', 'Tvdb']:
                if series_provider_ids.get(key_type):
                    cache_key = f"{key_type.lower()}_{series_provider_ids[key_type]}"
                    if cache_key not in local_id_cache:
                        local_id_cache.add(cache_key)
                        updated = True
    
    elif item_type == 'Movie':
        # Movies just need main cache update (already done above)
        log(f"ðŸ“Š Cache updated: Added movie {provider_ids.get('Imdb') or provider_ids.get('Tmdb')}")
    
    # Save updated cache to disk
    if updated:
        try:
            cache_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
            mi = local_match_index
            data = {
                'timestamp': cache_timestamp,
                'ids': list(local_id_cache),
                'episode_ids': list(episode_id_cache),
                'series_episodes': series_episode_counts,
            }
            if mi.get('built'):
                # Keep the title/ID match index (losing it broke duplicate detection after a restart)
                data['match'] = {
                    'movie_ids': list(mi['movie_ids']), 'series_ids': list(mi['series_ids']),
                    'movie_titles': {k: sorted(set(v)) for k, v in mi['movie_titles'].items()},
                    'series_titles': {k: sorted(set(v)) for k, v in mi['series_titles'].items()},
                    'episode_titles': list(mi['episode_titles']),
                }
            tmp = CACHE_FILE + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(data, f)
            os.replace(tmp, CACHE_FILE)
        except Exception as e:
            log(f"âš ï¸ Failed to save cache update: {e}")


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
    """Dynamically adjust the number of worker threads, respecting tier limits"""
    global active_workers, target_workers
    
    # Enforce tier limit
    limits = get_tier_limits()
    max_allowed = limits.get('max_concurrent_downloads', 2)
    
    with worker_lock:
        # User can't exceed their tier limit
        target_workers = max(1, min(new_count, max_allowed))
        
        while active_workers < target_workers:
            threading.Thread(target=worker, daemon=True).start()
            active_workers += 1
            log(f"Started worker (total: {active_workers})")


def adjust_transcode_workers(new_count, force=False):
    """Dynamically adjust the number of transcode worker threads"""
    global active_transcode_workers, target_transcode_workers
    
    # Only Pro users can have transcode workers (unless forced for test mode)
    if not force and not is_feature_available('transcoding'):
        log(f"âš ï¸ Transcode workers require Pro license (use test mode to bypass)")
        return
    
    with worker_lock:
        target_transcode_workers = max(0, min(new_count, 5))  # Max 5 transcode workers
        
        while active_transcode_workers < target_transcode_workers:
            active_transcode_workers += 1  # Increment BEFORE starting thread to prevent race
            threading.Thread(target=transcode_worker, daemon=True).start()
            log(f"Started transcode worker (total: {active_transcode_workers})")


# --- Per-Server Queue System (Pro Feature) ---

def get_server_queue(server_id):
    """Get or create a queue for a specific server"""
    global server_queues
    with server_worker_lock:
        if server_id not in server_queues:
            server_queues[server_id] = queue.Queue()
        return server_queues[server_id]


def ensure_server_workers(server_id, server_name=None):
    """Ensure workers exist for a specific server (Pro feature)"""
    global server_workers
    
    if not is_feature_available('arr_integration'):  # Use arr_integration as proxy for Pro
        return False
    
    cfg = load_config()
    if not cfg.get('per_server_workers', False):
        return False
    
    with server_worker_lock:
        if server_id not in server_workers or not server_workers[server_id].get('active', False):
            workers_per_server = cfg.get('per_server_worker_count', 2)
            workers_per_server = max(1, min(10, workers_per_server))  # 1-10 workers per server
            
            server_workers[server_id] = {
                'active': True,
                'count': workers_per_server,
                'name': server_name or server_id
            }
            
            # Start worker threads for this server
            for i in range(workers_per_server):
                t = threading.Thread(
                    target=server_worker,
                    args=(server_id, server_name or server_id),
                    daemon=True,
                    name=f"ServerWorker-{server_id[:8]}-{i+1}"
                )
                t.start()
            
            log(f"ðŸ“¡ Started {workers_per_server} worker(s) for server: {server_name or server_id}")
            return True
    return True


def server_worker(server_id, server_name):
    """Worker thread for a specific server's queue"""
    global pending_display, stop_after_current
    
    server_queue = get_server_queue(server_id)
    
    while True:
        # Check if server workers are still enabled
        with server_worker_lock:
            if server_id not in server_workers or not server_workers[server_id].get('active', False):
                log(f"ðŸ“¡ Server worker stopping for: {server_name}")
                return
        
        # Check global stop after current
        if stop_after_current:
            with download_lock:
                if len(active_downloads) == 0:
                    time.sleep(1)
                    continue
        
        try:
            task = server_queue.get(timeout=5)
        except queue.Empty:
            continue
        
        if task is None:
            server_queue.task_done()
            break
        
        if stop_after_current:
            server_queue.put(task)
            server_queue.task_done()
            time.sleep(1)
            continue
        
        tid = task['task_id']
        log(f"ðŸ“¡ Server worker ({server_name}) picked up task: {tid[:8]}...")
        
        with download_lock:
            pending_display = [x for x in pending_display if x['id'] != tid]
        
        if tid in cancelled_tasks:
            cancelled_tasks.discard(tid)
            server_queue.task_done()
            continue
        
        try:
            download_file(task)
        except Exception as e:
            log(f"Server Worker Error ({server_name}): {e}")
        
        server_queue.task_done()


def queue_to_server_or_global(task, server_id, server_name=None):
    """Route task to server-specific queue or global queue"""
    cfg = load_config()
    # Pro: remember queued downloads so a restart/power cut doesn't lose the queue
    if is_feature_available('transcoding') and not task.get('resume'):
        try:
            save_partial_state(task['task_id'], task, 0, 0, queued=True)
        except Exception as e:
            log(f"Could not save queue state: {e}")
    
    # Check if per-server workers are enabled (Pro feature)
    if cfg.get('per_server_workers', False) and is_feature_available('arr_integration'):
        # Ensure workers exist for this server
        ensure_server_workers(server_id, server_name)
        
        # Queue to server-specific queue
        server_queue = get_server_queue(server_id)
        server_queue.put(task)
        log(f"ðŸ“¡ Queued to server worker: {server_name or server_id}")
    else:
        # Use global queue
        task_queue.put(task)
        log(f"ðŸ“¥ Queued to global worker pool: {task.get('filepath', 'unknown')[-50:]}")


def get_per_server_status():
    """Get status of per-server workers"""
    status = {}
    with server_worker_lock:
        for server_id, info in server_workers.items():
            server_queue = server_queues.get(server_id)
            status[server_id] = {
                'name': info.get('name', server_id),
                'active': info.get('active', False),
                'workers': info.get('count', 0),
                'pending': server_queue.qsize() if server_queue else 0
            }
    return status


def stop_server_workers():
    """Stop all per-server workers"""
    global server_workers, server_queues
    with server_worker_lock:
        for server_id in list(server_workers.keys()):
            server_workers[server_id]['active'] = False
            # Send None to stop workers
            if server_id in server_queues:
                for _ in range(server_workers[server_id].get('count', 1)):
                    server_queues[server_id].put(None)
        server_workers.clear()
        log("ðŸ“¡ All per-server workers stopped")


def worker():
    """Download worker thread"""
    global active_workers, pending_display, stop_after_current, is_paused
    
    while True:
        with worker_lock:
            if active_workers > target_workers:
                active_workers -= 1
                log(f"Stopped worker (total: {active_workers})")
                return
        
        # Stop after current: once running downloads finish, pause the queue (Resume ▶️ restarts it)
        if stop_after_current:
            with download_lock:
                running = len(active_downloads)
            if running == 0:
                is_paused = True
                stop_after_current = False
                log("⏹️ Current downloads finished - queue paused (press Resume to continue)")
            time.sleep(1)
            continue
        if is_paused:
            time.sleep(1)
            continue
        
        try:
            task = task_queue.get(timeout=5)
        except queue.Empty:
            continue
        
        if task is None:
            task_queue.task_done()
            break
        
        # Check stop_after_current again after getting a task
        if stop_after_current:
            # Put task back and wait
            task_queue.put(task)
            task_queue.task_done()
            time.sleep(1)
            continue
        
        tid = task['task_id']
        log(f"ðŸ“¥ Worker picked up task: {tid[:8]}...")
        
        with download_lock:
            pending_display = [x for x in pending_display if x['id'] != tid]
        
        if tid in cancelled_tasks:
            cancelled_tasks.discard(tid)
            clear_partial_state(tid)
            task_queue.task_done()
            continue
        
        try:
            download_file(task)
        except Exception as e:
            log(f"Worker Error: {e}")
        
        task_queue.task_done()


def transcode_worker():
    """Worker thread for processing transcode queue"""
    global active_transcode_workers
    
    # Counter is incremented in adjust_transcode_workers before thread starts
    worker_id = threading.current_thread().name
    
    try:
        while not transcode_shutdown.is_set():
            # Check if we need to reduce workers
            with worker_lock:
                if active_transcode_workers > target_transcode_workers:
                    active_transcode_workers -= 1
                    log(f"Stopped transcode worker (total: {active_transcode_workers})")
                    return
            
            try:
                task = transcode_queue.get(timeout=5)
            except queue.Empty:
                continue
            
            if task is None:
                transcode_queue.task_done()
                break
            
            tid = task['task_id']
            filepath = task['filepath']
            filename = task['filename']
            preset = task['preset']
            total_size = task.get('total_size', 0)
            
            log(f"ðŸŽ¬ Transcode worker picked up task: {filename} (queue remaining: {transcode_queue.qsize()})")
            
            if tid in cancelled_tasks:
                cancelled_tasks.discard(tid)
                transcode_queue.task_done()
                log(f"â­ï¸ Skipped cancelled transcode: {filename}")
                continue
            
            try:
                log(f"ðŸŽ¬ Transcode worker processing: {filename}")
                
                # Remove from pending transcodes
                with transcode_lock:
                    pending_transcodes[:] = [x for x in pending_transcodes if x['id'] != tid]
                
                # Show transcoding status
                with transcode_lock:
                    active_transcodes[tid] = {
                        'id': tid,
                        'filename': f"ðŸ”„ {filename}",
                        'total': 100,
                        'current': 0,
                        'speed': 'Starting...',
                        'percent': 0,
                        'status': f'Transcoding ({preset})',
                        'transcode': True
                    }
                
                log(f"ðŸ“Š Active transcodes: {len(active_transcodes)}, Pending: {len(pending_transcodes)}")
                
                # Run transcode
                transcoded_path = transcode_file(filepath, task_id=tid)
                
                # Check if transcode actually produced a new file
                if transcoded_path and transcoded_path != filepath:
                    log(f"âœ… Transcode complete: {os.path.basename(transcoded_path)}")
                else:
                    log(f"âš ï¸ Transcode skipped/failed, keeping original: {filename}")
                
                with transcode_lock:
                    if tid in active_transcodes:
                        del active_transcodes[tid]
                
                # Determine final filepath and filename
                if transcoded_path and transcoded_path != filepath:
                    final_path = transcoded_path
                    final_filename = os.path.basename(transcoded_path)
                else:
                    final_path = filepath
                    final_filename = filename
                
                # Add to download history
                final_file_size = os.path.getsize(final_path) if os.path.exists(final_path) else total_size
                with download_lock:
                    download_history.appendleft({
                        'filename': final_filename,
                        'size': final_file_size,
                        'timestamp': datetime.datetime.now().isoformat(),
                        'path': final_path,
                        'transcoded': transcoded_path != filepath,
                        'server_id': task.get('server_id', 'unknown'),
                        'server_name': task.get('server_name', 'Unknown Server')
                    })
                
                # Update download statistics (use final size after transcoding)
                update_download_stats(final_file_size, task.get('server_id'), task.get('server_name'))
                
                # Save history periodically
                if len(download_history) % 5 == 0:
                    threading.Thread(target=save_download_history, daemon=True).start()
                
                # Notify *arr apps about the completed file (Pro feature)
                item_type = task.get('item_type')
                if item_type == 'episode':
                    # For episodes, use series_provider_ids for Sonarr (episode IDs are useless for Sonarr)
                    arr_provider_ids = task.get('series_provider_ids', {})
                    if not arr_provider_ids:
                        log(f"âš ï¸ [ARR] No series_provider_ids for episode - Sonarr add will be skipped")
                else:
                    # For movies, use the item's provider_ids for Radarr
                    arr_provider_ids = task.get('provider_ids', {})
                threading.Thread(target=notify_arr_download, args=(final_path, item_type, arr_provider_ids), daemon=True).start()
                
                # Update local cache incrementally (much faster than full rebuild)
                provider_ids = task.get('provider_ids', {})
                series_provider_ids = task.get('series_provider_ids', {})
                cache_item_type = 'Episode' if item_type == 'episode' else 'Movie' if item_type == 'movie' else 'Episode'
                update_cache_for_download(provider_ids, series_provider_ids, cache_item_type)
                    
            except Exception as e:
                log(f"âŒ Transcode worker error: {e}")
                with transcode_lock:
                    if tid in active_transcodes:
                        del active_transcodes[tid]

            with transcode_lock:
                if tid in _transcode_order:
                    _transcode_order.remove(tid)
            transcode_queue.task_done()
    
    except Exception as worker_error:
        log(f"âŒ Transcode worker crashed: {worker_error}")
        import traceback
        log(f"âŒ Traceback: {traceback.format_exc()[:500]}")
    
    finally:
        with worker_lock:
            active_transcode_workers -= 1
            log(f"Transcode worker stopped (total: {active_transcode_workers})")


def download_subtitles(server, item_id, video_filepath, languages=None):
    """Download external subtitles for a video file"""
    if languages is None:
        languages = ['eng']
    
    try:
        # Get item details to find available subtitles
        base_url = server['url']
        headers = get_auth_header(server['key'])
        
        # Fetch item with media streams
        response = requests.get(
            f"{base_url}/Items/{item_id}",
            headers=headers,
            params={'Fields': 'MediaStreams'},
            timeout=10
        )
        
        if not response.ok:
            return
        
        item = response.json()
        media_streams = item.get('MediaStreams', [])
        
        # Find external subtitle streams
        subtitle_streams = [
            s for s in media_streams 
            if s.get('Type') == 'Subtitle' and s.get('IsExternal', False)
        ]
        
        if not subtitle_streams:
            # No external subtitles available
            return
        
        video_base = os.path.splitext(video_filepath)[0]
        downloaded_count = 0
        
        for stream in subtitle_streams:
            stream_index = stream.get('Index')
            language = stream.get('Language', 'und')
            codec = stream.get('Codec', 'srt')
            title = stream.get('Title', '')
            
            # Check if this language is in our preferred list
            if language not in languages and 'all' not in languages:
                continue
            
            # Determine subtitle extension
            ext_map = {
                'srt': 'srt',
                'ass': 'ass',
                'ssa': 'ssa',
                'sub': 'sub',
                'vtt': 'vtt',
                'pgs': 'sup',
                'dvdsub': 'sub'
            }
            sub_ext = ext_map.get(codec.lower(), 'srt')
            
            # Build subtitle filename
            lang_suffix = f".{language}" if language != 'und' else ""
            forced_suffix = ".forced" if stream.get('IsForced') else ""
            sdh_suffix = ".sdh" if stream.get('IsSDH') or 'sdh' in title.lower() else ""
            
            sub_filename = f"{video_base}{lang_suffix}{forced_suffix}{sdh_suffix}.{sub_ext}"
            
            # Skip if subtitle file already exists
            if os.path.exists(sub_filename):
                continue
            
            # Download the subtitle
            try:
                sub_url = f"{base_url}/Videos/{item_id}/{item_id}/Subtitles/{stream_index}/Stream.{sub_ext}"
                sub_response = requests.get(sub_url, headers=headers, timeout=30)
                
                if sub_response.ok:
                    with open(sub_filename, 'wb') as f:
                        f.write(sub_response.content)
                    downloaded_count += 1
                    log(f"ðŸ“ Downloaded subtitle: {os.path.basename(sub_filename)}")
            except Exception as sub_err:
                log(f"âš  Failed to download subtitle {stream_index}: {sub_err}")
        
        if downloaded_count > 0:
            log(f"ðŸ“ Downloaded {downloaded_count} subtitle(s) for {os.path.basename(video_filepath)}")
            
    except Exception as e:
        log(f"âš  Subtitle download error: {e}")


SEGMENT_MIN_BYTES = 200 * 1024 * 1024     # only split files bigger than this
_active_order = []                         # task ids in the order they started (for worker-slot gating)


def stream_fallback_allowed():
    """Pro + the 'Download when a server blocks downloads' switch is on (default on)."""
    return is_feature_available('stream_downloads') and load_config().get('stream_fallback_enabled', True)


def _stream_url_for(task):
    """Original-quality stream URL (works when a server disallows /Download)."""
    item_id = task.get('item_id')
    server = task.get('server') or {}
    if not item_id or not server.get('url'):
        return None
    kind = 'Audio' if task.get('item_type') in ('audio', 'musicvideo_audio') else 'Videos'
    return f"{server['url'].rstrip('/')}/{kind}/{item_id}/stream?static=true"


DOWNLOAD_LOG_FILE = '/config/download_log.jsonl'   # persistent per-file history for detailed stats
recent_completed = deque(maxlen=500)   # item/series/season ids finished this session (instant ✓)


def record_completed_download(task, filepath, size, seconds):
    """Mark the item as owned right away and append it to the detailed-stats log."""
    ids = [i for i in (task.get('item_id'), task.get('series_id'), task.get('season_id')) if i]
    with download_lock:
        for i in ids:
            if i not in recent_completed:
                recent_completed.append(i)

    # Teach the duplicate matcher about it immediately (no rescan needed)
    t = (task.get('item_type') or '').lower()
    pkeys = _provider_keys(task.get('provider_ids'))
    if t == 'movie':
        local_match_index['movie_ids'] |= pkeys
        for n in (task.get('title'), task.get('original_title')):
            if normalize_title(n):
                local_match_index['movie_titles'].setdefault(normalize_title(n), []).append(task.get('year') or 0)
    elif t == 'episode':
        episode_id_cache.update(pkeys)
        spkeys = _provider_keys(task.get('series_provider_ids'))
        local_match_index['series_ids'] |= spkeys
        for k in spkeys:
            series_episode_counts[k] = series_episode_counts.get(k, 0) + 1
        sname = normalize_title(task.get('series_name'))
        if sname:
            local_match_index['series_titles'].setdefault(sname, []).append(0)
            local_match_index['episode_titles'].add(f"{sname}|{task.get('season_num')}|{task.get('episode_num')}")

    server = task.get('server') or {}
    entry = {
        'ts': datetime.datetime.now().isoformat(timespec='seconds'),
        'type': t or 'other',
        'title': task.get('title'),
        'series': task.get('series_name'),
        'season': task.get('season_num'),
        'episode': task.get('episode_num'),
        'year': task.get('year'),
        'file': os.path.basename(filepath),
        'size': int(size or (os.path.getsize(filepath) if os.path.exists(filepath) else 0)),
        'seconds': round(max(seconds, 0.001), 1),
        'server_id': server.get('id'),
        'server': server.get('name'),
    }
    entry['speed'] = int(entry['size'] / entry['seconds']) if entry['seconds'] else 0
    with open(DOWNLOAD_LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry) + '\n')


def wait_for_download_slot(tid):
    """#22: if the worker count was lowered, newer downloads pause until a slot frees up."""
    while True:
        # Kill switch holding traffic because the VPN is down -> wait instead of failing
        if vpn_blocking_downloads() and tid not in cancelled_tasks:
            with download_lock:
                if tid in active_downloads:
                    active_downloads[tid].update({'status': 'Waiting for VPN', 'speed': '0 B/s', 'speed_raw': 0})
            time.sleep(2)
            continue
        with download_lock:
            if tid not in _active_order:
                _active_order.append(tid)
            allowed = _active_order[:max(1, target_workers)]
            if tid in allowed or tid in cancelled_tasks:
                if tid in active_downloads and active_downloads[tid].get('status') == 'Waiting for a free slot':
                    active_downloads[tid]['status'] = 'Downloading'
                return
            if tid in active_downloads:
                active_downloads[tid].update({'status': 'Waiting for a free slot', 'speed': '0 B/s', 'speed_raw': 0})
        time.sleep(1)


def _release_download_slot(tid):
    with download_lock:
        if tid in _active_order:
            _active_order.remove(tid)


def _segmented_download(task, partial_file, timeout, speed_limit_kbs, connections):
    """Pro: multi-connection download into per-segment files, resumable after crashes/outages.

    Returns the total size on success, or None when the server can't do ranges / the file is small
    (caller then falls back to a single stream). Raises InterruptedError when cancelled.
    """
    tid = task['task_id']
    filename = os.path.basename(task['filepath'])
    headers = dict(task.get('headers', {}))

    probe = requests.get(task['url'], headers={**headers, 'Range': 'bytes=0-0'}, stream=True, timeout=timeout)
    if probe.status_code == 403 and '/Download' in task['url']:
        probe.close()
        alt = _stream_url_for(task) if stream_fallback_allowed() else None
        if not alt:
            return None          # single-stream path reports the "needs Pro" message
        log(f"⬇️ Server refused /Download for {filename} - using original-quality stream instead")
        task['url'] = alt
        probe = requests.get(alt, headers={**headers, 'Range': 'bytes=0-0'}, stream=True, timeout=timeout)
    content_range = probe.headers.get('Content-Range', '')
    probe.close()
    if probe.status_code != 206 or '/' not in content_range:
        return None
    try:
        total = int(content_range.split('/')[-1])
    except ValueError:
        return None
    if total < SEGMENT_MIN_BYTES:
        return None

    state_file = partial_file + '.jlseg'
    state = None
    if os.path.exists(state_file):
        try:
            with open(state_file) as f:
                state = json.load(f)
        except (OSError, ValueError):
            state = None
    if not state or state.get('total') != total:
        part = total // connections
        ranges = [[i * part, (total - 1) if i == connections - 1 else (i + 1) * part - 1] for i in range(connections)]
        state = {'total': total, 'ranges': ranges}
        for i in range(32):
            seg = f"{partial_file}.seg{i}"
            if os.path.exists(seg):
                os.remove(seg)
        with open(state_file, 'w') as f:
            json.dump(state, f)
    ranges = state['ranges']
    seg_files = [f"{partial_file}.seg{i}" for i in range(len(ranges))]
    per_conn_limit = (speed_limit_kbs * 1024 / len(ranges)) if speed_limit_kbs else 0
    errors = []

    def seg_size(i):
        return os.path.getsize(seg_files[i]) if os.path.exists(seg_files[i]) else 0

    def run_segment(i):
        start, end = ranges[i]
        expected = end - start + 1
        attempts = 0
        while True:
            have = seg_size(i)
            if have >= expected or tid in cancelled_tasks:
                return
            try:
                h = {**headers, 'Range': f'bytes={start + have}-{end}'}
                with requests.get(task['url'], headers=h, stream=True, timeout=timeout) as r:
                    if r.status_code != 206:
                        raise IOError(f"segment {i}: HTTP {r.status_code}")
                    with open(seg_files[i], 'ab') as f:
                        t0, got = time.time(), 0
                        for chunk in r.iter_content(1024 * 1024):
                            if tid in cancelled_tasks:
                                return
                            while is_paused and tid not in cancelled_tasks:
                                time.sleep(0.5)
                            if not chunk:
                                continue
                            f.write(chunk)
                            got += len(chunk)
                            if per_conn_limit:
                                ahead = got / per_conn_limit - (time.time() - t0)
                                if ahead > 0:
                                    time.sleep(ahead)
                attempts = 0
            except Exception as e:
                attempts += 1
                if attempts > 30:  # ~15+ minutes of failures for one segment
                    errors.append(f"segment {i}: {e}")
                    return
                log(f"⚠️ {filename}: connection dropped on part {i + 1} ({type(e).__name__}) - retrying")
                for _ in range(min(30, 2 * attempts)):
                    if tid in cancelled_tasks:
                        return
                    time.sleep(1)

    threads = [threading.Thread(target=run_segment, args=(i,), daemon=True) for i in range(len(ranges))]
    for t in threads:
        t.start()
    last_bytes, last_t = sum(seg_size(i) for i in range(len(ranges))), time.time()
    while any(t.is_alive() for t in threads):
        time.sleep(1)
        done = sum(seg_size(i) for i in range(len(ranges)))
        now = time.time()
        speed = max(0, (done - last_bytes) / (now - last_t)) if now > last_t else 0
        last_bytes, last_t = done, now
        with download_lock:
            if tid in active_downloads:
                active_downloads[tid].update({
                    'current': done, 'total': total, 'speed_raw': speed,
                    'speed': f"{format_bytes(speed)}/s",
                    'percent': int(done * 100 / total) if total else 0,
                    'status': 'Paused' if is_paused else f'Downloading ({len(ranges)} connections)'
                })
    if tid in cancelled_tasks:
        raise InterruptedError("Download cancelled")
    if errors:
        raise IOError('; '.join(errors))

    # Verify every part, then join them into the .partial file
    for i, (start, end) in enumerate(ranges):
        if seg_size(i) != end - start + 1:
            raise IOError(f"part {i + 1} is incomplete ({seg_size(i)} of {end - start + 1} bytes)")
    with download_lock:
        if tid in active_downloads:
            active_downloads[tid]['status'] = 'Verifying & joining'
    with open(partial_file, 'wb') as out:
        for seg in seg_files:
            with open(seg, 'rb') as src:
                shutil.copyfileobj(src, out, 8 * 1024 * 1024)
    if os.path.getsize(partial_file) != total:
        os.remove(partial_file)
        raise IOError("joined file size does not match the server - will retry")
    for seg in seg_files:
        os.remove(seg)
    os.remove(state_file)
    return total


def _verify_media_file(path):
    """Quick integrity check of a finished video with ffprobe (True if OK or not checkable)."""
    if not path.lower().endswith(('.mkv', '.mp4', '.m4v', '.avi', '.mov', '.ts', '.webm')) or not shutil.which('ffprobe'):
        return True
    try:
        r = subprocess.run(['ffprobe', '-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', path],
                           capture_output=True, text=True, timeout=120)
        return r.returncode == 0 and r.stdout.strip() not in ('', 'N/A')
    except Exception:
        return True


def download_file(task):
    """Download one file, holding a worker slot (so lowering the worker count pauses extras)."""
    tid = task['task_id']
    try:
        return _download_file(task)
    finally:
        _release_download_slot(tid)


def _download_file(task):
    """Download a single file with speed limiting, pause support, resume capability (Pro), and auto-retry"""
    global is_paused
    
    tid = task['task_id']
    filepath = task['filepath']
    filename = os.path.basename(filepath)
    partial_file = filepath + '.partial'
    is_resume = task.get('resume', False)
    
    cfg = load_config()
    speed_limit = cfg.get('speed_limit_kbs', 0)
    
    # Use resource-limited chunk size if enabled, otherwise use config setting
    resource_limits = get_resource_limits()
    if resource_limits:
        chunk_size = get_download_chunk_size()
    else:
        chunk_size = cfg.get('chunk_size_kb', 64) * 1024
    
    timeout = cfg.get('connection_timeout', 30)
    
    # Retry settings
    auto_retry = cfg.get('download_auto_retry', True)
    max_retries = cfg.get('download_retry_count', 3)
    retry_delay = cfg.get('download_retry_delay', 30)
    retry_count = task.get('_retry_count', 0)
    
    # Check Pro once per download - never inside the chunk loop
    pro_downloads = is_feature_available('transcoding')

    # Check for existing partial file (Pro resume feature)
    resume_bytes = 0
    if pro_downloads and os.path.exists(partial_file):
        resume_bytes = os.path.getsize(partial_file)
        is_resume = True
        log(f"ðŸ”„ Resuming download from {format_bytes(resume_bytes)}: {filename}")
    
    def should_retry(error):
        """Check if error is retryable"""
        retryable_errors = (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.ChunkedEncodingError,
            ConnectionResetError,
            ConnectionRefusedError,
            BrokenPipeError,
        )
        return isinstance(error, retryable_errors) or (
            isinstance(error, requests.exceptions.HTTPError) and 
            error.response is not None and 
            error.response.status_code in (502, 503, 504, 429)
        )
    
    def do_retry(error_msg):
        """Handle retry logic"""
        nonlocal retry_count
        if auto_retry and retry_count < max_retries:
            retry_count += 1
            log(f"âš ï¸ {error_msg}")
            log(f"ðŸ”„ Retrying in {retry_delay}s (attempt {retry_count}/{max_retries})...")
            
            with download_lock:
                if tid in active_downloads:
                    active_downloads[tid]['status'] = f'Retry in {retry_delay}s ({retry_count}/{max_retries})'
            
            # Wait for retry delay, checking for cancellation
            for i in range(retry_delay):
                if tid in cancelled_tasks:
                    raise InterruptedError("Cancelled during retry wait")
                time.sleep(1)
                with download_lock:
                    if tid in active_downloads:
                        active_downloads[tid]['status'] = f'Retry in {retry_delay - i - 1}s ({retry_count}/{max_retries})'
            
            # Retry the download
            task['_retry_count'] = retry_count
            return True
        return False
    
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
            status_msg = 'Resuming...' if is_resume else ('Retrying...' if retry_count > 0 else 'Starting')
            active_downloads[tid] = {
                'id': tid,
                'filename': filename,
                'total': 0,
                'current': resume_bytes,
                'speed': '0 B/s',
                'percent': 0,
                'status': status_msg
            }
        
        wait_for_download_slot(tid)
        transfer_started = time.time()
        if pro_downloads:
            save_partial_state(tid, task, resume_bytes, 0)  # now "in progress" for crash recovery

        segmented_total = None
        if pro_downloads and cfg.get('advanced_downloads', True) and resume_bytes == 0:
            try:
                connections = max(2, min(8, int(cfg.get('download_connections', 4))))
                segmented_total = _segmented_download(task, partial_file, timeout, speed_limit, connections)
            except InterruptedError:
                raise
            except Exception as seg_error:
                if do_retry(f"Multi-connection download failed for {filename}: {seg_error}"):
                    return download_file(task)
                raise
        if segmented_total is not None:
            total_size = segmented_total
        else:
            # Prepare headers with Range for resume
            headers = task.get('headers', {}).copy()
            if resume_bytes > 0:
                headers['Range'] = f'bytes={resume_bytes}-'
        
            # Connection with retry handling
            try:
                response = requests.get(task['url'], stream=True, timeout=timeout, headers=headers)
                if response.status_code == 403 and '/Download' in task['url']:
                    # The server has downloads turned off for this account
                    response.close()
                    if not is_feature_available('stream_downloads'):
                        raise PermissionError("This server has downloads turned off. JellyLooter Pro can download "
                                              "the original-quality stream instead.")
                    if not stream_fallback_allowed():
                        raise PermissionError("This server has downloads turned off. Turn on \"Download when a server "
                                              "blocks downloads\" in Settings -> Pro to use the stream instead.")
                    if not _stream_url_for(task):
                        raise PermissionError("This server has downloads turned off and no stream is available")
                    log(f"⬇️ Server refused /Download for {filename} - using original-quality stream instead (Pro)")
                    task['url'] = _stream_url_for(task)
                    response = requests.get(task['url'], stream=True, timeout=timeout, headers=headers)
                elif response.status_code == 401:
                    response.close()
                    raise PermissionError("The server rejected the saved login - edit the server in Settings and log in again")
                response.raise_for_status()
            except Exception as conn_error:
                if should_retry(conn_error) and do_retry(f"Connection failed for {filename}: {type(conn_error).__name__}"):
                    return download_file(task)
                raise
        
            # Handle resume response codes
            if response.status_code == 416:  # Range not satisfiable - file complete or changed
                log(f"âš  Cannot resume {filename} - restarting download")
                resume_bytes = 0
                if os.path.exists(partial_file):
                    os.remove(partial_file)
                # Retry without Range header
                headers.pop('Range', None)
                response = requests.get(task['url'], stream=True, timeout=timeout, headers=headers)
                response.raise_for_status()
        
            # Get total size - handle both fresh and resumed downloads
            if response.status_code == 206:  # Partial content (resume)
                content_range = response.headers.get('Content-Range', '')
                if '/' in content_range:
                    total_size = int(content_range.split('/')[-1])
                else:
                    total_size = resume_bytes + int(response.headers.get('content-length', 0))
            else:
                total_size = int(response.headers.get('content-length', 0))
                resume_bytes = 0  # Fresh download
        
            if total_size > 0 and resume_bytes == 0:
                space_ok, space_msg = check_disk_space(dir_path, total_size)
                if not space_ok:
                    raise Exception(space_msg)
        
            with download_lock:
                active_downloads[tid]['total'] = total_size
        
            downloaded = resume_bytes
            speed_window = []
            last_speed_update = time.time()
            last_config_check = time.time()
            last_partial_save = time.time()
        
            # Open file in append mode for resume, write mode for fresh
            file_mode = 'ab' if resume_bytes > 0 else 'wb'
            write_file = partial_file  # Always write to partial file first
        
            try:
                with open(write_file, file_mode) as f:
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
                                        'speed_raw': speed,  # Raw bytes/sec for ETA calc
                                        'status': 'Downloading',
                                        'percent': int((downloaded / total_size) * 100) if total_size > 0 else 0
                                    })
                            last_speed_update = now
                    
                        # Save partial state periodically (Pro feature) - every 30 seconds
                        if pro_downloads and now - last_partial_save >= 30:
                            save_partial_state(tid, task, downloaded, total_size)
                            last_partial_save = now
            except (requests.exceptions.ChunkedEncodingError, requests.exceptions.ConnectionError,
                    ConnectionResetError, BrokenPipeError) as transfer_error:
                # Connection error during transfer - try to retry
                if should_retry(transfer_error) and do_retry(f"Transfer failed for {filename}: {type(transfer_error).__name__}"):
                    return download_file(task)
                raise
            finally:
                # Close the response connection
                try:
                    response.close()
                except:
                    pass
        
        # Download complete - rename partial to final
        if os.path.exists(partial_file):
            if os.path.exists(filepath):
                os.remove(filepath)
            os.rename(partial_file, filepath)
        if pro_downloads and cfg.get('verify_downloads', True) and os.path.exists(filepath):
            with download_lock:
                if tid in active_downloads:
                    active_downloads[tid]['status'] = 'Verifying file'
            if not _verify_media_file(filepath):
                os.remove(filepath)
                if not task.get('_verify_retry'):
                    task['_verify_retry'] = True
                    log(f"⚠️ {filename} failed the integrity check - downloading it again")
                    return download_file(task)
                raise Exception('File failed the integrity check twice')
        
        # Clear partial state on successful completion
        clear_partial_state(tid)
        try:
            record_completed_download(task, filepath, total_size, time.time() - transfer_started)
        except Exception as rec_error:
            log(f"Stats record error: {rec_error}")
        if task.get('replace_local_id'):
            try:
                filepath = _replace_local_copy(task, filepath)
            except Exception as rep_error:
                log(f"⚠️ Quality upgrade: couldn't swap in the new file ({rep_error}) - your old copy is untouched")
        
        with download_lock:
            if tid in active_downloads:
                del active_downloads[tid]
        log(f"âœ“ Completed: {filename}")
        
        # Download subtitles if enabled (Free feature)
        cfg = load_config()
        if cfg.get('download_subtitles', True) and task.get('item_id') and task.get('server'):
            try:
                download_subtitles(task['server'], task['item_id'], filepath, cfg.get('subtitle_languages', ['eng']))
            except Exception as sub_error:
                log(f"âš  Subtitle download failed: {sub_error}")
        
        # Queue for transcode if enabled (Pro feature) or test mode
        test_mode = (DEV_MODE and cfg.get('_transcode_test_mode', False))
        transcode_enabled = cfg.get('transcode_enabled', False)
        has_transcode_feature = is_feature_available('transcoding')
        preset = cfg.get('transcode_preset', 'original')
        
        # Log transcode status for debugging
        log(f"ðŸŽ¬ [TRANSCODE CHECK] test_mode={test_mode}, enabled={transcode_enabled}, has_feature={has_transcode_feature}, preset={preset}")
        
        if (transcode_enabled and has_transcode_feature) or test_mode:
            if preset != 'original':
                # Ensure transcode workers are running
                num_transcode_workers = cfg.get('max_concurrent_transcodes', 1)
                if active_transcode_workers < num_transcode_workers:
                    log(f"ðŸ”§ Starting transcode workers (have: {active_transcode_workers}, need: {num_transcode_workers})")
                    adjust_transcode_workers(num_transcode_workers, force=test_mode)
                elif active_transcode_workers == 0:
                    log(f"âš ï¸ No transcode workers running, forcing restart")
                    adjust_transcode_workers(num_transcode_workers, force=test_mode)
                
                # Wait if transcode queue is full (max 10 pending)
                max_pending_transcodes = 10
                while transcode_queue.qsize() >= max_pending_transcodes:
                    log(f"â³ Transcode queue full ({max_pending_transcodes}), waiting...")
                    time.sleep(5)
                    # Check for cancellation while waiting
                    if tid in cancelled_tasks:
                        log(f"â­ï¸ Cancelled while waiting for transcode queue: {filename}")
                        return
                
                log(f"ðŸŽ¬ Queuing for transcode: {filename} (queue: {transcode_queue.qsize() + 1})")
                # Add to transcode queue instead of processing inline
                transcode_task = {
                    'task_id': tid,
                    'filepath': filepath,
                    'filename': filename,
                    'preset': preset,
                    'total_size': total_size,
                    'item_type': task.get('item_type'),
                    'provider_ids': task.get('provider_ids', {}),
                    'series_provider_ids': task.get('series_provider_ids', {}),
                    'server_id': task.get('server', {}).get('id', 'unknown'),
                    'server_name': task.get('server', {}).get('name', 'Unknown Server')
                }
                transcode_queue.put(transcode_task)
                
                # Add to pending transcode display
                with transcode_lock:
                    pending_transcodes.append({
                        'id': tid,
                        'name': filename,
                        'preset': preset
                    })
                
                # Don't add to history yet - transcode worker will do it
                # Send notification if enabled (Pro feature)
                send_notification(f"âœ“ Download Complete: {filename} (queued for transcode)", "download_complete")
                return  # Exit here, transcode worker will handle the rest
            else:
                log(f"â„¹ï¸ [TRANSCODE] Skipping - preset is 'original'")
        else:
            if not test_mode and not transcode_enabled:
                log(f"â„¹ï¸ [TRANSCODE] Skipping - transcoding not enabled (enable in settings or use test mode)")
            elif not has_transcode_feature:
                log(f"â„¹ï¸ [TRANSCODE] Skipping - Pro feature not available")
        
        # Add to download history (only if not transcoding)
        final_size = os.path.getsize(filepath) if os.path.exists(filepath) else total_size
        with download_lock:
            download_history.appendleft({
                'filename': filename,
                'size': final_size,
                'timestamp': datetime.datetime.now().isoformat(),
                'path': filepath,
                'server_id': task.get('server', {}).get('id', 'unknown'),
                'server_name': task.get('server', {}).get('name', 'Unknown Server')
            })
        
        # Update download statistics
        server_info = task.get('server', {})
        update_download_stats(final_size, server_info.get('id'), server_info.get('name'))
        
        # Save history periodically (every 5 downloads)
        if len(download_history) % 5 == 0:
            threading.Thread(target=save_download_history, daemon=True).start()
        
        # Notify *arr apps about the download (Pro feature)
        item_type = task.get('item_type', None)
        # Use series provider IDs for episodes, otherwise item provider IDs
        if item_type == 'episode':
            # For episodes, use series_provider_ids for Sonarr (episode IDs are useless for Sonarr)
            arr_provider_ids = task.get('series_provider_ids', {})
            if not arr_provider_ids:
                log(f"âš ï¸ [ARR] No series_provider_ids for episode - Sonarr add will be skipped")
        else:
            # For movies, use the item's provider_ids for Radarr
            arr_provider_ids = task.get('provider_ids', {})
        threading.Thread(target=notify_arr_download, args=(filepath, item_type, arr_provider_ids), daemon=True).start()
        
        # Update local cache incrementally (much faster than full rebuild)
        provider_ids = task.get('provider_ids', {})
        series_provider_ids = task.get('series_provider_ids', {})
        cache_item_type = 'Episode' if item_type == 'episode' else 'Movie' if item_type == 'movie' else 'Episode'
        update_cache_for_download(provider_ids, series_provider_ids, cache_item_type)
        
        # Send notification if enabled (Pro feature)
        send_notification(f"âœ“ Download Complete: {filename}", "download_complete")
        
    except InterruptedError:
        log(f"âœ— Cancelled: {filename}")
        # Save partial state for Pro users to resume later
        if is_feature_available('transcoding') and 'downloaded' in dir() and 'total_size' in dir():
            save_partial_state(tid, task, downloaded, total_size)
            log(f"ðŸ’¾ Partial download saved for resume: {filename}")
        _cleanup_download(tid, filepath, keep_partial=is_feature_available('transcoding'))
        
    except Exception as e:
        log(f"âœ— Failed {filename}: {e}")
        # Save partial state for Pro users to resume later
        if is_feature_available('transcoding'):
            try:
                partial_file = filepath + '.partial'
                if os.path.exists(partial_file + '.jlseg'):
                    save_partial_state(tid, task, sum(os.path.getsize(s) for s in glob.glob(partial_file + '.seg*')), 0)
                elif os.path.exists(partial_file):
                    downloaded = os.path.getsize(partial_file)
                    total_size = task.get('total_size', 0)
                    save_partial_state(tid, task, downloaded, total_size)
                    log(f"ðŸ’¾ Partial download saved for resume: {filename}")
            except:
                pass
        _cleanup_download(tid, filepath, keep_partial=is_feature_available('transcoding'))
        # Send error notification if enabled
        send_notification(f"âœ— Download Failed: {filename} - {e}", "download_error")


def _cleanup_download(tid, filepath, keep_partial=False):
    """Clean up after failed/cancelled download"""
    with download_lock:
        if tid in active_downloads:
            del active_downloads[tid]
    cancelled_tasks.discard(tid)
    
    # Only delete actual file, not partial (so Pro users can resume)
    if os.path.exists(filepath):
        try:
            os.remove(filepath)
        except Exception:
            pass
    
    # Delete partial file unless keeping for resume
    if not keep_partial:
        partial_file = filepath + '.partial'
        for leftover in [partial_file, partial_file + '.jlseg'] + glob.glob(partial_file + '.seg*'):
            try:
                os.remove(leftover)
            except OSError:
                pass
        clear_partial_state(tid)


def send_notification(message, event_type="info"):
    """Send notification via Apprise (Pro feature)"""
    if not is_feature_available('notifications'):
        return
    
    if not APPRISE_AVAILABLE:
        return
    
    cfg = load_config()
    
    # Check notification preferences
    if event_type == "download_complete" and not cfg.get('notify_on_complete', True):
        return
    if event_type == "download_error" and not cfg.get('notify_on_error', True):
        return
    
    notification_urls = cfg.get('notification_urls', [])
    if not notification_urls:
        return
    
    try:
        apobj = apprise.Apprise()
        for url in notification_urls:
            apobj.add(url)
        
        apobj.notify(
            title="JellyLooter",
            body=message,
            notify_type=apprise.NotifyType.SUCCESS if "Complete" in message else apprise.NotifyType.FAILURE
        )
    except Exception as e:
        log(f"Notification error: {e}")


def get_video_duration(filepath):
    """Get video duration in seconds using ffprobe"""
    try:
        result = subprocess.run(
            ['ffprobe', '-v', 'error', '-show_entries', 'format=duration', '-of', 'default=noprint_wrappers=1:nokey=1', filepath],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            return float(result.stdout.strip())
    except:
        pass
    return 0


def get_resource_limits():
    """Get resource limit settings from config"""
    cfg = load_config()
    if not cfg.get('resource_limits_enabled', False):
        return None
    
    return {
        'cpu_threads': cfg.get('cpu_limit_threads', 0),  # 0 = auto
        'cpu_priority': cfg.get('cpu_priority', 'normal'),  # low, normal, high
        'io_priority': cfg.get('io_priority', 'normal'),  # idle, low, normal
        'memory_buffer_mb': cfg.get('memory_buffer_mb', 64),  # 8-256 MB
        'transcode_memory_mb': cfg.get('transcode_memory_limit_mb', 0),  # 0 = unlimited
    }


def build_process_prefix():
    """Build nice/ionice prefix for subprocess commands"""
    limits = get_resource_limits()
    if not limits:
        return []
    
    prefix = []
    
    # CPU priority using nice (-20 to 19, higher = lower priority)
    nice_values = {
        'low': 15,      # Low priority
        'normal': 0,    # Normal priority  
        'high': -10     # Higher priority (may need root)
    }
    nice_val = nice_values.get(limits['cpu_priority'], 0)
    if nice_val != 0:
        prefix.extend(['nice', '-n', str(nice_val)])
    
    # I/O priority using ionice (class 3=idle, 2=best-effort, 1=realtime)
    # For best-effort, level 0-7 (lower = higher priority)
    io_settings = {
        'idle': ['-c', '3'],           # Idle - only when system idle
        'low': ['-c', '2', '-n', '7'], # Best-effort, lowest priority
        'normal': []                    # Don't set - use system default
    }
    io_args = io_settings.get(limits['io_priority'], [])
    if io_args:
        # ionice needs to wrap the command
        if prefix:
            # nice already set, ionice wraps nice
            prefix = ['ionice'] + io_args + prefix
        else:
            prefix = ['ionice'] + io_args
    
    return prefix


def get_ffmpeg_thread_args():
    """Get FFmpeg thread limiting arguments"""
    limits = get_resource_limits()
    if not limits or limits['cpu_threads'] == 0:
        return []
    
    threads = max(1, min(32, limits['cpu_threads']))
    return ['-threads', str(threads)]


def get_download_chunk_size():
    """Get download chunk size based on memory buffer setting"""
    limits = get_resource_limits()
    if not limits:
        return 64 * 1024  # Default 64KB chunks
    
    # Memory buffer in MB, convert to reasonable chunk size
    # Larger buffer = larger chunks = faster but more RAM
    buffer_mb = max(8, min(256, limits['memory_buffer_mb']))
    
    # Use buffer_mb as the read buffer, chunk size is 1/4 of that
    chunk_kb = buffer_mb * 256  # So 64MB buffer = 16KB chunks, scaled up
    return max(8 * 1024, min(1024 * 1024, chunk_kb * 1024))  # 8KB to 1MB


def transcode_file(filepath, force_software=False, task_id=None):
    """Transcode file using FFmpeg (Pro feature)"""
    cfg = load_config()
    
    # Check if test mode OR production transcoding is enabled
    test_mode = (DEV_MODE and cfg.get('_transcode_test_mode', False))
    transcode_enabled = cfg.get('transcode_enabled', False)
    has_pro = is_feature_available('transcoding')
    
    # Allow transcoding if: test_mode OR (Pro + enabled)
    if not test_mode and not (transcode_enabled and has_pro):
        return filepath
    
    mode_label = "TEST MODE" if test_mode else "PRO"
    log(f"ðŸŽ¬ [TRANSCODE {mode_label}] Processing: {os.path.basename(filepath)}")
    
    preset = cfg.get('transcode_preset', 'original')
    if preset == 'original':
        log(f"â„¹ï¸ [TRANSCODE] Preset is 'original' - skipping transcode")
        return filepath
    
    # Check if file is a video
    video_extensions = ['.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm', '.m4v']
    ext = os.path.splitext(filepath)[1].lower()
    if ext not in video_extensions:
        log(f"â„¹ï¸ [TRANSCODE] Not a video file ({ext}) - skipping")
        return filepath
    
    # Get video duration for progress tracking
    duration = get_video_duration(filepath)
    if duration > 0:
        log(f"ðŸ“Š [TRANSCODE] Video duration: {duration:.1f}s ({duration/60:.1f} min)")
    
    # Build FFmpeg command based on preset and encoder
    base_name = os.path.splitext(filepath)[0]
    filename_only = os.path.basename(base_name)
    encoder = 'software' if force_software else cfg.get('transcode_encoder', 'software')
    
    # Determine output extension based on preset
    if preset == 'avi':
        output_ext = '.avi'
    elif 'h265' in preset or 'hevc' in preset:
        output_ext = '.mkv'
    else:
        output_ext = '.mp4'
    
    # Determine output path - use cache drive if enabled
    use_cache = cfg.get('transcode_cache_enabled', False)
    cache_path = cfg.get('transcode_cache_path', '/tmp/transcode_cache')
    final_output_path = f"{base_name}_transcoded{output_ext}"
    
    if use_cache and cache_path:
        # Ensure cache directory exists
        try:
            os.makedirs(cache_path, exist_ok=True)
            # Test write permission
            test_file = os.path.join(cache_path, '.write_test')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            
            # Use cache path for transcoding
            output_path = os.path.join(cache_path, f"{filename_only}_transcoded{output_ext}")
            log(f"ðŸ“ [TRANSCODE] Using cache drive: {cache_path}")
        except Exception as cache_error:
            log(f"âš ï¸ [TRANSCODE] Cache drive not accessible ({cache_error}), using source directory")
            output_path = final_output_path
            use_cache = False
    else:
        output_path = final_output_path
    
    log(f"ðŸŽ¬ [TRANSCODE] Settings: preset={preset}, encoder={encoder}, output={output_ext}")
    
    # Encoder mappings
    h264_encoders = {
        'software': 'libx264',
        'nvenc': 'h264_nvenc',
        'qsv': 'h264_qsv',
        'vaapi': 'h264_vaapi'
    }
    h265_encoders = {
        'software': 'libx265',
        'nvenc': 'hevc_nvenc',
        'qsv': 'hevc_qsv',
        'vaapi': 'hevc_vaapi'
    }
    
    try:
        # Check if ffmpeg is available
        ffmpeg_check = subprocess.run(['ffmpeg', '-version'], capture_output=True, text=True, timeout=10)
        if ffmpeg_check.returncode != 0:
            log(f"âŒ [TRANSCODE] FFmpeg check failed: {ffmpeg_check.stderr[:200]}")
            return filepath
        log(f"âœ… [TRANSCODE] FFmpeg found: {ffmpeg_check.stdout.split(chr(10))[0][:80]}")
        
        # Check available encoders
        encoder_check = subprocess.run(['ffmpeg', '-encoders'], capture_output=True, text=True, timeout=10)
        available_encoders = encoder_check.stdout if encoder_check.returncode == 0 else ''
        
        # Log which hardware encoders are available
        hw_encoders_available = []
        for enc in ['hevc_nvenc', 'h264_nvenc', 'hevc_qsv', 'h264_qsv', 'hevc_vaapi', 'h264_vaapi']:
            if enc in available_encoders:
                hw_encoders_available.append(enc)
        if hw_encoders_available:
            log(f"âœ… [TRANSCODE] Hardware encoders available: {', '.join(hw_encoders_available)}")
        else:
            log(f"âš ï¸ [TRANSCODE] No hardware encoders found, will use software encoding")
        
        # AVI preset uses mpeg4 codec (software only, no hardware acceleration)
        if preset == 'avi':
            target_encoder = 'mpeg4'
            log(f"ðŸŽ¬ [TRANSCODE] AVI preset uses mpeg4 codec (software)")
        # Determine target encoder based on preset
        elif preset in ['h265', '4k']:
            target_encoder = h265_encoders.get(encoder, 'libx265')
        else:
            target_encoder = h264_encoders.get(encoder, 'libx264')
        
        # Check if hardware encoder is available, fall back to software if not (skip for AVI)
        if preset != 'avi' and encoder != 'software' and target_encoder not in available_encoders:
            log(f"âš ï¸ [TRANSCODE] {target_encoder} not available in this FFmpeg build")
            log(f"âš ï¸ [TRANSCODE] Falling back to software encoding")
            encoder = 'software'
            if preset in ['h265', '4k']:
                target_encoder = 'libx265'
            else:
                target_encoder = 'libx264'
        
        # Verify software encoder availability as final check (skip for AVI)
        if preset != 'avi' and encoder == 'software':
            if 'libx265' in target_encoder and 'libx265' not in available_encoders:
                log(f"âš ï¸ [TRANSCODE] libx265 not available, trying libx264 instead")
                target_encoder = 'libx264'
                preset = 'h264' if preset == 'h265' else preset
            if 'libx264' in target_encoder and 'libx264' not in available_encoders:
                log(f"âŒ [TRANSCODE] No compatible encoders available (libx264/libx265)")
                return filepath
        
        # Base ffmpeg args - use warning level for more visibility
        base_args = ['ffmpeg', '-hide_banner', '-loglevel', 'warning', '-stats']
        
        # Add thread limit if resource limits are enabled
        thread_args = get_ffmpeg_thread_args()
        if thread_args:
            base_args.extend(thread_args)
            log(f"ðŸ”§ [TRANSCODE] Thread limit: {thread_args[1]} threads")
        
        base_args.extend(['-i', filepath])
        
        # Use the target_encoder we already validated
        video_codec = target_encoder
        log(f"ðŸŽ¬ [TRANSCODE] Using codec: {video_codec}")
        
        if preset == 'h265':
            # H.265/HEVC encoding for smaller files
            if encoder == 'software':
                cmd = base_args + [
                    '-c:v', video_codec, '-crf', '28', '-preset', 'medium',
                    '-c:a', 'aac', '-b:a', '128k',
                    '-y', output_path
                ]
            else:
                # GPU encoders use different quality settings
                cmd = base_args + [
                    '-c:v', video_codec, '-preset', 'slow', '-b:v', '4M',
                    '-c:a', 'aac', '-b:a', '128k',
                    '-y', output_path
                ]
        elif preset == 'h264':
            # H.264 encoding
            if encoder == 'software':
                cmd = base_args + [
                    '-c:v', video_codec, '-crf', '23', '-preset', 'medium',
                    '-c:a', 'aac', '-b:a', '128k',
                    '-y', output_path
                ]
            else:
                cmd = base_args + [
                    '-c:v', video_codec, '-preset', 'slow', '-b:v', '6M',
                    '-c:a', 'aac', '-b:a', '128k',
                    '-y', output_path
                ]
        elif preset == 'avi':
            # AVI container with MPEG-4/DivX compatible encoding
            # Uses mpeg4 codec for broad compatibility with legacy devices
            cmd = base_args + [
                '-c:v', 'mpeg4', '-q:v', '4',  # Quality scale 1-31, lower is better
                '-c:a', 'mp3', '-b:a', '192k',
                '-y', output_path
            ]
            log(f"ðŸŽ¬ [TRANSCODE] Using AVI preset (mpeg4 + mp3)")
        elif preset == 'mobile':
            # Mobile-friendly (720p, lower bitrate) - mobile uses h264
            cmd = base_args + [
                '-c:v', video_codec, '-crf', '23', '-preset', 'fast',
                '-vf', 'scale=-2:720',
                '-c:a', 'aac', '-b:a', '128k',
                '-y', output_path
            ]
        elif preset == '4k':
            # 4K optimized
            cmd = base_args + [
                '-c:v', video_codec, '-crf', '22', '-preset', 'slow',
                '-c:a', 'aac', '-b:a', '192k',
                '-y', output_path
            ]
        elif preset == 'custom':
            # Custom FFmpeg arguments with sanitization
            custom_args = cfg.get('transcode_custom_args', '')
            if not custom_args:
                log(f"âŒ [TRANSCODE] Custom preset selected but no custom args provided")
                return filepath
            log(f"ðŸŽ¬ [TRANSCODE] Using custom args: {custom_args[:100]}...")
            # Sanitize: remove dangerous characters and limit arg length
            # Only allow alphanumeric, spaces, hyphens, colons, periods, equals
            import re
            sanitized = re.sub(r'[^a-zA-Z0-9\s\-\.:=]', '', custom_args)
            if len(sanitized) > 500:  # Limit total length
                log("âš ï¸ [TRANSCODE] Custom transcode args too long, truncating to 500 chars")
                sanitized = sanitized[:500]
            # Block dangerous ffmpeg options
            dangerous = ['-filter_complex', 'concat', 'file:', 'http:', 'https:', 'ftp:', 
                        'pipe:', 'tcp:', 'udp:', '-f', 'lavfi', 'movie=', 'amovie=']
            for d in dangerous:
                if d.lower() in sanitized.lower():
                    log(f"âŒ [TRANSCODE] Blocked dangerous ffmpeg arg: {d}")
                    return filepath
            cmd = base_args + sanitized.split() + ['-y', output_path]
        else:
            log(f"âŒ [TRANSCODE] Unknown preset: {preset}")
            return filepath
        
        original_name = os.path.basename(filepath)
        original_size = os.path.getsize(filepath)
        log(f"ðŸ”„ [TRANSCODE] Starting: {original_name} ({format_bytes(original_size)})")
        log(f"ðŸ”„ [TRANSCODE] Full command: {' '.join(cmd)}")
        
        start_time = time.time()
        log(f"ðŸ”„ [TRANSCODE] Executing FFmpeg... (this may take a while for large files)")
        
        # Use Popen for real-time progress tracking
        process = None
        cancelled = False
        last_stderr = ""
        stderr_lines = []
        stderr_thread = None
        
        def drain_stderr(proc, lines_list):
            """Drain stderr in background to prevent buffer blocking"""
            try:
                for line in proc.stderr:
                    lines_list.append(line)
            except:
                pass
        
        try:
            # Add -progress pipe:1 for machine-readable progress
            # Add -nostdin to prevent ffmpeg from waiting for input
            cmd_with_progress = cmd[:-2] + ['-nostdin', '-progress', 'pipe:1'] + cmd[-2:]  # Insert before -y output
            
            # Apply resource limits (nice/ionice prefix)
            process_prefix = build_process_prefix()
            if process_prefix:
                cmd_with_progress = process_prefix + cmd_with_progress
                log(f"ðŸ”§ [TRANSCODE] Process priority: {' '.join(process_prefix)}")
            
            process = subprocess.Popen(
                cmd_with_progress,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,  # Explicitly close stdin
                text=True,
                bufsize=1
            )
            
            # Start stderr drain thread to prevent blocking
            stderr_thread = threading.Thread(target=drain_stderr, args=(process, stderr_lines), daemon=True)
            stderr_thread.start()
            
            current_time_secs = 0
            last_cancel_check = time.time()
            last_heartbeat = time.time()
            last_progress_update = time.time()  # Track when progress last changed
            last_progress_percent = 0
            stall_warning_given = False
            
            # Make stdout non-blocking for better cancellation support
            try:
                fl = fcntl.fcntl(process.stdout.fileno(), fcntl.F_GETFL)
                fcntl.fcntl(process.stdout.fileno(), fcntl.F_SETFL, fl | os.O_NONBLOCK)
                nonblocking = True
            except:
                nonblocking = False
                log(f"âš ï¸ [TRANSCODE] Non-blocking mode not available, cancellation may be delayed")
            
            # Read progress from stdout
            if task_id:
                with transcode_lock:
                    if task_id not in _transcode_order:
                        _transcode_order.append(task_id)
            suspended = False
            while True:
                now = time.time()

                # Check for cancellation every 0.5 seconds
                if task_id and (now - last_cancel_check) > 0.5:
                    last_cancel_check = now
                    # #22: fewer transcode workers -> freeze the newest ffmpeg until a slot frees up
                    with transcode_lock:
                        allowed = task_id in _transcode_order[:max(1, target_transcode_workers)]
                    if not allowed and not suspended and task_id not in cancelled_tasks:
                        process.send_signal(signal.SIGSTOP)
                        suspended = True
                        log(f"⏸️ [TRANSCODE] Paused (worker count lowered) - will continue when a slot frees")
                        with transcode_lock:
                            if task_id in active_transcodes:
                                active_transcodes[task_id]['status'] = 'Waiting for a free slot'
                    elif (allowed or task_id in cancelled_tasks) and suspended:
                        process.send_signal(signal.SIGCONT)
                        suspended = False
                        log(f"▶️ [TRANSCODE] Continuing")
                    if suspended:
                        last_progress_update = now  # don't count frozen time as a stall
                        time.sleep(0.5)
                        continue
                    if task_id in cancelled_tasks:
                        log(f"âš ï¸ [TRANSCODE] Cancellation requested, stopping FFmpeg...")
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except:
                            process.kill()
                        cancelled = True
                        break
                
                # Stall detection - if no progress for 2 minutes, kill and fail
                time_since_progress = now - last_progress_update
                if time_since_progress > 120 and not stall_warning_given:
                    stall_warning_given = True
                    log(f"âš ï¸ [TRANSCODE] WARNING: No progress for 2 minutes, may be stuck at {last_progress_percent}%")
                
                if time_since_progress > 300:  # 5 minutes with no progress
                    log(f"âŒ [TRANSCODE] STALLED: No progress for 5 minutes, killing ffmpeg")
                    process.kill()
                    break
                
                # Heartbeat log every 30 seconds
                if (now - last_heartbeat) > 30:
                    last_heartbeat = now
                    percent = last_progress_percent
                    stall_time = int(time_since_progress)
                    if stall_time > 30:
                        log(f"ðŸ’“ [TRANSCODE] Running: {os.path.basename(filepath)} ({percent}%) - no progress for {stall_time}s")
                    else:
                        log(f"ðŸ’“ [TRANSCODE] Running: {os.path.basename(filepath)} ({percent}%)")
                
                # Check if process finished
                if process.poll() is not None:
                    break
                
                # Try to read a line (non-blocking if available)
                try:
                    if nonblocking:
                        try:
                            line = process.stdout.readline()
                        except (IOError, BlockingIOError):
                            # No data available, wait a bit
                            time.sleep(0.1)
                            continue
                    else:
                        # Blocking read with select timeout
                        ready, _, _ = select.select([process.stdout], [], [], 0.5)
                        if not ready:
                            continue
                        line = process.stdout.readline()
                    
                    if not line:
                        if process.poll() is not None:
                            break
                        time.sleep(0.1)
                        continue
                    
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Parse progress output
                    if line.startswith('out_time_ms='):
                        try:
                            time_us = int(line.split('=')[1])
                            current_time_secs = time_us / 1000000
                            
                            if duration > 0 and task_id:
                                percent = min(99, int((current_time_secs / duration) * 100))
                                elapsed = time.time() - start_time
                                speed = f"{current_time_secs/elapsed:.1f}x" if elapsed > 0 else "..."
                                
                                # Track progress changes for stall detection
                                if percent > last_progress_percent:
                                    last_progress_update = time.time()
                                    last_progress_percent = percent
                                    stall_warning_given = False  # Reset warning
                                
                                with transcode_lock:
                                    if task_id in active_transcodes:
                                        active_transcodes[task_id].update({
                                            'percent': percent,
                                            'current': int(current_time_secs),
                                            'total': int(duration),
                                            'speed': speed
                                        })
                        except:
                            pass
                    elif line.startswith('progress='):
                        if line == 'progress=end':
                            break
                except Exception as read_error:
                    # Log but don't crash on read errors
                    if process.poll() is not None:
                        break
                    time.sleep(0.1)
            
            # Get any remaining stderr from the drain thread
            if stderr_thread:
                stderr_thread.join(timeout=2)  # Wait for thread to finish
            
            # IMPORTANT: Wait for process to actually finish and get real return code
            if process.poll() is None:
                # Process still running, wait for it to finish
                try:
                    return_code = process.wait(timeout=30)  # Wait up to 30 seconds for finalization
                except subprocess.TimeoutExpired:
                    log(f"âš ï¸ [TRANSCODE] Process didn't finish in time, killing...")
                    process.kill()
                    return_code = process.wait()
            else:
                return_code = process.returncode
            
            last_stderr = ''.join(stderr_lines)
            
        except Exception as run_error:
            log(f"âŒ [TRANSCODE] subprocess failed: {type(run_error).__name__}: {run_error}")
            if process:
                try:
                    process.kill()
                except:
                    pass
            if stderr_thread:
                stderr_thread.join(timeout=1)
            return filepath
        
        elapsed = time.time() - start_time
        
        # Handle cancellation
        if cancelled:
            log(f"âŒ [TRANSCODE] Cancelled by user after {elapsed:.1f}s")
            if os.path.exists(output_path):
                os.remove(output_path)
            cancelled_tasks.discard(task_id)
            return filepath
        
        log(f"ðŸ”„ [TRANSCODE] FFmpeg finished in {elapsed:.1f}s with return code {return_code}")
        
        # Log any stderr output (filtered to exclude progress lines)
        if last_stderr:
            stderr_errors = [line for line in last_stderr.split('\n') 
                           if line.strip() and not line.strip().startswith('frame=')]
            if stderr_errors:
                log(f"ðŸ“‹ [TRANSCODE] FFmpeg stderr: {' | '.join(stderr_errors)[:500]}")
        
        # Special handling for return_code None (process killed or crashed)
        if return_code is None:
            log(f"âš ï¸ [TRANSCODE] Process exited abnormally (return code None)")
            
            # Check if output file exists and is valid (sometimes ffmpeg writes good output before crash)
            if os.path.exists(output_path):
                output_size = os.path.getsize(output_path)
                # If output is > 90% of expected size based on bitrate, it might be usable
                expected_min = original_size * 0.1  # At least 10% of original (for heavy compression)
                if output_size > expected_min:
                    # Try to validate the file with ffprobe
                    try:
                        probe_result = subprocess.run(
                            ['ffprobe', '-v', 'error', '-show_entries', 'format=duration', output_path],
                            capture_output=True, text=True, timeout=30
                        )
                        if probe_result.returncode == 0 and 'duration' in probe_result.stdout:
                            log(f"âœ… [TRANSCODE] Output file appears valid despite abnormal exit ({format_bytes(output_size)})")
                            return_code = 0  # Treat as success
                        else:
                            log(f"âš ï¸ [TRANSCODE] Output file validation failed: {probe_result.stderr[:200]}")
                    except Exception as probe_error:
                        log(f"âš ï¸ [TRANSCODE] Cannot validate output file: {probe_error}")
                else:
                    log(f"âš ï¸ [TRANSCODE] Output file too small ({format_bytes(output_size)})")
        
        if return_code == 0 and os.path.exists(output_path):
            new_size = os.path.getsize(output_path)
            savings = ((original_size - new_size) / original_size) * 100 if original_size > 0 else 0
            
            # Check if transcoded file is larger than original
            skip_larger = cfg.get('transcode_skip_larger', True)
            if new_size >= original_size and skip_larger:
                # Keep original, delete transcoded
                os.remove(output_path)
                log(f"âš ï¸ [TRANSCODE] Skipped: transcoded file larger ({format_bytes(new_size)} vs {format_bytes(original_size)})")
                log(f"âš ï¸ [TRANSCODE] Keeping original file: {os.path.basename(filepath)}")
                update_transcode_stats(original_size, new_size, kept_original=True)
                return filepath
            
            # If using cache, move file to final destination
            actual_final_path = output_path
            if use_cache and output_path != final_output_path:
                try:
                    log(f"ðŸ“¦ [TRANSCODE] Moving from cache to final destination...")
                    # Use shutil.move for cross-filesystem moves
                    import shutil
                    shutil.move(output_path, final_output_path)
                    actual_final_path = final_output_path
                    log(f"âœ… [TRANSCODE] Moved to: {final_output_path}")
                except Exception as move_error:
                    log(f"âŒ [TRANSCODE] Failed to move from cache: {move_error}")
                    # Try copy + delete as fallback
                    try:
                        shutil.copy2(output_path, final_output_path)
                        os.remove(output_path)
                        actual_final_path = final_output_path
                        log(f"âœ… [TRANSCODE] Copied to: {final_output_path}")
                    except Exception as copy_error:
                        log(f"âŒ [TRANSCODE] Copy also failed: {copy_error}")
                        log(f"âš ï¸ [TRANSCODE] Leaving file in cache: {output_path}")
                        actual_final_path = output_path
            
            # Remove original, keep transcoded
            os.remove(filepath)
            log(f"âœ… [TRANSCODE] Success: {os.path.basename(actual_final_path)}")
            log(f"âœ… [TRANSCODE] Size: {format_bytes(original_size)} â†’ {format_bytes(new_size)} (saved {savings:.1f}%)")
            log(f"âœ… [TRANSCODE] Time: {elapsed:.1f}s ({format_bytes(original_size/elapsed)}/s)")
            
            # Update stats
            update_transcode_stats(original_size, new_size, kept_original=False)
            
            return actual_final_path
        else:
            # Filter out FFmpeg progress lines from error output
            error_lines = [line for line in last_stderr.split('\n') 
                          if line.strip() and not line.strip().startswith('frame=')]
            error_msg = '\n'.join(error_lines) if error_lines else 'No error details (only progress output)'
            
            log(f"âŒ [TRANSCODE] Failed after {elapsed:.1f}s")
            log(f"âŒ [TRANSCODE] Return code: {return_code}")
            if error_lines:
                log(f"âŒ [TRANSCODE] Error: {error_msg[:500]}")
            
            # Check for hardware encoder errors and fallback to software
            hw_error_indicators = ['nvenc', 'qsv', 'vaapi', 'libnvidia', 'cuda', 'driver', 'gpu', 'hwaccel', 
                                   'cannot load', 'not found', 'no capable', 'initialization failed',
                                   'could not open', 'unknown encoder']
            if not force_software and encoder != 'software':
                if any(ind in error_msg.lower() for ind in hw_error_indicators):
                    log(f"âš ï¸ [TRANSCODE] Hardware encoder ({encoder}) failed, retrying with software encoding...")
                    if os.path.exists(output_path):
                        os.remove(output_path)
                    return transcode_file(filepath, force_software=True, task_id=task_id)
            
            if os.path.exists(output_path):
                os.remove(output_path)
                log(f"ðŸ—‘ï¸ [TRANSCODE] Cleaned up partial output file")
            return filepath
            
    except subprocess.TimeoutExpired:
        log(f"âŒ [TRANSCODE] Timeout (2 hours exceeded): {os.path.basename(filepath)}")
        if os.path.exists(output_path):
            os.remove(output_path)
        return filepath
    except FileNotFoundError:
        log("âŒ [TRANSCODE] FFmpeg not found - is it installed in the container?")
        log("âŒ [TRANSCODE] Install with: apt-get update && apt-get install -y ffmpeg")
        return filepath
    except Exception as e:
        log(f"âŒ [TRANSCODE] Unexpected error: {type(e).__name__}: {e}")
        import traceback
        log(f"âŒ [TRANSCODE] Traceback: {traceback.format_exc()[:500]}")
        return filepath


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
                # Try to get server name
                server_name = data.get("ServerId", "")
                if not server_name:
                    try:
                        info_resp = requests.get(f"{url}/System/Info/Public", timeout=5)
                        if info_resp.ok:
                            server_name = info_resp.json().get('ServerName', '')
                    except:
                        pass
                return {"token": token, "user_id": user_id, "server_name": server_name}
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

@app.route('/favicon.ico')
@app.route('/favicon.png')
@app.route('/favicon.svg')  # legacy path from older templates/bookmarks
def serve_favicon():
    """Serve the app icon (same artwork as the header logo) as the favicon"""
    return send_from_directory(app.static_folder, 'favicon-32.png', mimetype='image/png')


# --- Flask Routes: Health Check (No Auth Required) ---

@app.route('/health')
@app.route('/api/health')
def health_check():
    """
    Health check endpoint for Docker/Unraid/monitoring systems.
    No authentication required.
    Returns 200 if healthy, 503 if unhealthy.
    """
    try:
        config = load_config()
        
        # Check disk space on download path
        download_path = config.get('download_path', '/downloads')
        disk_ok = True
        disk_free = 0
        disk_total = 0
        
        if os.path.exists(download_path):
            try:
                stat = shutil.disk_usage(download_path)
                disk_free = stat.free
                disk_total = stat.total
                # Warning if less than 1GB free
                disk_ok = disk_free > 1024 * 1024 * 1024
            except:
                pass
        
        # Check remote server connectivity (quick check)
        servers_status = []
        for server in config.get('servers', [])[:3]:  # Only check first 3
            server_ok = False
            try:
                url = server.get('url', '').rstrip('/')
                if url:
                    r = requests.get(f"{url}/System/Info/Public", timeout=5)
                    server_ok = r.status_code == 200
            except:
                pass
            servers_status.append({
                'name': server.get('name', 'Unknown'),
                'healthy': server_ok
            })
        
        # Overall health
        is_healthy = disk_ok  # Add more checks as needed
        
        response = {
            'status': 'healthy' if is_healthy else 'unhealthy',
            'version': VERSION,
            'uptime_seconds': int(time.time() - app.start_time) if hasattr(app, 'start_time') else 0,
            'queue': {
                'active': len(active_downloads),
                'pending': task_queue.qsize(),
                'workers': active_workers,
                'paused': is_paused
            },
            'disk': {
                'path': download_path,
                'free_bytes': disk_free,
                'free_human': format_bytes(disk_free),
                'total_bytes': disk_total,
                'healthy': disk_ok
            },
            'servers': servers_status,
            'cache': {
                'items': len(local_id_cache),
                'last_scan': cache_timestamp
            },
            'license': {
                'tier': get_license_tier()
            }
        }
        
        status_code = 200 if is_healthy else 503
        return jsonify(response), status_code
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'version': VERSION
        }), 503


# ============================================================================
# API v1 - External Integration Endpoints (NZB360, Organizr, etc.)
# ============================================================================

@app.route('/api/v1/key/generate', methods=['POST'])
@login_required
def api_generate_key():
    """Generate a new API key (requires login)"""
    cfg = load_config()
    new_key = generate_api_key()
    cfg['api_key'] = new_key
    cfg['api_enabled'] = True
    save_config(cfg)
    
    log(f"ðŸ”‘ [API] New API key generated")
    
    return jsonify({
        'success': True,
        'api_key': new_key,
        'message': 'New API key generated. Save it securely - it cannot be retrieved later.'
    })


@app.route('/api/v1/key/revoke', methods=['POST'])
@login_required
def api_revoke_key():
    """Revoke/disable API key (requires login)"""
    cfg = load_config()
    cfg['api_key'] = ''
    cfg['api_enabled'] = False
    save_config(cfg)
    
    log(f"ðŸ”‘ [API] API key revoked")
    
    return jsonify({
        'success': True,
        'message': 'API key revoked. External integrations will no longer work.'
    })


@app.route('/api/v1/key/status', methods=['GET'])
@login_required
def api_key_status():
    """Check API key status (requires login)"""
    cfg = load_config()
    has_key = bool(cfg.get('api_key', ''))
    enabled = cfg.get('api_enabled', False)
    
    # SECURITY: Never reveal any part of the API key
    # Only indicate if one is set
    return jsonify({
        'success': True,
        'api_enabled': enabled,
        'api_key_set': has_key
    })


@app.route('/api/v1/status', methods=['GET'])
@api_key_required
def api_v1_status():
    """
    Get current status - queue, speeds, disk space.
    Compatible with NZB360 and other external apps.
    """
    cfg = load_config()
    download_path = cfg.get('download_path', '/downloads')
    
    # Disk stats
    disk_free = 0
    disk_total = 0
    if os.path.exists(download_path):
        try:
            stat = shutil.disk_usage(download_path)
            disk_free = stat.free
            disk_total = stat.total
        except:
            pass
    
    # Calculate total speed
    total_speed = sum(d.get('speed', 0) for d in active_downloads.values())
    
    # Queue counts
    active_count = len(active_downloads)
    pending_count = task_queue.qsize() + len(pending_display)
    
    return jsonify({
        'success': True,
        'version': VERSION,
        'status': 'paused' if is_paused else 'downloading' if active_count > 0 else 'idle',
        'queue': {
            'active': active_count,
            'pending': pending_count,
            'total': active_count + pending_count
        },
        'speed': {
            'bytes_per_sec': total_speed,
            'human': format_speed(total_speed)
        },
        'disk': {
            'free_bytes': disk_free,
            'total_bytes': disk_total,
            'free_human': format_bytes(disk_free),
            'total_human': format_bytes(disk_total),
            'percent_used': round((1 - disk_free / disk_total) * 100, 1) if disk_total > 0 else 0
        },
        'workers': {
            'download': active_workers,
            'transcode': transcode_workers_active
        },
        'paused': is_paused,
        'license_tier': get_license_tier()
    })


@app.route('/api/v1/queue', methods=['GET'])
@api_key_required
def api_v1_queue():
    """
    Get current download queue.
    Returns active downloads and pending items.
    """
    # Active downloads with progress
    active_list = []
    for tid, info in active_downloads.items():
        item = {
            'id': tid,
            'name': info.get('filename', 'Unknown'),
            'status': 'downloading',
            'progress': info.get('progress', 0),
            'speed': info.get('speed', 0),
            'speed_human': format_speed(info.get('speed', 0)),
            'size': info.get('size', 0),
            'size_human': format_bytes(info.get('size', 0)),
            'downloaded': info.get('downloaded', 0),
            'eta_seconds': int((info.get('size', 0) - info.get('downloaded', 0)) / info.get('speed', 1)) if info.get('speed', 0) > 0 else None
        }
        active_list.append(item)
    
    # Pending items
    pending_list = []
    for item in pending_display:
        pending_list.append({
            'id': item.get('id', ''),
            'name': item.get('name', 'Unknown'),
            'status': 'pending',
            'progress': 0,
            'speed': 0
        })
    
    # Transcode queue
    transcode_list = []
    for tid, info in active_transcodes.items():
        transcode_list.append({
            'id': tid,
            'name': info.get('filename', 'Unknown'),
            'status': 'transcoding',
            'progress': info.get('progress', 0),
            'speed': info.get('speed', '0x')
        })
    
    return jsonify({
        'success': True,
        'active': active_list,
        'pending': pending_list,
        'transcode': transcode_list,
        'counts': {
            'active': len(active_list),
            'pending': len(pending_list),
            'transcode': len(transcode_list)
        }
    })


@app.route('/api/v1/queue/add', methods=['POST'])
@api_key_required
def api_v1_queue_add():
    """
    Add item to download queue.
    Requires: server_id, item_id
    Optional: path (download destination)
    """
    data = request.json or {}
    server_id = data.get('server_id')
    item_id = data.get('item_id')
    custom_path = data.get('path')
    
    if not server_id or not item_id:
        return jsonify({
            'success': False,
            'error': 'Missing required fields: server_id, item_id'
        }), 400
    
    cfg = load_config()
    servers = cfg.get('servers', [])
    
    # Find server
    server = None
    for s in servers:
        if s.get('id') == server_id or s.get('name') == server_id:
            server = s
            break
    
    if not server:
        return jsonify({
            'success': False,
            'error': f'Server not found: {server_id}'
        }), 404
    
    # Determine download path
    base_path = custom_path or cfg.get('download_path', '/storage')
    
    # Generate task ID and start download
    tid = generate_id()
    
    try:
        # Start resolve in background
        threading.Thread(
            target=resolve_and_download,
            args=(server, item_id, base_path, tid, cfg.get('speed_limit', 0)),
            daemon=True
        ).start()
        
        log(f"ðŸ“¡ [API] Download queued via API: item={item_id} server={server.get('name')}")
        
        return jsonify({
            'success': True,
            'task_id': tid,
            'message': f'Download queued for item {item_id}'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/v1/queue/<task_id>', methods=['DELETE'])
@api_key_required
def api_v1_queue_remove(task_id):
    """Remove/cancel a download by task ID"""
    global pending_display, download_cancel_flags
    
    cancelled = False
    
    # Check active downloads
    if task_id in active_downloads:
        download_cancel_flags[task_id] = True
        cancelled = True
        log(f"ðŸ“¡ [API] Cancelling active download: {task_id}")
    
    # Check pending
    with download_lock:
        before = len(pending_display)
        pending_display = [p for p in pending_display if p.get('id') != task_id]
        if len(pending_display) < before:
            cancelled = True
            log(f"ðŸ“¡ [API] Removed pending download: {task_id}")
    
    if cancelled:
        return jsonify({
            'success': True,
            'message': f'Download {task_id} cancelled'
        })
    else:
        return jsonify({
            'success': False,
            'error': f'Task not found: {task_id}'
        }), 404


@app.route('/api/v1/queue/pause', methods=['POST'])
@api_key_required
def api_v1_queue_pause():
    """Pause all downloads"""
    global is_paused
    is_paused = True
    log(f"ðŸ“¡ [API] Downloads paused via API")
    
    return jsonify({
        'success': True,
        'paused': True,
        'message': 'Downloads paused'
    })


@app.route('/api/v1/queue/resume', methods=['POST'])
@api_key_required
def api_v1_queue_resume():
    """Resume downloads"""
    global is_paused
    is_paused = False
    log(f"ðŸ“¡ [API] Downloads resumed via API")
    
    return jsonify({
        'success': True,
        'paused': False,
        'message': 'Downloads resumed'
    })


@app.route('/api/v1/queue/clear', methods=['POST'])
@api_key_required
def api_v1_queue_clear():
    """Clear all pending downloads (does not cancel active)"""
    global pending_display
    
    with download_lock:
        count = len(pending_display)
        pending_display = []
    
    # Also clear the task queue
    cleared_from_queue = 0
    try:
        while not task_queue.empty():
            task_queue.get_nowait()
            cleared_from_queue += 1
    except:
        pass
    
    log(f"ðŸ“¡ [API] Cleared {count + cleared_from_queue} pending downloads via API")
    
    return jsonify({
        'success': True,
        'cleared': count + cleared_from_queue,
        'message': f'Cleared {count + cleared_from_queue} pending downloads'
    })


@app.route('/api/v1/history', methods=['GET'])
@api_key_required
def api_v1_history():
    """
    Get download history.
    Query params: limit (default 50), offset (default 0)
    """
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    
    # Clamp values
    limit = min(max(limit, 1), 500)
    offset = max(offset, 0)
    
    # Slice history
    history_slice = download_history[offset:offset + limit]
    
    return jsonify({
        'success': True,
        'history': history_slice,
        'total': len(download_history),
        'limit': limit,
        'offset': offset
    })


@app.route('/api/v1/servers', methods=['GET'])
@api_key_required
def api_v1_servers():
    """List configured remote servers"""
    cfg = load_config()
    servers = cfg.get('servers', [])
    
    # Return server info without sensitive data
    server_list = []
    for s in servers:
        server_list.append({
            'id': s.get('id', s.get('name', '')),
            'name': s.get('name', 'Unknown'),
            'url': s.get('url', ''),
            'type': 'jellyfin'  # Could detect emby later
        })
    
    return jsonify({
        'success': True,
        'servers': server_list,
        'count': len(server_list)
    })


@app.route('/api/v1/servers/<server_id>/browse', methods=['GET'])
@api_key_required
def api_v1_browse(server_id):
    """
    Browse server library.
    Query params: parent_id (optional, for folders), limit (default 100)
    """
    cfg = load_config()
    servers = cfg.get('servers', [])
    
    # Find server
    server = None
    for s in servers:
        if s.get('id') == server_id or s.get('name') == server_id:
            server = s
            break
    
    if not server:
        return jsonify({
            'success': False,
            'error': f'Server not found: {server_id}'
        }), 404
    
    parent_id = request.args.get('parent_id')
    limit = request.args.get('limit', 100, type=int)
    
    try:
        url = server['url'].rstrip('/')
        key = server.get('api_key') or server.get('key', '')
        headers = get_auth_header(key)
        
        # Get user ID
        user_resp = requests.get(f"{url}/Users", headers=headers, timeout=10)
        if not user_resp.ok:
            raise Exception("Could not get users")
        users = user_resp.json()
        user_id = users[0]['Id'] if users else None
        
        if not user_id:
            raise Exception("No user found")
        
        # Build request
        if parent_id:
            endpoint = f"{url}/Users/{user_id}/Items"
            params = {
                'ParentId': parent_id,
                'Limit': limit,
                'Fields': 'ProviderIds,Overview'
            }
        else:
            # Get root libraries
            endpoint = f"{url}/Users/{user_id}/Items"
            params = {
                'Limit': limit,
                'Fields': 'ProviderIds,Overview'
            }
        
        resp = requests.get(endpoint, headers=headers, params=params, timeout=30)
        
        if not resp.ok:
            raise Exception(f"Browse failed: {resp.status_code}")
        
        data = resp.json()
        items = data.get('Items', [])
        
        # Format items
        result_items = []
        for item in items:
            result_items.append({
                'id': item.get('Id'),
                'name': item.get('Name'),
                'type': item.get('Type'),
                'year': item.get('ProductionYear'),
                'provider_ids': item.get('ProviderIds', {}),
                'has_children': item.get('Type') in ['Series', 'Season', 'BoxSet', 'Folder', 'CollectionFolder']
            })
        
        return jsonify({
            'success': True,
            'items': result_items,
            'total': data.get('TotalRecordCount', len(items)),
            'parent_id': parent_id
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/v1/servers/<server_id>/search', methods=['GET'])
@api_key_required
def api_v1_search(server_id):
    """
    Search server library.
    Query params: q (search query), limit (default 50)
    """
    cfg = load_config()
    servers = cfg.get('servers', [])
    
    # Find server
    server = None
    for s in servers:
        if s.get('id') == server_id or s.get('name') == server_id:
            server = s
            break
    
    if not server:
        return jsonify({
            'success': False,
            'error': f'Server not found: {server_id}'
        }), 404
    
    query = request.args.get('q', '')
    limit = request.args.get('limit', 50, type=int)
    
    if not query:
        return jsonify({
            'success': False,
            'error': 'Missing search query (q parameter)'
        }), 400
    
    try:
        url = server['url'].rstrip('/')
        key = server.get('api_key') or server.get('key', '')
        headers = get_auth_header(key)
        
        # Get user ID
        user_resp = requests.get(f"{url}/Users", headers=headers, timeout=10)
        users = user_resp.json() if user_resp.ok else []
        user_id = users[0]['Id'] if users else None
        
        if not user_id:
            raise Exception("No user found")
        
        # Search
        resp = requests.get(
            f"{url}/Users/{user_id}/Items",
            headers=headers,
            params={
                'SearchTerm': query,
                'Limit': limit,
                'Recursive': 'true',
                'IncludeItemTypes': 'Movie,Series,Episode',
                'Fields': 'ProviderIds,Overview'
            },
            timeout=30
        )
        
        if not resp.ok:
            raise Exception(f"Search failed: {resp.status_code}")
        
        data = resp.json()
        items = data.get('Items', [])
        
        # Format results
        results = []
        for item in items:
            results.append({
                'id': item.get('Id'),
                'name': item.get('Name'),
                'type': item.get('Type'),
                'year': item.get('ProductionYear'),
                'series_name': item.get('SeriesName'),
                'provider_ids': item.get('ProviderIds', {}),
                'overview': item.get('Overview', '')[:200] + '...' if item.get('Overview') else None
            })
        
        return jsonify({
            'success': True,
            'query': query,
            'results': results,
            'total': len(results)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/v1/stats', methods=['GET'])
@api_key_required
def api_v1_stats():
    """Get download and transcode statistics"""
    cfg = load_config()
    
    # Get download stats from in-memory (includes session and persistent)
    dl_stats = get_download_stats()
    
    # Get transcode stats from in-memory
    with transcode_stats_lock:
        tc_stats = dict(transcode_stats)
    
    # Calculate average reduction percentage
    avg_reduction = 0
    if tc_stats.get('total_original_bytes', 0) > 0:
        avg_reduction = round((tc_stats.get('total_space_saved_bytes', 0) / tc_stats.get('total_original_bytes', 0)) * 100, 1)
    
    return jsonify({
        'success': True,
        'downloads': {
            'total_files': dl_stats.get('total_files', 0),
            'total_bytes': dl_stats.get('total_bytes', 0),
            'total_human': format_bytes(dl_stats.get('total_bytes', 0)),
            'session_files': dl_stats.get('session_files', 0),
            'session_bytes': dl_stats.get('session_bytes', 0),
            'session_human': format_bytes(dl_stats.get('session_bytes', 0)),
            'by_server': dl_stats.get('by_server', {}),
            'last_updated': dl_stats.get('last_updated')
        },
        'transcode': {
            'files_processed': tc_stats.get('files_transcoded', 0),
            'files_skipped': tc_stats.get('files_skipped_larger', 0),
            'original_bytes': tc_stats.get('total_original_bytes', 0),
            'transcoded_bytes': tc_stats.get('total_transcoded_bytes', 0),
            'space_saved_bytes': tc_stats.get('total_space_saved_bytes', 0),
            'space_saved_human': format_bytes(tc_stats.get('total_space_saved_bytes', 0)),
            'average_reduction_percent': avg_reduction
        }
    })


@app.route('/api/v1/docs', methods=['GET'])
def api_v1_docs():
    """API documentation endpoint (no auth required)"""
    docs = {
        'name': 'JellyLooter API',
        'version': 'v1',
        'app_version': VERSION,
        'auth': {
            'method': 'API Key',
            'header': 'X-Api-Key (recommended)',
            'query_param': 'apikey (less secure - may appear in logs)',
            'generate': 'POST /api/v1/key/generate (requires login)',
            'note': 'API keys are shown only once when generated. Store securely!'
        },
        'security': {
            'encryption': 'API keys are encrypted at rest',
            'rate_limiting': 'Brute force protection - 10 failed attempts triggers 5 minute lockout',
            'best_practices': [
                'Use X-Api-Key header instead of query param',
                'Regenerate key if compromised',
                'Use HTTPS in production',
                'Restrict network access if possible'
            ]
        },
        'endpoints': {
            'status': {
                'GET /api/v1/status': 'Get queue status, speeds, disk space'
            },
            'queue': {
                'GET /api/v1/queue': 'Get current download queue',
                'POST /api/v1/queue/add': 'Add item to queue (body: server_id, item_id, path?)',
                'DELETE /api/v1/queue/<task_id>': 'Cancel/remove download',
                'POST /api/v1/queue/pause': 'Pause all downloads',
                'POST /api/v1/queue/resume': 'Resume downloads',
                'POST /api/v1/queue/clear': 'Clear pending queue'
            },
            'history': {
                'GET /api/v1/history': 'Get download history (params: limit, offset)'
            },
            'servers': {
                'GET /api/v1/servers': 'List configured servers',
                'GET /api/v1/servers/<id>/browse': 'Browse server library (params: parent_id, limit)',
                'GET /api/v1/servers/<id>/search': 'Search server (params: q, limit)'
            },
            'stats': {
                'GET /api/v1/stats': 'Get download and transcode statistics'
            }
        },
        'integrations': {
            'nzb360': 'Use Custom Downloader with base URL and API key in header',
            'organizr': 'Add as custom tab with /api/v1/status widget',
            'home_assistant': 'Poll /api/v1/status for sensor data'
        }
    }
    
    return jsonify(docs)


# ============================================================================
# End of API v1 Endpoints
# ============================================================================


@app.route('/api/transcode_test_mode', methods=['GET', 'POST'])
@login_required
def transcode_test_mode():
    """
    Developer endpoint to toggle transcode test mode (JELLYLOOTER_DEV=1 only).
    GET: Check current status
    POST: Toggle on/off (pass {"enabled": true/false})
    """
    if not DEV_MODE:
        return jsonify({'error': 'Not found'}), 404
    cfg = load_config()
    
    if request.method == 'GET':
        test_mode = (DEV_MODE and cfg.get('_transcode_test_mode', False))
        return jsonify({
            'test_mode_enabled': test_mode,
            'transcode_enabled': cfg.get('transcode_enabled', False),
            'transcode_preset': cfg.get('transcode_preset', 'original'),
            'transcode_encoder': cfg.get('transcode_encoder', 'software'),
            'max_concurrent_transcodes': cfg.get('max_concurrent_transcodes', 1),
            'transcode_skip_larger': cfg.get('transcode_skip_larger', True),
            'transcode_cache_enabled': cfg.get('transcode_cache_enabled', False),
            'transcode_cache_path': cfg.get('transcode_cache_path', '/tmp/transcode_cache'),
            'note': 'This is a hidden testing feature. Transcoding is in beta.'
        })
    
    # POST - toggle test mode
    data = request.json or {}
    enabled = data.get('enabled', not (DEV_MODE and cfg.get('_transcode_test_mode', False)))
    
    cfg['_transcode_test_mode'] = enabled
    save_config(cfg)
    
    # Start/adjust transcode workers when test mode is enabled
    if enabled:
        num_workers = cfg.get('max_concurrent_transcodes', 1)
        adjust_transcode_workers(num_workers, force=True)  # Force=True for test mode
    
    status = 'enabled' if enabled else 'disabled'
    log(f"ðŸ§ª [TRANSCODE TEST MODE] {status.upper()} by user")
    
    return jsonify({
        'success': True,
        'test_mode_enabled': enabled,
        'message': f'Transcode test mode {status}. Check logs for detailed transcode output.'
    })


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


# --- License API Routes ---

@app.route('/api/license', methods=['GET'])
def api_license_status():
    """Get current license status"""
    tier = get_license_tier()
    limits = get_tier_limits()
    license_data = load_license()
    
    response = {
        'tier': tier,
        'limits': limits,
        'trial_days_remaining': get_trial_days_remaining() if tier == 'trial' else 0,
        'is_pro': is_pro(),
        'is_trial': is_trial(),
        'trial_available': tier == 'free' and not license_data.get('trial_started')
    }
    
    if tier == 'pro':
        response['activated_at'] = license_data.get('activated_at')
    
    return jsonify(response)


@app.route('/api/license/activate', methods=['POST'])
def api_activate_license():
    """Activate a Pro license key"""
    data = request.json
    key = data.get('key', '').strip().upper()
    
    if not key:
        return jsonify({'success': False, 'error': 'License key required'})
    
    result = activate_license(key)
    return jsonify(result)


@app.route('/api/license/trial', methods=['POST'])
def api_activate_trial():
    """Activate 14-day trial"""
    result = activate_trial()
    return jsonify(result)


@app.route('/api/license/deactivate', methods=['POST'])
def api_deactivate_license():
    """Deactivate license (revert to free)"""
    license_data = load_license()
    old_tier = license_data.get('tier', 'free')
    
    license_data['tier'] = 'free'
    license_data['key'] = None
    save_license(license_data)
    
    log(f"License deactivated (was: {old_tier})")
    return jsonify({'success': True, 'tier': 'free'})


@app.route('/api/license/check_backup', methods=['GET'])
@login_required
def api_check_backup_license():
    """Check if a backup license exists in library folders"""
    backup = check_backup_license()
    return jsonify({
        'found': backup.get('found', False),
        'message': 'Backup license found' if backup.get('found') else 'No backup license found'
    })


@app.route('/api/license/restore', methods=['POST'])
@login_required
def api_restore_license():
    """Restore license from backup in library folders"""
    result = restore_from_backup()
    if result.get('success'):
        return jsonify({
            'success': True,
            'tier': 'pro',
            'message': 'License restored from backup'
        })
    return jsonify({
        'success': False,
        'error': 'No valid backup license found'
    })


@app.route('/api/license/purge_all', methods=['POST'])
@login_required
def api_purge_all_licenses():
    """
    NUCLEAR OPTION: Remove ALL licenses including backups.
    Hidden endpoint for testing - requires special confirmation code.
    """
    data = request.json or {}
    confirm_code = data.get('confirm', '')
    
    # Require confirmation code to prevent accidental use
    if confirm_code != 'PURGE_ALL_LICENSES_CONFIRM':
        return jsonify({
            'success': False,
            'error': 'Confirmation code required. Send {"confirm": "PURGE_ALL_LICENSES_CONFIRM"}'
        })
    
    removed = {'primary': False, 'backups': 0}
    
    # Remove primary license
    try:
        if os.path.exists(LICENSE_FILE):
            os.remove(LICENSE_FILE)
            removed['primary'] = True
            log("ðŸ—‘ï¸ Primary license removed")
    except Exception as e:
        log(f"Error removing primary license: {e}")
    
    # Remove all backup licenses
    paths = _get_backup_paths()
    for path in paths:
        try:
            backup_dir = os.path.join(path, _BKP_FOLDER)
            backup_file = os.path.join(backup_dir, _BKP_FILE)
            
            if os.path.exists(backup_file):
                os.remove(backup_file)
                removed['backups'] += 1
                log(f"ðŸ—‘ï¸ Backup license removed from {path}")
            
            # Also remove the hidden folder if empty
            if os.path.exists(backup_dir) and not os.listdir(backup_dir):
                os.rmdir(backup_dir)
        except Exception as e:
            log(f"Error removing backup from {path}: {e}")
    
    log(f"â˜¢ï¸ License purge complete: primary={removed['primary']}, backups={removed['backups']}")
    
    return jsonify({
        'success': True,
        'removed': removed,
        'message': f"Purged primary license and {removed['backups']} backup(s)"
    })


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


# Rate limit decorator helper
def rate_limit_login(f):
    """Apply rate limiting to login if available"""
    if limiter:
        return limiter.limit("5 per minute")(f)
    return f


@app.route('/api/login', methods=['POST'])
@rate_limit_login
def api_login():
    """Handle login with rate limiting"""
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
        log(f"Login failed: unknown user '{username}'")
        return jsonify({"status": "error", "message": "Invalid credentials"})
    
    if not verify_password(password, auth['users'][username]):
        log(f"Login failed: wrong password for '{username}'")
        return jsonify({"status": "error", "message": "Invalid credentials"})
    
    session['user'] = username
    session.permanent = True
    
    # Set session timeout
    cfg = load_config()
    timeout = cfg.get('session_timeout_minutes', 30)
    app.permanent_session_lifetime = datetime.timedelta(minutes=timeout)
    
    log(f"User '{username}' logged in")
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
                           config=cfg,
                           is_pro=get_license_tier() in ('pro', 'trial'),
                           dev_mode=DEV_MODE)


@app.route('/changelog')
@login_required
def changelog():
    cfg = load_config()
    lang = cfg.get('language', 'en')
    return render_template('changelog.html', 
                           lang=lang,
                           t=get_all_translations(lang),
                           version=VERSION)


@app.route('/help')
@login_required
def help_page():
    cfg = load_config()
    lang = cfg.get('language', 'en')
    return render_template('help.html', 
                           lang=lang,
                           t=get_all_translations(lang),
                           version=VERSION)


@app.route('/api/config', methods=['GET', 'POST'])
@login_required
def config_api():
    if request.method == 'POST':
        updates = dict(request.json or {})
        # Servers are managed via /api/local_servers; GET /api/config sends them without
        # credentials, so never let a posted copy overwrite the stored keys.
        for protected in ('servers', 'local_servers', 'local_server_key', 'license_tier',
                          'vpn_wg_conf', 'vpn_pia_username', 'vpn_pia_password', 'vpn_enabled'):
            updates.pop(protected, None)   # VPN settings go through /api/vpn/save
        if updates.get('api_key') == '***REDACTED***':
            updates.pop('api_key')
        old_config = load_config()

        # Merge updates into existing config (preserves settings not sent)
        new_config = {**old_config, **updates}
        save_config(new_config)
        
        # Check if transcode settings changed
        new_transcode_enabled = new_config.get('transcode_enabled', False)
        new_transcode_workers = new_config.get('max_concurrent_transcodes', 1)
        test_mode = (DEV_MODE and new_config.get('_transcode_test_mode', False))
        preset = new_config.get('transcode_preset', 'original')
        
        # Log transcode settings when enabled
        if new_transcode_enabled or test_mode:
            log(f"ðŸŽ¬ Transcode settings: enabled={new_transcode_enabled}, test_mode={test_mode}, preset={preset}, workers={new_transcode_workers}")
            
            # Always ensure transcode workers are running when transcoding is enabled
            if is_feature_available('transcoding') or test_mode:
                if active_transcode_workers < new_transcode_workers:
                    log(f"ðŸŽ¬ Starting transcode workers (have: {active_transcode_workers}, need: {new_transcode_workers})...")
                    adjust_transcode_workers(new_transcode_workers, force=test_mode)
                log(f"ðŸŽ¬ Active transcode workers: {active_transcode_workers}")
            else:
                log(f"âš ï¸ Transcoding requires Pro license (or enable test mode)")
        
        # Check if download worker count changed
        old_workers = old_config.get('max_concurrent_downloads', 2)
        new_workers = new_config.get('max_concurrent_downloads', 2)
        if old_workers != new_workers:
            log(f"ðŸ“¥ Download workers changed: {old_workers} -> {new_workers}")
            adjust_workers(new_workers)
        
        return jsonify({"status": "ok"})
    cfg = load_config()
    # Add license tier to config for frontend
    cfg['license_tier'] = get_license_tier()
    
    # SECURITY: Redact sensitive keys from API response
    # These should never be sent to the frontend
    sensitive_keys = ['api_key', 'local_server_key']
    for key in sensitive_keys:
        if cfg.get(key):
            cfg[key] = '***REDACTED***'
    for key in ('vpn_wg_conf', 'vpn_pia_username', 'vpn_pia_password'):
        cfg.pop(key, None)
    # Server credentials never leave the backend (UI edits use PUT /api/local_servers/<id>)
    for list_name in ('servers', 'local_servers'):
        if cfg.get(list_name):
            cfg[list_name] = [_public_server(s) for s in cfg[list_name]]

    return jsonify(cfg)


@app.route('/api/skip_list', methods=['GET'])
@login_required
def get_skip_list():
    """Get the list of items to skip during auto-sync"""
    cfg = load_config()
    return jsonify({'skip_list': cfg.get('sync_skip_list', [])})


@app.route('/api/skip_list/add', methods=['POST'])
@login_required
def add_to_skip_list():
    """Add an item to the skip list"""
    data = request.json or {}
    item_id = data.get('id')
    item_name = data.get('name', 'Unknown')
    item_type = data.get('type', 'Unknown')
    server_id = data.get('server_id', '')
    
    if not item_id:
        return jsonify({'success': False, 'error': 'No item ID provided'})
    
    cfg = load_config()
    skip_list = cfg.get('sync_skip_list', [])
    
    # Check if already in list
    if any(item['id'] == item_id for item in skip_list):
        return jsonify({'success': False, 'error': 'Item already in skip list'})
    
    skip_list.append({
        'id': item_id,
        'name': item_name,
        'type': item_type,
        'server_id': server_id,
        'added': datetime.datetime.now().isoformat()
    })
    
    cfg['sync_skip_list'] = skip_list
    save_config(cfg)
    log(f"Added to skip list: {item_name} ({item_type})")
    
    return jsonify({'success': True, 'skip_list': skip_list})


@app.route('/api/skip_list/remove', methods=['POST'])
@login_required
def remove_from_skip_list():
    """Remove an item from the skip list"""
    data = request.json or {}
    item_id = data.get('id')
    
    if not item_id:
        return jsonify({'success': False, 'error': 'No item ID provided'})
    
    cfg = load_config()
    skip_list = cfg.get('sync_skip_list', [])
    
    # Find and remove the item
    original_len = len(skip_list)
    skip_list = [item for item in skip_list if item['id'] != item_id]
    
    if len(skip_list) == original_len:
        return jsonify({'success': False, 'error': 'Item not found in skip list'})
    
    cfg['sync_skip_list'] = skip_list
    save_config(cfg)
    log(f"Removed from skip list: {item_id}")
    
    return jsonify({'success': True, 'skip_list': skip_list})


@app.route('/api/skip_list/clear', methods=['POST'])
@login_required
def clear_skip_list():
    """Clear the entire skip list"""
    cfg = load_config()
    cfg['sync_skip_list'] = []
    save_config(cfg)
    log("Cleared skip list")
    return jsonify({'success': True, 'skip_list': []})


@app.route('/api/config/export')
@login_required
def export_config():
    """
    Export configuration as downloadable JSON file.
    Sensitive data (API keys, passwords) are masked for security.
    """
    config = load_config()
    
    # Create export copy with masked sensitive data
    export_data = config.copy()
    
    # Mask server API keys
    if 'servers' in export_data:
        masked_servers = []
        for server in export_data['servers']:
            s = server.copy()
            if s.get('key'):
                s['key'] = '***MASKED***'
            if s.get('password'):
                s['password'] = '***MASKED***'
            masked_servers.append(s)
        export_data['servers'] = masked_servers
    
    # Mask local server keys
    if export_data.get('local_server_key'):
        export_data['local_server_key'] = '***MASKED***'
    
    if 'local_servers' in export_data:
        masked_local = []
        for server in export_data['local_servers']:
            s = server.copy()
            if s.get('key'):
                s['key'] = '***MASKED***'
            masked_local.append(s)
        export_data['local_servers'] = masked_local
    
    # Mask *arr API keys
    for arr_key in ['sonarr_api_key', 'radarr_api_key', 'lidarr_api_key']:
        if export_data.get(arr_key):
            export_data[arr_key] = '***MASKED***'
    
    # Mask external API key
    if export_data.get('api_key'):
        export_data['api_key'] = '***MASKED***'
    
    # Mask metadata API keys
    for meta_key in ['tmdb_api_key', 'tvdb_api_key', 'tvdb_subscriber_pin', 'omdb_api_key']:
        if export_data.get(meta_key):
            export_data[meta_key] = '***MASKED***'
    
    # Mask notification URLs (may contain tokens)
    if export_data.get('notification_urls'):
        export_data['notification_urls'] = ['***MASKED***' for _ in export_data['notification_urls']]
    
    # Add export metadata
    for vpn_secret in ('vpn_wg_conf', 'vpn_pia_username', 'vpn_pia_password'):
        export_data.pop(vpn_secret, None)   # VPN private keys/passwords never leave the server
    export_data['_export'] = {
        'version': VERSION,
        'exported_at': datetime.datetime.now().isoformat(),
        'note': 'API keys and sensitive data have been masked. You will need to re-enter them after import.'
    }
    
    # Create response with download headers
    response = make_response(json.dumps(export_data, indent=2))
    response.headers['Content-Type'] = 'application/json'
    response.headers['Content-Disposition'] = f'attachment; filename=jellylooter_config_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    
    log("ðŸ“¤ Config exported")
    return response


@app.route('/api/config/import', methods=['POST'])
@login_required
def import_config():
    """
    Import configuration from JSON.
    Preserves existing API keys if imported ones are masked.
    """
    try:
        import_data = request.json
        if not import_data:
            return jsonify({'success': False, 'error': 'No data provided'})
        
        # Remove export metadata
        import_data.pop('_export', None)
        
        # Load current config to preserve sensitive data
        current_config = load_config()
        
        # Preserve masked API keys from current config
        if 'servers' in import_data:
            for i, server in enumerate(import_data['servers']):
                if server.get('key') == '***MASKED***':
                    # Try to find matching server in current config by URL
                    for curr_server in get_all_servers(current_config):
                        if curr_server.get('url') == server.get('url'):
                            server['key'] = curr_server.get('key', '')
                            break
                    else:
                        server['key'] = ''  # No match found
                
                if server.get('password') == '***MASKED***':
                    for curr_server in get_all_servers(current_config):
                        if curr_server.get('url') == server.get('url'):
                            server['password'] = curr_server.get('password', '')
                            break
                    else:
                        server['password'] = ''
        
        # Preserve local server keys
        if import_data.get('local_server_key') == '***MASKED***':
            import_data['local_server_key'] = current_config.get('local_server_key', '')
        
        if 'local_servers' in import_data:
            for server in import_data['local_servers']:
                if server.get('key') == '***MASKED***':
                    for curr_server in get_all_servers(current_config):
                        if curr_server.get('url') == server.get('url'):
                            server['key'] = curr_server.get('key', '')
                            break
                    else:
                        server['key'] = ''
        
        # Preserve *arr API keys
        for arr_key in ['sonarr_api_key', 'radarr_api_key', 'lidarr_api_key']:
            if import_data.get(arr_key) == '***MASKED***':
                import_data[arr_key] = current_config.get(arr_key, '')
        
        # Preserve notification URLs
        if import_data.get('notification_urls'):
            if all(url == '***MASKED***' for url in import_data['notification_urls']):
                import_data['notification_urls'] = current_config.get('notification_urls', [])
        
        # Save, then upgrade v3.x layouts (remote 'servers' list, software-in-'type') to v4
        import_data['config_version'] = 0
        save_config(import_data)
        migrate_config_file()
        load_config(force_reload=True)
        
        log("ðŸ“¥ Config imported successfully")
        return jsonify({
            'success': True,
            'message': 'Configuration imported. Masked API keys were preserved from existing config.'
        })
        
    except json.JSONDecodeError:
        return jsonify({'success': False, 'error': 'Invalid JSON format'})
    except Exception as e:
        log(f"Config import error: {e}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/translations')
def get_translations():
    """Get translations for current language"""
    cfg = load_config()
    lang = request.args.get('lang', cfg.get('language', 'en'))
    return jsonify(get_all_translations(lang))


@app.route('/api/status')
@login_required
def status():
    """Get current status with license info"""
    with download_lock:
        # Combine active downloads and transcodes for UI
        combined_active = dict(active_downloads)
        pending_list = list(pending_display)
    
    with transcode_lock:
        combined_active.update(dict(active_transcodes))
        pending_transcode_list = list(pending_transcodes)
    
    # Get license info
    tier = get_license_tier()
    limits = get_tier_limits()
    
    return jsonify({
        "active": combined_active,
        "pending": pending_list,
        "pending_transcodes": pending_transcode_list,
        "paused": is_paused,
        "stop_after_current": stop_after_current,
        "recent_completed": list(recent_completed),
        "worker_target": target_workers,
        "cache_time": cache_timestamp,
        "cache_count": len(local_id_cache),
        "scan_progress": dict(scan_progress),
        "queue_size": task_queue.qsize(),
        "transcode_queue_size": transcode_queue.qsize(),
        "worker_count": active_workers,
        "transcode_worker_count": active_transcode_workers,
        "version": VERSION,
        # License info
        "license": {
            "tier": tier,
            "is_pro": tier == 'pro',
            "is_trial": tier == 'trial',
            "show_ads": limits.get('show_ads', True),
            "trial_days_remaining": get_trial_days_remaining() if tier == 'trial' else 0
        }
    })


@app.route('/api/logs')
@login_required
def get_logs():
    with download_lock:
        return "\n".join(reversed(list(log_buffer)))


@app.route('/api/history')
@login_required
def get_history():
    with download_lock:
        return jsonify(list(download_history)[:50])  # Return last 50


@app.route('/api/stats')
@login_required
def get_stats():
    """Get download statistics"""
    try:
        today = datetime.datetime.now().date()
        
        # Copy history list quickly under lock to minimize contention
        with download_lock:
            history_copy = list(download_history)
            active_copy = dict(active_downloads)
            pending_count = len(pending_display)
        
        # Get persistent stats
        dl_stats = get_download_stats()
        
        # Calculate today's stats from history (outside lock)
        today_count = 0
        today_bytes = 0
        
        for item in history_copy:
            size = item.get('size', 0)
            
            # Check if download was today
            ts = item.get('timestamp', '')
            if ts:
                try:
                    # Try ISO format first (new format)
                    if 'T' in ts:
                        item_date = datetime.datetime.fromisoformat(ts).date()
                    else:
                        # Fallback to old space-separated format
                        item_date = datetime.datetime.strptime(ts, '%Y-%m-%d %H:%M:%S').date()
                    if item_date == today:
                        today_count += 1
                        today_bytes += size if isinstance(size, (int, float)) else 0
                except:
                    pass
        
        # Calculate current speed from active downloads
        current_speed = 0
        for dl in active_copy.values():
            speed = dl.get('speed_raw', 0)  # Use raw bytes/sec
            if isinstance(speed, (int, float)):
                current_speed += speed
        
        # Queue size
        queue_size = task_queue.qsize() + pending_count
        
        return jsonify({
            # Persistent stats (all-time)
            'total_files': dl_stats.get('total_files', 0),
            'total_bytes': dl_stats.get('total_bytes', 0),
            'total_human': format_bytes(dl_stats.get('total_bytes', 0)),
            # Session stats (this run)
            'session_files': dl_stats.get('session_files', 0),
            'session_bytes': dl_stats.get('session_bytes', 0),
            'session_human': format_bytes(dl_stats.get('session_bytes', 0)),
            # Today stats
            'today_count': today_count,
            'today_bytes': today_bytes,
            'today_human': format_bytes(today_bytes) if today_bytes > 0 else '0 B',
            # Live stats
            'current_speed': current_speed,
            'current_speed_human': format_bytes(current_speed) + '/s' if current_speed > 0 else '0 B/s',
            'queue_size': queue_size,
            'history_count': len(history_copy),
            # Per-server breakdown
            'by_server': dl_stats.get('by_server', {}),
            'last_updated': dl_stats.get('last_updated')
        })
    except Exception as e:
        log(f"Stats error: {e}")
        return jsonify({
            'total_files': 0,
            'total_bytes': 0,
            'total_human': '0 B',
            'session_files': 0,
            'session_bytes': 0,
            'session_human': '0 B',
            'today_count': 0,
            'today_bytes': 0,
            'today_human': '0 B',
            'current_speed': 0,
            'current_speed_human': '0 B/s',
            'queue_size': 0,
            'history_count': 0,
            'error': str(e)
        })


@app.route('/api/pause', methods=['POST'])
@login_required
def pause_dl():
    global is_paused
    is_paused = True
    log("Downloads paused")
    return jsonify({"paused": True})


@app.route('/api/transcode_stats')
@login_required
def get_transcode_stats():
    """Get transcode statistics"""
    with transcode_stats_lock:
        stats = dict(transcode_stats)
    
    # Calculate percentage saved
    if stats['total_original_bytes'] > 0:
        percent_saved = ((stats['total_original_bytes'] - stats['total_transcoded_bytes']) / stats['total_original_bytes']) * 100
    else:
        percent_saved = 0
    
    return jsonify({
        'files_transcoded': stats['files_transcoded'],
        'files_skipped_larger': stats['files_skipped_larger'],
        'total_original_bytes': stats['total_original_bytes'],
        'total_original_human': format_bytes(stats['total_original_bytes']),
        'total_transcoded_bytes': stats['total_transcoded_bytes'],
        'total_transcoded_human': format_bytes(stats['total_transcoded_bytes']),
        'total_space_saved_bytes': stats['total_space_saved_bytes'],
        'total_space_saved_human': format_bytes(stats['total_space_saved_bytes']),
        'percent_saved': round(percent_saved, 1)
    })


@app.route('/api/transcode_stats/reset', methods=['POST'])
@login_required
def reset_transcode_stats():
    """Reset transcode statistics"""
    global transcode_stats
    with transcode_stats_lock:
        transcode_stats = {
            'files_transcoded': 0,
            'files_skipped_larger': 0,
            'total_original_bytes': 0,
            'total_transcoded_bytes': 0,
            'total_space_saved_bytes': 0
        }
    save_transcode_stats()
    log("Transcode statistics reset")
    return jsonify({'success': True, 'message': 'Transcode stats reset'})


@app.route('/api/download_stats/reset', methods=['POST'])
@login_required
def reset_dl_stats():
    """Reset download statistics"""
    data = request.json or {}
    session_only = data.get('session_only', False)
    
    reset_download_stats(session_only=session_only)
    
    if session_only:
        log("ðŸ“Š Session download statistics reset")
    else:
        log("ðŸ“Š All download statistics reset")
    
    return jsonify({'success': True, 'message': 'Download stats reset', 'session_only': session_only})


@app.route('/api/transcode_cache/status', methods=['POST'])
@login_required
def transcode_cache_status():
    """Get transcode cache directory status"""
    data = request.json or {}
    cache_path = data.get('path', '/tmp/transcode_cache')
    
    # Security: validate path
    if '..' in cache_path or not cache_path.startswith('/'):
        return jsonify({'exists': False, 'error': 'Invalid path'})
    
    try:
        if not os.path.exists(cache_path):
            return jsonify({
                'exists': False,
                'file_count': 0,
                'total_size': 0,
                'total_size_human': '0 B'
            })
        
        # Count files and total size
        file_count = 0
        total_size = 0
        
        for entry in os.scandir(cache_path):
            if entry.is_file():
                # Only count transcode-related files
                if '_transcoded' in entry.name or entry.name.endswith(('.mkv', '.mp4', '.avi', '.mov')):
                    file_count += 1
                    total_size += entry.stat().st_size
        
        return jsonify({
            'exists': True,
            'file_count': file_count,
            'total_size': total_size,
            'total_size_human': format_bytes(total_size)
        })
        
    except Exception as e:
        return jsonify({'exists': False, 'error': str(e)})


@app.route('/api/transcode_cache/clear', methods=['POST'])
@login_required
def clear_transcode_cache():
    """Clear partial/failed transcode files from cache directory"""
    data = request.json or {}
    cache_path = data.get('path', '/tmp/transcode_cache')
    
    # Security: validate path
    if '..' in cache_path or not cache_path.startswith('/'):
        return jsonify({'success': False, 'error': 'Invalid path'})
    
    # Extra safety: don't allow clearing certain critical directories
    forbidden_paths = ['/', '/home', '/root', '/etc', '/var', '/usr', '/bin', '/sbin', 
                       '/storage', '/mnt', '/config', '/data']
    if cache_path.rstrip('/') in forbidden_paths:
        return jsonify({'success': False, 'error': 'Cannot clear this directory'})
    
    try:
        if not os.path.exists(cache_path):
            return jsonify({
                'success': True,
                'files_deleted': 0,
                'space_freed': 0,
                'space_freed_human': '0 B',
                'message': 'Cache directory does not exist'
            })
        
        files_deleted = 0
        space_freed = 0
        errors = []
        
        for entry in os.scandir(cache_path):
            if entry.is_file():
                # Only delete transcode-related files (safety measure)
                if '_transcoded' in entry.name or entry.name.endswith(('.mkv', '.mp4', '.avi', '.mov', '.tmp')):
                    try:
                        file_size = entry.stat().st_size
                        os.remove(entry.path)
                        files_deleted += 1
                        space_freed += file_size
                        log(f"ðŸ—‘ï¸ Cleared cache file: {entry.name} ({format_bytes(file_size)})")
                    except Exception as del_error:
                        errors.append(f"{entry.name}: {del_error}")
        
        log(f"ðŸ§¹ Transcode cache cleared: {files_deleted} files, {format_bytes(space_freed)} freed")
        
        return jsonify({
            'success': True,
            'files_deleted': files_deleted,
            'space_freed': space_freed,
            'space_freed_human': format_bytes(space_freed),
            'errors': errors if errors else None
        })
        
    except Exception as e:
        log(f"âŒ Failed to clear transcode cache: {e}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/resume', methods=['POST'])
@login_required
def resume_dl():
    global is_paused
    is_paused = False
    log("Downloads resumed")
    return jsonify({"paused": False})


@app.route('/api/downloads/resumable')
@login_required
def get_resumable():
    """Get list of downloads that can be resumed (Pro feature)"""
    if not is_feature_available('transcoding'):
        return jsonify({'resumable': [], 'pro_required': True})
    
    resumable = get_resumable_downloads()
    return jsonify({'resumable': resumable, 'pro_required': False})


@app.route('/api/downloads/resume_partial', methods=['POST'])
@login_required
def resume_partial():
    """Resume a partial download (Pro feature)"""
    if not is_feature_available('transcoding'):
        return jsonify({'success': False, 'error': 'Pro feature required'})
    
    data = request.json or {}
    task_id = data.get('task_id')
    
    if not task_id:
        return jsonify({'success': False, 'error': 'No task_id provided'})
    
    partials = load_partial_downloads()
    if task_id not in partials:
        return jsonify({'success': False, 'error': 'Partial download not found'})
    
    info = partials[task_id]

    # Reconstruct the task (credentials come from the current server config)
    task = task_from_partial(task_id, info)
    if not task:
        return jsonify({'success': False, 'error': 'The server for this download no longer exists'})
    
    # Add to pending and queue
    with download_lock:
        pending_display.append({
            'id': task_id,
            'name': f"ðŸ”„ {info.get('filename', 'Unknown')}"
        })
    
    # Route to server-specific queue or global queue
    server = info.get('server', {})
    server_id = server.get('id') or server.get('url', 'unknown')
    server_name = server.get('name') or server.get('url', 'Unknown')
    queue_to_server_or_global(task, server_id, server_name)
    
    log(f"ðŸ”„ Queued resume: {info.get('filename', 'Unknown')}")
    return jsonify({'success': True, 'message': f"Resuming {info.get('filename', 'Unknown')}"})


@app.route('/api/downloads/delete_partial', methods=['POST'])
@login_required
def delete_partial():
    """Delete a partial download (Pro feature)"""
    if not is_feature_available('transcoding'):
        return jsonify({'success': False, 'error': 'Pro feature required'})
    
    data = request.json or {}
    task_id = data.get('task_id')
    
    if not task_id:
        return jsonify({'success': False, 'error': 'No task_id provided'})
    
    partials = load_partial_downloads()
    if task_id not in partials:
        return jsonify({'success': False, 'error': 'Partial download not found'})
    
    info = partials[task_id]
    partial_file = info.get('partial_file', '')
    
    # Delete the partial file
    if partial_file and os.path.exists(partial_file):
        try:
            os.remove(partial_file)
        except:
            pass
    
    # Remove from manifest
    clear_partial_state(task_id)
    
    log(f"ðŸ—‘ï¸ Deleted partial: {info.get('filename', 'Unknown')}")
    return jsonify({'success': True, 'message': 'Partial download deleted'})


@app.route('/api/cancel', methods=['POST'])
@login_required
def cancel_dl():
    global pending_display, pending_transcodes
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
        
        with transcode_lock:
            for tid in active_transcodes:
                cancelled_tasks.add(tid)
            for item in pending_transcodes:
                cancelled_tasks.add(item['id'])
            pending_transcodes.clear()
        
        while not task_queue.empty():
            try:
                task = task_queue.get_nowait()
                task_queue.task_done()
            except queue.Empty:
                break
        
        # Also clear transcode queue
        while not transcode_queue.empty():
            try:
                task = transcode_queue.get_nowait()
                transcode_queue.task_done()
            except queue.Empty:
                break
        
        log("All downloads and transcodes cancelled")
        return jsonify({"status": "all_cancelled"})
    
    elif task_id:
        cancelled_tasks.add(task_id)
        
        # Check if it's a transcode
        is_transcode = False
        with transcode_lock:
            if task_id in active_transcodes:
                is_transcode = True
            pending_transcodes[:] = [x for x in pending_transcodes if x['id'] != task_id]
        
        with download_lock:
            pending_display = [x for x in pending_display if x['id'] != task_id]
        
        if is_transcode:
            log(f"Cancelled transcode: {task_id}")
            return jsonify({"status": "cancelled", "task_id": task_id, "type": "transcode"})
        else:
            log(f"Cancelled task: {task_id}")
            return jsonify({"status": "cancelled", "task_id": task_id, "type": "download"})
    
    return jsonify({"status": "error", "message": "No task_id provided"})


@app.route('/api/test_connection', methods=['POST'])
@login_required
def test_connection():
    data = request.json

    # Handle TVDB API test
    if data.get('type') == 'tvdb':
        token, error = tvdb_login(data.get('api_key', ''), data.get('pin', ''))
        return jsonify({"success": True} if token else {"success": False, "error": error})

    if data.get('type') == 'omdb':
        key = re.sub(r'\s+', '', data.get('api_key', '') or '')
        if not key:
            return jsonify({"success": False, "error": "Enter an OMDb API key"})
        try:
            r = requests.get('https://www.omdbapi.com/', params={'apikey': key, 'i': 'tt0111161'}, timeout=15)
            j = r.json() if r.content else {}
        except Exception as e:
            return jsonify({"success": False, "error": f"Couldn't reach OMDb ({type(e).__name__})"})
        if j.get('Response') == 'True':
            return jsonify({"success": True})
        err = j.get('Error') or f"HTTP {r.status_code}"
        if 'not activated' in err.lower():
            err = "OMDb key isn't activated yet - click the activation link OMDb emailed you"
        elif 'invalid' in err.lower():
            err = "OMDb says this API key is invalid - check it at omdbapi.com/apikey.aspx"
        elif 'limit' in err.lower():
            err = "OMDb daily request limit reached for this key (free keys get 1,000/day)"
        return jsonify({"success": False, "error": err})

    url = data.get('url', '').rstrip('/')

    # Validate URL
    url_valid, url_msg = validate_url(url)
    if not url_valid:
        return jsonify({"success": False, "error": url_msg})

    # Determine auth type - check explicit auth_type
    auth_type = data.get('auth_type', 'password')

    log(f"[TEST_CONN] Testing connection to {url}, auth_type={auth_type}")

    try:
        if auth_type == 'password':
            # Username/password auth
            username = data.get('username', '').strip()
            password = data.get('password', '')
            log(f"[TEST_CONN] Password auth for user: {username}")

            if not username:
                return jsonify({"success": False, "error": "Username is required"})

            auth_result = login_with_creds(url, username, password)
            if auth_result and auth_result.get('token'):
                token = auth_result['token']
                user_id = auth_result.get('user_id')
                server_name = auth_result.get('server_name', '')

                # Verify the token works by accessing the user's own data
                verify_response = requests.get(
                    f"{url}/Users/{user_id}" if user_id else f"{url}/Users",
                    headers=get_auth_header(token),
                    timeout=10
                )
                if verify_response.ok:
                    return jsonify({"success": True, "key": token, "user_id": user_id, "server_name": server_name})
                else:
                    return jsonify({"success": False, "error": "Token verification failed"})
            return jsonify({"success": False, "error": "Invalid credentials"})
        else:
            # API key auth - accept both 'key' and 'api_key'
            key = data.get('key', '').strip() or data.get('api_key', '').strip()
            if not key:
                return jsonify({"success": False, "error": "API key is required"})

            key_valid, key_msg = validate_api_key(key)
            if not key_valid:
                return jsonify({"success": False, "error": key_msg})

            response = requests.get(
                f"{url}/Users",
                headers=get_auth_header(key),
                timeout=10
            )
            if response.ok:
                users = response.json()
                if users and len(users) > 0:
                    # Try to get server name
                    server_name = ""
                    try:
                        info_resp = requests.get(f"{url}/System/Info/Public", timeout=5)
                        if info_resp.ok:
                            server_name = info_resp.json().get('ServerName', '')
                    except:
                        pass
                    return jsonify({"success": True, "key": key, "server_name": server_name})
                else:
                    return jsonify({"success": False, "error": "No users found - invalid API key?"})
            return jsonify({"success": False, "error": f"Server returned {response.status_code}"})
    except requests.exceptions.Timeout:
        return jsonify({"success": False, "error": "Connection timeout"})
    except requests.exceptions.ConnectionError:
        return jsonify({"success": False, "error": "Cannot connect to server"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route('/api/rebuild_cache', methods=['POST'])
@login_required
def rebuild_cache():
    threading.Thread(target=cache_worker, daemon=True).start()
    return jsonify({"status": "started"})


@app.route('/api/remove_local', methods=['POST'])
@login_required
def remove_local():
    """Remove single local server (backward compatibility)"""
    cfg = load_config()
    cfg['local_server_url'] = ""
    cfg['local_server_key'] = ""
    save_config(cfg)
    return jsonify({"status": "ok"})


@app.route('/api/local_servers', methods=['GET'])
@login_required
def get_local_servers():
    """Get list of local servers (Pro feature for multiple)"""
    cfg = load_config()
    
    # Support both old single-server format and new multi-server format
    local_servers = cfg.get('local_servers', [])
    
    # If empty but old format exists, migrate
    if not local_servers and cfg.get('local_server_url'):
        local_servers = [{
            'id': generate_id(),
            'name': 'Local Server',
            'url': cfg['local_server_url'],
            'key': cfg.get('local_server_key', ''),
            'type': cfg.get('local_server_type', 'jellyfin')
        }]

    return jsonify({"servers": [_public_server(s) for s in local_servers]})


def _public_server(server):
    """Server entry safe to send to the browser (credentials removed)."""
    safe = {k: v for k, v in server.items() if k not in ('key', 'password')}
    safe['has_key'] = bool(server.get('key'))
    return safe


@app.route('/api/local_servers', methods=['POST'])
@login_required
def add_local_server():
    """Add a local server (Pro feature for multiple)"""
    cfg = load_config()
    data = request.json
    
    # Get current local servers
    local_servers = cfg.get('local_servers', [])
    
    # Migrate from old format if needed
    if not local_servers and cfg.get('local_server_url'):
        local_servers = [{
            'id': generate_id(),
            'name': 'Local Server',
            'url': cfg['local_server_url'],
            'key': cfg.get('local_server_key', ''),
            'type': cfg.get('local_server_type', 'jellyfin')
        }]
    
    # Check limit for this server type (local and remote share this list)
    server_type = data.get('type', 'remote')  # 'local' or 'remote'
    if server_type == 'local':
        max_allowed = get_feature_limit('max_local_servers')
        same_type = [s for s in local_servers if s.get('type') == 'local']
        label = 'local'
    else:
        max_allowed = get_feature_limit('max_remote_servers')
        same_type = [s for s in local_servers if s.get('type') != 'local'] + list(cfg.get('servers') or [])
        label = 'remote'
    if len(same_type) >= max_allowed:
        return jsonify({"status": "error", "limit_reached": True, "limit": max_allowed, "limit_type": label,
                        "error": f"The free plan includes {max_allowed} {label} server{'s' if max_allowed != 1 else ''}. Upgrade to Pro to add more."})

    # Add new server
    new_server = {
        'id': generate_id(),
        'name': data.get('name', 'Server'),
        'url': data.get('url', '').rstrip('/'),
        'key': data.get('key', ''),
        'user_id': data.get('user_id'),
        'username': data.get('username', ''),
        'type': server_type,  # 'local' or 'remote'
        'server_type': 'jellyfin'  # 'jellyfin' or 'emby'
    }

    # Discover and save library names right away (names/ids only, no items)
    lib_error = None
    try:
        libs, user_id = fetch_server_libraries(new_server)
        new_server['libraries'] = libs
        new_server['libraries_updated'] = datetime.datetime.now().isoformat(timespec='seconds')
        if user_id and not new_server.get('user_id'):
            new_server['user_id'] = user_id
    except Exception as e:
        lib_error = _library_error_message(e)
        new_server['libraries'] = []
        log(f"Could not load libraries for new server {new_server['name']}: {lib_error}")

    local_servers.append(new_server)
    cfg['local_servers'] = local_servers

    # Also update old format for backward compatibility
    if len(local_servers) == 1:
        cfg['local_server_url'] = new_server['url']
        cfg['local_server_key'] = new_server['key']

    save_config(cfg)
    safe_server = {k: v for k, v in new_server.items() if k != 'key'}
    return jsonify({"status": "ok", "server": safe_server,
                    "libraries": new_server['libraries'], "library_error": lib_error})


@app.route('/api/local_servers/<server_id>', methods=['DELETE'])
@login_required
def delete_local_server(server_id):
    """Delete a local server"""
    cfg = load_config()
    local_servers = cfg.get('local_servers', [])
    
    cfg['local_servers'] = [s for s in local_servers if s['id'] != server_id]
    
    # Update old format
    if not cfg['local_servers']:
        cfg['local_server_url'] = ""
        cfg['local_server_key'] = ""
    
    save_config(cfg)
    return jsonify({"status": "ok"})


def get_all_servers(cfg):
    """Return remote (source) servers plus local servers, de-duplicated by id."""
    seen = set()
    merged = []
    for s in (cfg.get('servers') or []) + (cfg.get('local_servers') or []):
        if s.get('id') not in seen:
            seen.add(s.get('id'))
            merged.append(s)
    return merged


class ServerAuthError(Exception):
    """Raised when a media server rejects the stored credentials."""


def fetch_server_libraries(server, timeout=10):
    """Fetch a server's top-level libraries (names/ids only, no items).

    Returns (libraries, user_id). Raises ServerAuthError on 401/403 and
    other exceptions on connection problems.
    """
    url = server['url'].rstrip('/')
    headers = get_auth_header(server.get('key', ''))
    user_id = server.get('user_id')

    if not user_id:
        # /Users/Me works for user tokens (password login); /Users needs an admin/API key
        me = requests.get(f"{url}/Users/Me", headers=headers, timeout=timeout)
        if me.ok:
            user_id = me.json().get('Id')
        else:
            users = requests.get(f"{url}/Users", headers=headers, timeout=timeout)
            if users.status_code in (401, 403):
                raise ServerAuthError(f"Server rejected the saved login ({users.status_code}). Edit the server in Settings and log in again.")
            users.raise_for_status()
            users_data = users.json()
            if not users_data:
                raise ServerAuthError("No users returned - check the API key")
            user_id = users_data[0]['Id']

    views = requests.get(f"{url}/Users/{user_id}/Views", headers=headers, timeout=timeout)
    if views.status_code in (401, 403):
        raise ServerAuthError(f"Server rejected the saved login ({views.status_code}). Edit the server in Settings and log in again.")
    views.raise_for_status()

    libraries = [{
        'Id': item['Id'],
        'Name': item.get('Name', 'Library'),
        'CollectionType': item.get('CollectionType')
    } for item in views.json().get('Items', [])]
    return libraries, user_id


def _store_server_libraries(cfg, server_id, libraries, user_id=None):
    """Write fetched libraries (and a discovered user_id) onto the server entry in cfg."""
    stamp = datetime.datetime.now().isoformat(timespec='seconds')
    for list_name in ('servers', 'local_servers'):
        updated = []
        for s in cfg.get(list_name) or []:
            s = dict(s)
            if s.get('id') == server_id:
                s['libraries'] = libraries
                s['libraries_updated'] = stamp
                if user_id and not s.get('user_id'):
                    s['user_id'] = user_id
            updated.append(s)
        if list_name in cfg:
            cfg[list_name] = updated


def _library_error_message(e):
    if isinstance(e, ServerAuthError):
        return str(e)
    if isinstance(e, requests.exceptions.Timeout):
        return "Connection timed out"
    if isinstance(e, requests.exceptions.ConnectionError):
        return "Cannot connect to server"
    return str(e)


@app.route('/api/scan_libs')
@login_required
def scan_libs():
    """Refresh and return library lists for every configured server.

    Each entry: {server_id, server_name, type, libs, error, updated}.
    On failure, the last saved library list is returned with an error message.
    """
    cfg = load_config()
    results = []
    changed = False

    for server in get_all_servers(cfg):
        entry = {
            "server_id": server['id'],
            "server_name": server.get('name', server.get('url', '')),
            "type": server.get('type', 'remote'),
            "libs": server.get('libraries', []),
            "updated": server.get('libraries_updated'),
            "error": None
        }
        try:
            libs, user_id = fetch_server_libraries(server)
            _store_server_libraries(cfg, server['id'], libs, user_id)
            entry['libs'] = libs
            entry['updated'] = datetime.datetime.now().isoformat(timespec='seconds')
            changed = True
        except Exception as e:
            entry['error'] = _library_error_message(e)
            log(f"Scan libs error for {entry['server_name']}: {entry['error']}")
        results.append(entry)

    if changed:
        save_config(cfg)

    return jsonify(results)


@app.route('/api/local_servers/<server_id>/libraries', methods=['POST'])
@login_required
def refresh_server_libraries(server_id):
    """Refresh and save the library list for one server."""
    cfg = load_config()
    server = next((s for s in get_all_servers(cfg) if s['id'] == server_id), None)
    if not server:
        return jsonify({"success": False, "error": "Server not found", "libraries": []}), 404
    try:
        libs, user_id = fetch_server_libraries(server)
        _store_server_libraries(cfg, server_id, libs, user_id)
        save_config(cfg)
        return jsonify({"success": True, "libraries": libs})
    except Exception as e:
        msg = _library_error_message(e)
        log(f"Library refresh error for {server.get('name')}: {msg}")
        return jsonify({"success": False, "error": msg, "libraries": server.get('libraries', [])})


@app.route('/api/local_servers/<server_id>', methods=['PUT'])
@login_required
def update_local_server(server_id):
    """Edit a server in place (keeps its id so sync mappings stay attached)."""
    cfg = load_config()
    data = request.json or {}
    found = None
    for list_name in ('local_servers', 'servers'):
        servers = [dict(s) for s in cfg.get(list_name) or []]
        for s in servers:
            if s.get('id') == server_id:
                if data.get('name'):
                    s['name'] = data['name']
                if data.get('url'):
                    s['url'] = data['url'].rstrip('/')
                if data.get('type') in ('local', 'remote'):
                    s['type'] = data['type']
                if 'username' in data:
                    s['username'] = data.get('username', '')
                if data.get('key'):
                    # New credentials: replace key and user id
                    s['key'] = data['key']
                    s['user_id'] = data.get('user_id')
                found = s
        if found:
            cfg[list_name] = servers
            break
    if not found:
        return jsonify({"status": "error", "error": "Server not found"}), 404

    lib_error = None
    try:
        libs, user_id = fetch_server_libraries(found)
        _store_server_libraries(cfg, server_id, libs, user_id)
    except Exception as e:
        lib_error = _library_error_message(e)
    save_config(cfg)
    saved = next((s for s in get_all_servers(load_config()) if s['id'] == server_id), found)
    return jsonify({"status": "ok", "server": {k: v for k, v in saved.items() if k != 'key'},
                    "libraries": saved.get('libraries', []), "library_error": lib_error})


_IMAGE_ID_RE = re.compile(r'^[A-Za-z0-9-]{1,64}$')


@app.route('/api/image/<server_id>/<item_id>')
@login_required
def proxy_item_image(server_id, item_id):
    """Proxy a poster from a media server so the browser never needs direct access to it."""
    if not _IMAGE_ID_RE.match(server_id) or not _IMAGE_ID_RE.match(item_id):
        return '', 400
    cfg = load_config()
    server = next((s for s in get_all_servers(cfg) if s['id'] == server_id), None)
    if not server:
        return '', 404
    try:
        max_width = max(50, min(int(request.args.get('maxWidth', 300)), 800))
    except ValueError:
        max_width = 300
    try:
        upstream = requests.get(
            f"{server['url'].rstrip('/')}/Items/{item_id}/Images/Primary",
            headers=get_auth_header(server.get('key', '')),
            params={'maxWidth': max_width, 'quality': 85},
            timeout=15
        )
    except requests.RequestException:
        return '', 502
    if not upstream.ok:
        return '', upstream.status_code if upstream.status_code in (401, 403, 404) else 502
    resp = make_response(upstream.content)
    resp.headers['Content-Type'] = upstream.headers.get('Content-Type', 'image/jpeg')
    resp.headers['Cache-Control'] = 'private, max-age=86400'
    return resp


def _server_and_user(server_id):
    cfg = load_config()
    server = next((s for s in get_all_servers(cfg) if s['id'] == server_id), None)
    if not server:
        return None, None, None
    headers = get_auth_header(server.get('key', ''))
    uid = server.get('user_id')
    if not uid:
        me = requests.get(f"{server['url']}/Users/Me", headers=headers, timeout=10)
        uid = me.json().get('Id') if me.ok else None
    return server, headers, uid


_size_cache = {}          # (server_id, item_id) -> (timestamp, bytes)
_SIZE_CACHE_SECONDS = 6 * 3600


def _item_size(server, headers, uid, item_id):
    """Total bytes of a movie/episode, or of everything inside a series/season/folder."""
    key = (server['id'], item_id)
    hit = _size_cache.get(key)
    if hit and time.time() - hit[0] < _SIZE_CACHE_SECONDS:
        return hit[1]
    base = f"{server['url']}/Users/{uid}/Items"
    item = requests.get(f"{base}/{item_id}", headers=headers, timeout=20).json()
    total = 0
    if item.get('IsFolder'):
        start = 0
        while True:
            page = requests.get(base, headers=headers, timeout=60, params={
                'ParentId': item_id, 'Recursive': 'true', 'IncludeItemTypes': 'Movie,Episode,Audio,MusicVideo',
                'Fields': 'MediaSources', 'StartIndex': start, 'Limit': 500}).json()
            items = page.get('Items', [])
            for it in items:
                srcs = it.get('MediaSources') or []
                total += (srcs[0].get('Size') or 0) if srcs else 0
            start += len(items)
            if not items or start >= page.get('TotalRecordCount', 0):
                break
    else:
        srcs = item.get('MediaSources') or []
        total = (srcs[0].get('Size') or 0) if srcs else 0
    _size_cache[key] = (time.time(), total)
    return total


@app.route('/api/item_sizes', methods=['POST'])
@login_required
def api_item_sizes():
    """Sizes for poster cards: {ids: [...]} -> {sizes: {id: {bytes, human}}}."""
    data = request.json or {}
    ids = [i for i in (data.get('ids') or [])[:100] if _IMAGE_ID_RE.match(str(i))]
    server, headers, uid = _server_and_user(data.get('server_id'))
    if not server or not uid:
        return jsonify({'sizes': {}, 'error': 'Server not available'})
    out = {}

    def one(i):
        try:
            b = _item_size(server, headers, uid, i)
            out[i] = {'bytes': b, 'human': format_bytes(b) if b else ''}
        except Exception:
            pass
    threads = [threading.Thread(target=one, args=(i,)) for i in ids]
    for k in range(0, len(threads), 6):          # 6 at a time - be gentle on the remote server
        batch = threads[k:k + 6]
        for t in batch:
            t.start()
        for t in batch:
            t.join(timeout=90)
    return jsonify({'sizes': out})


# ---------------------------------------------------------------------------
# Compare a remote show/movie with your local copy: missing episodes + quality
# ---------------------------------------------------------------------------
QUALITY_LABELS = {4: '4K', 3: '1080p', 2: '720p', 1: 'SD', 0: '?'}
_compare_cache = {}
_COMPARE_CACHE_SECONDS = 900


def _video_rank(media_streams):
    for s in media_streams or []:
        if s.get('Type') == 'Video':
            w, h = s.get('Width') or 0, s.get('Height') or 0
            if w >= 3800 or h >= 2100:
                return 4
            if w >= 1900 or h >= 1000:
                return 3
            if w >= 1260 or h >= 700:
                return 2
            return 1 if (w or h) else 0
    return 0


def _episode_list(server, headers, uid, parent_id):
    out, start = [], 0
    while True:
        page = requests.get(f"{server['url']}/Users/{uid}/Items", headers=headers, timeout=60, params={
            'ParentId': parent_id, 'Recursive': 'true', 'IncludeItemTypes': 'Episode',
            'Fields': 'MediaStreams,ProviderIds,Path', 'StartIndex': start, 'Limit': 500}).json()
        items = page.get('Items', [])
        out += [e for e in items if e.get('LocationType') != 'Virtual']
        start += len(items)
        if not items or start >= page.get('TotalRecordCount', 0):
            return out


def _to_storage_path(jf_path):
    """Map a path as the local Jellyfin sees it (e.g. /data/tv/Show) to JellyLooter's /storage view."""
    if not jf_path:
        return None
    parts = [p for p in jf_path.replace('\\', '/').split('/') if p]
    for i in range(len(parts)):
        cand = os.path.join('/storage', *parts[i:])
        if os.path.exists(cand):
            return cand
    return None


def _local_servers_with_user():
    cfg = load_config()
    out = []
    for s in get_all_servers(cfg):
        if s.get('type') != 'local':
            continue
        h = get_auth_header(s.get('key', ''))
        uid = s.get('user_id')
        if not uid:
            me = requests.get(f"{s['url']}/Users/Me", headers=h, timeout=10)
            uid = me.json().get('Id') if me.ok else None
        if uid:
            out.append((s, h, uid))
    return out


def _find_local_copy(remote_item):
    """Find the local server's copy of a remote Series/Movie (provider IDs first, then title + year)."""
    kind = remote_item.get('Type')
    rkeys = _provider_keys(remote_item.get('ProviderIds'))
    names = [n for n in (remote_item.get('Name'), remote_item.get('OriginalTitle')) if n]

    def year_of(it):
        y = it.get('ProductionYear') or (it.get('PremiereDate') or '')[:4]
        try:
            return int(y)
        except (TypeError, ValueError):
            return None

    ryear = year_of(remote_item)
    title_hits = []
    for server, h, uid in _local_servers_with_user():
        for name in names:
            res = requests.get(f"{server['url']}/Users/{uid}/Items", headers=h, timeout=30, params={
                'IncludeItemTypes': kind, 'Recursive': 'true', 'SearchTerm': name,
                'Fields': 'ProviderIds,Path,ProductionYear,PremiereDate,MediaStreams', 'Limit': 25}).json().get('Items', [])
            for c in res:
                if rkeys & _provider_keys(c.get('ProviderIds')):
                    return server, h, uid, c          # same IMDb/TMDB/TVDB/... id: definitely the same title
            for c in res:
                if normalize_title(c.get('Name')) != normalize_title(name):
                    continue
                cy = year_of(c)
                if ryear and cy and abs(cy - ryear) > 1:
                    continue                          # e.g. One Piece (1999 anime) vs One Piece (2023)
                if c['Id'] not in [x[3]['Id'] for x in title_hits]:
                    title_hits.append((server, h, uid, c))
    # Title-only match must be unambiguous - never guess between two same-named shows
    if len(title_hits) == 1:
        return title_hits[0]
    if len(title_hits) > 1 and ryear:
        exact = [t for t in title_hits if year_of(t[3]) == ryear]
        if len(exact) == 1:
            return exact[0]
    return None


def compare_with_local(server, headers, uid, item_id):
    """What you have vs the remote: missing episodes, better-quality copies, and your folder."""
    key = (server['id'], item_id)
    hit = _compare_cache.get(key)
    if hit and time.time() - hit[0] < _COMPARE_CACHE_SECONDS:
        return hit[1]
    remote = requests.get(f"{server['url']}/Users/{uid}/Items/{item_id}", headers=headers, timeout=20).json()
    result = {'id': item_id, 'type': remote.get('Type'), 'owned': False}
    found = _find_local_copy(remote) if remote.get('Type') in ('Series', 'Movie') else None
    if not found:
        _compare_cache[key] = (time.time(), result)
        return result
    lserver, lh, luid, local = found
    result.update(owned=True, local_id=local['Id'], local_dir=_to_storage_path(local.get('Path')),
                  can_replace=True)
    if remote.get('Type') == 'Movie':
        rq = _video_rank(remote.get('MediaStreams'))
        lq = _video_rank(local.get('MediaStreams'))
        result.update(remote_quality=QUALITY_LABELS[rq], local_quality=QUALITY_LABELS[lq],
                      upgrade=rq > lq > 0, missing=0, missing_ids=[],
                      upgrades=[{'remote_id': item_id, 'local_id': local['Id']}] if rq > lq > 0 else [])
        if result['local_dir'] and os.path.isfile(result['local_dir']):
            result['local_dir'] = os.path.dirname(result['local_dir'])
    else:
        r_eps = {(e.get('ParentIndexNumber'), e.get('IndexNumber')): e for e in _episode_list(server, headers, uid, item_id)
                 if e.get('IndexNumber') is not None and (e.get('ParentIndexNumber') or 0) > 0}
        l_eps = {(e.get('ParentIndexNumber'), e.get('IndexNumber')): e for e in _episode_list(lserver, lh, luid, local['Id'])
                 if e.get('IndexNumber') is not None}
        missing = sorted(k for k in r_eps if k not in l_eps)
        upgrades, lq_counts = [], {}
        for k, le in l_eps.items():
            lq = _video_rank(le.get('MediaStreams'))
            lq_counts[lq] = lq_counts.get(lq, 0) + 1
            re_ = r_eps.get(k)
            if re_ and _video_rank(re_.get('MediaStreams')) > lq > 0:
                upgrades.append({'remote_id': re_['Id'], 'local_id': le['Id']})
        rq_best = max([_video_rank(e.get('MediaStreams')) for e in r_eps.values()] or [0])
        lq_common = max(lq_counts, key=lq_counts.get) if lq_counts else 0
        result.update(total=len(r_eps), have=len(r_eps) - len(missing), missing=len(missing),
                      missing_ids=[r_eps[k]['Id'] for k in missing],
                      missing_labels=[f"S{k[0]:02d}E{k[1]:02d}" for k in missing[:50]],
                      upgrade=bool(upgrades), upgrades=upgrades,
                      remote_quality=QUALITY_LABELS[rq_best], local_quality=QUALITY_LABELS[lq_common])
    _compare_cache[key] = (time.time(), result)
    return result


@app.route('/api/compare_items', methods=['POST'])
@login_required
def api_compare_items():
    """Batch compare for poster badges: {server_id, ids[], refresh?} -> {results: {id: {...}}}."""
    data = request.json or {}
    ids = [i for i in (data.get('ids') or [])[:60] if _IMAGE_ID_RE.match(str(i))]
    server, headers, uid = _server_and_user(data.get('server_id'))
    if not server or not uid or server.get('type') == 'local':
        return jsonify({'results': {}})
    if data.get('refresh'):
        for i in ids:
            _compare_cache.pop((server['id'], i), None)
    out = {}

    def one(i):
        try:
            r = compare_with_local(server, headers, uid, i)
            out[i] = {k: r.get(k) for k in ('owned', 'type', 'total', 'have', 'missing', 'upgrade',
                                            'remote_quality', 'local_quality')}
            out[i]['upgrade_count'] = len(r.get('upgrades') or [])
        except Exception as e:
            out[i] = {'error': str(e)[:100]}
    threads = [threading.Thread(target=one, args=(i,)) for i in ids]
    for k in range(0, len(threads), 4):
        batch = threads[k:k + 4]
        for t in batch:
            t.start()
        for t in batch:
            t.join(timeout=120)
    return jsonify({'results': out, 'upgrades_pro': not is_feature_available('quality_upgrades')})


@app.route('/api/compare_detail', methods=['POST'])
@login_required
def api_compare_detail():
    """Full comparison for one show/movie (used by the banner inside a show)."""
    data = request.json or {}
    item_id = data.get('item_id', '')
    if not _IMAGE_ID_RE.match(str(item_id)):
        return jsonify({'error': 'Invalid item'}), 400
    server, headers, uid = _server_and_user(data.get('server_id'))
    if not server or not uid or server.get('type') == 'local':
        return jsonify({'owned': False})
    if data.get('refresh'):
        _compare_cache.pop((server['id'], item_id), None)
    try:
        r = dict(compare_with_local(server, headers, uid, item_id))
    except Exception as e:
        return jsonify({'owned': False, 'error': str(e)})
    r['upgrades_allowed'] = is_feature_available('quality_upgrades')
    return jsonify(r)


def _sync_series_dir(server, headers, uid, series_id):
    """/storage folder of the local copy of a remote series (None if it can't be found)."""
    try:
        remote_series = requests.get(f"{server['url']}/Users/{uid}/Items/{series_id}", headers=headers, timeout=20).json()
        found = _find_local_copy(remote_series)
        return _to_storage_path(found[3].get('Path')) if found else None
    except Exception:
        return None


def _replace_local_copy(task, filepath):
    """After a verified better-quality download: swap the file in place, or remove the old copy via Jellyfin."""
    local_id = task.get('replace_local_id')
    final_path = task.get('replace_final_path')
    servers = _local_servers_with_user()
    refresh_targets = []
    for server, h, uid in servers:   # look up the show BEFORE anything is removed
        try:
            it = requests.get(f"{server['url']}/Users/{uid}/Items/{local_id}", headers=h, timeout=15)
            if it.ok:
                refresh_targets.append((server, h, it.json().get('SeriesId') or local_id))
        except Exception:
            pass
    if final_path:
        # Same file name: atomically put the new file where the old one was
        os.replace(filepath, final_path)
        filepath = final_path
        log(f"⬆️ Replaced with better quality: {os.path.basename(final_path)}")
    else:
        deleted = False
        for server, h, uid in servers:
            r = requests.delete(f"{server['url']}/Items/{local_id}", headers=h, timeout=30)
            if r.status_code in (200, 204):
                deleted = True
                break
        if deleted:
            log(f"⬆️ Better quality downloaded; removed the old copy via Jellyfin ({os.path.basename(filepath)})")
        else:
            log(f"⚠️ Better quality downloaded, but Jellyfin wouldn't delete the old copy - both are kept. "
                f"Allow content deletion for the JellyLooter user, or delete it yourself.")
    for server, h, target in refresh_targets:
        try:
            requests.post(f"{server['url']}/Items/{target}/Refresh", headers=h, timeout=15,
                          params={'Recursive': 'true', 'MetadataRefreshMode': 'Default', 'ImageRefreshMode': 'Default'})
        except Exception:
            pass
    return filepath


@app.route('/api/item_info', methods=['POST'])
@login_required
def api_item_info():
    """What's about to be downloaded: size, episode count and whether there are specials."""
    data = request.json or {}
    item_id = data.get('item_id', '')
    if not _IMAGE_ID_RE.match(str(item_id)):
        return jsonify({'error': 'Invalid item'}), 400
    server, headers, uid = _server_and_user(data.get('server_id'))
    if not server or not uid:
        return jsonify({'error': 'Server not available'})
    base = f"{server['url']}/Users/{uid}/Items"
    item = requests.get(f"{base}/{item_id}", headers=headers, timeout=20).json()
    info = {'type': item.get('Type'), 'name': item.get('Name'), 'is_folder': bool(item.get('IsFolder')),
            'has_specials': False, 'specials_count': 0, 'episode_count': 0}
    # Continuing vs ended (from the series itself, or the parent series for a season/episode)
    status = item.get('Status')
    if not status and item.get('SeriesId') and item.get('Type') in ('Season', 'Episode'):
        try:
            status = requests.get(f"{base}/{item['SeriesId']}", headers=headers, timeout=15).json().get('Status')
        except Exception:
            status = None
    info['series_status'] = status
    cfg = load_config()
    info['sonarr_ready'] = bool(is_feature_available('arr_integration') and cfg.get('arr_auto_import', True)
                                and cfg.get('sonarr_url') and cfg.get('sonarr_api_key'))
    if item.get('Type') in ('Series', 'Season', 'BoxSet', 'Folder', 'CollectionFolder'):
        eps = requests.get(base, headers=headers, timeout=60, params={
            'ParentId': item_id, 'Recursive': 'true', 'IncludeItemTypes': 'Episode,Movie', 'Limit': 5000}).json().get('Items', [])
        info['episode_count'] = len(eps)
        info['specials_count'] = sum(1 for e in eps if e.get('Type') == 'Episode' and e.get('ParentIndexNumber') == 0)
        info['has_specials'] = info['specials_count'] > 0
    try:
        size = _item_size(server, headers, uid, item_id)
        info.update(size=size, size_human=format_bytes(size) if size else '')
    except Exception:
        pass
    return jsonify(info)


@app.route('/api/stats/detailed')
@login_required
def api_stats_detailed():
    """Tautulli-style download statistics from the persistent download log (Pro)."""
    if not is_feature_available('analytics'):
        return jsonify({'pro_required': True})
    days = max(1, min(int(request.args.get('days', 30)), 3650))
    since = datetime.datetime.now() - datetime.timedelta(days=days)
    rows = []
    if os.path.exists(DOWNLOAD_LOG_FILE):
        with open(DOWNLOAD_LOG_FILE, encoding='utf-8') as f:
            for line in f:
                try:
                    r = json.loads(line)
                    if datetime.datetime.fromisoformat(r['ts']) >= since:
                        rows.append(r)
                except (ValueError, KeyError):
                    continue
    by_day, by_type, by_server, by_hour, by_weekday, shows = {}, {}, {}, [0] * 24, [0] * 7, {}
    for r in rows:
        ts = datetime.datetime.fromisoformat(r['ts'])
        d = by_day.setdefault(ts.date().isoformat(), {'count': 0, 'bytes': 0})
        d['count'] += 1
        d['bytes'] += r.get('size', 0)
        t = by_type.setdefault(r.get('type') or 'other', {'count': 0, 'bytes': 0})
        t['count'] += 1
        t['bytes'] += r.get('size', 0)
        s = by_server.setdefault(r.get('server') or 'Unknown', {'count': 0, 'bytes': 0})
        s['count'] += 1
        s['bytes'] += r.get('size', 0)
        by_hour[ts.hour] += 1
        by_weekday[ts.weekday()] += 1
        name = r.get('series') or r.get('title') or r.get('file')
        sh = shows.setdefault(name, {'name': name, 'type': r.get('type'), 'count': 0, 'bytes': 0, 'last': r['ts']})
        sh['count'] += 1
        sh['bytes'] += r.get('size', 0)
        sh['last'] = max(sh['last'], r['ts'])
    total_bytes = sum(r.get('size', 0) for r in rows)
    total_secs = sum(r.get('seconds', 0) for r in rows)
    day_list = []
    for i in range(days if days <= 90 else 90):
        day = (datetime.date.today() - datetime.timedelta(days=i)).isoformat()
        v = by_day.get(day, {'count': 0, 'bytes': 0})
        day_list.append({'date': day, **v})
    day_list.reverse()
    top = sorted(shows.values(), key=lambda x: x['bytes'], reverse=True)[:15]
    for x in top:
        x['human'] = format_bytes(x['bytes'])
    largest = sorted(rows, key=lambda r: r.get('size', 0), reverse=True)[:10]
    fastest = sorted(rows, key=lambda r: r.get('speed', 0), reverse=True)[:5]
    return jsonify({
        'days': days,
        'total_files': len(rows),
        'total_bytes': total_bytes,
        'total_human': format_bytes(total_bytes),
        'avg_speed_human': f"{format_bytes(total_bytes / total_secs)}/s" if total_secs else '—',
        'avg_size_human': format_bytes(total_bytes / len(rows)) if rows else '—',
        'by_day': day_list,
        'by_type': {k: {**v, 'human': format_bytes(v['bytes'])} for k, v in by_type.items()},
        'by_server': {k: {**v, 'human': format_bytes(v['bytes'])} for k, v in by_server.items()},
        'by_hour': by_hour,
        'by_weekday': by_weekday,
        'top': top,
        'largest': [{'file': r.get('file'), 'human': format_bytes(r.get('size', 0)), 'ts': r['ts']} for r in largest],
        'fastest': [{'file': r.get('file'), 'speed': f"{format_bytes(r.get('speed', 0))}/s"} for r in fastest],
        'recent': [{**r, 'human': format_bytes(r.get('size', 0))} for r in sorted(rows, key=lambda r: r['ts'], reverse=True)[:25]],
    })


@app.route('/api/arr_detect_storage', methods=['POST'])
@login_required
def api_arr_detect_storage():
    """Work out how Sonarr/Radarr/Lidarr see JellyLooter's /storage, from their root folders."""
    cfg = load_config()
    try:
        local_dirs = {e.name.lower(): e.name for e in os.scandir('/storage') if e.is_dir()}
    except OSError:
        local_dirs = {}
    guesses = {}
    for app_name, api in (('sonarr', 'v3'), ('radarr', 'v3'), ('lidarr', 'v1')):
        url = (cfg.get(f'{app_name}_url') or '').rstrip('/')
        key = cfg.get(f'{app_name}_api_key')
        if not url or not key:
            continue
        try:
            roots = requests.get(f"{url}/api/{api}/rootfolder", headers={'X-Api-Key': key}, timeout=10).json()
        except Exception:
            continue
        for r in roots:
            p = (r.get('path') or '').rstrip('/')
            parent, leaf = os.path.dirname(p), os.path.basename(p).lower()
            if leaf in local_dirs:
                guesses[parent] = guesses.get(parent, 0) + 1
    if not guesses:
        return jsonify({'success': False, 'error': "Couldn't match any *arr root folder to a folder in /storage"})
    best = max(guesses, key=guesses.get)
    return jsonify({'success': True, 'arr_storage_path': best})


@app.route('/api/mappings', methods=['POST'])
@login_required
def add_mapping():
    """Add a sync mapping: remote library -> local folder."""
    cfg = load_config()
    data = request.json or {}
    server_id = data.get('server_id')
    lib_id = data.get('lib_id')
    local_path = os.path.normpath(data.get('local_path') or '')

    if not server_id or not lib_id or not data.get('local_path'):
        return jsonify({"success": False, "error": "Server, library and destination folder are required"}), 400
    map_server = next((s for s in get_all_servers(cfg) if s['id'] == server_id), None)
    if not map_server:
        return jsonify({"success": False, "error": "Server not found"}), 404
    if map_server.get('type') == 'local':
        return jsonify({"success": False, "error": "Pick a remote server - your local server is where media is synced to"}), 400
    if '..' in local_path or not any(local_path == b or local_path.startswith(b + '/') for b in ('/storage', '/mnt')):
        return jsonify({"success": False, "error": "Destination must be inside /storage"}), 400

    mappings = list(cfg.get('mappings') or [])
    max_maps = get_feature_limit('max_sync_mappings')
    if len(mappings) >= max_maps:
        return jsonify({"success": False, "limit_reached": True, "limit": max_maps, "limit_type": "mapping",
                        "error": f"The free plan includes {max_maps} sync mapping{'s' if max_maps != 1 else ''}. Upgrade to Pro for unlimited."}), 403
    if any(m.get('server_id') == server_id and m.get('lib_id') == lib_id and m.get('local_path') == local_path for m in mappings):
        return jsonify({"success": False, "error": "That mapping already exists"}), 409

    mapping = {
        'id': generate_id(),
        'server_id': server_id,
        'lib_id': lib_id,
        'lib_name': data.get('lib_name') or lib_id,
        'local_path': local_path
    }
    mappings.append(mapping)
    cfg['mappings'] = mappings
    save_config(cfg)
    return jsonify({"success": True, "mapping": mapping})


@app.route('/api/mappings/<mapping_id>', methods=['PUT'])
@login_required
def update_mapping(mapping_id):
    """Change where a mapped library is saved."""
    cfg = load_config()
    local_path = os.path.normpath((request.json or {}).get('local_path') or '')
    if '..' in local_path.split('/') or not (local_path == '/storage' or local_path.startswith('/storage/')):
        return jsonify({"success": False, "error": "Destination must be inside /storage"}), 400
    mappings = [dict(m) for m in cfg.get('mappings') or []]
    for m in mappings:
        if m.get('id') == mapping_id:
            m['local_path'] = local_path
            cfg['mappings'] = mappings
            save_config(cfg)
            return jsonify({"success": True, "mapping": m})
    return jsonify({"success": False, "error": "Mapping not found"}), 404


@app.route('/api/mappings/<mapping_id>', methods=['DELETE'])
@login_required
def delete_mapping(mapping_id):
    cfg = load_config()
    cfg['mappings'] = [m for m in cfg.get('mappings') or [] if m.get('id') != mapping_id]
    save_config(cfg)
    return jsonify({"success": True})


@app.route('/api/queue/clear', methods=['POST'])
@login_required
def ui_queue_clear():
    """Clear pending downloads (UI version of /api/v1/queue/clear; active downloads keep going)."""
    global pending_display
    with download_lock:
        for item in pending_display:
            cancelled_tasks.add(item['id'])
        cleared_ids = [item['id'] for item in pending_display]
        count = len(pending_display)
        pending_display = []
    for cid in cleared_ids:
        clear_partial_state(cid)
    cleared = 0
    while True:
        try:
            task_queue.get_nowait()
            task_queue.task_done()
            cleared += 1
        except queue.Empty:
            break
    log(f"Cleared {count + cleared} pending downloads")
    return jsonify({"success": True, "cleared": count + cleared})


# --- Metadata Lookup Functions ---

_metadata_cache = {}  # In-memory cache
_metadata_cache_loaded = False

def load_metadata_cache():
    """Load metadata cache from disk (Pro feature)"""
    global _metadata_cache, _metadata_cache_loaded
    if _metadata_cache_loaded:
        return _metadata_cache
    
    if not is_feature_available('metadata_cache'):
        _metadata_cache_loaded = True
        return _metadata_cache
    
    try:
        if os.path.exists(METADATA_CACHE_FILE):
            with open(METADATA_CACHE_FILE, 'r') as f:
                _metadata_cache = json.load(f)
    except Exception as e:
        log(f"Failed to load metadata cache: {e}")
        _metadata_cache = {}
    
    _metadata_cache_loaded = True
    return _metadata_cache

def save_metadata_cache():
    """Save metadata cache to disk (Pro feature)"""
    if not is_feature_available('metadata_cache'):
        return
    
    try:
        with open(METADATA_CACHE_FILE, 'w') as f:
            json.dump(_metadata_cache, f, indent=2)
    except Exception as e:
        log(f"Failed to save metadata cache: {e}")

def get_cached_metadata(title, year=None, media_type='movie'):
    """Get cached metadata if available (Pro feature)"""
    load_metadata_cache()
    cache_key = f"{media_type}:{title}:{year or 'unknown'}"
    return _metadata_cache.get(cache_key)

def cache_metadata(title, year, media_type, metadata):
    """Cache metadata lookup result (Pro feature)"""
    if not is_feature_available('metadata_cache'):
        return
    
    load_metadata_cache()
    cache_key = f"{media_type}:{title}:{year or 'unknown'}"
    _metadata_cache[cache_key] = {
        **metadata,
        'cached_at': datetime.datetime.now().isoformat()
    }
    # Save every 10 additions
    if len(_metadata_cache) % 10 == 0:
        threading.Thread(target=save_metadata_cache, daemon=True).start()

def lookup_tmdb(title, year=None, media_type='movie'):
    """Lookup metadata from TMDB API"""
    cfg = load_config()
    api_key = cfg.get('tmdb_api_key', '')
    if not api_key:
        return None
    
    try:
        # Search for the title
        search_type = 'movie' if media_type == 'movie' else 'tv'
        params = {
            'api_key': api_key,
            'query': title,
            'language': 'en-US'
        }
        if year and media_type == 'movie':
            params['year'] = year
        elif year and media_type != 'movie':
            params['first_air_date_year'] = year
        
        resp = requests.get(
            f'https://api.themoviedb.org/3/search/{search_type}',
            params=params,
            timeout=10
        )
        
        if resp.status_code != 200:
            log(f"TMDB search failed: {resp.status_code}")
            return None
        
        results = resp.json().get('results', [])
        if not results:
            return None
        
        # Get the first (best) match
        item = results[0]
        tmdb_id = item.get('id')
        
        # Get external IDs (includes IMDB)
        ext_resp = requests.get(
            f'https://api.themoviedb.org/3/{search_type}/{tmdb_id}/external_ids',
            params={'api_key': api_key},
            timeout=10
        )
        
        external_ids = ext_resp.json() if ext_resp.status_code == 200 else {}
        
        return {
            'tmdb_id': str(tmdb_id),
            'imdb_id': external_ids.get('imdb_id', ''),
            'tvdb_id': str(external_ids.get('tvdb_id', '')) if external_ids.get('tvdb_id') else '',
            'title': item.get('title') or item.get('name', title),
            'year': (item.get('release_date') or item.get('first_air_date') or '')[:4],
            'source': 'tmdb'
        }
    except Exception as e:
        log(f"TMDB lookup error: {e}")
        return None

_tvdb_token_cache = {'key': None, 'token': None, 'at': 0.0}


def tvdb_login(api_key, pin=''):
    """Log in to TVDB v4. Returns (token, error). PIN is only needed for user-supported keys."""
    api_key = re.sub(r'\s+', '', api_key or '')
    pin = re.sub(r'\s+', '', pin or '')
    if not api_key:
        return None, "Enter a TVDB API key"
    body = {'apikey': api_key}
    if pin:
        body['pin'] = pin
    try:
        r = requests.post('https://api4.thetvdb.com/v4/login', json=body, timeout=15)
    except requests.RequestException as e:
        return None, f"Couldn't reach TVDB ({type(e).__name__})"
    try:
        j = r.json()
    except ValueError:
        j = {}
    token = (j.get('data') or {}).get('token')
    if r.ok and token:
        return token, None
    msg = (j.get('message') or '').lower()
    if 'apikey' in msg or 'api key' in msg:
        hint = ("TVDB says this API key is invalid. Use a v4 key from thetvdb.com → Dashboard → API Keys "
                "(it looks like xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx). Old v2/v3 \"legacy\" keys no longer work - TVDB shut that API down.")
        if not pin:
            hint += " If your key is a user-supported (subscriber) key, also enter your subscriber PIN."
        return None, hint
    if 'pin' in msg:
        return None, "TVDB rejected the subscriber PIN - copy it from your thetvdb.com account (only needed for user-supported keys)"
    return None, f"TVDB login failed: {j.get('message') or 'HTTP ' + str(r.status_code)}"


def _tvdb_token(cfg):
    """Cached TVDB token for lookups (tokens last ~30 days; refresh daily)."""
    api_key = cfg.get('tvdb_api_key', '')
    if not api_key:
        return None
    c = _tvdb_token_cache
    if c['key'] == api_key and c['token'] and time.time() - c['at'] < 86400:
        return c['token']
    token, error = tvdb_login(api_key, cfg.get('tvdb_subscriber_pin', ''))
    if not token:
        log(f"TVDB login failed: {error}")
        return None
    c.update(key=api_key, token=token, at=time.time())
    return token


def lookup_tvdb(title, year=None, media_type='series'):
    """Lookup metadata from TVDB API v4"""
    cfg = load_config()
    try:
        token = _tvdb_token(cfg)
        if not token:
            return None

        headers = {'Authorization': f'Bearer {token}'}
        
        # Search for the title
        search_type = 'movie' if media_type == 'movie' else 'series'
        resp = requests.get(
            f'https://api4.thetvdb.com/v4/search',
            params={'query': title, 'type': search_type},
            headers=headers,
            timeout=10
        )
        
        if resp.status_code != 200:
            return None
        
        results = resp.json().get('data', [])
        if not results:
            return None
        
        # Find best match (optionally filter by year)
        best_match = None
        for item in results:
            item_year = item.get('year') or (item.get('first_air_time') or '')[:4]
            if year and item_year and str(year) == str(item_year):
                best_match = item
                break
        
        if not best_match:
            best_match = results[0]
        
        tvdb_id = best_match.get('tvdb_id') or best_match.get('id', '')
        
        # Get extended info for remote IDs
        remote_ids = best_match.get('remote_ids', [])
        imdb_id = ''
        for rid in remote_ids:
            if rid.get('sourceName') == 'IMDB':
                imdb_id = rid.get('id', '')
                break
        
        return {
            'tvdb_id': str(tvdb_id),
            'imdb_id': imdb_id,
            'tmdb_id': '',
            'title': best_match.get('name', title),
            'year': best_match.get('year', year or ''),
            'source': 'tvdb'
        }
    except Exception as e:
        log(f"TVDB lookup error: {e}")
        return None

def lookup_omdb(title, year=None, media_type='movie'):
    """Lookup metadata from OMDb API"""
    cfg = load_config()
    api_key = cfg.get('omdb_api_key', '')
    if not api_key:
        return None
    
    try:
        params = {
            'apikey': api_key,
            't': title,
            'type': 'movie' if media_type == 'movie' else 'series'
        }
        if year:
            params['y'] = year
        
        resp = requests.get('http://www.omdbapi.com/', params=params, timeout=10)
        
        if resp.status_code != 200:
            return None
        
        data = resp.json()
        if data.get('Response') != 'True':
            return None
        
        return {
            'imdb_id': data.get('imdbID', ''),
            'title': data.get('Title', title),
            'year': data.get('Year', year or ''),
            'tmdb_id': '',
            'tvdb_id': '',
            'source': 'omdb'
        }
    except Exception as e:
        log(f"OMDb lookup error: {e}")
        return None


def lookup_imdb(title, year=None, media_type='movie'):
    """
    Lookup metadata from IMDB suggestion API (no API key required).
    Uses the unofficial IMDB suggestion endpoint.
    """
    try:
        # Clean title for URL - use first letter for the suggestion endpoint
        import urllib.parse
        clean_title = re.sub(r'[^\w\s]', '', title).strip()
        if not clean_title:
            return None
        
        first_letter = clean_title[0].lower()
        encoded_title = urllib.parse.quote(clean_title.lower())
        
        # IMDB suggestion API
        url = f'https://v2.sg.media-imdb.com/suggestion/{first_letter}/{encoded_title}.json'
        
        resp = requests.get(url, timeout=10, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        if resp.status_code != 200:
            log(f"IMDB lookup failed: HTTP {resp.status_code}")
            return None
        
        data = resp.json()
        suggestions = data.get('d', [])
        
        if not suggestions:
            return None
        
        # Filter by type: movie or TV series
        target_types = ['feature', 'movie', 'short'] if media_type == 'movie' else ['TV series', 'tvSeries', 'tvMiniSeries']
        
        best_match = None
        for item in suggestions:
            item_type = item.get('qid', '') or item.get('q', '')
            item_id = item.get('id', '')
            item_title = item.get('l', '')
            item_year = str(item.get('y', ''))
            
            # Must be a title (starts with tt)
            if not item_id.startswith('tt'):
                continue
            
            # Check type match
            type_match = any(t.lower() in item_type.lower() for t in target_types) if item_type else True
            
            # Check year match if provided
            year_match = True
            if year and item_year:
                year_match = abs(int(item_year) - int(year)) <= 1  # Allow 1 year tolerance
            
            # Title similarity check
            title_lower = title.lower()
            item_title_lower = item_title.lower()
            title_match = title_lower in item_title_lower or item_title_lower in title_lower
            
            if type_match and (year_match or not year) and title_match:
                best_match = item
                break
            
            # Keep first result as fallback
            if not best_match:
                best_match = item
        
        if best_match:
            imdb_id = best_match.get('id', '')
            return {
                'imdb_id': imdb_id,
                'title': best_match.get('l', title),
                'year': str(best_match.get('y', year or '')),
                'tmdb_id': '',
                'tvdb_id': '',
                'source': 'imdb'
            }
        
        return None
        
    except Exception as e:
        log(f"IMDB lookup error: {e}")
        return None

def lookup_metadata(title, year=None, media_type='movie', providers=None):
    """
    Lookup metadata from external APIs with fallback chain.
    Returns dict with imdb_id, tvdb_id, tmdb_id
    
    providers: optional dict of existing provider IDs from remote server
    """
    # Check cache first (Pro feature)
    cached = get_cached_metadata(title, year, media_type)
    if cached:
        log(f"ðŸ“‹ Metadata cache hit: {title} ({year or 'unknown year'})")
        return cached
    
    # If we already have all the IDs we need, just return them
    if providers:
        imdb = providers.get('Imdb', '')
        tvdb = providers.get('Tvdb', '')
        tmdb = providers.get('Tmdb', '')
        
        # If we have at least IMDB (for movies) or TVDB (for shows), we're good
        if (media_type == 'movie' and imdb) or (media_type != 'movie' and (tvdb or imdb)):
            log(f"âœ… Metadata from remote server: {title} - IMDB:{imdb or 'N/A'} TVDB:{tvdb or 'N/A'} TMDB:{tmdb or 'N/A'}")
            result = {
                'imdb_id': f"tt{imdb}" if imdb and not imdb.startswith('tt') else imdb,
                'tvdb_id': str(tvdb) if tvdb else '',
                'tmdb_id': str(tmdb) if tmdb else '',
                'title': title,
                'year': year or '',
                'source': 'remote_server'
            }
            cache_metadata(title, year, media_type, result)
            return result
        else:
            # Log what's missing
            missing = []
            if not imdb:
                missing.append('IMDB')
            if media_type != 'movie' and not tvdb:
                missing.append('TVDB')
            if media_type == 'movie' and not tmdb:
                missing.append('TMDB')
            log(f"âš ï¸ Remote server missing IDs for '{title}': {', '.join(missing)} - attempting API lookup")
    else:
        log(f"âš ï¸ No provider IDs from remote server for '{title}' - attempting API lookup")
    
    cfg = load_config()
    result = None
    apis_tried = []
    
    # Check if any API keys are configured
    has_tmdb = bool(cfg.get('tmdb_api_key'))
    has_tvdb = bool(cfg.get('tvdb_api_key'))
    has_omdb = bool(cfg.get('omdb_api_key'))
    has_imdb = cfg.get('imdb_lookup_enabled', True)  # IMDB doesn't need API key, enabled by default
    
    if not has_tmdb and not has_tvdb and not has_omdb and not has_imdb:
        log(f"âŒ No metadata APIs enabled - cannot lookup IDs for '{title}'")
        return None
    
    # Try TMDB first (best for movies, also has TV)
    if has_tmdb:
        apis_tried.append('TMDB')
        result = lookup_tmdb(title, year, media_type)
        if result and result.get('imdb_id'):
            log(f"âœ… TMDB lookup success: {title} -> IMDB:{result.get('imdb_id')} TMDB:{result.get('tmdb_id')}")
            cache_metadata(title, year, media_type, result)
            return result
        elif result:
            log(f"âš ï¸ TMDB found '{title}' but missing IMDB ID")
        else:
            log(f"âš ï¸ TMDB: No results for '{title}' ({year or 'unknown year'})")
    
    # Try TVDB for TV shows
    if media_type != 'movie' and has_tvdb:
        apis_tried.append('TVDB')
        tvdb_result = lookup_tvdb(title, year, media_type)
        if tvdb_result:
            log(f"âœ… TVDB lookup success: {title} -> TVDB:{tvdb_result.get('tvdb_id')} IMDB:{tvdb_result.get('imdb_id', 'N/A')}")
            # Merge with TMDB result if we have one
            if result:
                tvdb_result['tmdb_id'] = result.get('tmdb_id', '')
                if not tvdb_result.get('imdb_id'):
                    tvdb_result['imdb_id'] = result.get('imdb_id', '')
            result = tvdb_result
            if result.get('tvdb_id'):
                cache_metadata(title, year, media_type, result)
                return result
        else:
            log(f"âš ï¸ TVDB: No results for '{title}' ({year or 'unknown year'})")
    
    # Try OMDb as fallback (good for IMDB IDs)
    if has_omdb:
        apis_tried.append('OMDb')
        omdb_result = lookup_omdb(title, year, media_type)
        if omdb_result:
            log(f"âœ… OMDb lookup success: {title} -> IMDB:{omdb_result.get('imdb_id')}")
            # Merge with previous results
            if result:
                omdb_result['tmdb_id'] = result.get('tmdb_id', '')
                omdb_result['tvdb_id'] = result.get('tvdb_id', '')
            result = omdb_result
        else:
            log(f"âš ï¸ OMDb: No results for '{title}' ({year or 'unknown year'})")
    
    # Try IMDB direct lookup as final fallback (no API key needed)
    if has_imdb and (not result or not result.get('imdb_id')):
        apis_tried.append('IMDB')
        imdb_result = lookup_imdb(title, year, media_type)
        if imdb_result:
            log(f"âœ… IMDB lookup success: {title} -> IMDB:{imdb_result.get('imdb_id')}")
            # Merge with previous results
            if result:
                imdb_result['tmdb_id'] = result.get('tmdb_id', '')
                imdb_result['tvdb_id'] = result.get('tvdb_id', '')
            else:
                result = imdb_result
            # Always update imdb_id from this source if we got one
            if imdb_result.get('imdb_id'):
                if result:
                    result['imdb_id'] = imdb_result['imdb_id']
                else:
                    result = imdb_result
        else:
            log(f"âš ï¸ IMDB: No results for '{title}' ({year or 'unknown year'})")
    
    if result:
        cache_metadata(title, year, media_type, result)
        log(f"âœ… Final metadata for '{title}': IMDB:{result.get('imdb_id', 'N/A')} TVDB:{result.get('tvdb_id', 'N/A')} TMDB:{result.get('tmdb_id', 'N/A')}")
    else:
        log(f"âŒ Metadata lookup failed for '{title}' ({year or 'unknown year'}) - tried: {', '.join(apis_tried)}")
    
    return result

def format_folder_with_ids(name, year=None, media_type='movie', providers=None):
    """
    Format folder name with provider IDs using configured format.
    Delegates to build_folder_name_with_ids for consistency.
    """
    # Convert providers dict format if needed
    provider_ids = {}
    if providers:
        provider_ids = {
            'Imdb': providers.get('Imdb', providers.get('imdb_id', '')),
            'Tvdb': providers.get('Tvdb', providers.get('tvdb_id', '')),
            'Tmdb': providers.get('Tmdb', providers.get('tmdb_id', ''))
        }
    
    return build_folder_name_with_ids(name, provider_ids, str(year) if year else '', media_type)


@app.route('/api/refresh_metadata', methods=['POST'])
@login_required
def refresh_metadata():
    """Refresh metadata for an item from external APIs"""
    data = request.json
    title = data.get('title', '')
    year = data.get('year')
    media_type = data.get('media_type', 'movie')
    
    if not title:
        return jsonify({"error": "Title required"}), 400
    
    # Clear from cache first
    load_metadata_cache()
    cache_key = f"{media_type}:{title}:{year or 'unknown'}"
    if cache_key in _metadata_cache:
        del _metadata_cache[cache_key]
    
    # Lookup fresh
    result = lookup_metadata(title, year, media_type)
    
    if result:
        return jsonify({
            "success": True,
            "metadata": result
        })
    else:
        return jsonify({
            "success": False,
            "error": "No metadata found"
        })


@app.route('/api/lookup_metadata', methods=['POST'])
@login_required  
def api_lookup_metadata():
    """API endpoint to lookup metadata for an item"""
    data = request.json
    title = data.get('title', '')
    year = data.get('year')
    media_type = data.get('media_type', 'movie')
    providers = data.get('providers', {})
    
    if not title:
        return jsonify({"error": "Title required"}), 400
    
    result = lookup_metadata(title, year, media_type, providers)
    
    if result:
        return jsonify(result)
    else:
        return jsonify({"error": "No metadata found"}), 404


@app.route('/api/browse_remote', methods=['POST'])
@login_required
def browse_remote():
    data = request.json
    cfg = load_config()
    
    server = next(
        (s for s in get_all_servers(cfg) if s['id'] == data['server_id']),
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
            # User tokens (password login) can read /Users/Me but not /Users
            me_response = requests.get(f"{server['url']}/Users/Me", headers=headers, timeout=10)
            if me_response.ok:
                user_id = me_response.json().get('Id')

        if not user_id:
            users_response = requests.get(
                f"{server['url']}/Users",
                headers=headers,
                timeout=10
            )

            log(f"Users response: {users_response.status_code}")
            if users_response.status_code in (401, 403):
                return jsonify({"items": [], "total": 0, "auth_error": True,
                                "error": "Server rejected the saved login. Edit this server in Settings and log in again."})
            
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
                "HasImage": True,
                "CollectionType": item.get('CollectionType')
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
                'Fields': 'ImageTags,ProviderIds,SeriesProviderIds,OriginalTitle,CommunityRating,CriticRating,OfficialRating,MediaStreams,Width,Height,ChildCount,RecursiveItemCount',
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
            
            # Get episode cache for episode-level checking
            episode_ids, series_ep_counts = get_episode_cache()
            
            clean_items = []
            for item in response.get('Items', []):
                is_folder = item['Type'] in [
                    'Folder', 'CollectionFolder', 'Series',
                    'Season', 'BoxSet'
                ]
                
                exists = False  # False, 'partial', or 'full'
                local_episode_count = 0
                providers = item.get('ProviderIds', {})
                series_providers = item.get('SeriesProviderIds', {})
                
                if local_ids:
                    # Check various ID formats
                    imdb_key = f"imdb_{providers.get('Imdb')}" if providers.get('Imdb') else None
                    tmdb_key = f"tmdb_{providers.get('Tmdb')}" if providers.get('Tmdb') else None
                    tvdb_key = f"tvdb_{providers.get('Tvdb')}" if providers.get('Tvdb') else None
                    
                    # Also check series-level IDs for episodes
                    series_imdb_key = f"imdb_{series_providers.get('Imdb')}" if series_providers.get('Imdb') else None
                    series_tmdb_key = f"tmdb_{series_providers.get('Tmdb')}" if series_providers.get('Tmdb') else None
                    series_tvdb_key = f"tvdb_{series_providers.get('Tvdb')}" if series_providers.get('Tvdb') else None
                    
                    if item['Type'] == 'Episode':
                        # For episodes, check the episode's specific ID in episode_id_cache
                        ep_exists = False
                        if episode_ids:
                            ep_exists = ((imdb_key and imdb_key in episode_ids) or 
                                        (tmdb_key and tmdb_key in episode_ids) or 
                                        (tvdb_key and tvdb_key in episode_ids))
                        # Fallback to old behavior if no episode_ids cache
                        if not ep_exists and not episode_ids:
                            ep_exists = ((imdb_key and imdb_key in local_ids) or 
                                        (tmdb_key and tmdb_key in local_ids) or 
                                        (tvdb_key and tvdb_key in local_ids))
                        exists = 'full' if ep_exists else False
                        
                    elif item['Type'] == 'Series':
                        # For series, check if we have any episodes locally
                        series_key = tvdb_key or imdb_key or tmdb_key
                        if series_key and series_ep_counts:
                            local_episode_count = series_ep_counts.get(series_key, 0)
                            if local_episode_count > 0:
                                # We have episodes for this series - show as complete
                                # Note: We can't reliably compare to remote count because
                                # RecursiveItemCount includes specials, OVAs, etc.
                                exists = 'full'
                            else:
                                # No episodes locally for this series
                                exists = False
                        # Fallback: if no series_ep_counts cache, check if series ID exists
                        elif not series_ep_counts:
                            if ((tvdb_key and tvdb_key in local_ids) or 
                                (imdb_key and imdb_key in local_ids) or 
                                (tmdb_key and tmdb_key in local_ids)):
                                # We have something for this series
                                exists = 'full'
                                
                    elif item['Type'] == 'Season':
                        # For seasons, check parent series episode count
                        series_key = series_tvdb_key or series_imdb_key or series_tmdb_key
                        if series_key and series_ep_counts:
                            local_episode_count = series_ep_counts.get(series_key, 0)
                            if local_episode_count > 0:
                                exists = 'partial'  # Can't easily tell if this specific season is complete
                                
                    elif not is_folder:
                        # For movies, check IMDB/TMDB
                        movie_exists = ((imdb_key and imdb_key in local_ids) or 
                                       (tmdb_key and tmdb_key in local_ids))
                        exists = 'full' if movie_exists else False
                
                # Unified duplicate check: every provider id, then title + year
                exists = local_match_status(item)
                if item['Type'] == 'Series':
                    local_episode_count = local_series_episode_count(item)

                # Check what image types are available
                image_tags = item.get('ImageTags', {})
                has_primary = 'Primary' in image_tags
                
                # Get ratings - CommunityRating is typically IMDB/TMDB rating (0-10 scale)
                community_rating = item.get('CommunityRating')
                critic_rating = item.get('CriticRating')  # Rotten Tomatoes (0-100 scale)
                official_rating = item.get('OfficialRating')  # e.g., PG-13, R, TV-MA
                
                # Extract quality info from MediaStreams
                resolution = None
                is_hdr = False
                is_dolby_vision = False
                is_atmos = False
                video_codec = None
                
                media_streams = item.get('MediaStreams', [])
                for stream in media_streams:
                    if stream.get('Type') == 'Video':
                        width = stream.get('Width', 0)
                        height = stream.get('Height', 0)
                        
                        # Determine resolution
                        if width >= 3840 or height >= 2160:
                            resolution = '4K'
                        elif width >= 1920 or height >= 1080:
                            resolution = '1080p'
                        elif width >= 1280 or height >= 720:
                            resolution = '720p'
                        elif width > 0:
                            resolution = 'SD'
                        
                        # Check for HDR
                        video_range = stream.get('VideoRange', '')
                        video_range_type = stream.get('VideoRangeType', '')
                        if 'HDR' in video_range or 'HDR' in video_range_type:
                            is_hdr = True
                        if 'DoVi' in video_range_type or 'DolbyVision' in video_range_type:
                            is_dolby_vision = True
                        
                        # Get codec
                        video_codec = stream.get('Codec', '').upper()
                        
                    elif stream.get('Type') == 'Audio':
                        # Check for Atmos
                        audio_profile = stream.get('Profile', '')
                        codec = stream.get('Codec', '')
                        if 'atmos' in audio_profile.lower() or 'atmos' in codec.lower():
                            is_atmos = True
                
                # Always try Primary first - it's the poster image
                # If not available, the frontend will show placeholder
                clean_items.append({
                    "Id": item['Id'],
                    "Name": item['Name'],
                    "IsFolder": is_folder,
                    "HasPrimary": has_primary,
                    "ExistsLocally": exists,
                    "LocalEpisodeCount": local_episode_count,
                    "Type": item.get('Type', 'Unknown'),
                    "SeriesName": item.get('SeriesName'),
                    "ParentIndexNumber": item.get('ParentIndexNumber'),
                    "IndexNumber": item.get('IndexNumber'),
                    "ChildCount": item.get('ChildCount', 0),
                    "RecursiveItemCount": item.get('RecursiveItemCount', 0),
                    "CommunityRating": community_rating,
                    "CriticRating": critic_rating,
                    "OfficialRating": official_rating,
                    "ProductionYear": item.get('ProductionYear'),
                    "Resolution": resolution,
                    "IsHDR": is_hdr,
                    "IsDolbyVision": is_dolby_vision,
                    "IsAtmos": is_atmos,
                    "VideoCodec": video_codec,
                    "ProviderIds": item.get('ProviderIds', {}),
                    "SeriesProviderIds": item.get('SeriesProviderIds', {}),
                    "Status": item.get('Status')          # Series: Continuing / Ended
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


@app.route('/api/search', methods=['POST'])
@login_required
def search_library():
    """
    Search for items in a library by name.
    Returns movies, series, and episodes matching the query.
    """
    data = request.json
    cfg = load_config()
    
    query = data.get('query', '').strip()
    parent_id = data.get('parent_id')  # Library ID to search within
    limit = min(data.get('limit', 100), 200)  # Cap at 200 results
    
    if not query or len(query) < 2:
        return jsonify({"items": [], "error": "Query must be at least 2 characters"})
    
    server = next(
        (s for s in get_all_servers(cfg) if s['id'] == data.get('server_id')),
        None
    )
    if not server:
        return jsonify({"items": [], "error": "Server not found"})
    
    try:
        headers = get_auth_header(server['key'])
        user_id = server.get('user_id')
        
        # If no stored user_id, query /Users to get one
        if not user_id:
            users_response = requests.get(
                f"{server['url']}/Users",
                headers=headers,
                timeout=10
            )
            if users_response.ok:
                users_data = users_response.json()
                if users_data:
                    user_id = users_data[0]['Id']
            
            if not user_id:
                return jsonify({"items": [], "error": "Could not get user ID"})
        
        # Build search params
        params = {
            'SearchTerm': query,
            'IncludeItemTypes': 'Movie,Series,Episode',
            'Recursive': 'true',
            'Fields': 'ImageTags,ProviderIds,SeriesProviderIds,CommunityRating,OfficialRating',
            'Limit': limit,
            'SortBy': 'SortName',
            'SortOrder': 'Ascending'
        }
        
        # If a library/parent ID provided, search within it
        if parent_id:
            params['ParentId'] = parent_id
        
        log(f"ðŸ” Searching for: {query}")
        
        search_response = requests.get(
            f"{server['url']}/Users/{user_id}/Items",
            headers=headers,
            params=params,
            timeout=30
        )
        
        if not search_response.ok:
            log(f"Search Error: {search_response.status_code}")
            return jsonify({"items": [], "error": f"Search failed: {search_response.status_code}"})
        
        response = search_response.json()
        items = response.get('Items', [])
        
        log(f"ðŸ” Found {len(items)} results for '{query}'")
        
        # Get local cache for exists checking
        local_ids = local_id_cache
        episode_ids, series_ep_counts = get_episode_cache()
        
        clean_items = []
        for item in items:
            is_folder = item['Type'] in ['Series', 'Season', 'BoxSet']
            has_primary = 'Primary' in item.get('ImageTags', {})
            
            # Check if exists locally
            exists = False
            providers = item.get('ProviderIds', {})
            
            if local_ids:
                imdb_key = f"imdb_{providers.get('Imdb')}" if providers.get('Imdb') else None
                tmdb_key = f"tmdb_{providers.get('Tmdb')}" if providers.get('Tmdb') else None
                tvdb_key = f"tvdb_{providers.get('Tvdb')}" if providers.get('Tvdb') else None
                
                if item['Type'] == 'Episode' and episode_ids:
                    exists = 'full' if ((imdb_key and imdb_key in episode_ids) or 
                                       (tmdb_key and tmdb_key in episode_ids) or 
                                       (tvdb_key and tvdb_key in episode_ids)) else False
                elif item['Type'] == 'Series':
                    series_key = tvdb_key or imdb_key or tmdb_key
                    if series_key and series_ep_counts and series_ep_counts.get(series_key, 0) > 0:
                        exists = 'full'
                elif item['Type'] == 'Movie':
                    if ((imdb_key and imdb_key in local_ids) or 
                        (tmdb_key and tmdb_key in local_ids)):
                        exists = 'full'
            
            exists = local_match_status(item)
            clean_items.append({
                "Id": item['Id'],
                "Name": item['Name'],
                "IsFolder": is_folder,
                "HasPrimary": has_primary,
                "ExistsLocally": exists,
                "Type": item.get('Type', 'Unknown'),
                "SeriesName": item.get('SeriesName'),
                "ParentIndexNumber": item.get('ParentIndexNumber'),
                "IndexNumber": item.get('IndexNumber'),
                "CommunityRating": item.get('CommunityRating'),
                "OfficialRating": item.get('OfficialRating'),
                "ProviderIds": providers
            })
        
        return jsonify({
            "items": clean_items,
            "total": len(clean_items),
            "query": query,
            "base_url": server['url']
        })
        
    except Exception as e:
        log(f"Search Error: {e}")
        return jsonify({"items": [], "error": str(e)})


@app.route('/api/collection_items', methods=['POST'])
@login_required
def get_collection_items():
    """
    Get all downloadable items from a collection or playlist.
    Recursively fetches all movies/episodes.
    """
    data = request.json
    cfg = load_config()
    
    server = next(
        (s for s in get_all_servers(cfg) if s['id'] == data['server_id']),
        None
    )
    if not server:
        return jsonify({"items": [], "error": "Server not found"})

    collection_id = data.get('collection_id')
    if not collection_id:
        return jsonify({"items": [], "error": "No collection_id provided"})
    
    try:
        headers = get_auth_header(server['key'])
        user_id = server.get('user_id')
        
        if not user_id:
            users_response = requests.get(f"{server['url']}/Users", headers=headers, timeout=10)
            if users_response.ok:
                users_data = users_response.json()
                if users_data:
                    user_id = users_data[0]['Id']
        
        if not user_id:
            return jsonify({"items": [], "error": "Could not get user ID"})
        
        # Fetch all items in the collection recursively
        all_items = []
        
        def fetch_items(parent_id, depth=0):
            if depth > 5:  # Prevent infinite recursion
                return
            
            params = {
                'ParentId': parent_id,
                'Recursive': 'true',
                'IncludeItemTypes': 'Movie,Episode',
                'Fields': 'Path,MediaStreams',
                'Limit': 1000
            }
            
            response = requests.get(
                f"{server['url']}/Users/{user_id}/Items",
                headers=headers,
                params=params,
                timeout=60
            )
            
            if response.ok:
                items_data = response.json()
                for item in items_data.get('Items', []):
                    all_items.append({
                        'Id': item['Id'],
                        'Name': item['Name'],
                        'Type': item.get('Type', 'Unknown'),
                        'SeriesName': item.get('SeriesName'),
                        'ParentIndexNumber': item.get('ParentIndexNumber'),
                        'IndexNumber': item.get('IndexNumber')
                    })
        
        fetch_items(collection_id)
        
        log(f"ðŸ“¦ Collection has {len(all_items)} downloadable items")
        
        return jsonify({
            "items": all_items,
            "count": len(all_items)
        })
        
    except Exception as e:
        log(f"Collection fetch error: {e}")
        return jsonify({"items": [], "error": str(e)})


@app.route('/api/batch_download', methods=['POST'])
@login_required
def batch_download():
    data = request.json
    log(f"ðŸ“¥ batch_download called: {len(data.get('item_ids', []))} items")
    cfg = load_config()
    
    server = next(
        (s for s in get_all_servers(cfg) if s['id'] == data['server_id']),
        None
    )
    if not server:
        return jsonify({"status": "error", "message": "Server not found"})
    if server.get('type') == 'local':
        return jsonify({"status": "error", "message": "That's your own local server - you already have its media."})

    download_path = os.path.normpath(data.get('path') or '')
    if not (download_path == '/storage' or download_path.startswith('/storage/')):
        return jsonify({"status": "error", "message": "Downloads must go inside /storage"})
    space_ok, space_msg = check_disk_space(download_path)
    if not space_ok:
        return jsonify({"status": "error", "message": space_msg})

    download_order = cfg.get('download_order', 'library')
    include_specials = bool(data.get('include_specials', False))

    # Missing episodes / upgrades go into the show's existing folder
    series_dir = data.get('target_series_dir')
    if series_dir:
        series_dir = os.path.normpath(series_dir)
        if not series_dir.startswith('/storage/') or '..' in series_dir.split('/') or not os.path.isdir(series_dir):
            return jsonify({"status": "error", "message": "That show's folder couldn't be found inside /storage"})
    replace_map = {str(k): str(v) for k, v in (data.get('replace_map') or {}).items()
                   if _IMAGE_ID_RE.match(str(k)) and _IMAGE_ID_RE.match(str(v))}
    if replace_map and not is_feature_available('quality_upgrades'):
        return jsonify({"status": "error", "message": "Replacing with better quality is a Pro feature"})

    for item_id in data['item_ids']:
        tid = generate_id()
        with download_lock:
            pending_display.append({"name": "Resolving...", "id": tid})

        # Step one: tell Sonarr/Radarr/Lidarr about it before any file lands
        monitor_new = data.get('sonarr_monitor_new')          # None unless asked (continuing shows)
        monitor_new = None if monitor_new is None else bool(monitor_new)
        threading.Thread(target=_arr_add_for_download, args=(server, item_id, download_path, monitor_new), daemon=True).start()

        threading.Thread(
            target=recursive_resolve,
            args=(server, item_id, download_path, tid, cfg.get('speed_limit_kbs', 0), download_order, include_specials,
                  series_dir, replace_map),
            daemon=True
        ).start()
    
    return jsonify({"status": "queued", "count": len(data['item_ids'])})


@app.route('/api/disk_space', methods=['POST'])
@login_required
def get_disk_space():
    """Get disk space info for a path"""
    path = request.json.get('path', '/storage')
    
    # Security: Validate and sanitize path
    path = os.path.normpath(path)
    allowed_bases = ['/storage', '/mnt', '/config']
    
    # Check for path traversal
    if '..' in path:
        return jsonify({"status": "error", "message": "Invalid path"})
    
    # Verify path is within allowed directories
    if not any(path.startswith(base) for base in allowed_bases):
        path = '/storage'
    
    if not any(is_safe_path(base, path) for base in allowed_bases):
        return jsonify({"status": "error", "message": "Invalid path"})
    
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


# --- *arr Folder Naming Integration ---
# Cache for *arr lookups to avoid repeated API calls
_arr_cache = {
    'sonarr_series': {},  # tvdb_id -> folder_name
    'radarr_movies': {},  # tmdb_id -> folder_name
    'last_refresh': None
}

def refresh_arr_cache():
    """Refresh the *arr cache with all series/movies (Pro feature)"""
    global _arr_cache
    
    if not is_feature_available('arr_integration'):
        return
    
    cfg = load_config()
    
    # Refresh Sonarr cache
    sonarr_url = cfg.get('sonarr_url', '').rstrip('/')
    sonarr_key = cfg.get('sonarr_api_key', '')
    
    if sonarr_url and sonarr_key:
        try:
            response = requests.get(
                f"{sonarr_url}/api/v3/series",
                headers={'X-Api-Key': sonarr_key},
                timeout=30
            )
            if response.ok:
                for series in response.json():
                    tvdb_id = series.get('tvdbId')
                    path = series.get('path', '')
                    if tvdb_id and path:
                        # Extract folder name from path
                        folder_name = os.path.basename(path.rstrip('/'))
                        _arr_cache['sonarr_series'][str(tvdb_id)] = folder_name
                log(f"Refreshed Sonarr cache: {len(_arr_cache['sonarr_series'])} series")
        except Exception as e:
            log(f"Sonarr cache refresh error: {e}")
    
    # Refresh Radarr cache
    radarr_url = cfg.get('radarr_url', '').rstrip('/')
    radarr_key = cfg.get('radarr_api_key', '')
    
    if radarr_url and radarr_key:
        try:
            response = requests.get(
                f"{radarr_url}/api/v3/movie",
                headers={'X-Api-Key': radarr_key},
                timeout=30
            )
            if response.ok:
                for movie in response.json():
                    tmdb_id = movie.get('tmdbId')
                    imdb_id = movie.get('imdbId', '')
                    path = movie.get('path', '')
                    folder_name = movie.get('folderName', '')
                    
                    if not folder_name and path:
                        folder_name = os.path.basename(path.rstrip('/'))
                    
                    if folder_name:
                        if tmdb_id:
                            _arr_cache['radarr_movies'][f"tmdb_{tmdb_id}"] = folder_name
                        if imdb_id:
                            _arr_cache['radarr_movies'][f"imdb_{imdb_id}"] = folder_name
                log(f"Refreshed Radarr cache: {len(_arr_cache['radarr_movies'])} movies")
        except Exception as e:
            log(f"Radarr cache refresh error: {e}")
    
    _arr_cache['last_refresh'] = time.time()


def build_folder_name_with_ids(name, provider_ids, year='', media_type='series'):
    """Build folder name with provider IDs in selected format"""
    cfg = load_config()
    folder_name = clean_name(name)
    format_type = cfg.get('folder_naming_format', 'standard')
    
    # Add year for movies (always)
    base_name = folder_name
    if year:
        base_name = f"{folder_name} ({year})"
    
    # If standard format, just return base name
    if format_type == 'standard':
        return base_name
    
    # Get provider IDs from remote server
    imdb_id = provider_ids.get('Imdb', '')
    tvdb_id = provider_ids.get('Tvdb', '')
    tmdb_id = provider_ids.get('Tmdb', '')
    
    # Ensure IMDB has tt prefix
    if imdb_id and not str(imdb_id).startswith('tt'):
        imdb_id = f"tt{imdb_id}"
    
    # If missing IDs, try external API lookup
    if not imdb_id or (media_type != 'movie' and not tvdb_id) or (media_type == 'movie' and not tmdb_id):
        metadata = lookup_metadata(name, year, media_type, provider_ids)
        if metadata:
            if not imdb_id:
                imdb_id = metadata.get('imdb_id', '')
                if imdb_id and not str(imdb_id).startswith('tt'):
                    imdb_id = f"tt{imdb_id}"
            if not tvdb_id:
                tvdb_id = metadata.get('tvdb_id', '')
            if not tmdb_id:
                tmdb_id = metadata.get('tmdb_id', '')
    
    # Build folder name based on format
    if format_type == 'ids_space':
        # Format: Name (Year) tt1234567 12345
        id_parts = []
        if imdb_id:
            id_parts.append(str(imdb_id))
        if media_type != 'movie' and tvdb_id:
            id_parts.append(str(tvdb_id))
        elif media_type == 'movie' and tmdb_id:
            id_parts.append(str(tmdb_id))
        if id_parts:
            return f"{base_name} {' '.join(id_parts)}"
            
    elif format_type == 'ids_braces':
        # Format: Name (Year) {imdb-tt1234567} {tvdb-12345}
        id_parts = []
        if imdb_id:
            id_parts.append(f"{{imdb-{imdb_id}}}")
        if media_type != 'movie' and tvdb_id:
            id_parts.append(f"{{tvdb-{tvdb_id}}}")
        elif media_type == 'movie' and tmdb_id:
            id_parts.append(f"{{tmdb-{tmdb_id}}}")
        if id_parts:
            return f"{base_name} {' '.join(id_parts)}"
            
    elif format_type == 'ids_brackets':
        # Format: Name (Year) [imdb-tt1234567] [tvdb-12345]
        id_parts = []
        if imdb_id:
            id_parts.append(f"[imdb-{imdb_id}]")
        if media_type != 'movie' and tvdb_id:
            id_parts.append(f"[tvdb-{tvdb_id}]")
        elif media_type == 'movie' and tmdb_id:
            id_parts.append(f"[tmdb-{tmdb_id}]")
        if id_parts:
            return f"{base_name} {' '.join(id_parts)}"
            
    elif format_type == 'tmdb_only':
        # Format: Name (Year) {tmdb-12345}
        if tmdb_id:
            return f"{base_name} {{tmdb-{tmdb_id}}}"
            
    elif format_type == 'imdb_only':
        # Format: Name (Year) tt1234567
        if imdb_id:
            return f"{base_name} {imdb_id}"
    
    # Fallback to base name if no IDs found
    return base_name


def get_sonarr_series_folder(provider_ids, fallback_name):
    """Get series folder name from Sonarr (Pro feature)"""
    if not is_feature_available('arr_integration'):
        return None
    
    cfg = load_config()
    sonarr_url = cfg.get('sonarr_url', '').rstrip('/')
    sonarr_key = cfg.get('sonarr_api_key', '')
    
    if not sonarr_url or not sonarr_key:
        return None
    
    # Check cache first
    tvdb_id = provider_ids.get('Tvdb', '')
    if tvdb_id and str(tvdb_id) in _arr_cache['sonarr_series']:
        return _arr_cache['sonarr_series'][str(tvdb_id)]
    
    # If cache is stale (> 1 hour), refresh in background
    if not _arr_cache['last_refresh'] or (time.time() - _arr_cache['last_refresh']) > 3600:
        threading.Thread(target=refresh_arr_cache, daemon=True).start()
    
    # Try direct lookup by TVDB ID
    if tvdb_id:
        try:
            response = requests.get(
                f"{sonarr_url}/api/v3/series/lookup",
                headers={'X-Api-Key': sonarr_key},
                params={'term': f'tvdb:{tvdb_id}'},
                timeout=10
            )
            if response.ok:
                results = response.json()
                if results and len(results) > 0:
                    # Check if series exists in Sonarr
                    series = results[0]
                    path = series.get('path', '')
                    if path:
                        folder_name = os.path.basename(path.rstrip('/'))
                        _arr_cache['sonarr_series'][str(tvdb_id)] = folder_name
                        return folder_name
                    else:
                        # Series not in Sonarr but we have info - use title
                        title = series.get('title', '')
                        year = series.get('year', '')
                        if title:
                            if year:
                                folder_name = clean_name(f"{title} ({year})")
                            else:
                                folder_name = clean_name(title)
                            _arr_cache['sonarr_series'][str(tvdb_id)] = folder_name
                            return folder_name
        except Exception as e:
            log(f"Sonarr lookup error: {e}")
    
    return None


def get_radarr_movie_folder(provider_ids, fallback_name, year=''):
    """Get movie folder name from Radarr (Pro feature)"""
    if not is_feature_available('arr_integration'):
        return None
    
    cfg = load_config()
    radarr_url = cfg.get('radarr_url', '').rstrip('/')
    radarr_key = cfg.get('radarr_api_key', '')
    
    if not radarr_url or not radarr_key:
        return None
    
    # Check cache first
    tmdb_id = provider_ids.get('Tmdb', '')
    imdb_id = provider_ids.get('Imdb', '')
    
    if tmdb_id and f"tmdb_{tmdb_id}" in _arr_cache['radarr_movies']:
        return _arr_cache['radarr_movies'][f"tmdb_{tmdb_id}"]
    if imdb_id and f"imdb_{imdb_id}" in _arr_cache['radarr_movies']:
        return _arr_cache['radarr_movies'][f"imdb_{imdb_id}"]
    
    # If cache is stale (> 1 hour), refresh in background
    if not _arr_cache['last_refresh'] or (time.time() - _arr_cache['last_refresh']) > 3600:
        threading.Thread(target=refresh_arr_cache, daemon=True).start()
    
    # Try direct lookup
    lookup_term = None
    if tmdb_id:
        lookup_term = f'tmdb:{tmdb_id}'
    elif imdb_id:
        lookup_term = f'imdb:{imdb_id}'
    
    if lookup_term:
        try:
            response = requests.get(
                f"{radarr_url}/api/v3/movie/lookup",
                headers={'X-Api-Key': radarr_key},
                params={'term': lookup_term},
                timeout=10
            )
            if response.ok:
                results = response.json()
                if results and len(results) > 0:
                    movie = results[0]
                    
                    # If movie is in Radarr, use its folder
                    folder_name = movie.get('folderName', '')
                    path = movie.get('path', '')
                    
                    if not folder_name and path:
                        folder_name = os.path.basename(path.rstrip('/'))
                    
                    if folder_name:
                        if tmdb_id:
                            _arr_cache['radarr_movies'][f"tmdb_{tmdb_id}"] = folder_name
                        if imdb_id:
                            _arr_cache['radarr_movies'][f"imdb_{imdb_id}"] = folder_name
                        return folder_name
                    
                    # Movie not in Radarr - generate folder name from lookup data
                    title = movie.get('title', '')
                    movie_year = movie.get('year', year)
                    if title:
                        if movie_year:
                            folder_name = clean_name(f"{title} ({movie_year})")
                        else:
                            folder_name = clean_name(title)
                        if tmdb_id:
                            _arr_cache['radarr_movies'][f"tmdb_{tmdb_id}"] = folder_name
                        return folder_name
        except Exception as e:
            log(f"Radarr lookup error: {e}")
    
    return None


def recursive_resolve(server, item_id, base_path, tid, limit, download_order='library', include_specials=True,
                      series_dir=None, replace_map=None):
    """Resolve item and queue downloads (handles series/seasons)"""
    global pending_display
    
    try:
        headers = get_auth_header(server['key'])
        
        # Use stored user_id if available (for username/password auth)
        user_id = server.get('user_id')
        log(f"Using user ID: {user_id}")
        log(f"Using headers: {list(headers.keys())}")
        
        if not user_id:
            # Try to get user_id from /Users endpoint (may fail with non-admin auth)
            try:
                users_resp = requests.get(
                    f"{server['url']}/Users",
                    headers=headers,
                    timeout=10
                )
                if users_resp.status_code == 200:
                    user_id = users_resp.json()[0]['Id']
                else:
                    log(f"Users endpoint returned {users_resp.status_code}, trying /Users/Me")
                    # Fallback: try /Users/Me endpoint
                    me_resp = requests.get(
                        f"{server['url']}/Users/Me",
                        headers=headers,
                        timeout=10
                    )
                    if me_resp.status_code == 200:
                        user_id = me_resp.json()['Id']
                    else:
                        raise Exception(f"Cannot get user ID: /Users returned {users_resp.status_code}, /Users/Me returned {me_resp.status_code}")
            except Exception as e:
                log(f"Error getting user ID: {e}")
                raise
        
        log(f"Fetching item {item_id} for user {user_id}")
        item_resp = requests.get(
            f"{server['url']}/Users/{user_id}/Items/{item_id}",
            headers=headers,
            timeout=15
        )
        
        if item_resp.status_code != 200:
            log(f"Item request failed: {item_resp.status_code} - {item_resp.text[:200]}")
            raise Exception(f"Item request returned {item_resp.status_code}")
        
        item = item_resp.json()
        
        log(f"Item details: Name={item.get('Name')}, Type={item.get('Type')}, Container={item.get('Container')}")
        
        container_types = ['Series', 'Season', 'BoxSet', 'Folder', 'CollectionFolder']
        
        if item['Type'] in container_types:
            children_resp = requests.get(
                f"{server['url']}/Users/{user_id}/Items",
                headers=headers,
                params={
                    'ParentId': item_id,
                    'Recursive': 'true',
                    'IncludeItemTypes': 'Movie,Episode',
                    'Fields': 'ProviderIds,SeriesProviderIds,SeriesId,Container'
                },
                timeout=30
            )
            
            if children_resp.status_code != 200:
                log(f"Children request failed: {children_resp.status_code}")
                raise Exception(f"Children request returned {children_resp.status_code}")
            
            children = children_resp.json().get('Items', [])
            if not include_specials:
                before = len(children)
                children = [c for c in children if not (c.get('Type') == 'Episode' and c.get('ParentIndexNumber') == 0)]
                if before != len(children):
                    log(f"Skipping {before - len(children)} special(s) for {item.get('Name')}")

            with download_lock:
                pending_display = [x for x in pending_display if x['id'] != tid]
            
            # Sort children based on download order
            children = sort_download_queue(children, download_order)
            
            for child in children:
                sub_tid = generate_id()
                queue_item(server, child, base_path, sub_tid, limit, series_dir=series_dir,
                           replace_local_id=(replace_map or {}).get(child['Id']))
        else:
            queue_item(server, item, base_path, tid, limit, series_dir=series_dir,
                       replace_local_id=(replace_map or {}).get(item['Id']))
            
    except Exception as e:
        log(f"Resolve Error: {e}")
        with download_lock:
            pending_display = [x for x in pending_display if x['id'] != tid]


def queue_item(server, item, base_path, tid, limit, series_dir=None, replace_local_id=None):
    """Queue a single item for download.

    series_dir: put it in this existing show/movie folder (missing episodes, upgrades).
    replace_local_id: local Jellyfin item to replace once the better copy is verified (Pro).
    """
    global pending_display
    full_dir_override = None
    try:
        safe_name = clean_name(item['Name'])
        # Container can be comma-separated if multiple media sources exist (e.g., "mkv,webm")
        # Just use the first one
        ext = item.get('Container', 'mkv')
        if ',' in ext:
            ext = ext.split(',')[0].strip()
        
        log(f"Queueing item: {item['Name']} (Type: {item.get('Type', 'Unknown')}, Container: {ext})")
        
        # Get provider IDs for *arr lookup and folder naming
        provider_ids = item.get('ProviderIds', {})
        
        # Load config for folder naming format
        cfg = load_config()
        use_custom_format = cfg.get('folder_naming_format', 'standard') != 'standard'
        
        if item['Type'] == 'Episode':
            series = clean_name(item.get('SeriesName', 'Unknown'))
            season_num = item.get('ParentIndexNumber')
            if season_num is None:
                season_num = 1
            episode_num = item.get('IndexNumber') or 0
            
            # Get series provider IDs - need to fetch from parent series, not episode
            series_id = item.get('SeriesId')
            
            log(f"ðŸ“º Episode '{item['Name']}' of series '{series}' - SeriesId: {series_id or 'NOT FOUND'}")
            
            # First, check if SeriesProviderIds was included in the item response
            series_provider_ids = item.get('SeriesProviderIds', {})
            if series_provider_ids:
                log(f"âœ… Got series IDs from item: IMDB:{series_provider_ids.get('Imdb', 'N/A')} TVDB:{series_provider_ids.get('Tvdb', 'N/A')}")
            elif series_id:
                try:
                    # Fetch the series item to get its provider IDs
                    server_key = server.get('api_key') or server.get('key', '')
                    if not server_key:
                        log(f"âš ï¸ No API key found for server {server.get('name', server.get('url', 'unknown'))}")
                    headers = get_auth_header(server_key)
                    
                    # Try /Items?Ids= endpoint which works more reliably
                    series_url = f"{server['url']}/Items?Ids={series_id}&Fields=ProviderIds,ProductionYear,OriginalTitle"
                    log(f"ðŸ“¡ Fetching series info from: {series_url}")
                    series_resp = requests.get(series_url, headers=headers, timeout=cfg.get('connection_timeout', 30))
                    
                    if series_resp.ok:
                        series_result = series_resp.json()
                        items = series_result.get('Items', [])
                        if items:
                            series_data = items[0]
                            series_provider_ids = series_data.get('ProviderIds', {})
                            if series_provider_ids:
                                log(f"âœ… Fetched series IDs for '{series}': IMDB:{series_provider_ids.get('Imdb', 'N/A')} TVDB:{series_provider_ids.get('Tvdb', 'N/A')}")
                            else:
                                log(f"âš ï¸ Series '{series}' has no ProviderIds in API response")
                        else:
                            log(f"âš ï¸ Series fetch returned empty Items array")
                    else:
                        log(f"âš ï¸ Series fetch failed: HTTP {series_resp.status_code} - {series_resp.text[:200]}")
                except Exception as e:
                    log(f"âš ï¸ Could not fetch series provider IDs: {type(e).__name__}: {e}")
            else:
                log(f"âš ï¸ Episode has no SeriesId field - cannot fetch series info")
            
            # Fall back to NO IDs if we couldn't get series IDs
            # This ensures all episodes go into the same folder (just show name)
            # instead of each episode getting its own folder with episode IDs
            if not series_provider_ids:
                series_provider_ids = {}  # Empty dict = no IDs appended to folder name
                log(f"âš ï¸ Using folder name without IDs for '{series}' (series IDs not available)")
            
            # Try to get folder name from Sonarr if configured
            arr_folder = get_sonarr_series_folder(series_provider_ids, series)
            if arr_folder:
                series_folder = arr_folder
            else:
                # Build folder name with provider IDs (handles all formats including standard)
                series_folder = build_folder_name_with_ids(series, series_provider_ids, '', 'series')
            
            # Always a season folder (even for one-season shows); specials go in "Specials"
            season_folder = "Specials" if season_num == 0 else f"Season {season_num:02d}"
            rel_path = os.path.join(series_folder, season_folder)
            filename = f"{series_folder} - S{season_num:02d}E{episode_num:02d} - {safe_name}.{ext}"
            if series_dir:
                # Existing show folder: reuse its name and its own season folder naming
                existing_season = None
                try:
                    for d in os.listdir(series_dir):
                        m = re.match(r'(?i)^season\s*0*(\d+)$', d)
                        if (m and int(m.group(1)) == season_num) or (season_num == 0 and d.lower() in ('specials', 'season 0', 'season 00')):
                            existing_season = d
                            break
                except OSError:
                    pass
                series_name = os.path.basename(series_dir.rstrip('/'))
                full_dir_override = os.path.join(series_dir, existing_season or season_folder)
                filename = f"{series_name} - S{season_num:02d}E{episode_num:02d} - {safe_name}.{ext}"
        elif item['Type'] == 'Movie':
            # Get year if available
            year = item.get('ProductionYear', '')
            
            # Try to get folder name from Radarr if configured
            arr_folder = get_radarr_movie_folder(provider_ids, safe_name, year)
            if arr_folder:
                folder_name = arr_folder
            else:
                # Build folder name with provider IDs (handles all formats including standard)
                folder_name = build_folder_name_with_ids(safe_name, provider_ids, str(year) if year else '', 'movie')
            
            rel_path = folder_name
            filename = f"{folder_name}.{ext}"
            if series_dir:
                full_dir_override = series_dir
                filename = f"{os.path.basename(series_dir.rstrip('/'))}.{ext}"
        else:
            # Other media types (music, etc)
            rel_path = ""
            filename = f"{safe_name}.{ext}"
        
        full_dir = full_dir_override or os.path.join(base_path, rel_path)
        os.makedirs(full_dir, exist_ok=True)

        filepath = os.path.join(full_dir, filename)
        replace_final_path = None
        if replace_local_id and os.path.exists(filepath):
            # Same name as the copy being upgraded: download to a hidden temp name, swap after verifying
            replace_final_path = filepath
            filepath = os.path.join(full_dir, '.jlupgrade-' + filename)

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
        
        # For episodes, use the series_provider_ids we fetched/processed
        # For movies, use the item's provider_ids
        if item['Type'] == 'Episode':
            task_series_ids = series_provider_ids
            log(f"ðŸ“¦ Task series IDs for '{item['Name']}': TVDB:{task_series_ids.get('Tvdb', 'N/A')} IMDB:{task_series_ids.get('Imdb', 'N/A')}")
        else:
            task_series_ids = {}
        
        task = {
            'url': f"{server['url']}/Items/{item['Id']}/Download",
            'filepath': filepath,
            'task_id': tid,
            'limit': limit,
            'headers': get_auth_header(server['key']),
            'server': server,  # For subtitle download
            'item_id': item['Id'],  # For subtitle download
            'item_type': item.get('Type', '').lower(),  # movie, episode, etc.
            'provider_ids': provider_ids,  # IMDB/TMDB/TVDB IDs for *arr integration
            'series_provider_ids': task_series_ids,  # Series IDs for episodes (from fetched series data)
            # For instant "you have it" checkmarks and detailed stats
            'series_id': item.get('SeriesId'),
            'season_id': item.get('SeasonId'),
            'title': item.get('Name'),
            'original_title': item.get('OriginalTitle'),
            'series_name': item.get('SeriesName'),
            'season_num': item.get('ParentIndexNumber'),
            'episode_num': item.get('IndexNumber'),
            'year': item.get('ProductionYear'),
            'replace_local_id': replace_local_id,
            'replace_final_path': replace_final_path,
        }
        
        # Route to server-specific queue or global queue (Pro feature)
        server_id = server.get('id') or server.get('url', 'unknown')
        server_name = server.get('name') or server.get('url', 'Unknown')
        queue_to_server_or_global(task, server_id, server_name)
        
    except Exception as e:
        log(f"Queue Error: {e}")


def is_safe_path(base_path, target_path):
    """Check if target_path is safely within base_path (prevent path traversal)"""
    # Resolve both paths to absolute paths
    base_resolved = os.path.realpath(base_path)
    target_resolved = os.path.realpath(target_path)
    # Check if target starts with base (is inside base directory)
    return target_resolved.startswith(base_resolved)


_FOLDER_NAME_RE = re.compile(r'^[^/\\\x00]{1,120}$')


@app.route('/api/create_folder', methods=['POST'])
@login_required
def create_folder():
    """Create a subfolder inside /storage (used by the folder picker)."""
    data = request.json or {}
    parent = os.path.normpath(data.get('path') or '/storage')
    name = (data.get('name') or '').strip()

    if not _FOLDER_NAME_RE.match(name) or name in ('.', '..') or name.startswith('.'):
        return jsonify({"success": False, "error": "Enter a folder name without slashes"}), 400
    if '..' in parent.split('/') or not (parent == '/storage' or parent.startswith('/storage/')):
        return jsonify({"success": False, "error": "Folders can only be created inside /storage"}), 400
    if not is_safe_path('/storage', parent):
        return jsonify({"success": False, "error": "Invalid location"}), 400

    target = os.path.join(parent, name)
    if not is_safe_path('/storage', target):
        return jsonify({"success": False, "error": "Invalid folder name"}), 400
    if os.path.exists(target):
        return jsonify({"success": False, "error": "A folder with that name already exists"}), 409
    try:
        os.makedirs(target)
        log(f"ðŸ“ Created folder {target}")
        return jsonify({"success": True, "path": target})
    except OSError as e:
        return jsonify({"success": False, "error": f"Could not create folder: {e.strerror or e}"}), 500


@app.route('/api/browse_local', methods=['POST'])
@login_required
def browse_local():
    """Browse local filesystem for destination selection (with path traversal protection)"""
    path = request.json.get('path', '/storage')
    
    # Security: Validate path is within allowed directories
    allowed_bases = ['/storage', '/mnt']
    
    # Clean the path
    path = os.path.normpath(path)
    
    # Check for path traversal attempts
    if '..' in path:
        log(f"Path traversal blocked: {path}")
        return jsonify({"error": "Invalid path", "folders": [], "current": "/storage"})
    
    # Verify path starts with allowed base
    if not any(path.startswith(base) for base in allowed_bases):
        path = '/storage'
    
    # Double-check with realpath
    if not any(is_safe_path(base, path) for base in allowed_bases):
        log(f"Path traversal blocked (realpath): {path}")
        return jsonify({"error": "Invalid path", "folders": [], "current": "/storage"})
    
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
    cfg = load_config()
    if not cfg.get('mappings'):
        return jsonify({"status": "error", "error": "No sync mappings configured. Add one first."})
    include_existing = bool((request.json or {}).get('include_existing')) if request.is_json else False
    threading.Thread(target=sync_job, kwargs={'manual': True, 'include_existing': include_existing}, daemon=True).start()
    return jsonify({"status": "started", "mappings": len(cfg.get('mappings', [])), "include_existing": include_existing})


def sync_job(manual=False, include_existing=False):
    """Run sync for all configured mappings.

    manual=True ignores the auto-sync toggle; include_existing=True also downloads items you
    already have locally ("Sync Duplicate Media").
    """
    cfg = load_config()

    if not manual and not cfg.get('auto_sync_enabled', True):
        log("Sync skipped: Auto-sync disabled")
        return
    
    log("â”€â”€â”€ Sync Started â”€â”€â”€")
    load_cache_from_disk()
    
    download_order = cfg.get('download_order', 'library')
    skip_list = cfg.get('sync_skip_list', [])
    skip_ids = {item['id'] for item in skip_list}
    
    if skip_ids:
        log(f"Sync: {len(skip_ids)} items in skip list")
    
    for mapping in cfg['mappings']:
        server = next(
            (s for s in get_all_servers(cfg) if s['id'] == mapping['server_id']),
            None
        )
        if not server:
            continue
        
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
            
            items = requests.get(
                f"{server['url']}/Users/{user_id}/Items",
                headers=headers,
                params={
                    'ParentId': mapping['lib_id'],
                    'Recursive': 'true',
                    'IncludeItemTypes': 'Movie,Episode',
                    'Fields': 'ProviderIds,SeriesProviderIds,SeriesId,OriginalTitle'
                }
            ).json().get('Items', [])
            
            # Filter out items we already have or are in skip list
            items_to_queue = []
            skipped_count = 0
            fill_missing = cfg.get('sync_missing_episodes', True)
            series_dirs = {}
            for item in items:
                item_id = item.get('Id', '')
                series_id = item.get('SeriesId', '')
                
                # Check skip list (by item ID or parent series ID)
                if item_id in skip_ids or series_id in skip_ids:
                    skipped_count += 1
                    continue
                
                if local_id_cache and not include_existing:
                    # Skip anything already local: the item itself (ids or title/year)
                    if local_match_status(item):
                        continue
                    if item.get('Type') == 'Episode' and series_exists_locally(
                            item.get('SeriesProviderIds'), [item.get('SeriesName')]):
                        # A show you already have: fill in only its missing episodes, in its existing folder
                        if not fill_missing or (item.get('ParentIndexNumber') or 0) == 0:
                            continue
                        sid = item.get('SeriesId')
                        if sid not in series_dirs:
                            series_dirs[sid] = _sync_series_dir(server, headers, user_id, sid)
                        if not series_dirs[sid]:
                            continue   # couldn't find the show's folder - don't risk a duplicate folder
                        item['_series_dir'] = series_dirs[sid]
                items_to_queue.append(item)
            
            if skipped_count > 0:
                log(f"Sync: Skipped {skipped_count} items from skip list")
            
            # Sort based on download order
            items_to_queue = sort_download_queue(items_to_queue, download_order)
            
            queued = 0
            for item in items_to_queue:
                tid = generate_id()
                queue_item(server, item, mapping['local_path'], tid, cfg.get('speed_limit_kbs', 0),
                           series_dir=item.get('_series_dir'))
                queued += 1
            
            log(f"Sync: Queued {queued} items from {server['name']}")
            
        except Exception as e:
            log(f"Sync Error ({server['name']}): {e}")
    
    log("â”€â”€â”€ Sync Finished â”€â”€â”€")


# --- Application Startup ---

# --- *arr Integration (Pro) ---

def test_arr_connection(arr_type, url, api_key):
    """Test connection to Sonarr/Radarr/Lidarr"""
    if not url or not api_key:
        return {'success': False, 'error': 'URL and API key required'}

    # Clean up URL
    url = url.rstrip('/')

    # Lidarr uses API v1, Sonarr/Radarr use v3
    api_version = 'v1' if arr_type == 'lidarr' else 'v3'

    # Log for debugging
    log(f"[ARR TEST] Testing {arr_type} at {url} (API {api_version})")

    try:
        response = requests.get(
            f"{url}/api/{api_version}/system/status",
            headers={'X-Api-Key': api_key},
            timeout=10
        )
        if response.ok:
            data = response.json()
            return {
                'success': True,
                'version': data.get('version', 'Unknown'),
                'name': data.get('instanceName', arr_type.capitalize())
            }

        # Provide more specific error messages
        if response.status_code == 401:
            return {'success': False, 'error': '401 Unauthorized - Check your API key (Settings > General > API Key in Sonarr/Radarr)'}
        elif response.status_code == 404:
            return {'success': False, 'error': '404 Not Found - Check URL (should be http://host:port without /api)'}
        elif response.status_code == 403:
            return {'success': False, 'error': '403 Forbidden - API access may be disabled or IP restricted'}
        else:
            # Try to get error message from response
            try:
                err_data = response.json()
                err_msg = err_data.get('message') or err_data.get('error') or f"HTTP {response.status_code}"
            except:
                err_msg = f"HTTP {response.status_code}"
            return {'success': False, 'error': err_msg}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'error': f'Connection failed - Is {arr_type} running at {url}?'}
    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Connection timed out'}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def jl_to_arr_path(path, cfg=None):
    """Translate a JellyLooter path (/storage/...) to the path the *arr apps see."""
    cfg = cfg or load_config()
    arr_storage = (cfg.get('arr_storage_path') or '').rstrip('/')
    if arr_storage and (path == '/storage' or path.startswith('/storage/')):
        return arr_storage + path[len('/storage'):]
    for m in cfg.get('arr_path_mappings', []) or []:
        jl = (m.get('remotePath') or m.get('from') or '').rstrip('/')
        arr = (m.get('localPath') or m.get('to') or '').rstrip('/')
        if jl and (path == jl or path.startswith(jl + '/')):
            return arr + path[len(jl):]
    return path


def _arr_pick_root(roots, arr_dest):
    """Choose the *arr root folder that contains arr_dest (else the first one)."""
    paths = [r.get('path', '').rstrip('/') for r in roots if r.get('path')]
    best = [p for p in paths if arr_dest == p or arr_dest.startswith(p + '/')]
    if best:
        return max(best, key=len)
    return paths[0] if paths else None


def arr_ensure_added(kind, provider_ids, title, year, dest_dir, monitor_new=None):
    """Step one of a download (#10): make sure Sonarr/Radarr/Lidarr know about the show/movie/artist.

    Adds it monitored, WITHOUT an indexer search, in the root folder matching the download destination.
    Returns a short status string for the log/UI.
    """
    if not is_feature_available('arr_integration'):
        return 'arr integration needs Pro'
    cfg = load_config()
    if not cfg.get('arr_auto_import', True):
        return 'auto-import disabled'
    pid = {k.lower(): v for k, v in (provider_ids or {}).items() if v}
    app = {'series': 'sonarr', 'movie': 'radarr', 'artist': 'lidarr'}[kind]
    url = (cfg.get(f'{app}_url') or '').rstrip('/')
    key = cfg.get(f'{app}_api_key') or ''
    if not url or not key:
        return f'{app} not configured'
    api = 'v1' if app == 'lidarr' else 'v3'
    H = {'X-Api-Key': key}
    try:
        roots = requests.get(f"{url}/api/{api}/rootfolder", headers=H, timeout=10).json()
        profiles = requests.get(f"{url}/api/{api}/qualityprofile", headers=H, timeout=10).json()
        root = _arr_pick_root(roots, jl_to_arr_path(dest_dir, cfg))
        if not root or not profiles:
            return f'{app}: no root folder / quality profile configured'
        if app == 'sonarr':
            existing = requests.get(f"{url}/api/v3/series", headers=H, timeout=20).json()
            match = next((s for s in existing if (pid.get('tvdb') and str(s.get('tvdbId')) == str(pid['tvdb'])) or
                          (pid.get('imdb') and s.get('imdbId') == pid['imdb'])), None)
            if match:
                if monitor_new and not match.get('monitored'):
                    full = requests.get(f"{url}/api/v3/series/{match['id']}", headers=H, timeout=20).json()
                    full['monitored'] = True
                    requests.put(f"{url}/api/v3/series/{match['id']}", headers=H, json=full, timeout=30)
                    log(f"📡 [SONARR] Now monitoring \"{match.get('title')}\" for new episodes")
                    return 'already in Sonarr - now monitored for new episodes'
                return 'already in Sonarr'
            term = f"tvdb:{pid['tvdb']}" if pid.get('tvdb') else (f"imdb:{pid['imdb']}" if pid.get('imdb') else title)
            found = requests.get(f"{url}/api/v3/series/lookup", headers=H, params={'term': term}, timeout=20).json()
            if not found:
                return f'Sonarr could not find "{title}"'
            body = dict(found[0])
            # monitor_new: None = not asked (ended show), True = watch for new episodes, False = don't monitor
            if monitor_new is True:
                monitored, monitor_opt = True, 'future'
            elif monitor_new is False:
                monitored, monitor_opt = False, 'none'
            else:
                monitored, monitor_opt = True, 'all'
            body.update(qualityProfileId=profiles[0]['id'], rootFolderPath=root, monitored=monitored, seasonFolder=True,
                        addOptions={'searchForMissingEpisodes': False, 'monitor': monitor_opt})
            r = requests.post(f"{url}/api/v3/series", headers=H, json=body, timeout=30)
        elif app == 'radarr':
            existing = requests.get(f"{url}/api/v3/movie", headers=H, timeout=20).json()
            if any((pid.get('tmdb') and str(m.get('tmdbId')) == str(pid['tmdb'])) or
                   (pid.get('imdb') and m.get('imdbId') == pid['imdb']) for m in existing):
                return 'already in Radarr'
            if pid.get('tmdb'):
                found = [requests.get(f"{url}/api/v3/movie/lookup/tmdb", headers=H, params={'tmdbId': pid['tmdb']}, timeout=20).json()]
            else:
                term = f"imdb:{pid['imdb']}" if pid.get('imdb') else f"{title} {year or ''}".strip()
                found = requests.get(f"{url}/api/v3/movie/lookup", headers=H, params={'term': term}, timeout=20).json()
            if not found or not found[0]:
                return f'Radarr could not find "{title}"'
            body = dict(found[0])
            body.update(qualityProfileId=profiles[0]['id'], rootFolderPath=root, monitored=True,
                        addOptions={'searchForMovie': False})
            r = requests.post(f"{url}/api/v3/movie", headers=H, json=body, timeout=30)
        else:
            existing = requests.get(f"{url}/api/v1/artist", headers=H, timeout=20).json()
            mbid = pid.get('musicbrainzartist')
            if any((mbid and a.get('foreignArtistId') == mbid) or a.get('artistName', '').lower() == (title or '').lower() for a in existing):
                return 'already in Lidarr'
            term = f"lidarr:{mbid}" if mbid else title
            found = requests.get(f"{url}/api/v1/artist/lookup", headers=H, params={'term': term}, timeout=20).json()
            meta = requests.get(f"{url}/api/v1/metadataprofile", headers=H, timeout=10).json()
            if not found or not meta:
                return f'Lidarr could not find "{title}"'
            body = dict(found[0])
            body.update(qualityProfileId=profiles[0]['id'], metadataProfileId=meta[0]['id'], rootFolderPath=root,
                        monitored=True, addOptions={'searchForMissingAlbums': False, 'monitor': 'all'})
            r = requests.post(f"{url}/api/v1/artist", headers=H, json=body, timeout=30)
        if r.ok:
            log(f"📡 [{app.upper()}] Added \"{title}\" (root {root}, no search) before downloading")
            return f'added to {app.capitalize()}'
        return f'{app} refused: HTTP {r.status_code} {r.text[:120]}'
    except Exception as e:
        return f'{app} error: {type(e).__name__}: {e}'


def _arr_add_for_download(server, item_id, base_path, monitor_new=None):
    """Background: look up the item being downloaded and add its show/movie/artist to the *arr app."""
    try:
        headers = get_auth_header(server['key'])
        item = requests.get(f"{server['url']}/Items", headers=headers, timeout=15,
                            params={'Ids': item_id, 'Fields': 'ProviderIds,ProductionYear'}).json().get('Items', [{}])[0]
        t = item.get('Type')
        if t in ('Season', 'Episode') and item.get('SeriesId'):
            item = requests.get(f"{server['url']}/Items", headers=headers, timeout=15,
                                params={'Ids': item['SeriesId'], 'Fields': 'ProviderIds,ProductionYear'}).json().get('Items', [{}])[0]
            t = 'Series'
        kind = {'Series': 'series', 'Movie': 'movie', 'MusicArtist': 'artist'}.get(t)
        if t in ('MusicAlbum', 'Audio') and item.get('AlbumArtist'):
            kind, item = 'artist', {'Name': item.get('AlbumArtist'), 'ProviderIds': {}}
        if not kind:
            return
        status = arr_ensure_added(kind, item.get('ProviderIds'), item.get('Name'), item.get('ProductionYear'), base_path,
                                  monitor_new=monitor_new if kind == 'series' else None)
        log(f"📡 [ARR] {item.get('Name')}: {status}")
    except Exception as e:
        log(f"📡 [ARR] Could not add item before download: {e}")


def notify_arr_download(filepath, media_type=None, provider_ids=None):
    """
    Notify *arr apps about downloaded file, add to library if needed, and trigger scan.
    
    Args:
        filepath: Path to the downloaded file
        media_type: 'movie', 'episode', or None (auto-detect)
        provider_ids: Dict with 'imdb', 'tmdb', 'tvdb' IDs
    """
    if not is_feature_available('arr_integration'):
        log(f"ðŸ“¡ [ARR] Skipping - *arr integration not available (Pro feature)")
        return
    
    cfg = load_config()
    
    # Check if auto-import is enabled
    if not cfg.get('arr_auto_import', True):
        log(f"ðŸ“¡ [ARR] Skipping - arr_auto_import is disabled")
        return
    
    provider_ids = provider_ids or {}
    log(f"ðŸ“¡ [ARR] notify_arr_download called for: {os.path.basename(filepath)}")
    log(f"ðŸ“¡ [ARR] Raw provider IDs received: {provider_ids}")
    log(f"ðŸ“¡ [ARR] Media type: {media_type}")
    
    # Get the folder containing the file (for targeted scan)
    folder_path = os.path.dirname(filepath)
    
    # Apply path mappings if configured
    # Mappings convert JellyLooter paths to *arr paths
    # remotePath = JellyLooter's path (e.g., /storage/data/media/anime)
    # localPath = *arr's path (e.g., /anime)
    path_mappings = cfg.get('arr_path_mappings', [])
    
    # Also support legacy single mapping
    if not path_mappings:
        legacy_from = cfg.get('arr_path_mapping_from', '').rstrip('/')
        legacy_to = cfg.get('arr_path_mapping_to', '').rstrip('/')
        if legacy_from and legacy_to:
            path_mappings = [{'remotePath': legacy_from, 'localPath': legacy_to}]
    
    # Get base path prefix for simple prefix stripping (arr_base_path_prefix config)
    base_path_prefix = cfg.get('arr_base_path_prefix', '').rstrip('/')
    
    mapped_folder_path = folder_path
    mapping_applied = False
    if cfg.get('arr_storage_path') and folder_path.startswith('/storage'):
        mapped_folder_path = jl_to_arr_path(folder_path, cfg)
        mapping_applied = True
        log(f"📡 [ARR] ✅ {folder_path} -> {mapped_folder_path}")

    log(f"ðŸ“¡ [ARR] Looking for path mapping for: {folder_path}")
    
    # First try explicit mappings
    for mapping in path_mappings:
        # Support both new format (remotePath/localPath) and old format (from/to)
        # remotePath = JellyLooter path, localPath = *arr path
        jl_path = (mapping.get('remotePath') or mapping.get('from') or '').rstrip('/')
        arr_path = (mapping.get('localPath') or mapping.get('to') or '').rstrip('/')
        mapping_source = mapping.get('source', 'manual')
        
        if jl_path and folder_path.startswith(jl_path):
            # Found a match - convert JellyLooter path to *arr path
            mapped_folder_path = folder_path.replace(jl_path, arr_path, 1)
            log(f"ðŸ“¡ [ARR] âœ… Path mapping matched ({mapping_source})!")
            log(f"ðŸ“¡ [ARR]    {folder_path} -> {mapped_folder_path}")
            mapping_applied = True
            break
    
    # If no explicit mapping matched, try base path prefix stripping
    if not mapping_applied and base_path_prefix and folder_path.startswith(base_path_prefix):
        mapped_folder_path = folder_path[len(base_path_prefix):]
        if not mapped_folder_path.startswith('/'):
            mapped_folder_path = '/' + mapped_folder_path
        log(f"ðŸ“¡ [ARR] âœ… Base path prefix stripped!")
        log(f"ðŸ“¡ [ARR]    {folder_path} -> {mapped_folder_path}")
        mapping_applied = True
    
    # If still no match, try auto-detecting based on local server path mappings
    if not mapping_applied:
        local_path_mappings = cfg.get('path_mappings', [])
        for lm in local_path_mappings:
            local_path = lm.get('local_path', '').rstrip('/')
            if local_path and folder_path.startswith(local_path):
                # Strip the local server base path
                mapped_folder_path = folder_path[len(local_path):]
                if not mapped_folder_path.startswith('/'):
                    mapped_folder_path = '/' + mapped_folder_path
                log(f"ðŸ“¡ [ARR] âœ… Auto-stripped local server base path!")
                log(f"ðŸ“¡ [ARR]    {folder_path} -> {mapped_folder_path}")
                mapping_applied = True
                break
    
    if not mapping_applied:
        log(f"ðŸ“¡ [ARR] âš ï¸ No path mapping matched - using original path")
        log(f"ðŸ“¡ [ARR] TIP: Set 'arr_base_path_prefix' in config to auto-strip base path")
        log(f"ðŸ“¡ [ARR] Example: arr_base_path_prefix=/storage/data/media would convert")
        log(f"ðŸ“¡ [ARR]   {folder_path} -> {folder_path.replace('/storage/data/media', '', 1) if '/storage/data/media' in folder_path else '(path)'}")
        if path_mappings:
            log(f"ðŸ“¡ [ARR] Available mappings ({len(path_mappings)}):")
            for i, m in enumerate(path_mappings[:5]):  # Show first 5
                jl = m.get('remotePath') or m.get('from', '')
                arr = m.get('localPath') or m.get('to', '')
                log(f"ðŸ“¡ [ARR]   {i+1}. '{jl}' -> '{arr}'")
    
    # Auto-detect media type if not provided
    if media_type is None:
        lower_path = filepath.lower()
        if '/movies/' in lower_path or 'movie' in lower_path:
            media_type = 'movie'
        elif '/tv/' in lower_path or '/series/' in lower_path or 'season' in lower_path or re.search(r's\d{2}e\d{2}', lower_path, re.IGNORECASE):
            media_type = 'episode'
        log(f"ðŸ“¡ [ARR] Auto-detected media type: {media_type}")
    
    notified = False
    
    # Notify Radarr for movies
    if media_type in ('movie', None):
        radarr_url = cfg.get('radarr_url', '').rstrip('/')
        radarr_key = cfg.get('radarr_api_key', '')
        
        if radarr_url and radarr_key:
            log(f"ðŸ“¡ [RADARR] Attempting to notify Radarr at {radarr_url}")
            try:
                headers = {'X-Api-Key': radarr_key, 'Content-Type': 'application/json'}
                
                # Try to find or add the movie
                tmdb_id = provider_ids.get('tmdb') or provider_ids.get('Tmdb')
                imdb_id = provider_ids.get('imdb') or provider_ids.get('Imdb')
                
                log(f"ðŸ“¡ [RADARR] Looking up movie - TMDB: {tmdb_id}, IMDB: {imdb_id}")
                
                movie_id = None
                
                # First check if movie exists in Radarr
                if tmdb_id:
                    lookup_resp = requests.get(
                        f"{radarr_url}/api/v3/movie?tmdbId={tmdb_id}",
                        headers=headers, timeout=10
                    )
                    log(f"ðŸ“¡ [RADARR] Lookup by TMDB response: {lookup_resp.status_code}")
                    if lookup_resp.ok:
                        movies = lookup_resp.json()
                        if movies:
                            movie_id = movies[0].get('id')
                            log(f"ðŸ“¡ [RADARR] Found movie in library (ID: {movie_id})")
                        else:
                            log(f"ðŸ“¡ [RADARR] Movie not in library yet")
                
                # If not found, try to add it
                if not movie_id and (tmdb_id or imdb_id):
                    log(f"ðŸ“¡ [RADARR] Attempting to add movie to library...")
                    
                    # Get root folder
                    root_resp = requests.get(f"{radarr_url}/api/v3/rootfolder", headers=headers, timeout=10)
                    root_folders = root_resp.json() if root_resp.ok else []
                    root_path = root_folders[0]['path'] if root_folders else mapped_folder_path
                    log(f"ðŸ“¡ [RADARR] Root folder: {root_path}")
                    
                    # Get quality profile
                    profile_resp = requests.get(f"{radarr_url}/api/v3/qualityprofile", headers=headers, timeout=10)
                    profiles = profile_resp.json() if profile_resp.ok else []
                    quality_profile_id = profiles[0]['id'] if profiles else 1
                    
                    # Lookup movie info
                    lookup_url = f"{radarr_url}/api/v3/movie/lookup"
                    if tmdb_id:
                        lookup_url += f"?term=tmdb:{tmdb_id}"
                    elif imdb_id:
                        lookup_url += f"?term=imdb:{imdb_id}"
                    
                    lookup_resp = requests.get(lookup_url, headers=headers, timeout=15)
                    if lookup_resp.ok:
                        lookup_results = lookup_resp.json()
                        if lookup_results:
                            movie_data = lookup_results[0]
                            
                            # Add movie to Radarr
                            add_data = {
                                'title': movie_data.get('title'),
                                'tmdbId': movie_data.get('tmdbId'),
                                'year': movie_data.get('year'),
                                'qualityProfileId': quality_profile_id,
                                'rootFolderPath': root_path,
                                'monitored': True,
                                'addOptions': {
                                    'searchForMovie': False
                                }
                            }
                            
                            add_resp = requests.post(
                                f"{radarr_url}/api/v3/movie",
                                headers=headers,
                                json=add_data,
                                timeout=15
                            )
                            
                            if add_resp.ok:
                                movie_id = add_resp.json().get('id')
                                log(f"ðŸ“¡ [RADARR] Added movie: {movie_data.get('title')} (ID: {movie_id})")
                            elif add_resp.status_code == 400:
                                log(f"ðŸ“¡ [RADARR] Movie already exists or invalid: {add_resp.text[:200]}")
                            else:
                                log(f"âš ï¸ [RADARR] Failed to add movie: {add_resp.status_code} - {add_resp.text[:200]}")
                
                # Trigger scan - try multiple methods
                scan_success = False
                
                # Method 1: DownloadedMoviesScan (for download client integration)
                log(f"ðŸ“¡ [RADARR] Triggering DownloadedMoviesScan for: {mapped_folder_path}")
                import_resp = requests.post(
                    f"{radarr_url}/api/v3/command",
                    headers=headers,
                    json={
                        'name': 'DownloadedMoviesScan',
                        'path': mapped_folder_path
                    },
                    timeout=10
                )
                log(f"ðŸ“¡ [RADARR] DownloadedMoviesScan response: {import_resp.status_code}")
                if import_resp.ok:
                    log(f"âœ… [RADARR] DownloadedMoviesScan triggered successfully")
                    scan_success = True
                else:
                    log(f"âš ï¸ [RADARR] DownloadedMoviesScan failed: {import_resp.text[:200]}")
                
                # Method 2: RescanMovie if we have movie ID
                if movie_id:
                    log(f"ðŸ“¡ [RADARR] Triggering RescanMovie for ID: {movie_id}")
                    rescan_resp = requests.post(
                        f"{radarr_url}/api/v3/command",
                        headers=headers,
                        json={'name': 'RescanMovie', 'movieId': movie_id},
                        timeout=10
                    )
                    log(f"ðŸ“¡ [RADARR] RescanMovie response: {rescan_resp.status_code}")
                    if rescan_resp.ok:
                        log(f"âœ… [RADARR] RescanMovie triggered successfully")
                        scan_success = True
                
                # Method 3: RefreshMovie (updates metadata AND rescans disk)
                if movie_id:
                    log(f"ðŸ“¡ [RADARR] Triggering RefreshMovie for ID: {movie_id}")
                    refresh_resp = requests.post(
                        f"{radarr_url}/api/v3/command",
                        headers=headers,
                        json={'name': 'RefreshMovie', 'movieId': movie_id},
                        timeout=10
                    )
                    if refresh_resp.ok:
                        log(f"âœ… [RADARR] RefreshMovie triggered successfully")
                        scan_success = True
                
                notified = scan_success
                    
            except Exception as e:
                log(f"âŒ [RADARR] Notification failed: {type(e).__name__}: {e}")
        else:
            if media_type == 'movie':
                log(f"ðŸ“¡ [RADARR] Skipping - Radarr not configured (url: {bool(radarr_url)}, key: {bool(radarr_key)})")
    
    # Notify Sonarr for episodes/series
    if media_type in ('episode', 'series', None):
        sonarr_url = cfg.get('sonarr_url', '').rstrip('/')
        sonarr_key = cfg.get('sonarr_api_key', '')
        
        if sonarr_url and sonarr_key:
            log(f"ðŸ“¡ [SONARR] Attempting to notify Sonarr at {sonarr_url}")
            try:
                headers = {'X-Api-Key': sonarr_key, 'Content-Type': 'application/json'}
                
                # Handle both string and int TVDB IDs, and different casing
                tvdb_id = provider_ids.get('tvdb') or provider_ids.get('Tvdb')
                imdb_id = provider_ids.get('imdb') or provider_ids.get('Imdb')
                
                # Ensure tvdb_id is a string/int, not None
                if tvdb_id:
                    tvdb_id = str(tvdb_id).strip()
                if imdb_id:
                    imdb_id = str(imdb_id).strip()
                
                log(f"ðŸ“¡ [SONARR] Looking up series - TVDB: {tvdb_id}, IMDB: {imdb_id}")
                
                series_id = None
                
                # Check if series exists in Sonarr
                if tvdb_id:
                    try:
                        lookup_resp = requests.get(
                            f"{sonarr_url}/api/v3/series?tvdbId={tvdb_id}",
                            headers=headers, timeout=10
                        )
                        log(f"ðŸ“¡ [SONARR] Lookup by TVDB response: {lookup_resp.status_code}")
                        if lookup_resp.ok:
                            series_list = lookup_resp.json()
                            if series_list:
                                series_id = series_list[0].get('id')
                                log(f"ðŸ“¡ [SONARR] Found series in library (ID: {series_id})")
                            else:
                                log(f"ðŸ“¡ [SONARR] Series not in library yet (empty result)")
                        else:
                            log(f"âš ï¸ [SONARR] Lookup failed: {lookup_resp.status_code}")
                    except Exception as lookup_err:
                        log(f"âš ï¸ [SONARR] Lookup error: {lookup_err}")
                
                # If not found, try to add it
                if not series_id and (tvdb_id or imdb_id):
                    log(f"ðŸ“¡ [SONARR] Series not in library - attempting to add...")
                    
                    # Get root folders
                    root_resp = requests.get(f"{sonarr_url}/api/v3/rootfolder", headers=headers, timeout=10)
                    root_folders = root_resp.json() if root_resp.ok else []
                    log(f"ðŸ“¡ [SONARR] Available root folders: {[rf.get('path') for rf in root_folders]}")
                    
                    # Try to find the best matching root folder for our mapped path
                    root_path = None
                    if root_folders:
                        # First, try to find a root folder that matches our mapped path
                        for rf in root_folders:
                            rf_path = rf.get('path', '')
                            if mapped_folder_path.startswith(rf_path):
                                root_path = rf_path
                                log(f"ðŸ“¡ [SONARR] Matched root folder: {root_path}")
                                break
                        
                        # If no match, use the first root folder
                        if not root_path:
                            root_path = root_folders[0]['path']
                            log(f"ðŸ“¡ [SONARR] Using default root folder: {root_path}")
                    else:
                        # Extract root from mapped path (e.g., /anime from /anime/Show/Season 01)
                        path_parts = mapped_folder_path.strip('/').split('/')
                        if path_parts:
                            root_path = '/' + path_parts[0]
                        else:
                            root_path = '/tv'
                        log(f"ðŸ“¡ [SONARR] No root folders found, guessing: {root_path}")
                    
                    # Get quality profile
                    profile_resp = requests.get(f"{sonarr_url}/api/v3/qualityprofile", headers=headers, timeout=10)
                    profiles = profile_resp.json() if profile_resp.ok else []
                    quality_profile_id = profiles[0]['id'] if profiles else 1
                    log(f"ðŸ“¡ [SONARR] Using quality profile ID: {quality_profile_id}")
                    
                    # Lookup series info using proper API format
                    log(f"ðŸ“¡ [SONARR] Looking up series info for add...")
                    lookup_results = []
                    
                    if tvdb_id:
                        lookup_resp = requests.get(
                            f"{sonarr_url}/api/v3/series/lookup",
                            headers=headers,
                            params={'term': f'tvdb:{tvdb_id}'},
                            timeout=15
                        )
                        log(f"ðŸ“¡ [SONARR] Lookup by TVDB response: {lookup_resp.status_code}")
                        if lookup_resp.ok:
                            lookup_results = lookup_resp.json()
                    
                    # Fallback to IMDB if TVDB didn't work
                    if not lookup_results and imdb_id:
                        lookup_resp = requests.get(
                            f"{sonarr_url}/api/v3/series/lookup",
                            headers=headers,
                            params={'term': f'imdb:{imdb_id}'},
                            timeout=15
                        )
                        log(f"ðŸ“¡ [SONARR] Lookup by IMDB response: {lookup_resp.status_code}")
                        if lookup_resp.ok:
                            lookup_results = lookup_resp.json()
                    
                    log(f"ðŸ“¡ [SONARR] Lookup found {len(lookup_results)} result(s)")
                    
                    if lookup_results:
                        series_data = lookup_results[0]
                        log(f"ðŸ“¡ [SONARR] Adding series: {series_data.get('title')} (TVDB: {series_data.get('tvdbId')})")
                        
                        # Add series to Sonarr
                        add_data = {
                            'title': series_data.get('title'),
                            'tvdbId': series_data.get('tvdbId'),
                            'year': series_data.get('year'),
                            'qualityProfileId': quality_profile_id,
                            'rootFolderPath': root_path,
                            'monitored': True,
                            'seasonFolder': True,
                            'addOptions': {
                                'searchForMissingEpisodes': False
                            }
                        }
                        
                        log(f"ðŸ“¡ [SONARR] Add request: rootFolder={root_path}, title={series_data.get('title')}")
                        add_resp = requests.post(
                            f"{sonarr_url}/api/v3/series",
                            headers=headers,
                            json=add_data,
                            timeout=15
                        )
                        
                        if add_resp.ok:
                            series_id = add_resp.json().get('id')
                            log(f"âœ… [SONARR] Added series successfully! ID: {series_id}")
                        elif add_resp.status_code == 400:
                            error_text = add_resp.text
                            log(f"âš ï¸ [SONARR] Add failed (400): {error_text[:300]}")
                            # Try to extract series ID if it already exists
                            if 'already been added' in error_text.lower():
                                # Try to get series ID by searching
                                search_resp = requests.get(
                                    f"{sonarr_url}/api/v3/series?tvdbId={series_data.get('tvdbId')}",
                                    headers=headers, timeout=10
                                )
                                if search_resp.ok and search_resp.json():
                                    series_id = search_resp.json()[0].get('id')
                                    log(f"ðŸ“¡ [SONARR] Found existing series ID: {series_id}")
                        else:
                            log(f"âŒ [SONARR] Add failed: {add_resp.status_code} - {add_resp.text[:300]}")
                    else:
                        log(f"âš ï¸ [SONARR] Lookup returned no results for TVDB:{tvdb_id}")
                        
                        # Fallback: try to search by series title from folder path
                        # e.g., /anime/Zombie Land SAGA tt9054354 351953/Season 01
                        try:
                            path_parts = mapped_folder_path.strip('/').split('/')
                            if len(path_parts) >= 2:
                                # Extract series name (second part, before any IDs)
                                series_folder = path_parts[1]  # e.g., "Zombie Land SAGA tt9054354 351953"
                                # Remove common ID patterns
                                import re
                                series_name = re.sub(r'\s+tt\d+.*$', '', series_folder)
                                series_name = re.sub(r'\s+\d{5,}.*$', '', series_name)
                                series_name = series_name.strip()
                                
                                if series_name:
                                    log(f"ðŸ“¡ [SONARR] Trying fallback search by title: {series_name}")
                                    title_lookup = requests.get(
                                        f"{sonarr_url}/api/v3/series/lookup",
                                        headers=headers,
                                        params={'term': series_name},
                                        timeout=15
                                    )
                                    if title_lookup.ok:
                                        title_results = title_lookup.json()
                                        log(f"ðŸ“¡ [SONARR] Title search found {len(title_results)} result(s)")
                                        if title_results:
                                            series_data = title_results[0]
                                            log(f"ðŸ“¡ [SONARR] Best match: {series_data.get('title')}")
                        except Exception as fallback_err:
                            log(f"âš ï¸ [SONARR] Fallback search failed: {fallback_err}")
                
                # Trigger scan - try multiple methods
                scan_success = False
                
                # Method 1: DownloadedEpisodesScan
                log(f"ðŸ“¡ [SONARR] Triggering DownloadedEpisodesScan for: {mapped_folder_path}")
                import_resp = requests.post(
                    f"{sonarr_url}/api/v3/command",
                    headers=headers,
                    json={
                        'name': 'DownloadedEpisodesScan',
                        'path': mapped_folder_path
                    },
                    timeout=10
                )
                log(f"ðŸ“¡ [SONARR] DownloadedEpisodesScan response: {import_resp.status_code}")
                if import_resp.ok:
                    log(f"âœ… [SONARR] DownloadedEpisodesScan triggered successfully")
                    scan_success = True
                else:
                    log(f"âš ï¸ [SONARR] DownloadedEpisodesScan failed: {import_resp.text[:200]}")
                
                # Method 2: RescanSeries if we have series ID
                if series_id:
                    log(f"ðŸ“¡ [SONARR] Triggering RescanSeries for ID: {series_id}")
                    rescan_resp = requests.post(
                        f"{sonarr_url}/api/v3/command",
                        headers=headers,
                        json={'name': 'RescanSeries', 'seriesId': series_id},
                        timeout=10
                    )
                    log(f"ðŸ“¡ [SONARR] RescanSeries response: {rescan_resp.status_code}")
                    if rescan_resp.ok:
                        log(f"âœ… [SONARR] RescanSeries triggered successfully")
                        scan_success = True
                
                # Method 3: RefreshSeries (updates metadata AND rescans disk)
                if series_id:
                    log(f"ðŸ“¡ [SONARR] Triggering RefreshSeries for ID: {series_id}")
                    refresh_resp = requests.post(
                        f"{sonarr_url}/api/v3/command",
                        headers=headers,
                        json={'name': 'RefreshSeries', 'seriesId': series_id},
                        timeout=10
                    )
                    if refresh_resp.ok:
                        log(f"âœ… [SONARR] RefreshSeries triggered successfully")
                        scan_success = True
                
                notified = notified or scan_success
                    
            except Exception as e:
                log(f"âŒ [SONARR] Notification failed: {type(e).__name__}: {e}")
        else:
            if media_type in ('episode', 'series'):
                log(f"ðŸ“¡ [SONARR] Skipping - Sonarr not configured (url: {bool(sonarr_url)}, key: {bool(sonarr_key)})")
    
    if not notified:
        log(f"âš ï¸ [ARR] No *arr notification sent for: {os.path.basename(filepath)}")
    
    # Notify Lidarr for music
    if not notified and media_type in ('music', None):
        lidarr_url = cfg.get('lidarr_url')
        lidarr_key = cfg.get('lidarr_api_key')
        
        if lidarr_url and lidarr_key:
            try:
                requests.post(
                    f"{lidarr_url.rstrip('/')}/api/v1/command",
                    headers={'X-Api-Key': lidarr_key, 'Content-Type': 'application/json'},
                    json={'name': 'DownloadedAlbumsScan', 'path': folder_path},
                    timeout=10
                )
                log(f"ðŸ“¡ Notified Lidarr: {os.path.basename(filepath)}")
            except Exception as e:
                log(f"âš ï¸ Lidarr notification failed: {e}")


@app.route('/api/test_arr', methods=['POST'])
@login_required
def api_test_arr():
    """Test *arr connection"""
    if not is_feature_available('arr_integration'):
        return jsonify({'success': False, 'error': 'Pro feature - upgrade to unlock'})
    
    data = request.json
    arr_type = data.get('type', 'sonarr')
    url = data.get('url', '').strip()
    api_key = data.get('api_key', '').strip()
    
    result = test_arr_connection(arr_type, url, api_key)
    return jsonify(result)


@app.route('/api/fetch_arr_path_mappings', methods=['POST'])
@login_required
def api_fetch_arr_path_mappings():
    """Fetch root folders from Radarr/Sonarr and auto-detect JellyLooter paths by scanning filesystem"""
    if not is_feature_available('arr_integration'):
        return jsonify({'success': False, 'error': 'Pro feature - upgrade to unlock'})
    
    cfg = load_config()
    mappings = []
    errors = []
    
    # Collect all *arr root folder paths
    arr_root_folders = []  # List of (arr_path, source, free_space)
    
    # Fetch from Sonarr
    sonarr_url = cfg.get('sonarr_url', '').rstrip('/')
    sonarr_key = cfg.get('sonarr_api_key', '')
    
    if sonarr_url and sonarr_key:
        try:
            resp = requests.get(
                f"{sonarr_url}/api/v3/rootfolder",
                headers={'X-Api-Key': sonarr_key},
                timeout=10
            )
            if resp.ok:
                for rf in resp.json():
                    arr_path = rf.get('path', '').rstrip('/')
                    if arr_path:
                        arr_root_folders.append((arr_path, 'Sonarr', rf.get('freeSpace', 0)))
                log(f"ðŸ“¡ Fetched {len([x for x in arr_root_folders if x[1] == 'Sonarr'])} root folder(s) from Sonarr")
            else:
                errors.append(f"Sonarr: HTTP {resp.status_code}")
        except Exception as e:
            errors.append(f"Sonarr: {str(e)}")
            log(f"âš ï¸ Sonarr error: {e}")
    
    # Fetch from Radarr
    radarr_url = cfg.get('radarr_url', '').rstrip('/')
    radarr_key = cfg.get('radarr_api_key', '')
    
    if radarr_url and radarr_key:
        try:
            resp = requests.get(
                f"{radarr_url}/api/v3/rootfolder",
                headers={'X-Api-Key': radarr_key},
                timeout=10
            )
            if resp.ok:
                for rf in resp.json():
                    arr_path = rf.get('path', '').rstrip('/')
                    if arr_path:
                        # Check if already from Sonarr
                        existing = next((x for x in arr_root_folders if x[0] == arr_path), None)
                        if existing:
                            # Update source to Both
                            idx = arr_root_folders.index(existing)
                            arr_root_folders[idx] = (arr_path, 'Both', rf.get('freeSpace', 0))
                        else:
                            arr_root_folders.append((arr_path, 'Radarr', rf.get('freeSpace', 0)))
                log(f"ðŸ“¡ Fetched root folders from Radarr")
            else:
                errors.append(f"Radarr: HTTP {resp.status_code}")
        except Exception as e:
            errors.append(f"Radarr: {str(e)}")
            log(f"âš ï¸ Radarr error: {e}")
    
    if not arr_root_folders:
        return jsonify({
            'success': False,
            'error': 'No root folders found. Check *arr URLs and API keys.',
            'errors': errors
        })
    
    log(f"ðŸ“¡ [ARR] Found {len(arr_root_folders)} unique root folder(s) to map")
    
    # Now auto-detect JellyLooter paths for each *arr root folder
    # Strategy: Search common mount points and find where each folder actually exists
    
    # Build list of potential base paths to search
    search_bases = set()
    
    # 1. Get from download_path config
    download_path = cfg.get('download_path', '')
    if download_path:
        # Add the download path and its parents
        search_bases.add(download_path.rstrip('/'))
        parts = download_path.rstrip('/').split('/')
        for i in range(2, len(parts)):
            search_bases.add('/'.join(parts[:i]))
    
    # 2. Get from local server path mappings
    for lm in cfg.get('path_mappings', []):
        local_path = lm.get('local_path', '').rstrip('/')
        if local_path:
            search_bases.add(local_path)
            # Also add parent paths
            parts = local_path.split('/')
            for i in range(2, len(parts)):
                search_bases.add('/'.join(parts[:i]))
    
    # 3. Add common mount points
    common_mounts = [
        '/storage', '/storage/data', '/storage/data/media',
        '/mnt', '/mnt/user', '/mnt/media', '/mnt/data',
        '/data', '/data/media',
        '/media', '/srv', '/home',
        '/share', '/shares', '/volume1', '/volume2'
    ]
    search_bases.update(common_mounts)
    
    # 4. Scan /mnt and /storage for subdirectories
    for scan_root in ['/mnt', '/storage', '/data']:
        if os.path.isdir(scan_root):
            try:
                for entry in os.listdir(scan_root):
                    full_path = os.path.join(scan_root, entry)
                    if os.path.isdir(full_path):
                        search_bases.add(full_path)
                        # Also check one level deeper
                        try:
                            for sub in os.listdir(full_path):
                                sub_path = os.path.join(full_path, sub)
                                if os.path.isdir(sub_path):
                                    search_bases.add(sub_path)
                        except:
                            pass
            except:
                pass
    
    log(f"ðŸ“¡ [ARR] Searching {len(search_bases)} potential base paths")
    
    # For each *arr root folder, find where it exists on this system
    for arr_path, source, free_space in arr_root_folders:
        jl_path = None
        
        # First check if the arr_path itself exists (no mapping needed)
        if os.path.isdir(arr_path):
            jl_path = arr_path
            log(f"ðŸ“¡ [ARR] Direct match: {arr_path} exists")
        else:
            # Get the folder name from arr_path (e.g., /anime -> anime, /tv/tv -> tv)
            arr_folder = arr_path.rstrip('/').split('/')[-1] if arr_path else ''
            
            # Search for this folder in our potential bases
            for base in sorted(search_bases, key=len, reverse=True):  # Try longer paths first
                # Try exact path match: base + arr_path
                candidate = f"{base}{arr_path}"
                if os.path.isdir(candidate):
                    jl_path = candidate
                    log(f"ðŸ“¡ [ARR] Found: {arr_path} -> {jl_path}")
                    break
                
                # Try just the folder name: base/folder
                if arr_folder:
                    candidate = f"{base}/{arr_folder}"
                    if os.path.isdir(candidate):
                        jl_path = candidate
                        log(f"ðŸ“¡ [ARR] Found by folder name: {arr_path} -> {jl_path}")
                        break
        
        # Create the mapping
        mappings.append({
            'remotePath': jl_path or '',  # JellyLooter's path (empty if not found)
            'localPath': arr_path,         # *arr's path
            'source': source,
            'freeSpace': free_space,
            'accessible': bool(jl_path and os.path.isdir(jl_path))
        })
        
        if not jl_path:
            log(f"âš ï¸ [ARR] Could not find local path for: {arr_path}")
    
    # Count accessible
    accessible_count = sum(1 for m in mappings if m.get('accessible'))
    
    # Auto-detect base path prefix for any that weren't found
    if accessible_count > 0 and accessible_count < len(mappings):
        # Find the common base from accessible mappings
        accessible_paths = [m['remotePath'] for m in mappings if m.get('accessible') and m.get('remotePath')]
        if accessible_paths:
            # Find common prefix
            common = os.path.commonpath(accessible_paths) if len(accessible_paths) > 1 else os.path.dirname(accessible_paths[0])
            if common and common != '/':
                # Try to fix unmapped paths using this base
                for m in mappings:
                    if not m.get('accessible') and not m.get('remotePath'):
                        candidate = f"{common}{m['localPath']}"
                        if os.path.isdir(candidate):
                            m['remotePath'] = candidate
                            m['accessible'] = True
                            log(f"ðŸ“¡ [ARR] Fixed using common base: {m['localPath']} -> {candidate}")
    
    # Recount
    accessible_count = sum(1 for m in mappings if m.get('accessible'))
    log(f"ðŸ“¡ [ARR] Built {len(mappings)} path mappings, {accessible_count} accessible")
    
    # Save to config
    cfg['arr_path_mappings'] = mappings
    save_config(cfg)
    
    return jsonify({
        'success': True,
        'mappings': mappings,
        'accessible_count': accessible_count,
        'errors': errors if errors else None
    })


def build_jellylooter_path(base_path, arr_path):
    """
    Build JellyLooter's path from *arr's root folder path.
    
    Examples:
    - base="/storage/data/media", arr="/anime" -> "/storage/data/media/anime"
    - base="/storage/data/media", arr="/tv/tv" -> "/storage/data/media/tv/tv"
    - base=None, arr="/anime" -> "/anime" (no mapping, same path)
    """
    if not base_path:
        return arr_path
    
    base_path = base_path.rstrip('/')
    arr_path = arr_path.rstrip('/')
    
    # If arr_path is absolute and starts with /, combine with base
    # e.g., base="/storage/data/media" + arr="/anime" -> "/storage/data/media/anime"
    if arr_path.startswith('/'):
        return f"{base_path}{arr_path}"
    else:
        return f"{base_path}/{arr_path}"


@app.route('/api/refresh_arr_cache', methods=['POST'])
@login_required
def api_refresh_arr_cache():
    """Manually refresh *arr folder cache (Pro feature)"""
    if not is_feature_available('arr_integration'):
        return jsonify({'success': False, 'error': 'Pro feature - upgrade to unlock'})
    
    # Run refresh in background
    threading.Thread(target=refresh_arr_cache, daemon=True).start()
    
    return jsonify({
        'success': True,
        'message': 'Refreshing *arr cache in background',
        'cached_series': len(_arr_cache.get('sonarr_series', {})),
        'cached_movies': len(_arr_cache.get('radarr_movies', {}))
    })


@app.route('/api/arr_cache_status')
@login_required
def api_arr_cache_status():
    """Get *arr cache status"""
    last_refresh = _arr_cache.get('last_refresh')
    return jsonify({
        'sonarr_series_count': len(_arr_cache.get('sonarr_series', {})),
        'radarr_movies_count': len(_arr_cache.get('radarr_movies', {})),
        'last_refresh': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_refresh)) if last_refresh else None
    })


# --- Analytics (Pro) ---

@app.route('/api/analytics')
@login_required
def api_analytics():
    """Get download analytics (Pro feature)"""
    if not is_feature_available('analytics'):
        return jsonify({'error': 'Pro feature - upgrade to unlock'})
    
    with download_lock:
        history_list = list(download_history)
    
    # Calculate stats
    total_downloads = len(history_list)
    total_size = sum(h.get('size', 0) for h in history_list)
    
    # Group by date
    by_date = {}
    for h in history_list:
        date = h.get('timestamp', '')[:10]
        if date not in by_date:
            by_date[date] = {'count': 0, 'size': 0}
        by_date[date]['count'] += 1
        by_date[date]['size'] += h.get('size', 0)
    
    return jsonify({
        'total_downloads': total_downloads,
        'total_size': total_size,
        'total_size_formatted': format_bytes(total_size),
        'by_date': by_date,
        'recent': history_list[:20]
    })


# --- Download Scheduling (Pro) ---

def is_within_schedule():
    """Check if current time is within download schedule"""
    cfg = load_config()
    
    if not cfg.get('download_schedule_enabled', False):
        return True  # No schedule = always allowed
    
    if not is_feature_available('scheduling'):
        return True  # Free tier = no scheduling
    
    now = datetime.datetime.now()
    current_time = now.strftime('%H:%M')
    
    start_time = cfg.get('download_schedule_start', '02:00')
    end_time = cfg.get('download_schedule_end', '06:00')
    
    # Handle overnight schedules (e.g., 22:00 - 06:00)
    if start_time <= end_time:
        return start_time <= current_time <= end_time
    else:
        return current_time >= start_time or current_time <= end_time


def get_scheduled_speed_limit():
    """Get speed limit based on time of day"""
    cfg = load_config()
    
    if not cfg.get('bandwidth_schedule_enabled', False):
        return cfg.get('speed_limit_kbs', 0)
    
    if not is_feature_available('scheduling'):
        return cfg.get('speed_limit_kbs', 0)
    
    now = datetime.datetime.now()
    current_time = now.strftime('%H:%M')
    
    night_start = cfg.get('bandwidth_night_start', '22:00')
    night_end = cfg.get('bandwidth_night_end', '06:00')
    
    # Check if it's "night" time
    if night_start <= night_end:
        is_night = night_start <= current_time <= night_end
    else:
        is_night = current_time >= night_start or current_time <= night_end
    
    if is_night:
        return cfg.get('bandwidth_night_limit_kbs', 0)
    else:
        return cfg.get('bandwidth_day_limit_kbs', 1000)


# --- Stop After Current Downloads ---

stop_after_current = False

@app.route('/api/stop_after_current', methods=['POST'])
@login_required
def api_stop_after_current():
    """Stop starting new downloads after current ones complete"""
    global stop_after_current
    stop_after_current = True
    log("ðŸ›‘ Will stop after current downloads complete")
    return jsonify({'status': 'ok', 'stop_after_current': True})


@app.route('/api/cancel_stop_after_current', methods=['POST'])
@login_required  
def api_cancel_stop_after_current():
    """Cancel stop after current"""
    global stop_after_current
    stop_after_current = False
    log("â–¶ï¸ Cancelled stop-after-current")
    return jsonify({'status': 'ok', 'stop_after_current': False})


# --- Last Location Memory ---

@app.route('/api/save_location', methods=['POST'])
@login_required
def api_save_location():
    """Save last browsed location for a server"""
    data = request.json
    server_id = data.get('server_id')
    location_id = data.get('location_id')
    location_name = data.get('location_name', '')
    
    if not server_id:
        return jsonify({'error': 'Server ID required'})
    
    cfg = load_config()
    if 'last_locations' not in cfg:
        cfg['last_locations'] = {}
    
    cfg['last_locations'][server_id] = {
        'id': location_id,
        'name': location_name,
        'timestamp': time.time()
    }
    save_config(cfg)
    
    return jsonify({'status': 'ok'})


@app.route('/api/get_location/<server_id>')
@login_required
def api_get_location(server_id):
    """Get last browsed location for a server"""
    cfg = load_config()
    location = cfg.get('last_locations', {}).get(server_id)
    return jsonify(location or {})


# ============================================================================
# Built-in WireGuard VPN with optional kill switch (Pro)
# ============================================================================
# The whole container is routed through wg0 while LAN subnets stay direct (local Jellyfin,
# *arr apps, the web UI). Done with plain `ip`/`wg` so only NET_ADMIN is needed.

VPN_IFACE = 'wg0'
VPN_DIR = '/config/vpn'
VPN_DEFAULT_LAN = '192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,100.64.0.0/10'
PIA_SERVERLIST_URL = 'https://serverlist.piaservers.net/vpninfo/servers/v6'
PIA_TOKEN_URL = 'https://www.privateinternetaccess.com/api/client/v2/token'
PIA_CA_URL = 'https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt'
VPN_PROVIDERS = {
    'proton': 'Proton VPN', 'pia': 'Private Internet Access (PIA)', 'mullvad': 'Mullvad', 'ivpn': 'IVPN',
    'airvpn': 'AirVPN', 'windscribe': 'Windscribe', 'surfshark': 'Surfshark', 'custom': 'Other WireGuard provider',
}

vpn_lock = threading.RLock()
vpn_state = {
    'status': 'off',            # off | connecting | connected | down | error
    'message': '',
    'endpoint': None,
    'vpn_address': None,
    'public_ip': None,
    'direct_ip': None,
    'last_handshake': None,
    'connected_since': None,
    'killswitch_active': False,
    'saved_default': None,      # original "default via X dev Y" route
}


def _run(cmd, input_text=None, check=True, timeout=20):
    r = subprocess.run(cmd, input=input_text, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:3])}: {(r.stderr or r.stdout).strip()[:200]}")
    return r


def vpn_capable():
    """(ok, reason): are wg/ip/iptables present and do we have NET_ADMIN?"""
    for tool in ('wg', 'ip', 'iptables'):
        if not shutil.which(tool):
            return False, f"'{tool}' is missing from the image - update the container"
    try:
        r = subprocess.run(['ip', 'link', 'add', 'jlcaptest', 'type', 'dummy'], capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            msg = r.stderr.lower()
            if 'not permitted' in msg or 'permission' in msg:
                return False, 'The container needs the NET_ADMIN capability (add --cap-add=NET_ADMIN)'
            # dummy module may be missing; fall back to checking iptables access
        else:
            subprocess.run(['ip', 'link', 'del', 'jlcaptest'], capture_output=True, timeout=10)
        r = subprocess.run(['iptables', '-S', 'OUTPUT'], capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return False, 'The container needs the NET_ADMIN capability (add --cap-add=NET_ADMIN)'
    except Exception as e:
        return False, f'Could not check network permissions: {e}'
    return True, ''


def parse_wireguard_conf(text):
    """Parse a provider's WireGuard .conf -> dict (validates the essentials)."""
    iface, peer, section = {}, {}, None
    for raw in (text or '').splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if line.startswith('['):
            section = line.strip('[]').strip().lower()
            continue
        if '=' not in line:
            continue
        k, v = [x.strip() for x in line.split('=', 1)]
        target = iface if section == 'interface' else peer if section == 'peer' else None
        if target is not None:
            target[k.lower()] = v
    missing = [n for n, d, k in (('PrivateKey', iface, 'privatekey'), ('Address', iface, 'address'),
                                  ('PublicKey', peer, 'publickey'), ('Endpoint', peer, 'endpoint')) if not d.get(k)]
    if missing:
        raise ValueError('WireGuard config is missing: ' + ', '.join(missing))
    host, _, port = peer['endpoint'].rpartition(':')
    if not host or not port.isdigit():
        raise ValueError('Endpoint must look like host:port')
    v4_addrs = [a.strip() for a in iface['address'].split(',') if ':' not in a]
    if not v4_addrs:
        raise ValueError('The config needs an IPv4 Address')
    return {
        'private_key': iface['privatekey'],
        'addresses': v4_addrs,                       # IPv6 dropped: Docker bridges rarely have v6 (and it could leak)
        'dns': [d.strip() for d in iface.get('dns', '').split(',') if d.strip() and ':' not in d],
        'mtu': iface.get('mtu', '1420'),
        'public_key': peer['publickey'],
        'preshared_key': peer.get('presharedkey', ''),
        'endpoint_host': host.strip('[]'),
        'endpoint_port': int(port),
        'keepalive': peer.get('persistentkeepalive', '25'),
    }


def _default_route():
    out = _run(['ip', '-4', 'route', 'show', 'default'], check=False).stdout.strip().splitlines()
    for line in out:
        m = re.match(r'default via (\S+) dev (\S+)', line)
        if m:
            return {'gw': m.group(1), 'dev': m.group(2), 'line': line}
    return None


def _default_route_is_vpn():
    out = _run(['ip', '-4', 'route', 'show', 'default'], check=False).stdout
    return f'dev {VPN_IFACE}' in out


def _lan_subnets(cfg):
    return [s.strip() for s in (cfg.get('vpn_lan_subnets') or VPN_DEFAULT_LAN).split(',') if s.strip()]


def _resolve_endpoint(host):
    import socket
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
        return host
    return socket.gethostbyname(host)


def apply_killswitch(cfg, endpoint_ip=None, endpoint_port=None):
    """Block all outbound traffic except LAN, loopback and the VPN tunnel/endpoint."""
    _run(['iptables', '-N', 'JL_KILLSWITCH'], check=False)
    _run(['iptables', '-F', 'JL_KILLSWITCH'])
    rules = [['-o', 'lo', '-j', 'ACCEPT'], ['-o', VPN_IFACE, '-j', 'ACCEPT']]
    for net in _lan_subnets(cfg):
        rules.append(['-d', net, '-j', 'ACCEPT'])
    if endpoint_ip and endpoint_port:
        rules.append(['-p', 'udp', '-d', endpoint_ip, '--dport', str(endpoint_port), '-j', 'ACCEPT'])
    rules.append(['-j', 'REJECT'])
    for r in rules:
        _run(['iptables', '-A', 'JL_KILLSWITCH'] + r)
    if _run(['iptables', '-C', 'OUTPUT', '-j', 'JL_KILLSWITCH'], check=False).returncode != 0:
        _run(['iptables', '-I', 'OUTPUT', '1', '-j', 'JL_KILLSWITCH'])
    # IPv6: nothing should leave over v6 while the kill switch is on
    if shutil.which('ip6tables'):
        _run(['ip6tables', '-N', 'JL_KILLSWITCH'], check=False)
        _run(['ip6tables', '-F', 'JL_KILLSWITCH'], check=False)
        _run(['ip6tables', '-A', 'JL_KILLSWITCH', '-o', 'lo', '-j', 'ACCEPT'], check=False)
        _run(['ip6tables', '-A', 'JL_KILLSWITCH', '-d', 'fe80::/10', '-j', 'ACCEPT'], check=False)
        _run(['ip6tables', '-A', 'JL_KILLSWITCH', '-j', 'REJECT'], check=False)
        if _run(['ip6tables', '-C', 'OUTPUT', '-j', 'JL_KILLSWITCH'], check=False).returncode != 0:
            _run(['ip6tables', '-I', 'OUTPUT', '1', '-j', 'JL_KILLSWITCH'], check=False)
    vpn_state['killswitch_active'] = True


def remove_killswitch():
    for tool in ('iptables', 'ip6tables'):
        if not shutil.which(tool):
            continue
        while _run([tool, '-D', 'OUTPUT', '-j', 'JL_KILLSWITCH'], check=False).returncode == 0:
            pass
        _run([tool, '-F', 'JL_KILLSWITCH'], check=False)
        _run([tool, '-X', 'JL_KILLSWITCH'], check=False)
    vpn_state['killswitch_active'] = False


def _write_resolv(dns):
    if not dns:
        return
    backup = '/etc/resolv.conf.jl-orig'
    try:
        if not os.path.exists(backup):
            shutil.copy2('/etc/resolv.conf', backup)
        with open('/etc/resolv.conf', 'w') as f:
            f.write(''.join(f'nameserver {d}\n' for d in dns))
    except OSError as e:
        log(f"🛡️ VPN: could not set DNS ({e}) - using the container's DNS")


def _restore_resolv():
    backup = '/etc/resolv.conf.jl-orig'
    if os.path.exists(backup):
        try:
            shutil.copyfile(backup, '/etc/resolv.conf')
            os.remove(backup)
        except OSError:
            pass


def vpn_tunnel_down(keep_killswitch=False):
    """Remove wg0 and put the original default route back."""
    with vpn_lock:
        _run(['ip', 'link', 'del', VPN_IFACE], check=False)
        saved = vpn_state.get('saved_default')
        if saved:
            _run(['ip', 'route', 'replace', 'default', 'via', saved['gw'], 'dev', saved['dev']], check=False)
        ep = vpn_state.get('endpoint_ip')
        if ep:
            _run(['ip', 'route', 'del', f'{ep}/32'], check=False)
        _restore_resolv()
        if not keep_killswitch:
            remove_killswitch()
        vpn_state.update(endpoint_ip=None, vpn_address=None, last_handshake=None, connected_since=None)


def vpn_tunnel_up(conf, cfg):
    """Bring wg0 up from a parsed config; all non-LAN traffic goes through it."""
    with vpn_lock:
        vpn_tunnel_down(keep_killswitch=True)
        default = _default_route() or vpn_state.get('saved_default')
        if not default:
            raise RuntimeError('No default route found in the container')
        vpn_state['saved_default'] = {'gw': default['gw'], 'dev': default['dev']}
        endpoint_ip = _resolve_endpoint(conf['endpoint_host'])
        if cfg.get('vpn_kill_switch', True):
            apply_killswitch(cfg, endpoint_ip, conf['endpoint_port'])
        # Endpoint + LAN keep using the real gateway
        _run(['ip', 'route', 'replace', f'{endpoint_ip}/32', 'via', default['gw'], 'dev', default['dev']])
        for net in _lan_subnets(cfg):
            _run(['ip', 'route', 'replace', net, 'via', default['gw'], 'dev', default['dev']], check=False)
        _run(['ip', 'link', 'add', VPN_IFACE, 'type', 'wireguard'])
        os.makedirs(VPN_DIR, exist_ok=True)
        key_file = os.path.join(VPN_DIR, '.wg.key')
        psk_file = os.path.join(VPN_DIR, '.wg.psk')
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(conf['private_key'])
        cmd = ['wg', 'set', VPN_IFACE, 'private-key', key_file, 'peer', conf['public_key'],
               'endpoint', f"{endpoint_ip}:{conf['endpoint_port']}", 'allowed-ips', '0.0.0.0/0',
               'persistent-keepalive', str(conf.get('keepalive') or 25)]
        if conf.get('preshared_key'):
            fd = os.open(psk_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(conf['preshared_key'])
            cmd += ['preshared-key', psk_file]
        try:
            _run(cmd)
        finally:
            for p in (key_file, psk_file):
                if os.path.exists(p):
                    os.remove(p)
        for addr in conf['addresses']:
            _run(['ip', '-4', 'address', 'add', addr if '/' in addr else addr + '/32', 'dev', VPN_IFACE])
        _run(['ip', 'link', 'set', 'mtu', str(conf.get('mtu') or 1420), 'up', 'dev', VPN_IFACE])
        _run(['ip', 'route', 'replace', 'default', 'dev', VPN_IFACE])
        _write_resolv(conf.get('dns'))
        vpn_state.update(endpoint=f"{conf['endpoint_host']}:{conf['endpoint_port']}", endpoint_ip=endpoint_ip,
                         vpn_address=conf['addresses'][0])


def vpn_handshake_age():
    r = _run(['wg', 'show', VPN_IFACE, 'latest-handshakes'], check=False)
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        ts = int(r.stdout.split()[-1])
    except (ValueError, IndexError):
        return None
    return None if ts == 0 else time.time() - ts


def _public_ip(timeout=8):
    for url in ('https://api.ipify.org?format=json', 'https://ifconfig.co/json'):
        try:
            r = requests.get(url, timeout=timeout)
            if r.ok:
                return r.json().get('ip')
        except Exception:
            continue
    return None


# ---- PIA: generate a WireGuard config from username/password + region ----
def _pia_regions():
    txt = requests.get(PIA_SERVERLIST_URL, timeout=20).text
    data = json.loads(txt.split('\n')[0])
    regions = [r for r in data.get('regions', []) if r.get('servers', {}).get('wg')]
    return sorted(regions, key=lambda r: r.get('name', ''))


def _pia_ca_file():
    path = os.path.join(VPN_DIR, 'pia_ca.rsa.4096.crt')
    if not os.path.exists(path):
        os.makedirs(VPN_DIR, exist_ok=True)
        pem = requests.get(PIA_CA_URL, timeout=20).text
        if 'BEGIN CERTIFICATE' not in pem:
            raise RuntimeError('Could not download the PIA certificate')
        with open(path, 'w') as f:
            f.write(pem)
    return path


def pia_generate_conf(username, password, region_id):
    """Register a fresh WireGuard key with PIA and return a parsed config."""
    from requests.adapters import HTTPAdapter

    class _SNIAdapter(HTTPAdapter):
        """Connect to the server's IP but verify the TLS cert for its PIA hostname."""
        def __init__(self, hostname, **kw):
            self._hostname = hostname
            super().__init__(**kw)

        def init_poolmanager(self, *a, **kw):
            kw['assert_hostname'] = self._hostname
            kw['server_hostname'] = self._hostname
            super().init_poolmanager(*a, **kw)

    tok = requests.post(PIA_TOKEN_URL, data={'username': username, 'password': password}, timeout=20)
    if tok.status_code in (401, 403) or not tok.ok:
        raise RuntimeError('PIA rejected the username/password')
    token = tok.json().get('token')
    if not token:
        raise RuntimeError('PIA did not return a login token')
    region = next((r for r in _pia_regions() if r.get('id') == region_id), None)
    if not region:
        raise RuntimeError('Unknown PIA region')
    server = region['servers']['wg'][0]
    priv = _run(['wg', 'genkey']).stdout.strip()
    pub = _run(['wg', 'pubkey'], input_text=priv).stdout.strip()
    s = requests.Session()
    s.mount(f"https://{server['ip']}:1337", _SNIAdapter(server['cn']))
    resp = s.get(f"https://{server['ip']}:1337/addKey", params={'pt': token, 'pubkey': pub},
                 verify=_pia_ca_file(), timeout=20).json()
    if resp.get('status') != 'OK':
        raise RuntimeError(f"PIA refused the key: {resp.get('message', resp.get('status'))}")
    return {
        'private_key': priv, 'addresses': [resp['peer_ip'] + '/32'], 'dns': resp.get('dns_servers', [])[:2],
        'mtu': '1420', 'public_key': resp['server_key'], 'preshared_key': '',
        'endpoint_host': resp.get('server_ip', server['ip']), 'endpoint_port': int(resp['server_port']), 'keepalive': '25',
    }


def _vpn_conf_from_settings(cfg):
    provider = cfg.get('vpn_provider', 'custom')
    if provider == 'pia':
        user = decrypt_sensitive(cfg.get('vpn_pia_username', ''))
        pw = decrypt_sensitive(cfg.get('vpn_pia_password', ''))
        if not user or not pw or not cfg.get('vpn_pia_region'):
            raise RuntimeError('Enter your PIA username, password and region')
        return pia_generate_conf(user, pw, cfg['vpn_pia_region'])
    text = decrypt_sensitive(cfg.get('vpn_wg_conf', ''))
    if not text:
        raise RuntimeError('Paste or upload your WireGuard configuration first')
    return parse_wireguard_conf(text)


def vpn_connect():
    """Connect according to saved settings. Returns (ok, message)."""
    cfg = load_config()
    if not is_feature_available('vpn'):
        return False, 'VPN is a Pro feature'
    ok, reason = vpn_capable()
    if not ok:
        vpn_state.update(status='error', message=reason)
        return False, reason
    vpn_state.update(status='connecting', message='Connecting...')
    try:
        if not vpn_state.get('direct_ip') and not vpn_state.get('killswitch_active') and not _default_route_is_vpn():
            vpn_state['direct_ip'] = _public_ip()   # remember the real IP to prove it's hidden later
        if cfg.get('vpn_kill_switch', True):
            apply_killswitch(cfg)            # block before anything else can leak
        else:
            remove_killswitch()              # kill switch turned off -> drop any old block rules
        conf = _vpn_conf_from_settings(cfg)
        vpn_tunnel_up(conf, cfg)
        for _ in range(15):
            age = vpn_handshake_age()
            if age is not None and age < 180:
                break
            time.sleep(1)
        else:
            raise RuntimeError('No handshake from the VPN server (check the config / account)')
        ip = _public_ip()
        vpn_state.update(status='connected', message='Connected', public_ip=ip,
                         connected_since=datetime.datetime.now().isoformat(timespec='seconds'),
                         last_handshake=vpn_handshake_age())
        log(f"🛡️ VPN connected via {vpn_state['endpoint']} - public IP now {ip or 'unknown'}")
        return True, 'Connected'
    except Exception as e:
        msg = str(e)
        if cfg.get('vpn_kill_switch', True):
            vpn_tunnel_down(keep_killswitch=True)
            vpn_state.update(status='down', message=f'{msg} - kill switch is blocking internet traffic')
        else:
            vpn_tunnel_down()
            vpn_state.update(status='down', message=f'{msg} - continuing without the VPN')
        log(f"🛡️ VPN connect failed: {msg}")
        return False, msg


def vpn_disconnect():
    vpn_tunnel_down()
    vpn_state.update(status='off', message='VPN off', public_ip=None)
    log("🛡️ VPN disconnected")


def vpn_blocking_downloads():
    """True when the kill switch is holding traffic because the VPN is down."""
    return vpn_state.get('killswitch_active') and vpn_state.get('status') != 'connected'


def vpn_monitor():
    """Background: keep the tunnel healthy; reconnect or fall back depending on the kill switch."""
    failures = 0
    while True:
        time.sleep(30)
        try:
            cfg = load_config()
            if not cfg.get('vpn_enabled') or not is_feature_available('vpn'):
                if vpn_state['status'] not in ('off',) or vpn_state.get('killswitch_active'):
                    vpn_disconnect()
                continue
            age = vpn_handshake_age()
            healthy = vpn_state['status'] == 'connected' and age is not None and age < 180
            if healthy:
                failures = 0
                vpn_state['last_handshake'] = age
                continue
            failures += 1
            log(f"🛡️ VPN not responding (attempt {failures}) - reconnecting")
            vpn_connect()
        except Exception as e:
            log(f"🛡️ VPN monitor error: {e}")


def vpn_startup():
    cfg = load_config()
    if cfg.get('vpn_enabled') and is_feature_available('vpn'):
        vpn_connect()
    threading.Thread(target=vpn_monitor, daemon=True).start()


@app.route('/api/vpn/status')
@login_required
def api_vpn_status():
    cfg = load_config()
    ok, reason = vpn_capable()
    conf_summary = None
    if cfg.get('vpn_wg_conf'):
        try:
            c = parse_wireguard_conf(decrypt_sensitive(cfg['vpn_wg_conf']))
            conf_summary = {'endpoint': f"{c['endpoint_host']}:{c['endpoint_port']}", 'address': c['addresses'][0]}
        except Exception as e:
            conf_summary = {'error': str(e)}
    age = vpn_handshake_age() if vpn_state['status'] == 'connected' else None
    return jsonify({
        'pro': is_feature_available('vpn'),
        'capable': ok, 'capable_reason': reason,
        'enabled': bool(cfg.get('vpn_enabled')),
        'provider': cfg.get('vpn_provider', 'proton'),
        'kill_switch': cfg.get('vpn_kill_switch', True),
        'lan_subnets': cfg.get('vpn_lan_subnets') or VPN_DEFAULT_LAN,
        'pia_region': cfg.get('vpn_pia_region', ''),
        'pia_username_set': bool(cfg.get('vpn_pia_username')),
        'conf': conf_summary,
        'providers': list(VPN_PROVIDERS.items()),   # list keeps display order (jsonify sorts dict keys)
        'state': {k: v for k, v in vpn_state.items() if k not in ('saved_default', 'endpoint_ip')},
        'handshake_age': round(age) if age is not None else None,
        'blocking': bool(vpn_blocking_downloads()),
    })


@app.route('/api/vpn/save', methods=['POST'])
@login_required
def api_vpn_save():
    if not is_feature_available('vpn'):
        return jsonify({'success': False, 'error': 'VPN is a Pro feature'}), 403
    data = request.json or {}
    cfg = load_config()
    provider = data.get('provider', cfg.get('vpn_provider', 'proton'))
    if provider not in VPN_PROVIDERS:
        return jsonify({'success': False, 'error': 'Unknown provider'}), 400
    cfg['vpn_provider'] = provider
    cfg['vpn_kill_switch'] = bool(data.get('kill_switch', True))
    lan = (data.get('lan_subnets') or VPN_DEFAULT_LAN).strip()
    if not all(re.match(r'^\d+\.\d+\.\d+\.\d+/\d{1,2}$', s.strip()) for s in lan.split(',') if s.strip()):
        return jsonify({'success': False, 'error': 'LAN subnets must look like 192.168.0.0/16, 10.0.0.0/8'}), 400
    cfg['vpn_lan_subnets'] = lan
    if data.get('wg_conf'):
        try:
            parse_wireguard_conf(data['wg_conf'])
        except ValueError as e:
            return jsonify({'success': False, 'error': str(e)}), 400
        cfg['vpn_wg_conf'] = encrypt_sensitive(data['wg_conf'])
    if provider == 'pia':
        if data.get('pia_username'):
            cfg['vpn_pia_username'] = encrypt_sensitive(data['pia_username'])
        if data.get('pia_password'):
            cfg['vpn_pia_password'] = encrypt_sensitive(data['pia_password'])
        if data.get('pia_region'):
            cfg['vpn_pia_region'] = data['pia_region']
    cfg['vpn_enabled'] = bool(data.get('enabled'))
    save_config(cfg)
    # Apply immediately
    if cfg['vpn_enabled']:
        threading.Thread(target=vpn_connect, daemon=True).start()
    elif vpn_state['status'] != 'off' or vpn_state.get('killswitch_active'):
        vpn_disconnect()
    return jsonify({'success': True})


@app.route('/api/vpn/connect', methods=['POST'])
@login_required
def api_vpn_connect():
    ok, msg = vpn_connect()
    return jsonify({'success': ok, 'message': msg, 'public_ip': vpn_state.get('public_ip')})


@app.route('/api/vpn/disconnect', methods=['POST'])
@login_required
def api_vpn_disconnect():
    vpn_disconnect()
    return jsonify({'success': True})


@app.route('/api/vpn/pia_regions')
@login_required
def api_vpn_pia_regions():
    try:
        regions = _pia_regions()
        return jsonify({'regions': [{'id': r['id'], 'name': r['name'], 'country': r.get('country'),
                                     'port_forward': r.get('port_forward', False)} for r in regions]})
    except Exception as e:
        return jsonify({'regions': [], 'error': f'Could not load PIA regions: {e}'})


@app.route('/api/vpn/check_ip', methods=['POST'])
@login_required
def api_vpn_check_ip():
    ip = _public_ip()
    if vpn_state['status'] == 'connected':
        vpn_state['public_ip'] = ip
    return jsonify({'public_ip': ip, 'direct_ip': vpn_state.get('direct_ip'),
                    'hidden': bool(ip and vpn_state.get('direct_ip') and ip != vpn_state['direct_ip'])})


CONFIG_SCHEMA_VERSION = 4


def migrate_config_file():
    """One-time upgrade of a v3.x config to the v4 layout, done on the raw file.

    v3.2 kept remote servers in cfg['servers'] and used a server's 'type' for the server software
    ('jellyfin'); v4 keeps every server in cfg['local_servers'] with type 'local' or 'remote'.
    Keys are moved exactly as stored (still encrypted) and server ids are kept, so sync mappings,
    passwords/tokens and user ids all carry over. The original file is backed up first.
    """
    if not os.path.exists(CONFIG_FILE):
        return
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            raw = json.load(f)
    except (OSError, ValueError) as e:
        log(f"⚠️ Config migration skipped - could not read config: {e}")
        return
    if raw.get('config_version', 0) >= CONFIG_SCHEMA_VERSION:
        return

    servers_out, seen = [], set()
    notes = []

    def add(entry, kind):
        s = dict(entry)
        if not s.get('id'):
            s['id'] = generate_id()
        if s['id'] in seen:
            return
        software = s.get('server_type') or (s.get('type') if s.get('type') not in ('local', 'remote', None) else None)
        s['server_type'] = software or 'jellyfin'
        s['type'] = kind
        s.setdefault('name', s.get('url', 'Server'))
        if 'api_key' in s and not s.get('key'):
            s['key'] = s.pop('api_key')
        seen.add(s['id'])
        servers_out.append(s)

    # 1. Existing local_servers: v3.2 stored software in 'type' -> these are LOCAL servers
    for s in raw.get('local_servers') or []:
        kind = s.get('type') if s.get('type') in ('local', 'remote') else 'local'
        add(s, kind)
    # 2. Legacy single local server (v2.x / v3.0)
    if not any(s['type'] == 'local' for s in servers_out) and raw.get('local_server_url'):
        add({'name': 'Local Server', 'url': raw['local_server_url'].rstrip('/'),
             'key': raw.get('local_server_key', ''), 'server_type': raw.get('local_server_type', 'jellyfin')}, 'local')
        notes.append('legacy local server')
    # 3. v3.x remote servers
    moved = 0
    for s in raw.get('servers') or []:
        before = len(servers_out)
        add(s, 'remote')
        moved += len(servers_out) - before

    if moved:
        notes.append(f'{moved} remote server(s)')
    changed = (raw.get('local_servers') != servers_out) or bool(raw.get('servers'))

    if changed:
        backup = CONFIG_FILE + '.v3-backup.json'
        if not os.path.exists(backup):
            shutil.copy2(CONFIG_FILE, backup)
    raw['local_servers'] = servers_out
    raw['servers'] = []
    raw['config_version'] = CONFIG_SCHEMA_VERSION
    tmp = CONFIG_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(raw, f, indent=4)
    os.replace(tmp, CONFIG_FILE)
    if changed:
        log(f"⬆️ Upgraded settings from v3 ({', '.join(notes) or 'server list'}) - "
            f"{len(servers_out)} server(s) kept with their logins. Backup: {os.path.basename(CONFIG_FILE)}.v3-backup.json")


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
    try:
        migrate_config_file()   # v3.x -> v4 server layout; must run before anything reads the config
    except Exception as mig_error:
        log(f"⚠️ Config migration error (settings left untouched): {mig_error}")
    init_app()
    load_cache_from_disk()
    load_download_history()  # Load persistent download history
    load_download_stats()    # Load persistent download statistics
    load_transcode_stats()   # Load persistent transcode stats
    
    # Track uptime for health checks
    app.start_time = time.time()
    
    # Clean up old partial downloads (Pro feature)
    cleanup_old_partials(max_age_days=7)
    
    # VPN first, so nothing downloads outside the tunnel when the kill switch is on
    try:
        vpn_startup()
    except Exception as vpn_error:
        log(f"🛡️ VPN startup error: {vpn_error}")

    cfg = load_config()
    num_workers = cfg.get('max_concurrent_downloads', 2)
    adjust_workers(num_workers)
    
    # Start transcode workers if Pro user OR test mode enabled
    num_transcode_workers = cfg.get('max_concurrent_transcodes', 1)
    test_mode_enabled = (DEV_MODE and cfg.get('_transcode_test_mode', False))
    transcode_enabled = cfg.get('transcode_enabled', False)
    
    if transcode_enabled or test_mode_enabled:
        if is_feature_available('transcoding') or test_mode_enabled:
            adjust_transcode_workers(num_transcode_workers, force=test_mode_enabled)
            log(f"ðŸŽ¬ Transcoding: ENABLED (preset: {cfg.get('transcode_preset', 'h265')}, encoder: {cfg.get('transcode_encoder', 'auto')})")
            if test_mode_enabled:
                log(f"ðŸ§ª Transcode test mode is ENABLED")
        else:
            log(f"ðŸŽ¬ Transcoding: Disabled (requires Pro license)")
    else:
        log(f"ðŸŽ¬ Transcoding: Disabled")
    
    setup_schedule()
    threading.Thread(target=schedule_runner, daemon=True).start()

    # Pro: pick unfinished/queued downloads back up after a restart or power cut
    threading.Thread(target=lambda: (time.sleep(5), auto_resume_partials()), daemon=True).start()

    # Check timezone support
    check_timezone_support()
    
    log(f"JellyLooter v{VERSION} started")
    log(f"Download workers: {active_workers}, Transcode workers: {active_transcode_workers}")
    log(f"Speed limit: {cfg.get('speed_limit_kbs', 0)} KB/s")
    log(f"Auth: {'Enabled' if cfg.get('auth_enabled', False) else 'Disabled'}")
    log(f"Task queue size: {task_queue.qsize()}, Target workers: {target_workers}")
    app.run(host='0.0.0.0', port=5000, threaded=True)
