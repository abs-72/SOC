# auth.py
# CogSOC — Local Authentication Module
# Credentials stored in local JSON file unique to each system deployment.
# Passwords are salted + SHA-256 hashed — never stored in plaintext.
# Usage: from auth import AuthManager

import json
import os
import hashlib
import secrets
import time
from datetime import datetime, timezone

# ══════════════════════════════════════════════
#  SETTINGS
# ══════════════════════════════════════════════
# Credential file lives alongside the tool — unique per system
CREDENTIALS_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS_FILE = os.path.join(CREDENTIALS_DIR, '.cogsoc_credentials.json')

# Session settings
SESSION_EXPIRY_HOURS = 24   # sessions expire after 24 hours
TOKEN_LENGTH = 64           # length of session token hex string


# ══════════════════════════════════════════════
#  AUTH MANAGER
# ══════════════════════════════════════════════
class AuthManager:
    """
    Local credential and session manager for CogSOC.
    
    Credentials are stored in a JSON file on the local system.
    Each system deployment has its own file, so credentials are
    unique per system — two machines running CogSOC will have
    completely independent user accounts.
    
    Password storage: PBKDF2-like (salt + SHA-256, 100k iterations)
    Session tokens: cryptographically random hex strings
    """

    def __init__(self, cred_file=None):
        self.cred_file = cred_file or CREDENTIALS_FILE
        self._sessions = {}  # {token: {'username': str, 'created': float, 'expires': float}}
        self._load_or_create()

    def _load_or_create(self):
        """Load credentials file or create empty one."""
        if os.path.exists(self.cred_file):
            try:
                with open(self.cred_file, 'r') as f:
                    self._data = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._data = {'users': {}, 'system_id': secrets.token_hex(16)}
        else:
            self._data = {
                'users': {},
                'system_id': secrets.token_hex(16),  # unique ID per deployment
                'created': datetime.now(timezone.utc).isoformat(),
            }
            self._save()

    def _save(self):
        """Save credentials to local file."""
        try:
            with open(self.cred_file, 'w') as f:
                json.dump(self._data, f, indent=2)
        except IOError as e:
            print(f"[AUTH] Error saving credentials: {e}")

    @staticmethod
    def _hash_password(password, salt=None):
        """
        Hash password with salt using SHA-256 (100k iterations).
        Returns (hash_hex, salt_hex).
        """
        if salt is None:
            salt = secrets.token_hex(32)
        # PBKDF2-style: iterate SHA-256 100k times with salt
        h = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                                 salt.encode('utf-8'), 100_000)
        return h.hex(), salt

    def signup(self, username, password, full_name='', role='analyst', recovery_key=''):
        """
        Register a new user.
        Returns: (success: bool, message: str)
        """
        username = username.strip().lower()

        # Validation
        if not username or not password:
            return False, 'Username and password are required'
        if len(username) < 3:
            return False, 'Username must be at least 3 characters'
        if len(password) < 6:
            return False, 'Password must be at least 6 characters'
        if not recovery_key:
            return False, 'System Recovery Key is required'
        if username in self._data['users']:
            return False, 'Username already exists on this system'

        # Hash and store
        pw_hash, salt = self._hash_password(password)
        rec_hash, rec_salt = self._hash_password(recovery_key)
        
        self._data['users'][username] = {
            'password_hash': pw_hash,
            'salt': salt,
            'recovery_hash': rec_hash,
            'recovery_salt': rec_salt,
            'full_name': full_name.strip(),
            'role': role,
            'created': datetime.now(timezone.utc).isoformat(),
            'last_login': None,
        }
        self._save()
        print(f"[AUTH] New user registered: {username} (role: {role})")
        return True, 'Account created successfully'

    def reset_password(self, username, recovery_key, new_password):
        """
        Force reset a password using the recovery key.
        """
        username = username.strip().lower()
        if username not in self._data['users']:
            return False, 'Invalid username or recovery key'
            
        user = self._data['users'][username]
        if not user.get('recovery_hash'):
            return False, 'No recovery key was set for this legacy account'
            
        rec_hash, _ = self._hash_password(recovery_key, user.get('recovery_salt'))
        if rec_hash != user['recovery_hash']:
            return False, 'Invalid username or recovery key'
            
        if len(new_password) < 6:
            return False, 'New password must be at least 6 characters'
            
        pw_hash, salt = self._hash_password(new_password)
        user['password_hash'] = pw_hash
        user['salt'] = salt
        
        # Invalidate any active sessions for this user
        tokens_to_del = [t for t, s in self._sessions.items() if s['username'] == username]
        for t in tokens_to_del:
            del self._sessions[t]
            
        self._save()
        print(f"[AUTH] Password forcefully reset via recovery key: {username}")
        return True, 'Password reset successful'

    def login(self, username, password):
        """
        Authenticate user and create session.
        Returns: (success: bool, token_or_message: str)
        """
        username = username.strip().lower()

        if username not in self._data['users']:
            return False, 'Invalid username or password'

        user = self._data['users'][username]
        pw_hash, _ = self._hash_password(password, user['salt'])

        if pw_hash != user['password_hash']:
            return False, 'Invalid username or password'

        # Create session token
        token = secrets.token_hex(TOKEN_LENGTH // 2)
        now = time.time()
        self._sessions[token] = {
            'username': username,
            'full_name': user.get('full_name', username),
            'role': user.get('role', 'analyst'),
            'created': now,
            'expires': now + (SESSION_EXPIRY_HOURS * 3600),
        }

        # Update last login
        user['last_login'] = datetime.now(timezone.utc).isoformat()
        self._save()

        print(f"[AUTH] Login successful: {username}")
        return True, token

    def validate_session(self, token):
        """
        Check if a session token is valid.
        Returns: (is_valid: bool, session_data: dict or None)
        """
        if not token or token not in self._sessions:
            return False, None

        session = self._sessions[token]
        if time.time() > session['expires']:
            # Session expired
            del self._sessions[token]
            return False, None

        return True, session

    def logout(self, token):
        """Invalidate a session token."""
        if token in self._sessions:
            username = self._sessions[token].get('username', '?')
            del self._sessions[token]
            print(f"[AUTH] Logout: {username}")
            return True
        return False

    def get_user_count(self):
        """Return number of registered users."""
        return len(self._data.get('users', {}))

    def get_system_id(self):
        """Return unique system deployment ID."""
        return self._data.get('system_id', 'unknown')

    def cleanup_sessions(self):
        """Remove expired sessions."""
        now = time.time()
        expired = [t for t, s in self._sessions.items() if now > s['expires']]
        for t in expired:
            del self._sessions[t]
        return len(expired)
