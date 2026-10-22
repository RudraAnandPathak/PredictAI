from __future__ import annotations
import hashlib, hmac, os, secrets, sqlite3
from pathlib import Path

DB_PATH = Path(os.getenv('PREDICTAI_ACCOUNTS_DB', str(Path.home()/'.predictai'/'accounts.db'))).expanduser()
ITERATIONS = 310_000

def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY COLLATE NOCASE, salt TEXT NOT NULL,
        password_hash TEXT NOT NULL, special_access INTEGER NOT NULL DEFAULT 0,
        role TEXT NOT NULL DEFAULT 'regular',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        email TEXT,
        full_legal_name TEXT,
        is_blocked INTEGER NOT NULL DEFAULT 0)''')
    cols = {row['name'] for row in conn.execute("PRAGMA table_info(users)")}
    # Safe in-place migrations: existing accounts are preserved and their new profile fields remain blank.
    if 'role' not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'regular'")
    if 'email' not in cols:
        conn.execute('ALTER TABLE users ADD COLUMN email TEXT')
    if 'full_legal_name' not in cols:
        conn.execute('ALTER TABLE users ADD COLUMN full_legal_name TEXT')
    if 'is_blocked' not in cols:
        conn.execute('ALTER TABLE users ADD COLUMN is_blocked INTEGER NOT NULL DEFAULT 0')
    conn.execute('''CREATE TABLE IF NOT EXISTS daily_ai_tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL COLLATE NOCASE,
        task_date TEXT NOT NULL, task_key TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'reserved',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(username, task_date, task_key))''')
    conn.execute('''CREATE TABLE IF NOT EXISTS usage_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, event_type TEXT NOT NULL,
        detail TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    return conn

def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS)

def register(username: str, password: str, special_code: str = '', owner_setup_secret: str = '', email: str = '', full_legal_name: str = '') -> dict:
    username = str(username or '').strip()
    if len(username) < 3 or len(username) > 64: raise ValueError('Username must contain 3–64 characters.')
    if any(ch.isspace() for ch in username): raise ValueError('Username cannot contain spaces.')
    if len(password or '') < 12: raise ValueError('Password must be at least 12 characters long.')
    full_legal_name = ' '.join(str(full_legal_name or '').split())
    email = str(email or '').strip().lower()
    if len(full_legal_name) < 3 or len(full_legal_name) > 120:
        raise ValueError('Enter your full legal name (3–120 characters).')
    import re
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise ValueError('Enter a valid email address.')
    expected_special = os.getenv('PREDICTAI_SPECIAL_ACCESS_CODE', '')
    special = bool(expected_special and special_code and hmac.compare_digest(special_code, expected_special))
    configured_owner = os.getenv('PREDICTAI_OWNER_USERNAME', '').strip()
    configured_setup = os.getenv('PREDICTAI_OWNER_SETUP_SECRET', '')
    role = 'regular'
    if configured_owner and username.casefold() == configured_owner.casefold():
        if not configured_setup or not owner_setup_secret or not hmac.compare_digest(owner_setup_secret, configured_setup):
            raise ValueError('This username is reserved for the configured owner. Use the protected owner setup secret.')
        role, special = 'owner', False
    salt = secrets.token_bytes(16)
    hashed = _hash_password(password, salt)
    try:
        with _connect() as conn:
            if conn.execute('SELECT 1 FROM users WHERE lower(email)=lower(?)', (email,)).fetchone():
                raise ValueError('That email address is already registered.')
            if role == 'owner' and conn.execute("SELECT 1 FROM users WHERE role='owner'").fetchone():
                raise ValueError('An owner account has already been initialized.')
            conn.execute('INSERT INTO users(username,salt,password_hash,special_access,role,email,full_legal_name) VALUES(?,?,?,?,?,?,?)',
                         (username, salt.hex(), hashed.hex(), int(special), role, email, full_legal_name))
            conn.execute('INSERT INTO usage_events(username,event_type,detail) VALUES(?,?,?)',
                         (username, 'registration', 'owner account initialized' if role == 'owner' else 'account created'))
    except sqlite3.IntegrityError as exc: raise ValueError('That username is already registered.') from exc
    return {'username': username, 'special_access': special, 'role': role, 'email': email, 'full_legal_name': full_legal_name, 'is_blocked': False}

def authenticate(username: str, password: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute('SELECT username,salt,password_hash,special_access,role,email,full_legal_name,is_blocked FROM users WHERE username=?',
                           (str(username or '').strip(),)).fetchone()
    if not row or bool(row['is_blocked']): return None
    actual = _hash_password(password or '', bytes.fromhex(row['salt'])).hex()
    if not hmac.compare_digest(actual, row['password_hash']): return None
    with _connect() as conn:
        conn.execute('INSERT INTO usage_events(username,event_type,detail) VALUES(?,?,?)',
                     (row['username'], 'login', 'successful login'))
    return {'username': row['username'], 'special_access': bool(row['special_access']), 'role': row['role'], 'email': row['email'], 'full_legal_name': row['full_legal_name'], 'is_blocked': bool(row['is_blocked'])}

def record_event(username: str, event_type: str, detail: str = '') -> None:
    allowed = {'registration','document_upload','question_asked','report_generated','ai_success','ai_error','login','admin_action'}
    if event_type not in allowed: raise ValueError('Unsupported usage event.')
    with _connect() as conn:
        conn.execute('INSERT INTO usage_events(username,event_type,detail) VALUES(?,?,?)',
                     (str(username or '')[:64], event_type, str(detail or '')[:200]))

def list_users() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute('SELECT username,full_legal_name,email,special_access,role,is_blocked,created_at FROM users ORDER BY created_at DESC').fetchall()
    return [dict(r) for r in rows]

def set_special_access(actor: dict, username: str, enabled: bool) -> None:
    if not actor or actor.get('role') != 'owner': raise PermissionError('Owner privileges are required.')
    with _connect() as conn:
        row = conn.execute('SELECT role FROM users WHERE username=?', (username,)).fetchone()
        if not row: raise ValueError('User not found.')
        if row['role'] == 'owner': raise ValueError('Owner privileges cannot be changed here.')
        conn.execute('UPDATE users SET special_access=? WHERE username=?', (int(bool(enabled)), username))
        conn.execute('INSERT INTO usage_events(username,event_type,detail) VALUES(?,?,?)',
                     (actor['username'], 'admin_action', f"special access {'granted' if enabled else 'revoked'} for {username}"))


def daily_task_usage(username: str, task_date: str) -> int:
    with _connect() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM daily_ai_tasks WHERE username=? AND task_date=? AND status IN ('reserved','completed')", (username, task_date)).fetchone()[0])

def reserve_daily_task(username: str, task_date: str, task_key: str, limit: int = 3) -> bool:
    """Atomically reserve a daily task slot; returns False when the quota is full."""
    with _connect() as conn:
        conn.execute('BEGIN IMMEDIATE')
        used = int(conn.execute("SELECT COUNT(*) FROM daily_ai_tasks WHERE username=? AND task_date=? AND status IN ('reserved','completed')", (username, task_date)).fetchone()[0])
        if used >= limit:
            return False
        conn.execute("INSERT OR IGNORE INTO daily_ai_tasks(username,task_date,task_key,status) VALUES(?,?,?,'reserved')", (username, task_date, task_key))
        conn.commit()
        return True

def finish_daily_task(username: str, task_date: str, task_key: str, success: bool) -> None:
    with _connect() as conn:
        if success:
            conn.execute("UPDATE daily_ai_tasks SET status='completed' WHERE username=? AND task_date=? AND task_key=?", (username, task_date, task_key))
        else:
            conn.execute("DELETE FROM daily_ai_tasks WHERE username=? AND task_date=? AND task_key=? AND status='reserved'", (username, task_date, task_key))


def get_account_status(username: str) -> dict | None:
    """Return minimal current account state for session revalidation."""
    with _connect() as conn:
        row = conn.execute('SELECT username,role,special_access,is_blocked,email,full_legal_name FROM users WHERE username=?', (str(username or '').strip(),)).fetchone()
    return dict(row) if row else None

def set_blocked(actor: dict, username: str, blocked: bool) -> None:
    """Owner-only block/unblock for regular accounts; the owner cannot be targeted."""
    if not actor or actor.get('role') != 'owner':
        raise PermissionError('Owner privileges are required.')
    username = str(username or '').strip()
    with _connect() as conn:
        row = conn.execute('SELECT role FROM users WHERE username=?', (username,)).fetchone()
        if not row:
            raise ValueError('User not found.')
        if row['role'] == 'owner':
            raise ValueError('The owner account is protected and cannot be blocked here.')
        conn.execute('UPDATE users SET is_blocked=? WHERE username=?', (int(bool(blocked)), username))
        conn.execute('INSERT INTO usage_events(username,event_type,detail) VALUES(?,?,?)',
                     (actor['username'], 'admin_action', f"{'blocked' if blocked else 'unblocked'} account {username}"))
