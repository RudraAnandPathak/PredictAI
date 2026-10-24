from __future__ import annotations
import hashlib, hmac, os, secrets, sqlite3
from pathlib import Path
from typing import Any

ITERATIONS = 310_000
DB_PATH = Path(os.getenv("PREDICTAI_ACCOUNTS_DB", str(Path.home() / ".predictai" / "accounts.db"))).expanduser()
_ALLOWED_EVENTS = {"registration", "document_upload", "question_asked", "report_generated", "ai_success", "ai_error", "login", "admin_action"}

def _setting(name: str, default: str = "") -> str:
    """Read deployment config from environment variables or Streamlit Secrets."""
    value = os.getenv(name)
    if value is not None and str(value).strip():
        return str(value).strip()
    try:
        import streamlit as st
        value = st.secrets.get(name, default)
        return str(value).strip() if value is not None else default
    except Exception:
        return default

def _remote_enabled() -> bool:
    return bool(_setting("PREDICTAI_API_URL") and _setting("PREDICTAI_API_TOKEN"))

def _api_url(path: str) -> str:
    return _setting("PREDICTAI_API_URL").rstrip("/") + "/" + path.lstrip("/")

def _api(path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    import requests
    token = _setting("PREDICTAI_API_TOKEN")
    if not token:
        raise RuntimeError("PREDICTAI_API_TOKEN is not configured.")
    try:
        response = requests.post(_api_url(path), json=payload or {},
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, timeout=(5, 20))
    except requests.RequestException as exc:
        raise RuntimeError("PredictAI account service is temporarily unavailable. Please try again shortly.") from exc
    try:
        data = response.json()
    except ValueError:
        data = {}
    if not response.ok:
        message = data.get("error") or f"Account service returned HTTP {response.status_code}."
        if response.status_code in (400, 401, 403, 404, 409, 429):
            raise ValueError(str(message))
        raise RuntimeError(str(message))
    return data

def _connect():
    if _remote_enabled():
        raise RuntimeError("Direct SQLite access is disabled in Cloudflare mode. Use account API helpers.")
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY COLLATE NOCASE, salt TEXT NOT NULL,
        password_hash TEXT NOT NULL, special_access INTEGER NOT NULL DEFAULT 0,
        role TEXT NOT NULL DEFAULT 'regular', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        email TEXT, full_legal_name TEXT, is_blocked INTEGER NOT NULL DEFAULT 0)''')
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    for col, ddl in [
        ("role", "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'regular'"),
        ("email", "ALTER TABLE users ADD COLUMN email TEXT"),
        ("full_legal_name", "ALTER TABLE users ADD COLUMN full_legal_name TEXT"),
        ("is_blocked", "ALTER TABLE users ADD COLUMN is_blocked INTEGER NOT NULL DEFAULT 0"),
    ]:
        if col not in cols: conn.execute(ddl)
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
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)

def register(username: str, password: str, special_code: str = "", owner_setup_secret: str = "", email: str = "", full_legal_name: str = "") -> dict:
    username, password = str(username or "").strip(), str(password or "")
    email = str(email or "").strip().lower()
    full_legal_name = " ".join(str(full_legal_name or "").split())
    if len(username) < 3 or len(username) > 64: raise ValueError("Username must contain 3–64 characters.")
    if any(ch.isspace() for ch in username): raise ValueError("Username cannot contain spaces.")
    if len(password) < 10: raise ValueError("Password must be at least 10 characters long.")
    if email:
        import re
        if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            raise ValueError("Enter a valid email address.")
    if _remote_enabled():
        data = _api("register", {"username": username, "password": password, "special_code": special_code or "",
            "owner_setup_secret": owner_setup_secret or "", "email": email or None, "full_legal_name": full_legal_name or None})
        return data.get("user", data)
    expected_special = _setting("PREDICTAI_SPECIAL_ACCESS_CODE")
    special = bool(expected_special and special_code and hmac.compare_digest(special_code, expected_special))
    configured_owner = _setting("PREDICTAI_OWNER_USERNAME")
    configured_setup = _setting("PREDICTAI_OWNER_SETUP_SECRET")
    role = "regular"
    if configured_owner and username.casefold() == configured_owner.casefold():
        if not configured_setup or not owner_setup_secret or not hmac.compare_digest(owner_setup_secret, configured_setup):
            raise ValueError("This username is reserved for the configured owner. Use the protected owner setup secret.")
        role, special = "owner", False
    salt = secrets.token_bytes(16)
    hashed = _hash_password(password, salt).hex()
    try:
        with _connect() as conn:
            if email and conn.execute("SELECT 1 FROM users WHERE lower(email)=lower(?)", (email,)).fetchone():
                raise ValueError("That email address is already registered.")
            if role == "owner" and conn.execute("SELECT 1 FROM users WHERE role='owner'").fetchone():
                raise ValueError("An owner account has already been initialized.")
            conn.execute("INSERT INTO users(username,salt,password_hash,special_access,role,email,full_legal_name) VALUES(?,?,?,?,?,?,?)",
                (username, salt.hex(), hashed, int(special), role, email or None, full_legal_name or None))
            conn.execute("INSERT INTO usage_events(username,event_type,detail) VALUES(?,?,?)",
                (username, "registration", "owner account initialized" if role == "owner" else "account created"))
    except sqlite3.IntegrityError as exc: raise ValueError("That username or email is already registered.") from exc
    return {"username": username, "special_access": special, "role": role, "email": email, "full_legal_name": full_legal_name, "is_blocked": False}

def authenticate(username: str, password: str) -> dict | None:
    username, password = str(username or "").strip(), str(password or "")
    if _remote_enabled():
        try: return _api("login", {"username": username, "password": password}).get("user")
        except ValueError: return None
    with _connect() as conn:
        row = conn.execute("SELECT username,salt,password_hash,special_access,role,email,full_legal_name,is_blocked FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
    if not row or bool(row["is_blocked"]): return None
    actual = _hash_password(password, bytes.fromhex(row["salt"])).hex()
    if not hmac.compare_digest(actual, row["password_hash"]): return None
    with _connect() as conn:
        conn.execute("INSERT INTO usage_events(username,event_type,detail) VALUES(?,?,?)", (row["username"], "login", "successful login"))
    return {"username": row["username"], "special_access": bool(row["special_access"]), "role": row["role"],
        "email": row["email"], "full_legal_name": row["full_legal_name"], "is_blocked": bool(row["is_blocked"])}

def record_event(username: str, event_type: str, detail: str = "") -> None:
    if event_type not in _ALLOWED_EVENTS: raise ValueError("Unsupported usage event.")
    username, detail = str(username or "")[:64], str(detail or "")[:200]
    if _remote_enabled():
        _api("event", {"username": username, "event_type": event_type, "detail": detail}); return
    with _connect() as conn:
        conn.execute("INSERT INTO usage_events(username,event_type,detail) VALUES(?,?,?)", (username, event_type, detail))

def list_users(actor: dict | None = None) -> list[dict]:
    if _remote_enabled():
        if not actor or actor.get("role") != "owner":
            raise PermissionError("Owner privileges are required.")
        return _api("users", {"actor_username": actor.get("username")}).get("users", [])
    with _connect() as conn:
        rows = conn.execute("SELECT username,full_legal_name,email,special_access,role,is_blocked,created_at FROM users ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]

def set_special_access(actor: dict, username: str, enabled: bool) -> None:
    if not actor or actor.get("role") != "owner": raise PermissionError("Owner privileges are required.")
    if _remote_enabled():
        _api("special-access", {"actor_username": actor.get("username"), "username": username, "enabled": bool(enabled)}); return
    with _connect() as conn:
        row = conn.execute("SELECT role FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
        if not row: raise ValueError("User not found.")
        if row["role"] == "owner": raise ValueError("Owner privileges cannot be changed here.")
        conn.execute("UPDATE users SET special_access=? WHERE username=?", (int(bool(enabled)), username))
        conn.execute("INSERT INTO usage_events(username,event_type,detail) VALUES(?,?,?)", (actor["username"], "admin_action", f"special access {'granted' if enabled else 'revoked'} for {username}"))

def set_blocked(actor: dict, username: str, blocked: bool) -> None:
    if not actor or actor.get("role") != "owner": raise PermissionError("Owner privileges are required.")
    if _remote_enabled():
        _api("block", {"actor_username": actor.get("username"), "username": username, "blocked": bool(blocked)}); return
    with _connect() as conn:
        row = conn.execute("SELECT role FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
        if not row: raise ValueError("User not found.")
        if row["role"] == "owner": raise ValueError("The owner account cannot be blocked.")
        conn.execute("UPDATE users SET is_blocked=? WHERE username=?", (int(bool(blocked)), username))
        conn.execute("INSERT INTO usage_events(username,event_type,detail) VALUES(?,?,?)", (actor["username"], "admin_action", f"{'blocked' if blocked else 'unblocked'} account {username}"))

def get_account_status(username: str) -> dict | None:
    if _remote_enabled(): return _api("status", {"username": str(username or "").strip()}).get("user")
    with _connect() as conn:
        row = conn.execute("SELECT username,role,special_access,is_blocked,email,full_legal_name FROM users WHERE username=? COLLATE NOCASE", (str(username or "").strip(),)).fetchone()
    return dict(row) if row else None

def daily_task_usage(username: str, task_date: str) -> int:
    if _remote_enabled(): return int(_api("daily-usage", {"username": username, "task_date": task_date}).get("count", 0))
    with _connect() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM daily_ai_tasks WHERE username=? AND task_date=? AND status IN ('reserved','completed')", (username, task_date)).fetchone()[0])

def reserve_daily_task(username: str, task_date: str, task_key: str, limit: int = 3) -> bool:
    if _remote_enabled():
        return bool(_api("reserve-task", {"username": username, "task_date": task_date, "task_key": task_key, "limit": int(limit)}).get("reserved"))
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        used = int(conn.execute("SELECT COUNT(*) FROM daily_ai_tasks WHERE username=? AND task_date=? AND status IN ('reserved','completed')", (username, task_date)).fetchone()[0])
        if used >= limit: conn.rollback(); return False
        conn.execute("INSERT OR IGNORE INTO daily_ai_tasks(username,task_date,task_key,status) VALUES(?,?,?, 'reserved')", (username, task_date, task_key))
        conn.commit(); return True

def finish_daily_task(username: str, task_date: str, task_key: str, success: bool) -> None:
    if _remote_enabled():
        _api("finish-task", {"username": username, "task_date": task_date, "task_key": task_key, "success": bool(success)}); return
    with _connect() as conn:
        if success: conn.execute("UPDATE daily_ai_tasks SET status='completed' WHERE username=? AND task_date=? AND task_key=?", (username, task_date, task_key))
        else: conn.execute("DELETE FROM daily_ai_tasks WHERE username=? AND task_date=? AND task_key=? AND status='reserved'", (username, task_date, task_key))

def count_events(username: str, event_type: str) -> int:
    if _remote_enabled(): return int(_api("event-count", {"username": username, "event_type": event_type}).get("count", 0))
    with _connect() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM usage_events WHERE username=? AND event_type=?", (username, event_type)).fetchone()[0])

def get_analytics(actor: dict | None = None) -> dict:
    if _remote_enabled():
        if not actor or actor.get("role") != "owner":
            raise PermissionError("Owner privileges are required.")
        return _api("analytics", {"actor_username": actor.get("username")})
    with _connect() as conn:
        users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        special = conn.execute("SELECT COUNT(*) FROM users WHERE special_access=1 AND role!='owner'").fetchone()[0]
        events = {r["event_type"]: r["n"] for r in conn.execute("SELECT event_type, COUNT(*) AS n FROM usage_events GROUP BY event_type")}
        daily = [dict(r) for r in conn.execute("SELECT date(created_at) AS day, event_type, COUNT(*) AS count FROM usage_events GROUP BY date(created_at), event_type ORDER BY day DESC LIMIT 100")]
    return {"registered_users": users, "special_users": special, "documents_uploaded": events.get("document_upload", 0),
        "questions_asked": events.get("question_asked", 0), "reports_generated": events.get("report_generated", 0),
        "ai_requests_succeeded": events.get("ai_success", 0), "ai_requests_failed": events.get("ai_error", 0),
        "daily_usage": daily, "tracked_events": events}
