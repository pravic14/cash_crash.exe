"""Users + server-side sessions in SQLite.

- Passwords: scrypt (stdlib) with a random per-user salt. Only the hash string is stored.
- Sessions: the browser gets a random token in an HttpOnly cookie; the DB stores ONLY its SHA-256,
  so a leaked database cannot be used to hijack a session.
- Nothing here ever returns a hash, a token or a full user record.
"""
import hashlib
import hmac
import secrets
import sqlite3
import threading
import time

_N, _R, _P, _DKLEN = 2 ** 14, 8, 1, 32


class EmailTaken(Exception):
    pass


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=_DKLEN)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${dk.hex()}"


def verify_password(password, stored):
    try:
        scheme, n, r, p, salt_hex, hash_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex),
                            n=int(n), r=int(r), p=int(p), dklen=len(bytes.fromhex(hash_hex)))
        return hmac.compare_digest(dk, bytes.fromhex(hash_hex))
    except (ValueError, TypeError):
        return False


def _token_hash(cookie_value):
    return hashlib.sha256(cookie_value.encode()).hexdigest()


class UserStore:
    def __init__(self, path=":memory:", clock=time.time, session_ttl=8 * 3600):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._clock = clock
        self.session_ttl = session_ttl
        with self._lock:
            self._conn.execute("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, display_name TEXT NOT NULL, "
                               "email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at REAL NOT NULL)")
            self._conn.execute("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, "
                               "created_at REAL NOT NULL, expires_at REAL NOT NULL)")
            self._conn.commit()
        self._dummy_hash = hash_password("not-a-real-password")   # equalises timing for unknown emails

    def create_user(self, display_name, email, password):
        user_id = "u_" + secrets.token_hex(8)
        pw_hash = hash_password(password)
        try:
            with self._lock:
                self._conn.execute("INSERT INTO users VALUES (?,?,?,?,?)",
                                   (user_id, display_name, email, pw_hash, self._clock()))
                self._conn.commit()
        except sqlite3.IntegrityError:
            raise EmailTaken()
        return {"id": user_id, "display_name": display_name}

    def authenticate(self, email, password):
        with self._lock:
            row = self._conn.execute("SELECT id, display_name, password_hash FROM users WHERE email=?",
                                     (email,)).fetchone()
        if row is None:
            verify_password(password, self._dummy_hash)
            return None
        return {"id": row[0], "display_name": row[1]} if verify_password(password, row[2]) else None

    def create_session(self, user_id):
        cookie_value = secrets.token_urlsafe(32)
        now = self._clock()
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            self._conn.execute("INSERT INTO sessions VALUES (?,?,?,?)",
                               (_token_hash(cookie_value), user_id, now, now + self.session_ttl))
            self._conn.commit()
        return cookie_value

    def session_user(self, cookie_value):
        if not cookie_value or not isinstance(cookie_value, str):
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT u.id, u.display_name FROM sessions s JOIN users u ON u.id = s.user_id "
                "WHERE s.token_hash=? AND s.expires_at > ?", (_token_hash(cookie_value), self._clock())).fetchone()
        return {"id": row[0], "display_name": row[1]} if row else None

    def delete_session(self, cookie_value):
        if not cookie_value:
            return
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE token_hash=?", (_token_hash(cookie_value),))
            self._conn.commit()
