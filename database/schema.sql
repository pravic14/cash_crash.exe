-- BreakMyAgent SQLite schema (reference copy). The Python code creates these tables itself
-- (CREATE TABLE IF NOT EXISTS), and tests/test_db.py checks this file stays in sync with the code.
-- Three database files live in ./data : users.db, ledger.db, audit.db

-- ===== users.db ================================================================
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,          -- scrypt$N$r$p$salt$hash  (never the password)
    created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,          -- SHA-256 of the cookie value (never the cookie itself)
    user_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL);

-- ===== ledger.db ===============================================================
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY, owner TEXT NOT NULL,
    balance_pence INTEGER NOT NULL CHECK (balance_pence >= 0),
    daily_limit_pence INTEGER NOT NULL CHECK (daily_limit_pence >= 0));
CREATE TABLE IF NOT EXISTS payees (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, account_id TEXT NOT NULL, mule INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS known_payees (
    account_id TEXT NOT NULL, payee_id TEXT NOT NULL, PRIMARY KEY (account_id, payee_id));
CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT, proposal_id TEXT NOT NULL UNIQUE, session_id TEXT NOT NULL,
    account_id TEXT NOT NULL, payee_id TEXT NOT NULL,
    amount_pence INTEGER NOT NULL CHECK (amount_pence > 0), day TEXT NOT NULL, created_at REAL NOT NULL);

-- ===== audit.db (hash-chained, tamper-evident) =================================
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY, event_id TEXT, timestamp TEXT, session_id TEXT, event_type TEXT,
    details TEXT, previous_hash TEXT, event_hash TEXT);
