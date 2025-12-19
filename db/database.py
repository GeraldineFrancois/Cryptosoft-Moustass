import os
import pathlib
import sqlite3
import sys
import getpass
import mysql.connector
from mysql.connector import errorcode
from typing import Optional, List, Dict, Any


class CursorWrapper:
    def __init__(self, conn_obj: Any, cursor: Any, is_sqlite: bool, dict_cursor: bool = False):
        self._conn_obj = conn_obj
        self._cursor = cursor
        self._is_sqlite = is_sqlite
        self._dict = dict_cursor

    def execute(self, query: str, params: Optional[tuple] = None):
        q = query
        if self._is_sqlite:
            q = query.replace("%s", "?")
        if params is None:
            return self._cursor.execute(q)
        return self._cursor.execute(q, params)

    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None:
            return None
        if self._is_sqlite and self._dict:
            return dict(row)
        return row

    def fetchall(self):
        rows = self._cursor.fetchall()
        if self._is_sqlite and self._dict:
            return [dict(r) for r in rows]
        return rows

    @property
    def lastrowid(self):
        return getattr(self._cursor, 'lastrowid', None)

    def close(self):
        try:
            self._cursor.close()
        except Exception:
            pass


class ConnectionWrapper:
    def __init__(self, conn_obj: Any, is_sqlite: bool = False):
        self._conn = conn_obj
        self._is_sqlite = is_sqlite

    def cursor(self, dictionary: bool = False):
        if self._is_sqlite:
            cur = self._conn.cursor()
            return CursorWrapper(self._conn, cur, True, dict_cursor=dictionary)
        else:
            try:
                cur = self._conn.cursor(dictionary=dictionary)
            except TypeError:
                cur = self._conn.cursor()
            return CursorWrapper(self._conn, cur, False, dict_cursor=dictionary)

    def commit(self):
        return self._conn.commit()

    def close(self):
        try:
            return self._conn.close()
        except Exception:
            pass

    def is_connected(self):
        if self._is_sqlite:
            return True
        try:
            return self._conn.is_connected()
        except Exception:
            return False


def _apply_sqlite_schema(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          firstname TEXT NOT NULL,
          lastname TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE,
          role TEXT NOT NULL DEFAULT 'USER',
          password_hash TEXT NOT NULL,
          password_salt TEXT NOT NULL,
          public_key TEXT NULL,
          first_login INTEGER NOT NULL DEFAULT 1,
          user_date_created DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS code_files (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          file_name TEXT NOT NULL,
          file_hash TEXT NOT NULL,
          file_date_created DATETIME DEFAULT CURRENT_TIMESTAMP,
          user_id INTEGER NOT NULL,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS signatures (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          signature_value TEXT NOT NULL,
          signature_date DATETIME DEFAULT CURRENT_TIMESTAMP,
          file_id INTEGER NOT NULL,
          user_id INTEGER NOT NULL,
          FOREIGN KEY (file_id) REFERENCES code_files(id) ON DELETE CASCADE,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS users_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          action_type TEXT NOT NULL,
          file_name TEXT NULL,
          file_hash TEXT NULL,
          signature_value TEXT NULL,
          public_key TEXT NULL,
          success INTEGER NOT NULL,
          log_date DATETIME DEFAULT CURRENT_TIMESTAMP,
          user_id INTEGER NOT NULL,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )
    conn.commit()
    cur.close()


def _read_password_from_file(path: str) -> Optional[str]:
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read().strip()
    except Exception:
        return None


def get_connection() -> ConnectionWrapper:
    """
    Return a ConnectionWrapper for MySQL if available, otherwise fallback
    to a local SQLite database so the application remains functional.
    """
    db_host = os.getenv('DB_HOST', 'localhost')
    db_user = os.getenv('DB_USER', 'root')
    db_name = os.getenv('DB_NAME', 'cryptosoft_moustass')

    password = os.getenv('DB_PASSWORD')
    if not password:
        pw_file = os.getenv('DB_PASSWORD_FILE')
        if pw_file:
            password = _read_password_from_file(pw_file)
        else:
            try:
                if sys.stdin.isatty():
                    password = getpass.getpass(f'MySQL password for {db_user}@{db_host}: ')
            except Exception:
                password = None

    try:
        conn = mysql.connector.connect(host=db_host, user=db_user, password=password, database=db_name)
        if conn.is_connected():
            return ConnectionWrapper(conn, is_sqlite=False)
    except mysql.connector.Error as e:
        print(f"[DATABASE] MySQL unavailable or denied: {e}. Falling back to SQLite local DB.")

    sqlite_path = pathlib.Path(__file__).resolve().parents[1] / 'db' / 'local.db'
    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    sqlite_conn = sqlite3.connect(str(sqlite_path), check_same_thread=False)
    sqlite_conn.row_factory = sqlite3.Row
    _apply_sqlite_schema(sqlite_conn)
    return ConnectionWrapper(sqlite_conn, is_sqlite=True)


# --- Helper functions matching previous API ---


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    query = (
        "SELECT id, firstname, lastname, email, role, password_hash, password_salt, public_key, first_login "
        "FROM users WHERE email=%s"
    )
    cur.execute(query, (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user


def insert_user(firstname: str, lastname: str, email: str, password_hash: str, password_salt: str, role: str = 'USER') -> int:
    conn = get_connection()
    cur = conn.cursor()
    query = (
        "INSERT INTO users (firstname, lastname, email, role, password_hash, password_salt, first_login, user_date_created) "
        "VALUES (%s, %s, %s, %s, %s, %s, 1, CURRENT_TIMESTAMP)"
    )
    cur.execute(query, (firstname, lastname, email, role, password_hash, password_salt))
    conn.commit()
    last_id = cur.lastrowid
    cur.close()
    conn.close()
    return last_id


def insert_code_file(file_name: str, file_hash: str, user_id: int) -> int:
    conn = get_connection()
    cur = conn.cursor()
    query = "INSERT INTO code_files (file_name, file_hash, file_date_created, user_id) VALUES (%s, %s, CURRENT_TIMESTAMP, %s)"
    cur.execute(query, (file_name, file_hash, user_id))
    conn.commit()
    last_id = cur.lastrowid
    cur.close()
    conn.close()
    return last_id


def insert_signature(signature_value: str, file_id: int, user_id: int) -> int:
    conn = get_connection()
    cur = conn.cursor()
    query = "INSERT INTO signatures (signature_value, signature_date, file_id, user_id) VALUES (%s, CURRENT_TIMESTAMP, %s, %s)"
    cur.execute(query, (signature_value, file_id, user_id))
    conn.commit()
    last_id = cur.lastrowid
    cur.close()
    conn.close()
    return last_id


def insert_user_log(action_type: str, file_name: Optional[str], file_hash: Optional[str], signature_value: Optional[str], public_key: Optional[str], success: bool, user_id: int) -> int:
    conn = get_connection()
    cur = conn.cursor()
    query = (
        "INSERT INTO users_logs (action_type, file_name, file_hash, signature_value, public_key, success, log_date, user_id) "
        "VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, %s)"
    )
    cur.execute(query, (action_type, file_name, file_hash, signature_value, public_key, int(bool(success)), user_id))
    conn.commit()
    last_id = cur.lastrowid
    cur.close()
    conn.close()
    return last_id


def get_user_logs(user_id: int, is_admin: bool = False) -> List[Dict[str, Any]]:
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    if is_admin:
        cur.execute("SELECT * FROM users_logs ORDER BY log_date DESC LIMIT 1000")
    else:
        cur.execute("SELECT * FROM users_logs WHERE user_id=%s ORDER BY log_date DESC", (user_id,))
    results = cur.fetchall()
    cur.close()
    conn.close()
    return results

