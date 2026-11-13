"""Database access: connections, schema/migrations and small shared helpers."""
import os
import sqlite3

from flask import current_app, g, make_response, abort

STATUS_LABELS = {1: "Pass", 0: "Fail", None: "Pending"}

# child tables keyed by test_id, with the column each is listed in
_CHILD_TABLES = {
    "attachments": "created_at, id",
    "test_history": "changed_at DESC, id DESC",
    "test_comments": "created_at, id",
}


def connect(path):
    """Open a raw connection (rows as sqlite3.Row, foreign keys enforced)."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    # SQLite leaves FK enforcement (and ON DELETE CASCADE) off unless enabled per connection
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db():
    """Return the connection for the current request, opening it on first use."""
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(exc=None):
    """Close the request connection; uncommitted work is rolled back."""
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def fetch_or_404(sql, params, what):
    """Run a single-row query, aborting with '<what> not found' (404) if no row."""
    row = get_db().execute(sql, params).fetchone()
    if row is None:
        abort(make_response(f"{what} not found", 404))
    return row


def get_project_or_404(project_id):
    return fetch_or_404("SELECT * FROM projects WHERE id = ?", (project_id,), "Project")


def get_test_or_404(test_id):
    return fetch_or_404("SELECT * FROM tests WHERE id = ?", (test_id,), "Test")


def children_by_test(table, test_ids):
    """Fetch rows of a child table for many tests in one query, grouped by test_id."""
    order = _CHILD_TABLES[table]  # whitelist: table/order are never user input
    grouped = {tid: [] for tid in test_ids}
    if not test_ids:
        return grouped
    placeholders = ",".join("?" * len(test_ids))
    rows = get_db().execute(
        f"SELECT * FROM {table} WHERE test_id IN ({placeholders}) ORDER BY {order}",
        list(test_ids),
    ).fetchall()
    for row in rows:
        grouped[row["test_id"]].append(row)
    return grouped


def remove_attachment_files(where_sql, params):
    """Delete stored files for attachments whose test matches the given WHERE clause."""
    rows = get_db().execute(
        "SELECT a.stored_name FROM attachments a JOIN tests t ON a.test_id = t.id WHERE " + where_sql,
        params,
    ).fetchall()
    upload_dir = current_app.config["UPLOAD_DIR"]
    for row in rows:
        path = os.path.join(upload_dir, row["stored_name"])
        if os.path.exists(path):
            os.remove(path)


def init_db(path):
    """Create tables and apply in-place migrations for older databases."""
    conn = connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # migrate: add is_admin if missing
    user_cols = [row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
    if "is_admin" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
        # promote the first user to admin
        first = conn.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()
        if first:
            conn.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (first["id"],))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            archived INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # migrate: add archived if missing
    proj_cols = [row[1] for row in conn.execute("PRAGMA table_info(projects)").fetchall()]
    if "archived" not in proj_cols:
        conn.execute("ALTER TABLE projects ADD COLUMN archived INTEGER DEFAULT 0")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            description TEXT NOT NULL,
            steps TEXT NOT NULL,
            passed INTEGER DEFAULT NULL,
            output TEXT DEFAULT '',
            created_by TEXT DEFAULT '',
            executed_by TEXT DEFAULT '',
            executed_at TIMESTAMP DEFAULT NULL,
            sort_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            test_id INTEGER NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (test_id) REFERENCES tests(id) ON DELETE CASCADE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS test_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            test_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (test_id) REFERENCES tests(id) ON DELETE CASCADE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS test_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            test_id INTEGER NOT NULL,
            old_status TEXT,
            new_status TEXT,
            changed_by TEXT NOT NULL,
            changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (test_id) REFERENCES tests(id) ON DELETE CASCADE
        )
    """)
    # migrate: add created_by / executed_by if missing
    cols = [row[1] for row in conn.execute("PRAGMA table_info(tests)").fetchall()]
    if "created_by" not in cols:
        conn.execute("ALTER TABLE tests ADD COLUMN created_by TEXT DEFAULT ''")
    if "executed_by" not in cols:
        conn.execute("ALTER TABLE tests ADD COLUMN executed_by TEXT DEFAULT ''")
    if "executed_at" not in cols:
        conn.execute("ALTER TABLE tests ADD COLUMN executed_at TIMESTAMP DEFAULT NULL")
    if "notes" not in cols:
        conn.execute("ALTER TABLE tests ADD COLUMN notes TEXT DEFAULT ''")
    if "assigned_to" not in cols:
        conn.execute("ALTER TABLE tests ADD COLUMN assigned_to TEXT DEFAULT ''")
    if "sort_order" not in cols:
        conn.execute("ALTER TABLE tests ADD COLUMN sort_order INTEGER DEFAULT 0")
        # initialise sort_order for existing tests based on created_at
        conn.execute("""
            UPDATE tests SET sort_order = (
                SELECT COUNT(*) FROM tests t2
                WHERE t2.project_id = tests.project_id AND t2.created_at <= tests.created_at AND t2.id <= tests.id
            ) - 1
        """)
    conn.commit()
    conn.close()

