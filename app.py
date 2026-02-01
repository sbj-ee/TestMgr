from flask import (
    Flask, render_template, request, redirect, url_for,
    send_from_directory, session, g,
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
import os
import uuid

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32))
DB_PATH = os.path.join(os.path.dirname(__file__), "tests.db")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
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
    # migrate: add created_by / executed_by if missing
    cols = [row[1] for row in conn.execute("PRAGMA table_info(tests)").fetchall()]
    if "created_by" not in cols:
        conn.execute("ALTER TABLE tests ADD COLUMN created_by TEXT DEFAULT ''")
    if "executed_by" not in cols:
        conn.execute("ALTER TABLE tests ADD COLUMN executed_by TEXT DEFAULT ''")
    conn.commit()
    conn.close()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if not g.user or not g.user["is_admin"]:
            return "Access denied", 403
        return f(*args, **kwargs)
    return decorated


@app.before_request
def load_user():
    g.user = None
    if "user_id" in session:
        conn = get_db()
        g.user = conn.execute(
            "SELECT * FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        conn.close()


# --- Auth routes ---

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            return redirect(url_for("index"))
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        if not username or not password:
            error = "Username and password are required."
        elif password != confirm_password:
            error = "Passwords do not match."
        else:
            conn = get_db()
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if existing:
                error = "Username already taken."
                conn.close()
            else:
                # first user becomes admin
                user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                is_admin = 1 if user_count == 0 else 0
                conn.execute(
                    "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), is_admin),
                )
                conn.commit()
                user = conn.execute(
                    "SELECT * FROM users WHERE username = ?", (username,)
                ).fetchone()
                conn.close()
                session["user_id"] = user["id"]
                return redirect(url_for("index"))
    return render_template("register.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- App routes ---

@app.route("/")
@login_required
def index():
    conn = get_db()
    projects = conn.execute(
        "SELECT p.*, "
        "(SELECT COUNT(*) FROM tests WHERE project_id = p.id) AS test_count, "
        "(SELECT COUNT(*) FROM tests WHERE project_id = p.id AND passed = 1) AS pass_count, "
        "(SELECT COUNT(*) FROM tests WHERE project_id = p.id AND passed = 0) AS fail_count "
        "FROM projects p ORDER BY p.created_at DESC"
    ).fetchall()
    conn.close()
    return render_template("index.html", projects=projects)


@app.route("/projects", methods=["POST"])
@login_required
def create_project():
    name = request.form.get("name", "").strip()
    if name:
        conn = get_db()
        conn.execute("INSERT INTO projects (name) VALUES (?)", (name,))
        conn.commit()
        conn.close()
    return redirect(url_for("index"))


@app.route("/projects/<int:project_id>")
@login_required
def project_detail(project_id):
    conn = get_db()
    project = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not project:
        conn.close()
        return "Project not found", 404
    tests = conn.execute(
        "SELECT * FROM tests WHERE project_id = ? ORDER BY created_at DESC", (project_id,)
    ).fetchall()
    attachments_by_test = {}
    for test in tests:
        attachments_by_test[test["id"]] = conn.execute(
            "SELECT * FROM attachments WHERE test_id = ? ORDER BY created_at", (test["id"],)
        ).fetchall()
    conn.close()
    return render_template("project.html", project=project, tests=tests, attachments=attachments_by_test)


@app.route("/projects/<int:project_id>/delete", methods=["POST"])
@login_required
def delete_project(project_id):
    conn = get_db()
    # clean up attachment files
    rows = conn.execute(
        "SELECT a.stored_name FROM attachments a "
        "JOIN tests t ON a.test_id = t.id WHERE t.project_id = ?", (project_id,)
    ).fetchall()
    for row in rows:
        path = os.path.join(UPLOAD_DIR, row["stored_name"])
        if os.path.exists(path):
            os.remove(path)
    conn.execute(
        "DELETE FROM attachments WHERE test_id IN "
        "(SELECT id FROM tests WHERE project_id = ?)", (project_id,)
    )
    conn.execute("DELETE FROM tests WHERE project_id = ?", (project_id,))
    conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("index"))


@app.route("/projects/<int:project_id>/tests", methods=["POST"])
@login_required
def create_test(project_id):
    description = request.form.get("description", "").strip()
    steps = request.form.get("steps", "").strip()
    if description and steps:
        conn = get_db()
        conn.execute(
            "INSERT INTO tests (project_id, description, steps, created_by) VALUES (?, ?, ?, ?)",
            (project_id, description, steps, g.user["username"]),
        )
        conn.commit()
        conn.close()
    return redirect(url_for("project_detail", project_id=project_id))


@app.route("/tests/<int:test_id>/update", methods=["POST"])
@login_required
def update_test(test_id):
    conn = get_db()
    test = conn.execute("SELECT * FROM tests WHERE id = ?", (test_id,)).fetchone()
    if not test:
        conn.close()
        return "Test not found", 404

    description = request.form.get("description", "").strip()
    steps = request.form.get("steps", "").strip()
    output = request.form.get("output", "")
    passed_val = request.form.get("passed")

    if passed_val == "1":
        passed = 1
    elif passed_val == "0":
        passed = 0
    else:
        passed = None

    # track who executed the test when result changes
    executed_by = test["executed_by"]
    if passed is not None and passed != test["passed"]:
        executed_by = g.user["username"]

    conn.execute(
        "UPDATE tests SET description = ?, steps = ?, passed = ?, output = ?, executed_by = ? WHERE id = ?",
        (description, steps, passed, output, executed_by, test_id),
    )
    conn.commit()
    project_id = test["project_id"]
    conn.close()
    return redirect(url_for("project_detail", project_id=project_id))


@app.route("/tests/<int:test_id>/delete", methods=["POST"])
@login_required
def delete_test(test_id):
    conn = get_db()
    test = conn.execute("SELECT * FROM tests WHERE id = ?", (test_id,)).fetchone()
    if not test:
        conn.close()
        return "Test not found", 404
    project_id = test["project_id"]
    # clean up attachment files
    rows = conn.execute("SELECT stored_name FROM attachments WHERE test_id = ?", (test_id,)).fetchall()
    for row in rows:
        path = os.path.join(UPLOAD_DIR, row["stored_name"])
        if os.path.exists(path):
            os.remove(path)
    conn.execute("DELETE FROM attachments WHERE test_id = ?", (test_id,))
    conn.execute("DELETE FROM tests WHERE id = ?", (test_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("project_detail", project_id=project_id))


@app.route("/tests/<int:test_id>/attachments", methods=["POST"])
@login_required
def upload_attachment(test_id):
    conn = get_db()
    test = conn.execute("SELECT * FROM tests WHERE id = ?", (test_id,)).fetchone()
    if not test:
        conn.close()
        return "Test not found", 404
    file = request.files.get("file")
    if file and file.filename:
        ext = os.path.splitext(file.filename)[1]
        stored_name = uuid.uuid4().hex + ext
        file.save(os.path.join(UPLOAD_DIR, stored_name))
        conn.execute(
            "INSERT INTO attachments (test_id, original_name, stored_name) VALUES (?, ?, ?)",
            (test_id, file.filename, stored_name),
        )
        conn.commit()
    conn.close()
    return redirect(url_for("project_detail", project_id=test["project_id"]))


@app.route("/attachments/<int:attachment_id>")
@login_required
def download_attachment(attachment_id):
    conn = get_db()
    att = conn.execute("SELECT * FROM attachments WHERE id = ?", (attachment_id,)).fetchone()
    conn.close()
    if not att:
        return "Attachment not found", 404
    return send_from_directory(UPLOAD_DIR, att["stored_name"], download_name=att["original_name"])


@app.route("/attachments/<int:attachment_id>/delete", methods=["POST"])
@login_required
def delete_attachment(attachment_id):
    conn = get_db()
    att = conn.execute("SELECT * FROM attachments WHERE id = ?", (attachment_id,)).fetchone()
    if not att:
        conn.close()
        return "Attachment not found", 404
    test = conn.execute("SELECT * FROM tests WHERE id = ?", (att["test_id"],)).fetchone()
    path = os.path.join(UPLOAD_DIR, att["stored_name"])
    if os.path.exists(path):
        os.remove(path)
    conn.execute("DELETE FROM attachments WHERE id = ?", (attachment_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("project_detail", project_id=test["project_id"]))


# --- User management routes ---

@app.route("/users")
@admin_required
def user_list():
    conn = get_db()
    users = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template("users.html", users=users)


@app.route("/users/add", methods=["POST"])
@admin_required
def add_user():
    error = None
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    is_admin = 1 if request.form.get("is_admin") else 0
    if not username or not password:
        error = "Username and password are required."
    else:
        conn = get_db()
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            error = "Username already taken."
            conn.close()
        else:
            conn.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), is_admin),
            )
            conn.commit()
            conn.close()
            return redirect(url_for("user_list"))
    # re-render with error
    conn = get_db()
    users = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template("users.html", users=users, error=error)


@app.route("/users/<int:user_id>/toggle-admin", methods=["POST"])
@admin_required
def toggle_admin(user_id):
    if user_id == g.user["id"]:
        return redirect(url_for("user_list"))
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user:
        new_val = 0 if user["is_admin"] else 1
        conn.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_val, user_id))
        conn.commit()
    conn.close()
    return redirect(url_for("user_list"))


@app.route("/users/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def reset_password(user_id):
    new_password = request.form.get("new_password", "")
    if new_password:
        conn = get_db()
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user_id),
        )
        conn.commit()
        conn.close()
    return redirect(url_for("user_list"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    if user_id == g.user["id"]:
        return redirect(url_for("user_list"))
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("user_list"))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5021, debug=True)
