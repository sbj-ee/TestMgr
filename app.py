from flask import (
    Flask, render_template, request, redirect, url_for,
    send_from_directory, session, g, Response, flash,
)
from werkzeug.security import generate_password_hash, check_password_hash
from logging.handlers import RotatingFileHandler
from functools import wraps
from datetime import datetime, timezone
from io import StringIO
import sqlite3
import logging
import shutil
import csv
import os
import uuid

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")
DB_PATH = os.path.join(os.path.dirname(__file__), "tests.db")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Configure logging
file_handler = RotatingFileHandler(
    os.path.join(LOG_DIR, "app.log"), maxBytes=1_000_000, backupCount=5
)
file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)


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


@app.after_request
def log_request(response):
    user = g.user["username"] if g.user else "anonymous"
    app.logger.info("%s %s %s %s %s", request.remote_addr, user,
                    request.method, request.path, response.status_code)
    return response


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
            app.logger.info("Login successful: %s", username)
            return redirect(url_for("index"))
        app.logger.warning("Login failed: %s", username)
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
                app.logger.info("User registered: %s (admin=%s)", username, is_admin)
                return redirect(url_for("index"))
    return render_template("register.html", error=error)


@app.route("/logout")
def logout():
    username = g.user["username"] if g.user else "unknown"
    session.clear()
    app.logger.info("Logout: %s", username)
    return redirect(url_for("login"))


# --- App routes ---

@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "").strip()
    results = []
    if q:
        conn = get_db()
        results = conn.execute(
            "SELECT t.*, p.name AS project_name FROM tests t "
            "JOIN projects p ON t.project_id = p.id "
            "WHERE t.description LIKE ? OR t.steps LIKE ? OR t.output LIKE ? OR t.notes LIKE ? "
            "ORDER BY p.name, t.sort_order",
            (f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"),
        ).fetchall()
        conn.close()
    return render_template("search.html", q=q, results=results)


@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    # overall stats
    total_projects = conn.execute(
        "SELECT COUNT(*) FROM projects WHERE archived = 0"
    ).fetchone()[0]
    total_tests = conn.execute(
        "SELECT COUNT(*) FROM tests t JOIN projects p ON t.project_id = p.id WHERE p.archived = 0"
    ).fetchone()[0]
    total_pass = conn.execute(
        "SELECT COUNT(*) FROM tests t JOIN projects p ON t.project_id = p.id WHERE p.archived = 0 AND t.passed = 1"
    ).fetchone()[0]
    total_fail = conn.execute(
        "SELECT COUNT(*) FROM tests t JOIN projects p ON t.project_id = p.id WHERE p.archived = 0 AND t.passed = 0"
    ).fetchone()[0]
    total_pending = total_tests - total_pass - total_fail
    pass_rate = round(total_pass / total_tests * 100, 1) if total_tests > 0 else 0

    # per-project summary
    project_stats = conn.execute(
        "SELECT p.id, p.name, "
        "COUNT(t.id) AS test_count, "
        "SUM(CASE WHEN t.passed = 1 THEN 1 ELSE 0 END) AS pass_count, "
        "SUM(CASE WHEN t.passed = 0 THEN 1 ELSE 0 END) AS fail_count, "
        "SUM(CASE WHEN t.passed IS NULL THEN 1 ELSE 0 END) AS pending_count "
        "FROM projects p LEFT JOIN tests t ON t.project_id = p.id "
        "WHERE p.archived = 0 "
        "GROUP BY p.id ORDER BY p.name"
    ).fetchall()

    # recent activity
    recent = conn.execute(
        "SELECT h.*, t.description AS test_desc, p.name AS project_name, p.id AS project_id "
        "FROM test_history h "
        "JOIN tests t ON h.test_id = t.id "
        "JOIN projects p ON t.project_id = p.id "
        "ORDER BY h.changed_at DESC LIMIT 10"
    ).fetchall()

    conn.close()
    return render_template("dashboard.html",
        total_projects=total_projects, total_tests=total_tests,
        total_pass=total_pass, total_fail=total_fail, total_pending=total_pending,
        pass_rate=pass_rate, project_stats=project_stats, recent=recent)


@app.route("/")
@login_required
def index():
    conn = get_db()
    base_query = (
        "SELECT p.*, "
        "(SELECT COUNT(*) FROM tests WHERE project_id = p.id) AS test_count, "
        "(SELECT COUNT(*) FROM tests WHERE project_id = p.id AND passed = 1) AS pass_count, "
        "(SELECT COUNT(*) FROM tests WHERE project_id = p.id AND passed = 0) AS fail_count "
        "FROM projects p WHERE p.archived = ? ORDER BY p.created_at DESC"
    )
    projects = conn.execute(base_query, (0,)).fetchall()
    archived_projects = conn.execute(base_query, (1,)).fetchall()
    conn.close()
    return render_template("index.html", projects=projects, archived_projects=archived_projects)


@app.route("/projects", methods=["POST"])
@login_required
def create_project():
    name = request.form.get("name", "").strip()
    if name:
        conn = get_db()
        conn.execute("INSERT INTO projects (name) VALUES (?)", (name,))
        conn.commit()
        conn.close()
        app.logger.info("Project created: '%s' by %s", name, g.user["username"])
        flash("Project created.")
    return redirect(url_for("index"))


@app.route("/projects/<int:project_id>")
@login_required
def project_detail(project_id):
    conn = get_db()
    project = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not project:
        conn.close()
        return "Project not found", 404
    status_filter = request.args.get("status", "all")
    assigned_filter = request.args.get("assigned", "")
    if status_filter == "pass":
        tests = conn.execute(
            "SELECT * FROM tests WHERE project_id = ? AND passed = 1 ORDER BY sort_order", (project_id,)
        ).fetchall()
    elif status_filter == "fail":
        tests = conn.execute(
            "SELECT * FROM tests WHERE project_id = ? AND passed = 0 ORDER BY sort_order", (project_id,)
        ).fetchall()
    elif status_filter == "pending":
        tests = conn.execute(
            "SELECT * FROM tests WHERE project_id = ? AND passed IS NULL ORDER BY sort_order", (project_id,)
        ).fetchall()
    else:
        status_filter = "all"
        tests = conn.execute(
            "SELECT * FROM tests WHERE project_id = ? ORDER BY sort_order", (project_id,)
        ).fetchall()
    if assigned_filter == "me":
        tests = [t for t in tests if t["assigned_to"] == g.user["username"]]
    users = conn.execute("SELECT username FROM users ORDER BY username").fetchall()
    attachments_by_test = {}
    history_by_test = {}
    comments_by_test = {}
    for test in tests:
        attachments_by_test[test["id"]] = conn.execute(
            "SELECT * FROM attachments WHERE test_id = ? ORDER BY created_at", (test["id"],)
        ).fetchall()
        history_by_test[test["id"]] = conn.execute(
            "SELECT * FROM test_history WHERE test_id = ? ORDER BY changed_at DESC", (test["id"],)
        ).fetchall()
        comments_by_test[test["id"]] = conn.execute(
            "SELECT * FROM test_comments WHERE test_id = ? ORDER BY created_at", (test["id"],)
        ).fetchall()
    conn.close()
    return render_template("project.html", project=project, tests=tests,
        attachments=attachments_by_test, history=history_by_test,
        comments=comments_by_test, users=users,
        status_filter=status_filter, assigned_filter=assigned_filter)


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
        "DELETE FROM test_comments WHERE test_id IN "
        "(SELECT id FROM tests WHERE project_id = ?)", (project_id,)
    )
    conn.execute(
        "DELETE FROM test_history WHERE test_id IN "
        "(SELECT id FROM tests WHERE project_id = ?)", (project_id,)
    )
    conn.execute(
        "DELETE FROM attachments WHERE test_id IN "
        "(SELECT id FROM tests WHERE project_id = ?)", (project_id,)
    )
    conn.execute("DELETE FROM tests WHERE project_id = ?", (project_id,))
    project_name = conn.execute("SELECT name FROM projects WHERE id = ?", (project_id,)).fetchone()
    conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    conn.commit()
    conn.close()
    app.logger.info("Project deleted: id=%s by %s", project_id, g.user["username"])
    flash("Project deleted.")
    return redirect(url_for("index"))


@app.route("/projects/<int:project_id>/clone", methods=["POST"])
@login_required
def clone_project(project_id):
    conn = get_db()
    project = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not project:
        conn.close()
        return "Project not found", 404
    # create cloned project
    cursor = conn.execute(
        "INSERT INTO projects (name, archived) VALUES (?, 0)",
        (project["name"] + " (Copy)",),
    )
    new_project_id = cursor.lastrowid
    # clone all tests (reset results, preserve order)
    tests = conn.execute("SELECT * FROM tests WHERE project_id = ? ORDER BY sort_order", (project_id,)).fetchall()
    for test in tests:
        cursor = conn.execute(
            "INSERT INTO tests (project_id, description, steps, passed, output, notes, created_by, executed_by, sort_order) "
            "VALUES (?, ?, ?, NULL, '', ?, ?, '', ?)",
            (new_project_id, test["description"], test["steps"], test["notes"], g.user["username"], test["sort_order"]),
        )
        new_test_id = cursor.lastrowid
        # clone attachments
        atts = conn.execute("SELECT * FROM attachments WHERE test_id = ?", (test["id"],)).fetchall()
        for att in atts:
            ext = os.path.splitext(att["stored_name"])[1]
            new_stored = uuid.uuid4().hex + ext
            src = os.path.join(UPLOAD_DIR, att["stored_name"])
            dst = os.path.join(UPLOAD_DIR, new_stored)
            if os.path.exists(src):
                shutil.copy2(src, dst)
            conn.execute(
                "INSERT INTO attachments (test_id, original_name, stored_name) VALUES (?, ?, ?)",
                (new_test_id, att["original_name"], new_stored),
            )
    conn.commit()
    conn.close()
    app.logger.info("Project cloned: '%s' -> id=%s by %s", project["name"], new_project_id, g.user["username"])
    flash("Project cloned.")
    return redirect(url_for("project_detail", project_id=new_project_id))


@app.route("/projects/<int:project_id>/archive", methods=["POST"])
@login_required
def archive_project(project_id):
    conn = get_db()
    project = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not project:
        conn.close()
        return "Project not found", 404
    new_val = 0 if project["archived"] else 1
    conn.execute("UPDATE projects SET archived = ? WHERE id = ?", (new_val, project_id))
    conn.commit()
    conn.close()
    action = "archived" if new_val else "unarchived"
    app.logger.info("Project %s: '%s' by %s", action, project["name"], g.user["username"])
    flash("Project %s." % action)
    return redirect(url_for("index"))


@app.route("/projects/<int:project_id>/export")
@login_required
def export_project(project_id):
    conn = get_db()
    project = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not project:
        conn.close()
        return "Project not found", 404
    tests = conn.execute(
        "SELECT * FROM tests WHERE project_id = ? ORDER BY sort_order", (project_id,)
    ).fetchall()

    fmt = request.args.get("format", "markdown")
    app.logger.info("Export %s: '%s' by %s", fmt, project["name"], g.user["username"])

    if fmt == "csv":
        # CSV export
        si = StringIO()
        writer = csv.writer(si)
        writer.writerow(["#", "Description", "Steps", "Status", "Assigned To", "Created By",
                         "Executed By", "Executed At", "Output", "Notes", "Attachments", "Comments"])
        for i, test in enumerate(tests, 1):
            if test["passed"] == 1:
                status = "Pass"
            elif test["passed"] == 0:
                status = "Fail"
            else:
                status = "Pending"
            atts = conn.execute(
                "SELECT original_name FROM attachments WHERE test_id = ? ORDER BY created_at",
                (test["id"],),
            ).fetchall()
            att_names = "; ".join(a["original_name"] for a in atts)
            cmts = conn.execute(
                "SELECT username, body, created_at FROM test_comments WHERE test_id = ? ORDER BY created_at",
                (test["id"],),
            ).fetchall()
            cmt_text = "; ".join(f"{c['username']}: {c['body']}" for c in cmts)
            writer.writerow([
                i, test["description"], test["steps"], status, test["assigned_to"],
                test["created_by"], test["executed_by"], test["executed_at"] or "",
                test["output"], test["notes"], att_names, cmt_text,
            ])
        conn.close()
        filename = project["name"].replace(" ", "_") + "_report.csv"
        return Response(
            si.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # Markdown export
    total = len(tests)
    passed = sum(1 for t in tests if t["passed"] == 1)
    failed = sum(1 for t in tests if t["passed"] == 0)
    pending = total - passed - failed

    lines = []
    lines.append(f"# {project['name']} — Test Report")
    lines.append("")
    lines.append(f"**Generated:** {project['created_at']}  ")
    lines.append(f"**Exported by:** {g.user['username']}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Total | Passed | Failed | Pending |")
    lines.append(f"|-------|--------|--------|---------|")
    lines.append(f"| {total} | {passed} | {failed} | {pending} |")
    lines.append("")

    if tests:
        lines.append("## Test Results")
        lines.append("")
        for i, test in enumerate(tests, 1):
            if test["passed"] == 1:
                status = "PASS"
            elif test["passed"] == 0:
                status = "FAIL"
            else:
                status = "PENDING"

            lines.append(f"### {i}. {test['description']}")
            lines.append("")
            lines.append(f"**Status:** `{status}`  ")
            if test["assigned_to"]:
                lines.append(f"**Assigned to:** {test['assigned_to']}  ")
            if test["created_by"]:
                lines.append(f"**Created by:** {test['created_by']}  ")
            if test["executed_by"]:
                executed_info = f"**Executed by:** {test['executed_by']}"
                if test["executed_at"]:
                    executed_info += f" on {test['executed_at']}"
                lines.append(executed_info + "  ")
            lines.append("")
            lines.append("**Steps:**")
            lines.append("")
            for step_line in test["steps"].splitlines():
                lines.append(f"> {step_line}")
            lines.append("")
            if test["output"]:
                lines.append("**Output:**")
                lines.append("")
                lines.append("```")
                lines.append(test["output"])
                lines.append("```")
                lines.append("")
            if test["notes"]:
                lines.append("**Notes:**")
                lines.append("")
                lines.append(test["notes"])
                lines.append("")

            # attachments
            atts = conn.execute(
                "SELECT original_name FROM attachments WHERE test_id = ? ORDER BY created_at",
                (test["id"],),
            ).fetchall()
            if atts:
                lines.append("**Attachments:**")
                lines.append("")
                for att in atts:
                    lines.append(f"- {att['original_name']}")
                lines.append("")

            # history
            hist = conn.execute(
                "SELECT * FROM test_history WHERE test_id = ? ORDER BY changed_at DESC",
                (test["id"],),
            ).fetchall()
            if hist:
                lines.append("**History:**")
                lines.append("")
                for entry in hist:
                    lines.append(
                        f"- {entry['changed_by']}: "
                        f"{entry['old_status'] or 'Pending'} → {entry['new_status'] or 'Pending'} "
                        f"({entry['changed_at']})"
                    )
                lines.append("")

            # comments
            cmts = conn.execute(
                "SELECT * FROM test_comments WHERE test_id = ? ORDER BY created_at",
                (test["id"],),
            ).fetchall()
            if cmts:
                lines.append("**Comments:**")
                lines.append("")
                for cmt in cmts:
                    lines.append(f"- **{cmt['username']}** ({cmt['created_at']}): {cmt['body']}")
                lines.append("")

            lines.append("---")
            lines.append("")

    conn.close()
    md = "\n".join(lines)
    filename = project["name"].replace(" ", "_") + "_report.md"
    return Response(
        md,
        mimetype="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/projects/<int:project_id>/tests", methods=["POST"])
@login_required
def create_test(project_id):
    description = request.form.get("description", "").strip()
    steps = request.form.get("steps", "").strip()
    if description and steps:
        conn = get_db()
        max_order = conn.execute(
            "SELECT COALESCE(MAX(sort_order), -1) FROM tests WHERE project_id = ?", (project_id,)
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO tests (project_id, description, steps, created_by, sort_order) VALUES (?, ?, ?, ?, ?)",
            (project_id, description, steps, g.user["username"], max_order + 1),
        )
        conn.commit()
        conn.close()
        app.logger.info("Test created: '%s' in project %s by %s", description, project_id, g.user["username"])
        flash("Test added.")
    return redirect(url_for("project_detail", project_id=project_id))


@app.route("/tests/<int:test_id>/move/<direction>", methods=["POST"])
@login_required
def move_test(test_id, direction):
    conn = get_db()
    test = conn.execute("SELECT * FROM tests WHERE id = ?", (test_id,)).fetchone()
    if not test:
        conn.close()
        return "Test not found", 404
    project_id = test["project_id"]
    current_order = test["sort_order"]

    if direction == "up":
        neighbor = conn.execute(
            "SELECT * FROM tests WHERE project_id = ? AND sort_order < ? ORDER BY sort_order DESC LIMIT 1",
            (project_id, current_order),
        ).fetchone()
    elif direction == "down":
        neighbor = conn.execute(
            "SELECT * FROM tests WHERE project_id = ? AND sort_order > ? ORDER BY sort_order ASC LIMIT 1",
            (project_id, current_order),
        ).fetchone()
    else:
        conn.close()
        return "Invalid direction", 400

    if neighbor:
        conn.execute("UPDATE tests SET sort_order = ? WHERE id = ?", (neighbor["sort_order"], test_id))
        conn.execute("UPDATE tests SET sort_order = ? WHERE id = ?", (current_order, neighbor["id"]))
        conn.commit()
        app.logger.info("Test moved %s: id=%s by %s", direction, test_id, g.user["username"])
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
    notes = request.form.get("notes", "")
    assigned_to = request.form.get("assigned_to", "")
    passed_val = request.form.get("passed")

    if passed_val == "1":
        passed = 1
    elif passed_val == "0":
        passed = 0
    else:
        passed = None

    # track who executed the test and when result changes
    executed_by = test["executed_by"]
    executed_at = test["executed_at"]
    if passed != test["passed"]:
        executed_by = g.user["username"]
        executed_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        # record history
        status_map = {1: "Pass", 0: "Fail", None: "Pending"}
        conn.execute(
            "INSERT INTO test_history (test_id, old_status, new_status, changed_by) VALUES (?, ?, ?, ?)",
            (test_id, status_map.get(test["passed"]), status_map.get(passed), g.user["username"]),
        )

    conn.execute(
        "UPDATE tests SET description = ?, steps = ?, passed = ?, output = ?, notes = ?, assigned_to = ?, executed_by = ?, executed_at = ? WHERE id = ?",
        (description, steps, passed, output, notes, assigned_to, executed_by, executed_at, test_id),
    )
    conn.commit()
    project_id = test["project_id"]
    conn.close()
    if passed != test["passed"]:
        status_labels = {1: "Pass", 0: "Fail", None: "Pending"}
        app.logger.info("Test status changed: id=%s %s->%s by %s", test_id,
                        status_labels.get(test["passed"]), status_labels.get(passed), g.user["username"])
        flash("Test saved. Status changed to %s." % status_labels.get(passed))
    else:
        app.logger.info("Test updated: id=%s by %s", test_id, g.user["username"])
        flash("Test saved.")
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
    conn.execute("DELETE FROM test_comments WHERE test_id = ?", (test_id,))
    conn.execute("DELETE FROM test_history WHERE test_id = ?", (test_id,))
    conn.execute("DELETE FROM attachments WHERE test_id = ?", (test_id,))
    conn.execute("DELETE FROM tests WHERE id = ?", (test_id,))
    conn.commit()
    conn.close()
    app.logger.info("Test deleted: id=%s by %s", test_id, g.user["username"])
    flash("Test deleted.")
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
        app.logger.info("Attachment uploaded: '%s' on test %s by %s", file.filename, test_id, g.user["username"])
        flash("Attachment uploaded.")
    conn.close()
    return redirect(url_for("project_detail", project_id=test["project_id"]))


@app.route("/tests/<int:test_id>/comments", methods=["POST"])
@login_required
def add_comment(test_id):
    conn = get_db()
    test = conn.execute("SELECT * FROM tests WHERE id = ?", (test_id,)).fetchone()
    if not test:
        conn.close()
        return "Test not found", 404
    body = request.form.get("body", "").strip()
    if body:
        conn.execute(
            "INSERT INTO test_comments (test_id, username, body) VALUES (?, ?, ?)",
            (test_id, g.user["username"], body),
        )
        conn.commit()
        app.logger.info("Comment added on test %s by %s", test_id, g.user["username"])
        flash("Comment added.")
    conn.close()
    return redirect(url_for("project_detail", project_id=test["project_id"]))


@app.route("/comments/<int:comment_id>/delete", methods=["POST"])
@login_required
def delete_comment(comment_id):
    conn = get_db()
    comment = conn.execute("SELECT * FROM test_comments WHERE id = ?", (comment_id,)).fetchone()
    if not comment:
        conn.close()
        return "Comment not found", 404
    # only the comment author or an admin can delete
    if comment["username"] != g.user["username"] and not g.user["is_admin"]:
        conn.close()
        return "Access denied", 403
    test = conn.execute("SELECT project_id FROM tests WHERE id = ?", (comment["test_id"],)).fetchone()
    conn.execute("DELETE FROM test_comments WHERE id = ?", (comment_id,))
    conn.commit()
    conn.close()
    app.logger.info("Comment deleted: id=%s by %s", comment_id, g.user["username"])
    flash("Comment deleted.")
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
    app.logger.info("Attachment deleted: '%s' (id=%s) by %s", att["original_name"], attachment_id, g.user["username"])
    flash("Attachment removed.")
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
            app.logger.info("User added: '%s' (admin=%s) by %s", username, is_admin, g.user["username"])
            flash("User added.")
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
        app.logger.info("Admin toggled: '%s' admin=%s by %s", user["username"], new_val, g.user["username"])
        flash("Admin role updated.")
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
        app.logger.info("Password reset: user_id=%s by %s", user_id, g.user["username"])
        flash("Password reset.")
    return redirect(url_for("user_list"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    if user_id == g.user["id"]:
        return redirect(url_for("user_list"))
    conn = get_db()
    user = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    app.logger.info("User deleted: '%s' (id=%s) by %s", user["username"] if user else "unknown", user_id, g.user["username"])
    flash("User deleted.")
    return redirect(url_for("user_list"))


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5021, debug=True)
