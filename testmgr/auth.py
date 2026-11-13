"""Authentication: login/register/logout, CSRF protection and access decorators."""
from functools import wraps
import hmac
import secrets

from flask import (
    Blueprint, current_app, g, redirect, render_template, request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db

bp = Blueprint("auth", __name__)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        if not g.user["is_admin"]:
            return "Access denied", 403
        return f(*args, **kwargs)
    return decorated


def csrf_token():
    """Return the per-session CSRF token, creating it if needed."""
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(32)
        session["csrf_token"] = token
    return token


def csrf_protect():
    if not current_app.config.get("CSRF_ENABLED", True):
        return None
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    expected = session.get("csrf_token")
    submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not expected or not submitted or not hmac.compare_digest(expected, submitted):
        current_app.logger.warning("CSRF check failed: %s %s from %s",
                                   request.method, request.path, request.remote_addr)
        return "Invalid or missing CSRF token. Reload the page and try again.", 400
    return None


def load_user():
    g.user = None
    if "user_id" in session:
        g.user = get_db().execute(
            "SELECT * FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if g.user is None:
            # user was deleted while logged in; drop the stale session
            session.clear()


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            current_app.logger.info("Login successful: %s", username)
            return redirect(url_for("main.index"))
        current_app.logger.warning("Login failed: %s", username)
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@bp.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        conn = get_db()
        if not username or not password:
            error = "Username and password are required."
        elif password != confirm_password:
            error = "Passwords do not match."
        elif conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
            error = "Username already taken."
        else:
            # first user becomes admin
            user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            is_admin = 1 if user_count == 0 else 0
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), is_admin),
            )
            conn.commit()
            session["user_id"] = cursor.lastrowid
            current_app.logger.info("User registered: %s (admin=%s)", username, is_admin)
            return redirect(url_for("main.index"))
    return render_template("register.html", error=error)


@bp.route("/logout")
def logout():
    username = g.user["username"] if g.user else "unknown"
    session.clear()
    current_app.logger.info("Logout: %s", username)
    return redirect(url_for("auth.login"))
