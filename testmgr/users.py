"""Admin-only user management."""
from flask import Blueprint, current_app, flash, g, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash

from .auth import admin_required
from .db import get_db

bp = Blueprint("users", __name__)


def _all_users():
    return get_db().execute("SELECT * FROM users ORDER BY created_at DESC, id DESC").fetchall()


@bp.route("/users")
@admin_required
def user_list():
    return render_template("users.html", users=_all_users())


@bp.route("/users/add", methods=["POST"])
@admin_required
def add_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    is_admin = 1 if request.form.get("is_admin") else 0
    conn = get_db()
    if not username or not password:
        error = "Username and password are required."
    elif conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
        error = "Username already taken."
    else:
        conn.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), is_admin),
        )
        conn.commit()
        current_app.logger.info("User added: '%s' (admin=%s) by %s", username, is_admin, g.user["username"])
        flash("User added.")
        return redirect(url_for("users.user_list"))
    return render_template("users.html", users=_all_users(), error=error)


@bp.route("/users/<int:user_id>/toggle-admin", methods=["POST"])
@admin_required
def toggle_admin(user_id):
    if user_id == g.user["id"]:
        return redirect(url_for("users.user_list"))
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user:
        new_val = 0 if user["is_admin"] else 1
        conn.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_val, user_id))
        conn.commit()
        current_app.logger.info("Admin toggled: '%s' admin=%s by %s",
                                user["username"], new_val, g.user["username"])
        flash("Admin role updated.")
    return redirect(url_for("users.user_list"))


@bp.route("/users/<int:user_id>/reset-password", methods=["POST"])
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
        current_app.logger.info("Password reset: user_id=%s by %s", user_id, g.user["username"])
        flash("Password reset.")
    return redirect(url_for("users.user_list"))


@bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    if user_id == g.user["id"]:
        return redirect(url_for("users.user_list"))
    conn = get_db()
    user = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    current_app.logger.info("User deleted: '%s' (id=%s) by %s",
                            user["username"] if user else "unknown", user_id, g.user["username"])
    flash("User deleted.")
    return redirect(url_for("users.user_list"))
