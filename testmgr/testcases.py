"""Test case routes: create/edit/reorder/duplicate/delete, attachments and comments."""
from datetime import datetime, timezone
import os
import uuid

from flask import (
    Blueprint, current_app, flash, g, redirect, request, send_from_directory, url_for,
)

from .auth import login_required
from .db import (
    STATUS_LABELS, fetch_or_404, get_db, get_project_or_404, get_test_or_404,
    remove_attachment_files,
)

bp = Blueprint("testcases", __name__)

_PASSED_VALUES = {"1": 1, "0": 0}


def _back_to(project_id):
    return redirect(url_for("projects.project_detail", project_id=project_id))


def _next_sort_order(project_id):
    return get_db().execute(
        "SELECT COALESCE(MAX(sort_order), -1) + 1 FROM tests WHERE project_id = ?", (project_id,)
    ).fetchone()[0]


@bp.route("/projects/<int:project_id>/tests", methods=["POST"])
@login_required
def create_test(project_id):
    get_project_or_404(project_id)
    description = request.form.get("description", "").strip()
    steps = request.form.get("steps", "").strip()
    if not (description and steps):
        flash("Description and steps are required.")
        return _back_to(project_id)
    conn = get_db()
    conn.execute(
        "INSERT INTO tests (project_id, description, steps, created_by, sort_order) VALUES (?, ?, ?, ?, ?)",
        (project_id, description, steps, g.user["username"], _next_sort_order(project_id)),
    )
    conn.commit()
    current_app.logger.info("Test created: '%s' in project %s by %s",
                            description, project_id, g.user["username"])
    flash("Test added.")
    return _back_to(project_id)


@bp.route("/tests/<int:test_id>/move/<direction>", methods=["POST"])
@login_required
def move_test(test_id, direction):
    test = get_test_or_404(test_id)
    if direction == "up":
        neighbor_sql = "sort_order < ? ORDER BY sort_order DESC"
    elif direction == "down":
        neighbor_sql = "sort_order > ? ORDER BY sort_order ASC"
    else:
        return "Invalid direction", 400
    conn = get_db()
    neighbor = conn.execute(
        "SELECT * FROM tests WHERE project_id = ? AND " + neighbor_sql + " LIMIT 1",
        (test["project_id"], test["sort_order"]),
    ).fetchone()
    if neighbor:
        conn.execute("UPDATE tests SET sort_order = ? WHERE id = ?", (neighbor["sort_order"], test_id))
        conn.execute("UPDATE tests SET sort_order = ? WHERE id = ?", (test["sort_order"], neighbor["id"]))
        conn.commit()
        current_app.logger.info("Test moved %s: id=%s by %s", direction, test_id, g.user["username"])
    return _back_to(test["project_id"])


@bp.route("/tests/<int:test_id>/update", methods=["POST"])
@login_required
def update_test(test_id):
    test = get_test_or_404(test_id)
    description = request.form.get("description", "").strip()
    steps = request.form.get("steps", "").strip()
    if not (description and steps):
        flash("Description and steps are required. Changes were not saved.")
        return _back_to(test["project_id"])
    passed = _PASSED_VALUES.get(request.form.get("passed"))
    status_changed = passed != test["passed"]

    conn = get_db()
    # track who executed the test and when the result changes
    executed_by = test["executed_by"]
    executed_at = test["executed_at"]
    if status_changed:
        executed_by = g.user["username"]
        executed_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO test_history (test_id, old_status, new_status, changed_by) VALUES (?, ?, ?, ?)",
            (test_id, STATUS_LABELS[test["passed"]], STATUS_LABELS[passed], g.user["username"]),
        )
    conn.execute(
        "UPDATE tests SET description = ?, steps = ?, passed = ?, output = ?, notes = ?, "
        "assigned_to = ?, executed_by = ?, executed_at = ? WHERE id = ?",
        (description, steps, passed, request.form.get("output", ""),
         request.form.get("notes", ""), request.form.get("assigned_to", ""),
         executed_by, executed_at, test_id),
    )
    conn.commit()
    if status_changed:
        current_app.logger.info("Test status changed: id=%s %s->%s by %s", test_id,
                                STATUS_LABELS[test["passed"]], STATUS_LABELS[passed], g.user["username"])
        flash("Test saved. Status changed to %s." % STATUS_LABELS[passed])
    else:
        current_app.logger.info("Test updated: id=%s by %s", test_id, g.user["username"])
        flash("Test saved.")
    return _back_to(test["project_id"])


@bp.route("/tests/<int:test_id>/duplicate", methods=["POST"])
@login_required
def duplicate_test(test_id):
    test = get_test_or_404(test_id)
    conn = get_db()
    conn.execute(
        "INSERT INTO tests (project_id, description, steps, passed, output, notes, assigned_to, created_by, sort_order) "
        "VALUES (?, ?, ?, NULL, '', ?, '', ?, ?)",
        (test["project_id"], test["description"] + " (Copy)", test["steps"], test["notes"],
         g.user["username"], _next_sort_order(test["project_id"])),
    )
    conn.commit()
    current_app.logger.info("Test duplicated: id=%s by %s", test_id, g.user["username"])
    flash("Test duplicated.")
    return _back_to(test["project_id"])


@bp.route("/tests/<int:test_id>/delete", methods=["POST"])
@login_required
def delete_test(test_id):
    test = get_test_or_404(test_id)
    conn = get_db()
    remove_attachment_files("t.id = ?", (test_id,))
    # attachments, history and comments are removed by ON DELETE CASCADE
    conn.execute("DELETE FROM tests WHERE id = ?", (test_id,))
    conn.commit()
    current_app.logger.info("Test deleted: id=%s by %s", test_id, g.user["username"])
    flash("Test deleted.")
    return _back_to(test["project_id"])


@bp.route("/tests/<int:test_id>/attachments", methods=["POST"])
@login_required
def upload_attachment(test_id):
    test = get_test_or_404(test_id)
    file = request.files.get("file")
    if file and file.filename:
        stored_name = uuid.uuid4().hex + os.path.splitext(file.filename)[1]
        file.save(os.path.join(current_app.config["UPLOAD_DIR"], stored_name))
        conn = get_db()
        conn.execute(
            "INSERT INTO attachments (test_id, original_name, stored_name) VALUES (?, ?, ?)",
            (test_id, file.filename, stored_name),
        )
        conn.commit()
        current_app.logger.info("Attachment uploaded: '%s' on test %s by %s",
                                file.filename, test_id, g.user["username"])
        flash("Attachment uploaded.")
    return _back_to(test["project_id"])


@bp.route("/attachments/<int:attachment_id>")
@login_required
def download_attachment(attachment_id):
    att = fetch_or_404("SELECT * FROM attachments WHERE id = ?", (attachment_id,), "Attachment")
    # force download so uploaded HTML/SVG can never render (and run scripts) on our origin
    response = send_from_directory(
        current_app.config["UPLOAD_DIR"], att["stored_name"],
        download_name=att["original_name"], as_attachment=True,
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@bp.route("/attachments/<int:attachment_id>/delete", methods=["POST"])
@login_required
def delete_attachment(attachment_id):
    att = fetch_or_404(
        "SELECT a.*, t.project_id FROM attachments a JOIN tests t ON a.test_id = t.id WHERE a.id = ?",
        (attachment_id,), "Attachment",
    )
    path = os.path.join(current_app.config["UPLOAD_DIR"], att["stored_name"])
    if os.path.exists(path):
        os.remove(path)
    conn = get_db()
    conn.execute("DELETE FROM attachments WHERE id = ?", (attachment_id,))
    conn.commit()
    current_app.logger.info("Attachment deleted: '%s' (id=%s) by %s",
                            att["original_name"], attachment_id, g.user["username"])
    flash("Attachment removed.")
    return _back_to(att["project_id"])


@bp.route("/tests/<int:test_id>/comments", methods=["POST"])
@login_required
def add_comment(test_id):
    test = get_test_or_404(test_id)
    body = request.form.get("body", "").strip()
    if body:
        conn = get_db()
        conn.execute(
            "INSERT INTO test_comments (test_id, username, body) VALUES (?, ?, ?)",
            (test_id, g.user["username"], body),
        )
        conn.commit()
        current_app.logger.info("Comment added on test %s by %s", test_id, g.user["username"])
        flash("Comment added.")
    return _back_to(test["project_id"])


@bp.route("/comments/<int:comment_id>/delete", methods=["POST"])
@login_required
def delete_comment(comment_id):
    comment = fetch_or_404(
        "SELECT c.*, t.project_id FROM test_comments c JOIN tests t ON c.test_id = t.id WHERE c.id = ?",
        (comment_id,), "Comment",
    )
    # only the comment author or an admin can delete
    if comment["username"] != g.user["username"] and not g.user["is_admin"]:
        return "Access denied", 403
    conn = get_db()
    conn.execute("DELETE FROM test_comments WHERE id = ?", (comment_id,))
    conn.commit()
    current_app.logger.info("Comment deleted: id=%s by %s", comment_id, g.user["username"])
    flash("Comment deleted.")
    return _back_to(comment["project_id"])
