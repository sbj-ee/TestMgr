"""Project routes: CRUD, clone/archive, export, import and bulk test actions."""
from datetime import datetime, timezone
from io import StringIO
from urllib.parse import quote
import csv
import os
import shutil
import uuid

from flask import (
    Blueprint, Response, current_app, flash, g, redirect, render_template, request, url_for,
)
from werkzeug.utils import secure_filename

from .auth import login_required
from .db import (
    STATUS_LABELS, children_by_test, get_db, get_project_or_404, remove_attachment_files,
)

bp = Blueprint("projects", __name__)

_STATUS_FILTERS = {
    "pass": " AND passed = 1",
    "fail": " AND passed = 0",
    "pending": " AND passed IS NULL",
    "all": "",
}


def _back_to(project_id):
    return redirect(url_for("projects.project_detail", project_id=project_id))


def download_response(body, mimetype, base_name, ext):
    """Build a download Response with a Content-Disposition header safe for any name."""
    ascii_name = secure_filename(base_name) or "project"
    utf8_name = quote(base_name.replace(" ", "_") + ext, safe="")
    disposition = f"attachment; filename=\"{ascii_name}{ext}\"; filename*=UTF-8''{utf8_name}"
    return Response(body, mimetype=mimetype, headers={"Content-Disposition": disposition})


@bp.route("/projects", methods=["POST"])
@login_required
def create_project():
    name = request.form.get("name", "").strip()
    if name:
        conn = get_db()
        conn.execute("INSERT INTO projects (name) VALUES (?)", (name,))
        conn.commit()
        current_app.logger.info("Project created: '%s' by %s", name, g.user["username"])
        flash("Project created.")
    return redirect(url_for("main.index"))


@bp.route("/projects/<int:project_id>")
@login_required
def project_detail(project_id):
    project = get_project_or_404(project_id)
    conn = get_db()
    status_filter = request.args.get("status", "all")
    if status_filter not in _STATUS_FILTERS:
        status_filter = "all"
    assigned_filter = request.args.get("assigned", "")

    sql = "SELECT * FROM tests WHERE project_id = ?" + _STATUS_FILTERS[status_filter]
    params = [project_id]
    if assigned_filter == "me":
        sql += " AND assigned_to = ?"
        params.append(g.user["username"])
    tests = conn.execute(sql + " ORDER BY sort_order", params).fetchall()

    test_ids = [t["id"] for t in tests]
    users = conn.execute("SELECT username FROM users ORDER BY username").fetchall()
    return render_template("project.html", project=project, tests=tests,
        attachments=children_by_test("attachments", test_ids),
        history=children_by_test("test_history", test_ids),
        comments=children_by_test("test_comments", test_ids),
        users=users, status_filter=status_filter, assigned_filter=assigned_filter)


@bp.route("/projects/<int:project_id>/rename", methods=["POST"])
@login_required
def rename_project(project_id):
    name = request.form.get("name", "").strip()
    if name:
        conn = get_db()
        conn.execute("UPDATE projects SET name = ? WHERE id = ?", (name, project_id))
        conn.commit()
        current_app.logger.info("Project %d renamed to '%s' by %s", project_id, name, g.user["username"])
        flash("Project renamed.")
    return redirect(url_for("main.index"))


@bp.route("/projects/<int:project_id>/delete", methods=["POST"])
@login_required
def delete_project(project_id):
    conn = get_db()
    remove_attachment_files("t.project_id = ?", (project_id,))
    # tests, attachments, history and comments are removed by ON DELETE CASCADE
    conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    conn.commit()
    current_app.logger.info("Project deleted: id=%s by %s", project_id, g.user["username"])
    flash("Project deleted.")
    return redirect(url_for("main.index"))


@bp.route("/projects/<int:project_id>/clone", methods=["POST"])
@login_required
def clone_project(project_id):
    project = get_project_or_404(project_id)
    conn = get_db()
    upload_dir = current_app.config["UPLOAD_DIR"]
    cursor = conn.execute(
        "INSERT INTO projects (name, archived) VALUES (?, 0)",
        (project["name"] + " (Copy)",),
    )
    new_project_id = cursor.lastrowid
    # clone all tests (reset results, preserve order)
    tests = conn.execute(
        "SELECT * FROM tests WHERE project_id = ? ORDER BY sort_order", (project_id,)
    ).fetchall()
    attachments = children_by_test("attachments", [t["id"] for t in tests])
    for test in tests:
        cursor = conn.execute(
            "INSERT INTO tests (project_id, description, steps, passed, output, notes, created_by, executed_by, sort_order) "
            "VALUES (?, ?, ?, NULL, '', ?, ?, '', ?)",
            (new_project_id, test["description"], test["steps"], test["notes"],
             g.user["username"], test["sort_order"]),
        )
        new_test_id = cursor.lastrowid
        for att in attachments[test["id"]]:
            ext = os.path.splitext(att["stored_name"])[1]
            new_stored = uuid.uuid4().hex + ext
            src = os.path.join(upload_dir, att["stored_name"])
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(upload_dir, new_stored))
            conn.execute(
                "INSERT INTO attachments (test_id, original_name, stored_name) VALUES (?, ?, ?)",
                (new_test_id, att["original_name"], new_stored),
            )
    conn.commit()
    current_app.logger.info("Project cloned: '%s' -> id=%s by %s",
                            project["name"], new_project_id, g.user["username"])
    flash("Project cloned.")
    return _back_to(new_project_id)


@bp.route("/projects/<int:project_id>/archive", methods=["POST"])
@login_required
def archive_project(project_id):
    project = get_project_or_404(project_id)
    conn = get_db()
    new_val = 0 if project["archived"] else 1
    conn.execute("UPDATE projects SET archived = ? WHERE id = ?", (new_val, project_id))
    conn.commit()
    action = "archived" if new_val else "unarchived"
    current_app.logger.info("Project %s: '%s' by %s", action, project["name"], g.user["username"])
    flash("Project %s." % action)
    return redirect(url_for("main.index"))


def _csv_report(tests, attachments, comments):
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(["#", "Description", "Steps", "Status", "Assigned To", "Created By",
                     "Executed By", "Executed At", "Output", "Notes", "Attachments", "Comments"])
    for i, test in enumerate(tests, 1):
        att_names = "; ".join(a["original_name"] for a in attachments[test["id"]])
        cmt_text = "; ".join(f"{c['username']}: {c['body']}" for c in comments[test["id"]])
        writer.writerow([
            i, test["description"], test["steps"], STATUS_LABELS[test["passed"]],
            test["assigned_to"], test["created_by"], test["executed_by"],
            test["executed_at"] or "", test["output"], test["notes"], att_names, cmt_text,
        ])
    return si.getvalue()


def _markdown_report(project, tests, attachments, history, comments):
    total = len(tests)
    passed = sum(1 for t in tests if t["passed"] == 1)
    failed = sum(1 for t in tests if t["passed"] == 0)
    pending = total - passed - failed
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        f"# {project['name']} — Test Report",
        "",
        f"**Generated:** {generated}  ",
        f"**Project created:** {project['created_at']}  ",
        f"**Exported by:** {g.user['username']}",
        "",
        "## Summary",
        "",
        "| Total | Passed | Failed | Pending |",
        "|-------|--------|--------|---------|",
        f"| {total} | {passed} | {failed} | {pending} |",
        "",
    ]
    if tests:
        lines += ["## Test Results", ""]
    for i, test in enumerate(tests, 1):
        lines.append(f"### {i}. {test['description']}")
        lines.append("")
        lines.append(f"**Status:** `{STATUS_LABELS[test['passed']].upper()}`  ")
        if test["assigned_to"]:
            lines.append(f"**Assigned to:** {test['assigned_to']}  ")
        if test["created_by"]:
            lines.append(f"**Created by:** {test['created_by']}  ")
        if test["executed_by"]:
            executed_info = f"**Executed by:** {test['executed_by']}"
            if test["executed_at"]:
                executed_info += f" on {test['executed_at']}"
            lines.append(executed_info + "  ")
        lines += ["", "**Steps:**", ""]
        lines += [f"> {step_line}" for step_line in test["steps"].splitlines()]
        lines.append("")
        if test["output"]:
            lines += ["**Output:**", "", "```", test["output"], "```", ""]
        if test["notes"]:
            lines += ["**Notes:**", "", test["notes"], ""]
        if attachments[test["id"]]:
            lines += ["**Attachments:**", ""]
            lines += [f"- {att['original_name']}" for att in attachments[test["id"]]]
            lines.append("")
        if history[test["id"]]:
            lines += ["**History:**", ""]
            lines += [
                f"- {entry['changed_by']}: "
                f"{entry['old_status'] or 'Pending'} → {entry['new_status'] or 'Pending'} "
                f"({entry['changed_at']})"
                for entry in history[test["id"]]
            ]
            lines.append("")
        if comments[test["id"]]:
            lines += ["**Comments:**", ""]
            lines += [f"- **{c['username']}** ({c['created_at']}): {c['body']}"
                      for c in comments[test["id"]]]
            lines.append("")
        lines += ["---", ""]
    return "\n".join(lines)


@bp.route("/projects/<int:project_id>/export")
@login_required
def export_project(project_id):
    project = get_project_or_404(project_id)
    tests = get_db().execute(
        "SELECT * FROM tests WHERE project_id = ? ORDER BY sort_order", (project_id,)
    ).fetchall()
    test_ids = [t["id"] for t in tests]
    attachments = children_by_test("attachments", test_ids)
    comments = children_by_test("test_comments", test_ids)

    fmt = request.args.get("format", "markdown")
    current_app.logger.info("Export %s: '%s' by %s", fmt, project["name"], g.user["username"])

    if fmt == "csv":
        body = _csv_report(tests, attachments, comments)
        return download_response(body, "text/csv", project["name"], "_report.csv")
    history = children_by_test("test_history", test_ids)
    body = _markdown_report(project, tests, attachments, history, comments)
    return download_response(body, "text/markdown", project["name"], "_report.md")


@bp.route("/projects/<int:project_id>/bulk", methods=["POST"])
@login_required
def bulk_action(project_id):
    get_project_or_404(project_id)
    conn = get_db()
    action = request.form.get("action", "")
    requested = [int(x) for x in request.form.get("test_ids", "").split(",") if x.strip().isdigit()]
    if not action or not requested:
        return _back_to(project_id)
    # only ever act on tests that actually belong to this project
    test_ids = [r["id"] for r in conn.execute(
        f"SELECT id FROM tests WHERE id IN ({','.join('?' * len(requested))}) AND project_id = ?",
        requested + [project_id],
    ).fetchall()]
    if not test_ids:
        return _back_to(project_id)
    placeholders = ",".join("?" * len(test_ids))
    user = g.user["username"]

    if action in ("pass", "fail", "pending"):
        new_passed = {"pass": 1, "fail": 0, "pending": None}[action]
        tests = conn.execute(
            f"SELECT id, passed FROM tests WHERE id IN ({placeholders})", test_ids,
        ).fetchall()
        # match single-test edits: only tests whose status actually changes get
        # a history entry and a new executed_by / executed_at
        changed = [t for t in tests if t["passed"] != new_passed]
        conn.executemany(
            "INSERT INTO test_history (test_id, old_status, new_status, changed_by) VALUES (?, ?, ?, ?)",
            [(t["id"], STATUS_LABELS[t["passed"]], STATUS_LABELS[new_passed], user) for t in changed],
        )
        if changed:
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                f"UPDATE tests SET passed = ?, executed_by = ?, executed_at = ? "
                f"WHERE id IN ({','.join('?' * len(changed))})",
                [new_passed, user, now] + [t["id"] for t in changed],
            )
        conn.commit()
        label = STATUS_LABELS[new_passed]
        unchanged = len(tests) - len(changed)
        current_app.logger.info("Bulk %s: %d test(s) in project %s by %s",
                                label, len(changed), project_id, user)
        msg = "Marked %d test(s) as %s." % (len(changed), label)
        if unchanged:
            msg += " %d already %s." % (unchanged, label)
        flash(msg)

    elif action == "assign":
        assign_to = request.form.get("assign_to", "")
        conn.execute(
            f"UPDATE tests SET assigned_to = ? WHERE id IN ({placeholders})",
            [assign_to] + test_ids,
        )
        conn.commit()
        label = assign_to or "Unassigned"
        current_app.logger.info("Bulk assign '%s': %d test(s) in project %s by %s",
                                label, len(test_ids), project_id, user)
        flash("Assigned %d test(s) to %s." % (len(test_ids), label))

    elif action == "delete":
        remove_attachment_files(f"t.id IN ({placeholders})", test_ids)
        # attachments, history and comments are removed by ON DELETE CASCADE
        conn.execute(f"DELETE FROM tests WHERE id IN ({placeholders})", test_ids)
        conn.commit()
        current_app.logger.info("Bulk delete: %d test(s) in project %s by %s",
                                len(test_ids), project_id, user)
        flash("Deleted %d test(s)." % len(test_ids))

    return _back_to(project_id)


@bp.route("/projects/<int:project_id>/import", methods=["POST"])
@login_required
def import_tests(project_id):
    get_project_or_404(project_id)
    file = request.files.get("file")
    if not file or not file.filename:
        flash("No file selected.")
        return _back_to(project_id)
    try:
        content = file.read().decode("utf-8-sig")
    except UnicodeDecodeError:
        flash("Could not read file. Please upload a UTF-8 CSV.")
        return _back_to(project_id)
    reader = csv.DictReader(StringIO(content))
    if not reader.fieldnames:
        flash("CSV file is empty or has no headers.")
        return _back_to(project_id)
    headers = {h.strip().lower() for h in reader.fieldnames}
    if "description" not in headers or "steps" not in headers:
        flash("CSV must have 'Description' and 'Steps' columns.")
        return _back_to(project_id)

    conn = get_db()
    max_order = conn.execute(
        "SELECT COALESCE(MAX(sort_order), -1) FROM tests WHERE project_id = ?", (project_id,)
    ).fetchone()[0]
    status_values = {"pass": 1, "fail": 0}
    imported = 0
    for row in reader:
        # extra cells beyond the header land under a None key as a list; ignore them
        norm = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k is not None}
        description = norm.get("description", "")
        steps = norm.get("steps", "")
        if not description or not steps:
            continue
        passed = status_values.get(norm.get("status", "").lower())
        max_order += 1
        conn.execute(
            "INSERT INTO tests (project_id, description, steps, passed, output, notes, created_by, sort_order) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (project_id, description, steps, passed, norm.get("output", ""),
             norm.get("notes", ""), g.user["username"], max_order),
        )
        imported += 1
    conn.commit()
    current_app.logger.info("Imported %d test(s) into project %s by %s",
                            imported, project_id, g.user["username"])
    flash("Imported %d test(s)." % imported)
    return _back_to(project_id)
