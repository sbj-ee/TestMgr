"""Top-level pages: project index, dashboard and global search."""
from flask import Blueprint, render_template, request

from .auth import login_required
from .db import get_db

bp = Blueprint("main", __name__)

# per-project counts, shared by the index and dashboard
_PROJECT_STATS_SQL = (
    "SELECT p.*, "
    "COUNT(t.id) AS test_count, "
    "COALESCE(SUM(t.passed = 1), 0) AS pass_count, "
    "COALESCE(SUM(t.passed = 0), 0) AS fail_count, "
    "COALESCE(SUM(t.id IS NOT NULL AND t.passed IS NULL), 0) AS pending_count "
    "FROM projects p LEFT JOIN tests t ON t.project_id = p.id "
    "WHERE p.archived = ? GROUP BY p.id "
)


@bp.route("/")
@login_required
def index():
    conn = get_db()
    order = "ORDER BY p.created_at DESC, p.id DESC"
    projects = conn.execute(_PROJECT_STATS_SQL + order, (0,)).fetchall()
    archived_projects = conn.execute(_PROJECT_STATS_SQL + order, (1,)).fetchall()
    return render_template("index.html", projects=projects, archived_projects=archived_projects)


@bp.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    project_stats = conn.execute(_PROJECT_STATS_SQL + "ORDER BY p.name", (0,)).fetchall()
    total_projects = len(project_stats)
    total_tests = sum(p["test_count"] for p in project_stats)
    total_pass = sum(p["pass_count"] for p in project_stats)
    total_fail = sum(p["fail_count"] for p in project_stats)
    total_pending = total_tests - total_pass - total_fail
    pass_rate = round(total_pass / total_tests * 100, 1) if total_tests > 0 else 0

    recent = conn.execute(
        "SELECT h.*, t.description AS test_desc, p.name AS project_name, p.id AS project_id "
        "FROM test_history h "
        "JOIN tests t ON h.test_id = t.id "
        "JOIN projects p ON t.project_id = p.id "
        "ORDER BY h.changed_at DESC, h.id DESC LIMIT 10"
    ).fetchall()

    return render_template("dashboard.html",
        total_projects=total_projects, total_tests=total_tests,
        total_pass=total_pass, total_fail=total_fail, total_pending=total_pending,
        pass_rate=pass_rate, project_stats=project_stats, recent=recent)


@bp.route("/search")
@login_required
def search():
    q = request.args.get("q", "").strip()
    results = []
    if q:
        like = f"%{q}%"
        results = get_db().execute(
            "SELECT t.*, p.name AS project_name FROM tests t "
            "JOIN projects p ON t.project_id = p.id "
            "WHERE t.description LIKE ? OR t.steps LIKE ? OR t.output LIKE ? OR t.notes LIKE ? "
            "ORDER BY p.name, t.sort_order",
            (like, like, like, like),
        ).fetchall()
    return render_template("search.html", q=q, results=results)
