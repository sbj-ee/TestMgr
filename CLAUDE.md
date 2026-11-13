# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Flask web application for managing test repositories. Tracks test cases across projects with descriptions, steps, pass/fail results, output, and file attachments. Includes user authentication, admin user management, and test result history tracking.

## Requirements

- Python 3
- Flask: `pip install flask`
- SQLite3 (included with Python)

## Running

```bash
# Development (FLASK_DEBUG=1 enables auto-reload + debugger)
FLASK_DEBUG=1 python3 app.py

# Production (with gunicorn)
gunicorn -b 0.0.0.0:5021 -w 2 app:app
```

Runs on `http://0.0.0.0:5021`. The SQLite database (`tests.db`) and `uploads/` directory are created automatically on first run. `SECRET_KEY` comes from the env var, else a random key persisted to `.secret_key`.

Every POST form must include `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">` (tests disable CSRF via `CSRF_ENABLED=False`, except `TestSecurity`).

## Architecture

Flask app in the `testmgr/` package (app factory + blueprints), Jinja2 templates in `templates/`, SQLite3 backend. `app.py` is only the entry point: it calls `create_app()` and exposes `app` (for gunicorn) and `get_db()` (a standalone connection, used by tests).

- `testmgr/__init__.py`: `create_app(config)`, `load_secret_key()`, logging, before/after-request hooks
- `testmgr/db.py`: `get_db()` returns one connection per request (on `g`, closed in teardown; uncommitted work rolls back). Also `init_db(path)`, `STATUS_LABELS`, `get_project_or_404` / `get_test_or_404` / `fetch_or_404`, `children_by_test()` (batch-loads attachments/history/comments for many tests in one query), `remove_attachment_files()`
- Blueprints: `auth` (login/register/logout, CSRF, `login_required`/`admin_required`), `main` (index, dashboard, search), `projects`, `testcases` (tests, attachments, comments), `users` (admin)
- Templates must use blueprint-qualified endpoints, e.g. `url_for('projects.project_detail', ...)`
- Paths are config, not globals: `DATABASE`, `UPLOAD_DIR`, `LOG_DIR` in `app.config` (tests override them per test)
- Routes don't close connections; never call `conn.close()` on the result of `testmgr.db.get_db()`

### Database Tables

- **users**: Authentication with hashed passwords, admin flag
- **projects**: Test project containers with archive support
- **tests**: Test cases with description, steps, pass/fail, output, sort order, created/executed by tracking
- **attachments**: File attachments linked to tests (stored in `uploads/`)
- **test_comments**: Comments on individual tests
- **test_history**: Audit log of test result changes

Foreign keys are enforced (`PRAGMA foreign_keys = ON` per connection), so deleting a project/test cascades to its child rows; only the files in `uploads/` need removing by hand.

### Key Features

- Session-based auth with login/register, admin user management
- Project CRUD with clone, archive/unarchive, and Markdown report export
- Test CRUD with pass/fail/pending status, file attachments, reordering, and result history
- Status filtering and global search across all tests
- Auto-migration for schema changes on existing databases

### Templates

- `base.html`: Layout with nav header
- `index.html`: Project listing (active + archived)
- `project.html`: Project detail with test management
- `login.html` / `register.html`: Authentication forms
- `users.html`: Admin user management
- `search.html`: Global test search
