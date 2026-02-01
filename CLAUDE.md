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
# Development (with auto-reload)
python3 app.py

# Production (with gunicorn)
gunicorn -b 0.0.0.0:5021 -w 2 app:app
```

Runs on `http://0.0.0.0:5021`. The SQLite database (`tests.db`) and `uploads/` directory are created automatically on first run. Set `SECRET_KEY` env var in production.

## Architecture

Single-file Flask app (`app.py`) with Jinja2 templates and SQLite3 backend.

### Database Tables

- **users**: Authentication with hashed passwords, admin flag
- **projects**: Test project containers with archive support
- **tests**: Test cases with description, steps, pass/fail, output, sort order, created/executed by tracking
- **attachments**: File attachments linked to tests (stored in `uploads/`)
- **test_history**: Audit log of test result changes

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
