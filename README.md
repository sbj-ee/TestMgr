# Test Repository

A Flask web application for managing test cases across projects. Track test descriptions, steps, results, output, and attachments with full user authentication and audit history.

## Features

- **Projects**: Create, clone, archive/unarchive, and delete test projects
- **Test Cases**: Each test includes description, steps, pass/fail/pending status, output, and notes
- **Test Assignment**: Assign tests to specific users, filter by "Assigned to Me"
- **Comments**: Discussion thread per test, with delete for authors and admins
- **File Attachments**: Upload and manage files attached to individual tests
- **User Authentication**: Login/register with hashed passwords, session-based auth
- **Admin User Management**: Add users, reset passwords, toggle admin roles, delete users
- **Test Reordering**: Move tests up/down within a project
- **Status Filtering**: Filter tests by All, Passed, Failed, Pending, or Assigned to Me
- **Global Search**: Search across all test descriptions, steps, output, and notes
- **Test History**: Audit log tracking who changed test results and when
- **Dashboard**: Cross-project stats with total pass rate, per-project summary, and recent activity
- **Dark Mode**: Toggle between light and dark themes, persisted in browser
- **Export**: Download project test results as Markdown or CSV
- **Logging**: Request and application event logging with rotating log files

## Requirements

- Python 3
- Flask (`pip install flask`)

## Quick Start

```bash
pip install -r requirements.txt

# Development
python3 app.py

# Production
gunicorn -b 0.0.0.0:5021 -w 2 app:app
```

Set the `SECRET_KEY` environment variable in production:

```bash
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

The SQLite database and uploads directory are created automatically.

The first user to register is automatically granted admin privileges.

## Project Structure

```
app.py                  # Flask application (routes, models, auth)
requirements.txt        # Python dependencies
templates/
  base.html             # Base layout template
  index.html            # Project listing page
  project.html          # Project detail with test management
  login.html            # Login form
  register.html         # Registration form
  users.html            # Admin user management
  search.html           # Global search page
  dashboard.html        # Cross-project stats dashboard
uploads/                # Uploaded attachment files (auto-created)
logs/                   # Application log files (auto-created)
tests.db                # SQLite database (auto-created)
```

## Database Schema

| Table | Purpose |
|-------|---------|
| `users` | User accounts with hashed passwords and admin flag |
| `projects` | Test project containers with archive support |
| `tests` | Test cases with status, output, notes, assignment, ordering, and user tracking |
| `attachments` | File attachments linked to tests |
| `test_comments` | Discussion comments on individual tests |
| `test_history` | Audit log of test result status changes |
