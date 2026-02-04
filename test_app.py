import pytest
import os
import io
import sys
import sqlite3

sys.path.insert(0, os.path.dirname(__file__))

import app as flask_app


# --- Fixtures ---

@pytest.fixture
def test_app(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test.db")
    upload_dir = str(tmp_path / "uploads")
    os.makedirs(upload_dir, exist_ok=True)

    monkeypatch.setattr(flask_app, "DB_PATH", db_path)
    monkeypatch.setattr(flask_app, "UPLOAD_DIR", upload_dir)

    flask_app.app.config["TESTING"] = True
    flask_app.app.config["SECRET_KEY"] = "test-secret"

    flask_app.init_db()

    yield flask_app.app


@pytest.fixture
def client(test_app):
    return test_app.test_client()


@pytest.fixture
def auth_client(client):
    """Register first user (auto-admin) and stay logged in."""
    client.post("/register", data={
        "username": "admin",
        "password": "password123",
        "confirm_password": "password123",
    })
    return client


@pytest.fixture
def non_admin_client(client):
    """Register admin first, then a second non-admin user, logged in as the non-admin."""
    client.post("/register", data={
        "username": "admin",
        "password": "password123",
        "confirm_password": "password123",
    })
    client.get("/logout")
    client.post("/register", data={
        "username": "user2",
        "password": "password123",
        "confirm_password": "password123",
    })
    return client


# --- Helpers ---

def create_project(client, name="Test Project"):
    return client.post("/projects", data={"name": name}, follow_redirects=True)


def create_test_case(client, project_id, description="Test Case 1", steps="Step 1"):
    return client.post(f"/projects/{project_id}/tests", data={
        "description": description,
        "steps": steps,
    }, follow_redirects=True)


def get_project_id(client):
    """Create a project and return its id."""
    create_project(client)
    conn = flask_app.get_db()
    project = conn.execute("SELECT id FROM projects ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    return project["id"]


def get_test_id(client, project_id):
    """Create a test case and return its id."""
    create_test_case(client, project_id)
    conn = flask_app.get_db()
    test = conn.execute("SELECT id FROM tests ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    return test["id"]


# ============================================================
# 1. Authentication
# ============================================================

class TestAuth:
    def test_login_page_renders(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b"Login" in resp.data

    def test_register_page_renders(self, client):
        resp = client.get("/register")
        assert resp.status_code == 200
        assert b"Register" in resp.data

    def test_register_first_user_is_admin(self, auth_client):
        conn = flask_app.get_db()
        user = conn.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
        conn.close()
        assert user["is_admin"] == 1

    def test_register_second_user_is_not_admin(self, non_admin_client):
        conn = flask_app.get_db()
        user = conn.execute("SELECT * FROM users WHERE username = 'user2'").fetchone()
        conn.close()
        assert user["is_admin"] == 0

    def test_register_duplicate_username(self, auth_client):
        resp = auth_client.post("/register", data={
            "username": "admin",
            "password": "other",
            "confirm_password": "other",
        }, follow_redirects=True)
        assert b"Username already taken" in resp.data

    def test_register_password_mismatch(self, client):
        resp = client.post("/register", data={
            "username": "newuser",
            "password": "abc",
            "confirm_password": "xyz",
        }, follow_redirects=True)
        assert b"Passwords do not match" in resp.data

    def test_register_empty_fields(self, client):
        resp = client.post("/register", data={
            "username": "",
            "password": "",
            "confirm_password": "",
        }, follow_redirects=True)
        assert b"Username and password are required" in resp.data

    def test_login_valid_credentials(self, client):
        client.post("/register", data={
            "username": "testuser",
            "password": "pass",
            "confirm_password": "pass",
        })
        client.get("/logout")
        resp = client.post("/login", data={
            "username": "testuser",
            "password": "pass",
        }, follow_redirects=True)
        assert b"Projects" in resp.data

    def test_login_invalid_credentials(self, client):
        client.post("/register", data={
            "username": "testuser",
            "password": "pass",
            "confirm_password": "pass",
        })
        client.get("/logout")
        resp = client.post("/login", data={
            "username": "testuser",
            "password": "wrong",
        }, follow_redirects=True)
        assert b"Invalid username or password" in resp.data

    def test_logout(self, auth_client):
        resp = auth_client.get("/logout", follow_redirects=True)
        assert b"Login" in resp.data


# ============================================================
# 2. Login Required
# ============================================================

class TestLoginRequired:
    def test_index_requires_login(self, client):
        resp = client.get("/")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_dashboard_requires_login(self, client):
        resp = client.get("/dashboard")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_search_requires_login(self, client):
        resp = client.get("/search")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


# ============================================================
# 3. Projects CRUD
# ============================================================

class TestProjects:
    def test_index_lists_projects(self, auth_client):
        create_project(auth_client, "My Project")
        resp = auth_client.get("/")
        assert b"My Project" in resp.data

    def test_create_project(self, auth_client):
        resp = create_project(auth_client, "New Project")
        assert b"Project created" in resp.data
        assert b"New Project" in resp.data

    def test_create_project_empty_name(self, auth_client):
        resp = create_project(auth_client, "")
        conn = flask_app.get_db()
        count = conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
        conn.close()
        assert count == 0

    def test_project_detail(self, auth_client):
        pid = get_project_id(auth_client)
        resp = auth_client.get(f"/projects/{pid}")
        assert resp.status_code == 200
        assert b"Test Project" in resp.data

    def test_project_detail_not_found(self, auth_client):
        resp = auth_client.get("/projects/9999")
        assert resp.status_code == 404

    def test_rename_project(self, auth_client):
        pid = get_project_id(auth_client)
        resp = auth_client.post(f"/projects/{pid}/rename", data={"name": "Renamed"}, follow_redirects=True)
        assert b"Project renamed" in resp.data
        assert b"Renamed" in resp.data

    def test_delete_project(self, auth_client):
        pid = get_project_id(auth_client)
        resp = auth_client.post(f"/projects/{pid}/delete", follow_redirects=True)
        assert b"Project deleted" in resp.data
        conn = flask_app.get_db()
        count = conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
        conn.close()
        assert count == 0

    def test_archive_project(self, auth_client):
        pid = get_project_id(auth_client)
        resp = auth_client.post(f"/projects/{pid}/archive", follow_redirects=True)
        assert b"archived" in resp.data
        conn = flask_app.get_db()
        project = conn.execute("SELECT archived FROM projects WHERE id = ?", (pid,)).fetchone()
        conn.close()
        assert project["archived"] == 1

    def test_unarchive_project(self, auth_client):
        pid = get_project_id(auth_client)
        auth_client.post(f"/projects/{pid}/archive")  # archive
        resp = auth_client.post(f"/projects/{pid}/archive", follow_redirects=True)  # unarchive
        assert b"unarchived" in resp.data
        conn = flask_app.get_db()
        project = conn.execute("SELECT archived FROM projects WHERE id = ?", (pid,)).fetchone()
        conn.close()
        assert project["archived"] == 0

    def test_clone_project(self, auth_client):
        pid = get_project_id(auth_client)
        create_test_case(auth_client, pid, "Clone Me", "Steps")
        resp = auth_client.post(f"/projects/{pid}/clone", follow_redirects=True)
        assert b"Project cloned" in resp.data
        conn = flask_app.get_db()
        projects = conn.execute("SELECT * FROM projects ORDER BY id").fetchall()
        conn.close()
        assert len(projects) == 2
        assert projects[1]["name"] == "Test Project (Copy)"


# ============================================================
# 4. Tests CRUD
# ============================================================

class TestTestsCRUD:
    def test_create_test(self, auth_client):
        pid = get_project_id(auth_client)
        resp = create_test_case(auth_client, pid, "My Test", "Do stuff")
        assert b"Test added" in resp.data

    def test_create_test_empty_fields(self, auth_client):
        pid = get_project_id(auth_client)
        auth_client.post(f"/projects/{pid}/tests", data={
            "description": "",
            "steps": "",
        })
        conn = flask_app.get_db()
        count = conn.execute("SELECT COUNT(*) FROM tests").fetchone()[0]
        conn.close()
        assert count == 0

    def test_update_test_description(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        auth_client.post(f"/tests/{tid}/update", data={
            "description": "Updated",
            "steps": "New steps",
            "output": "some output",
            "notes": "a note",
            "assigned_to": "",
            "passed": "",
        }, follow_redirects=True)
        conn = flask_app.get_db()
        test = conn.execute("SELECT * FROM tests WHERE id = ?", (tid,)).fetchone()
        conn.close()
        assert test["description"] == "Updated"
        assert test["steps"] == "New steps"
        assert test["output"] == "some output"
        assert test["notes"] == "a note"

    def test_update_test_status_pass(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        auth_client.post(f"/tests/{tid}/update", data={
            "description": "Test", "steps": "Steps",
            "output": "", "notes": "", "assigned_to": "",
            "passed": "1",
        })
        conn = flask_app.get_db()
        test = conn.execute("SELECT * FROM tests WHERE id = ?", (tid,)).fetchone()
        conn.close()
        assert test["passed"] == 1
        assert test["executed_by"] == "admin"
        assert test["executed_at"] is not None

    def test_update_test_status_fail(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        auth_client.post(f"/tests/{tid}/update", data={
            "description": "Test", "steps": "Steps",
            "output": "", "notes": "", "assigned_to": "",
            "passed": "0",
        })
        conn = flask_app.get_db()
        test = conn.execute("SELECT * FROM tests WHERE id = ?", (tid,)).fetchone()
        conn.close()
        assert test["passed"] == 0

    def test_update_test_status_creates_history(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        auth_client.post(f"/tests/{tid}/update", data={
            "description": "Test", "steps": "Steps",
            "output": "", "notes": "", "assigned_to": "",
            "passed": "1",
        })
        conn = flask_app.get_db()
        history = conn.execute("SELECT * FROM test_history WHERE test_id = ?", (tid,)).fetchall()
        conn.close()
        assert len(history) == 1
        assert history[0]["old_status"] == "Pending"
        assert history[0]["new_status"] == "Pass"

    def test_update_test_assign_to(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        auth_client.post(f"/tests/{tid}/update", data={
            "description": "Test", "steps": "Steps",
            "output": "", "notes": "", "assigned_to": "admin",
            "passed": "",
        })
        conn = flask_app.get_db()
        test = conn.execute("SELECT * FROM tests WHERE id = ?", (tid,)).fetchone()
        conn.close()
        assert test["assigned_to"] == "admin"

    def test_delete_test(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        resp = auth_client.post(f"/tests/{tid}/delete", follow_redirects=True)
        assert b"Test deleted" in resp.data
        conn = flask_app.get_db()
        count = conn.execute("SELECT COUNT(*) FROM tests").fetchone()[0]
        conn.close()
        assert count == 0

    def test_delete_test_not_found(self, auth_client):
        resp = auth_client.post("/tests/9999/delete")
        assert resp.status_code == 404

    def test_update_test_not_found(self, auth_client):
        resp = auth_client.post("/tests/9999/update", data={
            "description": "x", "steps": "x",
            "output": "", "notes": "", "assigned_to": "",
            "passed": "",
        })
        assert resp.status_code == 404


# ============================================================
# 4b. Test Duplication
# ============================================================

class TestDuplicate:
    def test_duplicate_test(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        # Update original with some data
        auth_client.post(f"/tests/{tid}/update", data={
            "description": "Original", "steps": "Step 1\nStep 2",
            "output": "some output", "notes": "a note",
            "assigned_to": "admin", "passed": "1",
        })
        resp = auth_client.post(f"/tests/{tid}/duplicate", follow_redirects=True)
        assert b"Test duplicated" in resp.data
        conn = flask_app.get_db()
        tests = conn.execute("SELECT * FROM tests WHERE project_id = ? ORDER BY id", (pid,)).fetchall()
        conn.close()
        assert len(tests) == 2
        clone = tests[1]
        assert clone["description"] == "Original (Copy)"
        assert clone["steps"] == "Step 1\nStep 2"
        assert clone["notes"] == "a note"
        assert clone["passed"] is None  # reset to pending
        assert clone["output"] == ""  # cleared
        assert clone["assigned_to"] == ""  # cleared
        assert clone["created_by"] == "admin"

    def test_duplicate_test_sort_order(self, auth_client):
        pid = get_project_id(auth_client)
        tid1 = get_test_id(auth_client, pid)
        tid2 = get_test_id(auth_client, pid)
        auth_client.post(f"/tests/{tid1}/duplicate")
        conn = flask_app.get_db()
        tests = conn.execute(
            "SELECT sort_order FROM tests WHERE project_id = ? ORDER BY sort_order", (pid,)
        ).fetchall()
        conn.close()
        assert len(tests) == 3
        # Duplicated test should be at the end
        assert tests[2]["sort_order"] > tests[1]["sort_order"]

    def test_duplicate_test_not_found(self, auth_client):
        resp = auth_client.post("/tests/9999/duplicate")
        assert resp.status_code == 404


# ============================================================
# 5. Test Reordering
# ============================================================

class TestReordering:
    def test_move_test_down(self, auth_client):
        pid = get_project_id(auth_client)
        tid1 = get_test_id(auth_client, pid)
        tid2 = get_test_id(auth_client, pid)
        auth_client.post(f"/tests/{tid1}/move/down", follow_redirects=True)
        conn = flask_app.get_db()
        t1 = conn.execute("SELECT sort_order FROM tests WHERE id = ?", (tid1,)).fetchone()
        t2 = conn.execute("SELECT sort_order FROM tests WHERE id = ?", (tid2,)).fetchone()
        conn.close()
        assert t1["sort_order"] > t2["sort_order"]

    def test_move_test_up(self, auth_client):
        pid = get_project_id(auth_client)
        tid1 = get_test_id(auth_client, pid)
        tid2 = get_test_id(auth_client, pid)
        auth_client.post(f"/tests/{tid2}/move/up", follow_redirects=True)
        conn = flask_app.get_db()
        t1 = conn.execute("SELECT sort_order FROM tests WHERE id = ?", (tid1,)).fetchone()
        t2 = conn.execute("SELECT sort_order FROM tests WHERE id = ?", (tid2,)).fetchone()
        conn.close()
        assert t2["sort_order"] < t1["sort_order"]

    def test_move_test_invalid_direction(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        resp = auth_client.post(f"/tests/{tid}/move/sideways")
        assert resp.status_code == 400


# ============================================================
# 6. Status Filtering
# ============================================================

class TestFiltering:
    def _setup_tests(self, auth_client):
        pid = get_project_id(auth_client)
        tid1 = get_test_id(auth_client, pid)
        tid2 = get_test_id(auth_client, pid)
        tid3 = get_test_id(auth_client, pid)
        # tid1 = pass, tid2 = fail, tid3 = pending
        auth_client.post(f"/tests/{tid1}/update", data={
            "description": "Pass Test", "steps": "s", "output": "", "notes": "", "assigned_to": "", "passed": "1",
        })
        auth_client.post(f"/tests/{tid2}/update", data={
            "description": "Fail Test", "steps": "s", "output": "", "notes": "", "assigned_to": "", "passed": "0",
        })
        return pid

    def test_filter_by_pass(self, auth_client):
        pid = self._setup_tests(auth_client)
        resp = auth_client.get(f"/projects/{pid}?status=pass")
        assert b"Pass Test" in resp.data
        assert b"Fail Test" not in resp.data

    def test_filter_by_fail(self, auth_client):
        pid = self._setup_tests(auth_client)
        resp = auth_client.get(f"/projects/{pid}?status=fail")
        assert b"Fail Test" in resp.data
        assert b"Pass Test" not in resp.data

    def test_filter_by_pending(self, auth_client):
        pid = self._setup_tests(auth_client)
        resp = auth_client.get(f"/projects/{pid}?status=pending")
        assert b"Test Case 1" in resp.data
        assert b"Pass Test" not in resp.data
        assert b"Fail Test" not in resp.data


# ============================================================
# 7. Attachments
# ============================================================

class TestAttachments:
    def test_upload_attachment(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        data = {"file": (io.BytesIO(b"hello world"), "test.txt")}
        resp = auth_client.post(f"/tests/{tid}/attachments", data=data,
                                content_type="multipart/form-data", follow_redirects=True)
        assert b"Attachment uploaded" in resp.data
        conn = flask_app.get_db()
        att = conn.execute("SELECT * FROM attachments WHERE test_id = ?", (tid,)).fetchone()
        conn.close()
        assert att is not None
        assert att["original_name"] == "test.txt"
        assert os.path.exists(os.path.join(flask_app.UPLOAD_DIR, att["stored_name"]))

    def test_upload_attachment_no_file(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        resp = auth_client.post(f"/tests/{tid}/attachments", data={},
                                content_type="multipart/form-data", follow_redirects=True)
        conn = flask_app.get_db()
        count = conn.execute("SELECT COUNT(*) FROM attachments").fetchone()[0]
        conn.close()
        assert count == 0

    def test_download_attachment(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        data = {"file": (io.BytesIO(b"file content"), "doc.txt")}
        auth_client.post(f"/tests/{tid}/attachments", data=data,
                         content_type="multipart/form-data")
        conn = flask_app.get_db()
        att = conn.execute("SELECT id FROM attachments LIMIT 1").fetchone()
        conn.close()
        resp = auth_client.get(f"/attachments/{att['id']}")
        assert resp.status_code == 200
        assert b"file content" in resp.data

    def test_download_attachment_not_found(self, auth_client):
        resp = auth_client.get("/attachments/9999")
        assert resp.status_code == 404

    def test_delete_attachment(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        data = {"file": (io.BytesIO(b"content"), "remove.txt")}
        auth_client.post(f"/tests/{tid}/attachments", data=data,
                         content_type="multipart/form-data")
        conn = flask_app.get_db()
        att = conn.execute("SELECT * FROM attachments LIMIT 1").fetchone()
        stored_path = os.path.join(flask_app.UPLOAD_DIR, att["stored_name"])
        conn.close()
        assert os.path.exists(stored_path)
        resp = auth_client.post(f"/attachments/{att['id']}/delete", follow_redirects=True)
        assert b"Attachment removed" in resp.data
        assert not os.path.exists(stored_path)


# ============================================================
# 8. Comments
# ============================================================

class TestComments:
    def test_add_comment(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        resp = auth_client.post(f"/tests/{tid}/comments", data={"body": "Nice test!"},
                                follow_redirects=True)
        assert b"Comment added" in resp.data
        conn = flask_app.get_db()
        cmt = conn.execute("SELECT * FROM test_comments WHERE test_id = ?", (tid,)).fetchone()
        conn.close()
        assert cmt["body"] == "Nice test!"
        assert cmt["username"] == "admin"

    def test_add_empty_comment(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        auth_client.post(f"/tests/{tid}/comments", data={"body": ""})
        conn = flask_app.get_db()
        count = conn.execute("SELECT COUNT(*) FROM test_comments").fetchone()[0]
        conn.close()
        assert count == 0

    def test_delete_comment_by_author(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        auth_client.post(f"/tests/{tid}/comments", data={"body": "delete me"})
        conn = flask_app.get_db()
        cmt = conn.execute("SELECT id FROM test_comments LIMIT 1").fetchone()
        conn.close()
        resp = auth_client.post(f"/comments/{cmt['id']}/delete", follow_redirects=True)
        assert b"Comment deleted" in resp.data

    def test_delete_comment_by_admin(self, client):
        # Register admin
        client.post("/register", data={
            "username": "admin", "password": "pass", "confirm_password": "pass",
        })
        pid = get_project_id(client)
        tid = get_test_id(client, pid)
        client.get("/logout")
        # Register user2
        client.post("/register", data={
            "username": "user2", "password": "pass", "confirm_password": "pass",
        })
        # user2 adds a comment
        client.post(f"/tests/{tid}/comments", data={"body": "user2 comment"})
        conn = flask_app.get_db()
        cmt = conn.execute("SELECT id FROM test_comments LIMIT 1").fetchone()
        conn.close()
        # Log in as admin
        client.get("/logout")
        client.post("/login", data={"username": "admin", "password": "pass"})
        # Admin deletes user2's comment
        resp = client.post(f"/comments/{cmt['id']}/delete", follow_redirects=True)
        assert b"Comment deleted" in resp.data

    def test_delete_comment_non_author_non_admin(self, client):
        # Register admin
        client.post("/register", data={
            "username": "admin", "password": "pass", "confirm_password": "pass",
        })
        pid = get_project_id(client)
        tid = get_test_id(client, pid)
        # Admin adds a comment
        client.post(f"/tests/{tid}/comments", data={"body": "admin comment"})
        conn = flask_app.get_db()
        cmt = conn.execute("SELECT id FROM test_comments LIMIT 1").fetchone()
        conn.close()
        # Register and log in as user2 (non-admin)
        client.get("/logout")
        client.post("/register", data={
            "username": "user2", "password": "pass", "confirm_password": "pass",
        })
        resp = client.post(f"/comments/{cmt['id']}/delete")
        assert resp.status_code == 403


# ============================================================
# 9. User Management (Admin Routes)
# ============================================================

class TestUserManagement:
    def test_user_list_admin(self, auth_client):
        resp = auth_client.get("/users")
        assert resp.status_code == 200
        assert b"admin" in resp.data

    def test_user_list_non_admin(self, non_admin_client):
        resp = non_admin_client.get("/users")
        assert resp.status_code == 403

    def test_user_list_unauthenticated(self, client):
        resp = client.get("/users")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_add_user_admin(self, auth_client):
        resp = auth_client.post("/users/add", data={
            "username": "newuser",
            "password": "pass123",
        }, follow_redirects=True)
        assert b"User added" in resp.data
        conn = flask_app.get_db()
        user = conn.execute("SELECT * FROM users WHERE username = 'newuser'").fetchone()
        conn.close()
        assert user is not None

    def test_add_user_duplicate(self, auth_client):
        auth_client.post("/users/add", data={"username": "dup", "password": "pass"})
        resp = auth_client.post("/users/add", data={"username": "dup", "password": "pass"},
                                follow_redirects=True)
        assert b"Username already taken" in resp.data

    def test_toggle_admin(self, auth_client):
        auth_client.post("/users/add", data={"username": "user2", "password": "pass"})
        conn = flask_app.get_db()
        user = conn.execute("SELECT * FROM users WHERE username = 'user2'").fetchone()
        conn.close()
        assert user["is_admin"] == 0
        auth_client.post(f"/users/{user['id']}/toggle-admin", follow_redirects=True)
        conn = flask_app.get_db()
        user = conn.execute("SELECT * FROM users WHERE username = 'user2'").fetchone()
        conn.close()
        assert user["is_admin"] == 1

    def test_toggle_admin_self(self, auth_client):
        conn = flask_app.get_db()
        admin = conn.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
        conn.close()
        auth_client.post(f"/users/{admin['id']}/toggle-admin", follow_redirects=True)
        conn = flask_app.get_db()
        admin = conn.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
        conn.close()
        assert admin["is_admin"] == 1  # unchanged

    def test_reset_password(self, auth_client):
        auth_client.post("/users/add", data={"username": "user2", "password": "old"})
        conn = flask_app.get_db()
        user = conn.execute("SELECT * FROM users WHERE username = 'user2'").fetchone()
        conn.close()
        resp = auth_client.post(f"/users/{user['id']}/reset-password",
                                data={"new_password": "newpass"}, follow_redirects=True)
        assert b"Password reset" in resp.data
        # Verify new password works
        auth_client.get("/logout")
        resp = auth_client.post("/login", data={"username": "user2", "password": "newpass"},
                                follow_redirects=True)
        assert b"Projects" in resp.data

    def test_delete_user(self, auth_client):
        auth_client.post("/users/add", data={"username": "todelete", "password": "pass"})
        conn = flask_app.get_db()
        user = conn.execute("SELECT * FROM users WHERE username = 'todelete'").fetchone()
        conn.close()
        resp = auth_client.post(f"/users/{user['id']}/delete", follow_redirects=True)
        assert b"User deleted" in resp.data
        conn = flask_app.get_db()
        user = conn.execute("SELECT * FROM users WHERE username = 'todelete'").fetchone()
        conn.close()
        assert user is None

    def test_delete_user_self(self, auth_client):
        conn = flask_app.get_db()
        admin = conn.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
        conn.close()
        auth_client.post(f"/users/{admin['id']}/delete", follow_redirects=True)
        conn = flask_app.get_db()
        admin = conn.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
        conn.close()
        assert admin is not None  # not deleted


# ============================================================
# 10. Search
# ============================================================

class TestSearch:
    def test_search_empty_query(self, auth_client):
        resp = auth_client.get("/search?q=")
        assert resp.status_code == 200

    def test_search_finds_by_description(self, auth_client):
        pid = get_project_id(auth_client)
        create_test_case(auth_client, pid, "UniqueSearchTerm", "steps")
        resp = auth_client.get("/search?q=UniqueSearchTerm")
        assert b"UniqueSearchTerm" in resp.data

    def test_search_finds_by_steps(self, auth_client):
        pid = get_project_id(auth_client)
        create_test_case(auth_client, pid, "desc", "SpecialStepKeyword")
        resp = auth_client.get("/search?q=SpecialStepKeyword")
        assert b"SpecialStepKeyword" in resp.data


# ============================================================
# 11. Dashboard
# ============================================================

class TestDashboard:
    def test_dashboard_renders(self, auth_client):
        resp = auth_client.get("/dashboard")
        assert resp.status_code == 200

    def test_dashboard_stats_accuracy(self, auth_client):
        pid = get_project_id(auth_client)
        tid1 = get_test_id(auth_client, pid)
        tid2 = get_test_id(auth_client, pid)
        get_test_id(auth_client, pid)  # pending
        auth_client.post(f"/tests/{tid1}/update", data={
            "description": "t", "steps": "s", "output": "", "notes": "", "assigned_to": "", "passed": "1",
        })
        auth_client.post(f"/tests/{tid2}/update", data={
            "description": "t", "steps": "s", "output": "", "notes": "", "assigned_to": "", "passed": "0",
        })
        resp = auth_client.get("/dashboard")
        # Total 3 tests, 1 pass, 1 fail, 1 pending
        assert b"3" in resp.data


# ============================================================
# 12. Export
# ============================================================

class TestExport:
    def test_export_markdown(self, auth_client):
        pid = get_project_id(auth_client)
        create_test_case(auth_client, pid, "Export Test", "Do things")
        resp = auth_client.get(f"/projects/{pid}/export")
        assert resp.status_code == 200
        assert "text/markdown" in resp.content_type
        assert b"Content-Disposition" in b"".join(
            f"{k}: {v}".encode() for k, v in resp.headers
        ) or "attachment" in resp.headers.get("Content-Disposition", "")

    def test_export_markdown_content(self, auth_client):
        pid = get_project_id(auth_client)
        create_test_case(auth_client, pid, "Export Test", "Do things")
        resp = auth_client.get(f"/projects/{pid}/export")
        assert b"Export Test" in resp.data
        assert b"PENDING" in resp.data

    def test_export_csv(self, auth_client):
        pid = get_project_id(auth_client)
        create_test_case(auth_client, pid, "CSV Test", "Steps here")
        resp = auth_client.get(f"/projects/{pid}/export?format=csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.content_type

    def test_export_csv_content(self, auth_client):
        pid = get_project_id(auth_client)
        create_test_case(auth_client, pid, "CSV Test", "Steps here")
        resp = auth_client.get(f"/projects/{pid}/export?format=csv")
        assert b"CSV Test" in resp.data
        assert b"Pending" in resp.data


# ============================================================
# 13. CSV Import
# ============================================================

class TestImport:
    def test_import_csv_basic(self, auth_client):
        pid = get_project_id(auth_client)
        csv_data = "Description,Steps\nImported Test,Step 1\n"
        data = {"file": (io.BytesIO(csv_data.encode()), "tests.csv")}
        resp = auth_client.post(f"/projects/{pid}/import", data=data,
                                content_type="multipart/form-data", follow_redirects=True)
        assert b"Imported 1 test(s)" in resp.data

    def test_import_csv_with_status(self, auth_client):
        pid = get_project_id(auth_client)
        csv_data = "Description,Steps,Status\nT1,S1,Pass\nT2,S2,Fail\nT3,S3,Pending\n"
        data = {"file": (io.BytesIO(csv_data.encode()), "tests.csv")}
        auth_client.post(f"/projects/{pid}/import", data=data,
                         content_type="multipart/form-data")
        conn = flask_app.get_db()
        tests = conn.execute("SELECT * FROM tests WHERE project_id = ? ORDER BY id", (pid,)).fetchall()
        conn.close()
        assert tests[0]["passed"] == 1
        assert tests[1]["passed"] == 0
        assert tests[2]["passed"] is None

    def test_import_csv_no_file(self, auth_client):
        pid = get_project_id(auth_client)
        resp = auth_client.post(f"/projects/{pid}/import", data={},
                                content_type="multipart/form-data", follow_redirects=True)
        assert b"No file selected" in resp.data

    def test_import_csv_missing_columns(self, auth_client):
        pid = get_project_id(auth_client)
        csv_data = "Name,Value\nA,B\n"
        data = {"file": (io.BytesIO(csv_data.encode()), "bad.csv")}
        resp = auth_client.post(f"/projects/{pid}/import", data=data,
                                content_type="multipart/form-data", follow_redirects=True)
        assert b"Description" in resp.data and b"Steps" in resp.data

    def test_import_csv_skips_empty_rows(self, auth_client):
        pid = get_project_id(auth_client)
        csv_data = "Description,Steps\nGood,Steps\n,\n"
        data = {"file": (io.BytesIO(csv_data.encode()), "tests.csv")}
        resp = auth_client.post(f"/projects/{pid}/import", data=data,
                                content_type="multipart/form-data", follow_redirects=True)
        assert b"Imported 1 test(s)" in resp.data


# ============================================================
# 14. Bulk Actions
# ============================================================

class TestBulkActions:
    def _setup(self, auth_client):
        pid = get_project_id(auth_client)
        tid1 = get_test_id(auth_client, pid)
        tid2 = get_test_id(auth_client, pid)
        return pid, tid1, tid2

    def test_bulk_pass(self, auth_client):
        pid, tid1, tid2 = self._setup(auth_client)
        auth_client.post(f"/projects/{pid}/bulk", data={
            "test_ids": f"{tid1},{tid2}",
            "action": "pass",
        }, follow_redirects=True)
        conn = flask_app.get_db()
        tests = conn.execute("SELECT passed FROM tests WHERE project_id = ?", (pid,)).fetchall()
        conn.close()
        assert all(t["passed"] == 1 for t in tests)

    def test_bulk_fail(self, auth_client):
        pid, tid1, tid2 = self._setup(auth_client)
        auth_client.post(f"/projects/{pid}/bulk", data={
            "test_ids": f"{tid1},{tid2}",
            "action": "fail",
        })
        conn = flask_app.get_db()
        tests = conn.execute("SELECT passed FROM tests WHERE project_id = ?", (pid,)).fetchall()
        conn.close()
        assert all(t["passed"] == 0 for t in tests)

    def test_bulk_pending(self, auth_client):
        pid, tid1, tid2 = self._setup(auth_client)
        # First mark as pass
        auth_client.post(f"/projects/{pid}/bulk", data={
            "test_ids": f"{tid1},{tid2}", "action": "pass",
        })
        # Then reset to pending
        auth_client.post(f"/projects/{pid}/bulk", data={
            "test_ids": f"{tid1},{tid2}", "action": "pending",
        })
        conn = flask_app.get_db()
        tests = conn.execute("SELECT passed FROM tests WHERE project_id = ?", (pid,)).fetchall()
        conn.close()
        assert all(t["passed"] is None for t in tests)

    def test_bulk_assign(self, auth_client):
        pid, tid1, tid2 = self._setup(auth_client)
        auth_client.post(f"/projects/{pid}/bulk", data={
            "test_ids": f"{tid1},{tid2}",
            "action": "assign",
            "assign_to": "admin",
        })
        conn = flask_app.get_db()
        tests = conn.execute("SELECT assigned_to FROM tests WHERE project_id = ?", (pid,)).fetchall()
        conn.close()
        assert all(t["assigned_to"] == "admin" for t in tests)

    def test_bulk_delete(self, auth_client):
        pid, tid1, tid2 = self._setup(auth_client)
        auth_client.post(f"/projects/{pid}/bulk", data={
            "test_ids": f"{tid1},{tid2}",
            "action": "delete",
        })
        conn = flask_app.get_db()
        count = conn.execute("SELECT COUNT(*) FROM tests WHERE project_id = ?", (pid,)).fetchone()[0]
        conn.close()
        assert count == 0


# ============================================================
# 15. Cascade / Edge Cases
# ============================================================

class TestCascade:
    def test_delete_project_cascades_attachments(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        data = {"file": (io.BytesIO(b"data"), "att.txt")}
        auth_client.post(f"/tests/{tid}/attachments", data=data,
                         content_type="multipart/form-data")
        conn = flask_app.get_db()
        att = conn.execute("SELECT stored_name FROM attachments LIMIT 1").fetchone()
        stored_path = os.path.join(flask_app.UPLOAD_DIR, att["stored_name"])
        conn.close()
        assert os.path.exists(stored_path)
        auth_client.post(f"/projects/{pid}/delete")
        assert not os.path.exists(stored_path)

    def test_delete_project_cascades_comments(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        auth_client.post(f"/tests/{tid}/comments", data={"body": "comment"})
        auth_client.post(f"/projects/{pid}/delete")
        conn = flask_app.get_db()
        count = conn.execute("SELECT COUNT(*) FROM test_comments").fetchone()[0]
        conn.close()
        assert count == 0

    def test_delete_project_cascades_history(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        auth_client.post(f"/tests/{tid}/update", data={
            "description": "t", "steps": "s", "output": "", "notes": "", "assigned_to": "", "passed": "1",
        })
        auth_client.post(f"/projects/{pid}/delete")
        conn = flask_app.get_db()
        count = conn.execute("SELECT COUNT(*) FROM test_history").fetchone()[0]
        conn.close()
        assert count == 0

    def test_delete_test_cascades_attachments(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        data = {"file": (io.BytesIO(b"data"), "att.txt")}
        auth_client.post(f"/tests/{tid}/attachments", data=data,
                         content_type="multipart/form-data")
        conn = flask_app.get_db()
        att = conn.execute("SELECT stored_name FROM attachments LIMIT 1").fetchone()
        stored_path = os.path.join(flask_app.UPLOAD_DIR, att["stored_name"])
        conn.close()
        auth_client.post(f"/tests/{tid}/delete")
        assert not os.path.exists(stored_path)

    def test_clone_project_copies_attachments(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        data = {"file": (io.BytesIO(b"clone me"), "clone.txt")}
        auth_client.post(f"/tests/{tid}/attachments", data=data,
                         content_type="multipart/form-data")
        auth_client.post(f"/projects/{pid}/clone")
        conn = flask_app.get_db()
        atts = conn.execute("SELECT * FROM attachments ORDER BY id").fetchall()
        conn.close()
        assert len(atts) == 2
        assert atts[0]["stored_name"] != atts[1]["stored_name"]
        assert atts[1]["original_name"] == "clone.txt"
        assert os.path.exists(os.path.join(flask_app.UPLOAD_DIR, atts[1]["stored_name"]))

    def test_clone_project_resets_status(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        auth_client.post(f"/tests/{tid}/update", data={
            "description": "t", "steps": "s", "output": "", "notes": "", "assigned_to": "", "passed": "1",
        })
        auth_client.post(f"/projects/{pid}/clone")
        conn = flask_app.get_db()
        cloned = conn.execute(
            "SELECT * FROM tests WHERE project_id != ?", (pid,)
        ).fetchone()
        conn.close()
        assert cloned["passed"] is None


# ============================================================
# 16. Migration (old schema)
# ============================================================

class TestMigration:
    def test_migrate_adds_missing_columns(self, tmp_path, monkeypatch):
        """Create an old-schema DB missing columns and verify init_db migrates them."""
        db_path = str(tmp_path / "old.db")
        upload_dir = str(tmp_path / "uploads")
        os.makedirs(upload_dir, exist_ok=True)

        # Create old-schema tables without the columns that get migrated
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE tests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                description TEXT NOT NULL,
                steps TEXT NOT NULL,
                passed INTEGER DEFAULT NULL,
                output TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                test_id INTEGER NOT NULL,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE test_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                test_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE test_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                test_id INTEGER NOT NULL,
                old_status TEXT,
                new_status TEXT,
                changed_by TEXT NOT NULL,
                changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Insert a user so admin promotion runs
        from werkzeug.security import generate_password_hash
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("olduser", generate_password_hash("pass")),
        )
        # Insert a project and test so sort_order migration runs
        conn.execute("INSERT INTO projects (name) VALUES ('Old Project')")
        conn.execute(
            "INSERT INTO tests (project_id, description, steps) VALUES (1, 'Old Test', 'Steps')"
        )
        conn.commit()
        conn.close()

        monkeypatch.setattr(flask_app, "DB_PATH", db_path)
        monkeypatch.setattr(flask_app, "UPLOAD_DIR", upload_dir)
        flask_app.init_db()

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        # Check users got is_admin column and first user promoted
        user = conn.execute("SELECT * FROM users WHERE username = 'olduser'").fetchone()
        assert user["is_admin"] == 1
        # Check projects got archived column
        proj_cols = [row[1] for row in conn.execute("PRAGMA table_info(projects)").fetchall()]
        assert "archived" in proj_cols
        # Check tests got all migrated columns
        test_cols = [row[1] for row in conn.execute("PRAGMA table_info(tests)").fetchall()]
        for col in ["created_by", "executed_by", "executed_at", "notes", "assigned_to", "sort_order"]:
            assert col in test_cols
        # Check sort_order was initialized
        test = conn.execute("SELECT sort_order FROM tests LIMIT 1").fetchone()
        assert test["sort_order"] is not None
        conn.close()


# ============================================================
# 17. 404 on not-found resources
# ============================================================

class TestNotFound:
    def test_clone_project_not_found(self, auth_client):
        resp = auth_client.post("/projects/9999/clone")
        assert resp.status_code == 404

    def test_archive_project_not_found(self, auth_client):
        resp = auth_client.post("/projects/9999/archive")
        assert resp.status_code == 404

    def test_export_project_not_found(self, auth_client):
        resp = auth_client.get("/projects/9999/export")
        assert resp.status_code == 404

    def test_bulk_project_not_found(self, auth_client):
        resp = auth_client.post("/projects/9999/bulk", data={
            "test_ids": "1", "action": "pass",
        })
        assert resp.status_code == 404

    def test_import_project_not_found(self, auth_client):
        csv_data = "Description,Steps\nT,S\n"
        data = {"file": (io.BytesIO(csv_data.encode()), "t.csv")}
        resp = auth_client.post("/projects/9999/import", data=data,
                                content_type="multipart/form-data")
        assert resp.status_code == 404

    def test_move_test_not_found(self, auth_client):
        resp = auth_client.post("/tests/9999/move/up")
        assert resp.status_code == 404

    def test_upload_attachment_test_not_found(self, auth_client):
        data = {"file": (io.BytesIO(b"x"), "f.txt")}
        resp = auth_client.post("/tests/9999/attachments", data=data,
                                content_type="multipart/form-data")
        assert resp.status_code == 404

    def test_add_comment_test_not_found(self, auth_client):
        resp = auth_client.post("/tests/9999/comments", data={"body": "hi"})
        assert resp.status_code == 404

    def test_delete_comment_not_found(self, auth_client):
        resp = auth_client.post("/comments/9999/delete")
        assert resp.status_code == 404

    def test_delete_attachment_not_found(self, auth_client):
        resp = auth_client.post("/attachments/9999/delete")
        assert resp.status_code == 404


# ============================================================
# 18. Bulk action edge cases
# ============================================================

class TestBulkEdgeCases:
    def test_bulk_empty_test_ids(self, auth_client):
        pid = get_project_id(auth_client)
        resp = auth_client.post(f"/projects/{pid}/bulk", data={
            "test_ids": "", "action": "pass",
        })
        assert resp.status_code == 302

    def test_bulk_no_action(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        resp = auth_client.post(f"/projects/{pid}/bulk", data={
            "test_ids": str(tid), "action": "",
        })
        assert resp.status_code == 302

    def test_bulk_invalid_test_ids(self, auth_client):
        pid = get_project_id(auth_client)
        resp = auth_client.post(f"/projects/{pid}/bulk", data={
            "test_ids": "abc,xyz", "action": "pass",
        })
        assert resp.status_code == 302

    def test_bulk_delete_with_attachments(self, auth_client):
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        data = {"file": (io.BytesIO(b"data"), "att.txt")}
        auth_client.post(f"/tests/{tid}/attachments", data=data,
                         content_type="multipart/form-data")
        conn = flask_app.get_db()
        att = conn.execute("SELECT stored_name FROM attachments LIMIT 1").fetchone()
        stored_path = os.path.join(flask_app.UPLOAD_DIR, att["stored_name"])
        conn.close()
        assert os.path.exists(stored_path)
        auth_client.post(f"/projects/{pid}/bulk", data={
            "test_ids": str(tid), "action": "delete",
        })
        assert not os.path.exists(stored_path)


# ============================================================
# 19. Import edge cases
# ============================================================

class TestImportEdgeCases:
    def test_import_csv_unicode_error(self, auth_client):
        pid = get_project_id(auth_client)
        # Invalid UTF-8 bytes
        data = {"file": (io.BytesIO(b"\xff\xfe\x00\x01"), "bad.csv")}
        resp = auth_client.post(f"/projects/{pid}/import", data=data,
                                content_type="multipart/form-data", follow_redirects=True)
        assert b"Could not read file" in resp.data

    def test_import_csv_empty_file(self, auth_client):
        pid = get_project_id(auth_client)
        data = {"file": (io.BytesIO(b""), "empty.csv")}
        resp = auth_client.post(f"/projects/{pid}/import", data=data,
                                content_type="multipart/form-data", follow_redirects=True)
        assert b"empty or has no headers" in resp.data


# ============================================================
# 20. Export with rich content (covers markdown branches)
# ============================================================

class TestExportRichContent:
    def test_export_markdown_with_all_fields(self, auth_client):
        """Cover markdown export branches for assigned_to, executed_by, output, notes, attachments, history, comments."""
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        # Set status to pass (creates history, sets executed_by/executed_at)
        auth_client.post(f"/tests/{tid}/update", data={
            "description": "Rich Test", "steps": "Step 1\nStep 2",
            "output": "test output here", "notes": "some notes",
            "assigned_to": "admin", "passed": "1",
        })
        # Add attachment
        data = {"file": (io.BytesIO(b"attach"), "report.pdf")}
        auth_client.post(f"/tests/{tid}/attachments", data=data,
                         content_type="multipart/form-data")
        # Add comment
        auth_client.post(f"/tests/{tid}/comments", data={"body": "Looks good"})
        # Change status again to add more history
        auth_client.post(f"/tests/{tid}/update", data={
            "description": "Rich Test", "steps": "Step 1\nStep 2",
            "output": "test output here", "notes": "some notes",
            "assigned_to": "admin", "passed": "0",
        })

        resp = auth_client.get(f"/projects/{pid}/export")
        content = resp.data.decode()
        assert "FAIL" in content
        assert "Assigned to:" in content
        assert "Executed by:" in content
        assert "test output here" in content
        assert "some notes" in content
        assert "report.pdf" in content
        assert "History:" in content
        assert "Comments:" in content
        assert "Looks good" in content

    def test_export_markdown_pass_status(self, auth_client):
        """Cover the PASS branch in markdown export."""
        pid = get_project_id(auth_client)
        tid = get_test_id(auth_client, pid)
        auth_client.post(f"/tests/{tid}/update", data={
            "description": "Passing Test", "steps": "s",
            "output": "", "notes": "", "assigned_to": "", "passed": "1",
        })
        resp = auth_client.get(f"/projects/{pid}/export")
        assert b"PASS" in resp.data

    def test_export_csv_with_all_fields(self, auth_client):
        """Cover CSV export branches for pass/fail status labels."""
        pid = get_project_id(auth_client)
        tid1 = get_test_id(auth_client, pid)
        tid2 = get_test_id(auth_client, pid)
        auth_client.post(f"/tests/{tid1}/update", data={
            "description": "T1", "steps": "S", "output": "", "notes": "",
            "assigned_to": "", "passed": "1",
        })
        auth_client.post(f"/tests/{tid2}/update", data={
            "description": "T2", "steps": "S", "output": "", "notes": "",
            "assigned_to": "", "passed": "0",
        })
        resp = auth_client.get(f"/projects/{pid}/export?format=csv")
        content = resp.data.decode()
        assert "Pass" in content
        assert "Fail" in content


# ============================================================
# 21. Assigned filter
# ============================================================

class TestAssignedFilter:
    def test_filter_assigned_to_me(self, auth_client):
        pid = get_project_id(auth_client)
        tid1 = get_test_id(auth_client, pid)
        tid2 = get_test_id(auth_client, pid)
        auth_client.post(f"/tests/{tid1}/update", data={
            "description": "MyAssignedTask", "steps": "s", "output": "", "notes": "",
            "assigned_to": "admin", "passed": "",
        })
        auth_client.post(f"/tests/{tid2}/update", data={
            "description": "SomeoneElseTask", "steps": "s", "output": "", "notes": "",
            "assigned_to": "", "passed": "",
        })
        resp = auth_client.get(f"/projects/{pid}?assigned=me")
        assert b"MyAssignedTask" in resp.data
        assert b"SomeoneElseTask" not in resp.data


# ============================================================
# 22. Admin add user empty fields
# ============================================================

class TestAdminEdgeCases:
    def test_add_user_empty_fields(self, auth_client):
        resp = auth_client.post("/users/add", data={
            "username": "", "password": "",
        }, follow_redirects=True)
        assert b"Username and password are required" in resp.data
