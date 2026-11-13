"""TestMgr: a Flask app for managing test cases across projects."""
from logging.handlers import RotatingFileHandler
import logging
import os
import secrets

from flask import Flask, g, request

from . import db

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_secret_key(key_file=None):
    """Use SECRET_KEY from the environment, else a random key persisted to key_file."""
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    key_file = key_file or os.path.join(BASE_DIR, ".secret_key")
    if os.path.exists(key_file):
        with open(key_file) as f:
            key = f.read().strip()
        if key:
            return key
    # write to a temp file, then hard-link it into place: the link fails if another
    # process (e.g. a second gunicorn worker) won the race, so everyone uses one key
    tmp = "%s.%d.tmp" % (key_file, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secrets.token_hex(32))
    try:
        os.link(tmp, key_file)
    except FileExistsError:
        pass
    finally:
        os.remove(tmp)
    with open(key_file) as f:
        return f.read().strip()


def _configure_logging(app, log_dir):
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.abspath(os.path.join(log_dir, "app.log"))
    app.logger.setLevel(logging.INFO)
    # the logger is shared across app instances; don't attach the same file twice
    if any(getattr(h, "baseFilename", None) == log_path for h in app.logger.handlers):
        return
    handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=5)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)


def create_app(config=None):
    app = Flask(
        __name__,
        template_folder=os.path.join(BASE_DIR, "templates"),
    )
    app.secret_key = load_secret_key()
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        CSRF_ENABLED=True,
        DATABASE=os.path.join(BASE_DIR, "tests.db"),
        UPLOAD_DIR=os.path.join(BASE_DIR, "uploads"),
        LOG_DIR=os.path.join(BASE_DIR, "logs"),
    )
    if config:
        app.config.update(config)

    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)
    _configure_logging(app, app.config["LOG_DIR"])

    from . import auth, main, projects, testcases, users
    for module in (auth, main, projects, testcases, users):
        app.register_blueprint(module.bp)

    # order matters: reject bad CSRF before touching the database
    app.before_request(auth.csrf_protect)
    app.before_request(auth.load_user)
    app.jinja_env.globals["csrf_token"] = auth.csrf_token
    app.teardown_appcontext(db.close_db)

    @app.after_request
    def log_request(response):
        user = g.user["username"] if g.get("user") else "anonymous"
        app.logger.info("%s %s %s %s %s", request.remote_addr, user,
                        request.method, request.path, response.status_code)
        return response

    db.init_db(app.config["DATABASE"])
    return app
