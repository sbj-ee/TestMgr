"""Entry point: `python3 app.py` for development, `gunicorn app:app` for production.

The application lives in the `testmgr` package; see testmgr/__init__.py.
"""
import os

from testmgr import create_app
from testmgr.db import connect

app = create_app()


def get_db():
    """Open a standalone connection to the app's database (for scripts and tests)."""
    return connect(app.config["DATABASE"])


if __name__ == "__main__":
    # never enable the Werkzeug debugger by default: it allows remote code execution
    app.run(host="0.0.0.0", port=5021, debug=os.environ.get("FLASK_DEBUG") == "1")
