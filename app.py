import os
import sqlite3
from functools import wraps
from pathlib import Path
from uuid import uuid4

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
UPLOAD_DIR = BASE_DIR / "uploads"
DATABASE = INSTANCE_DIR / "dashboard.db"

INSTANCE_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config.update(
    SECRET_KEY="change-this-secret-key",  # consider loading from env
    UPLOAD_FOLDER=str(UPLOAD_DIR),
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,  # 20 MB
    _DB_INIT=False,  # guard to ensure init_db() runs once in Flask 3.x
)


def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                uploader_id INTEGER NOT NULL,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (uploader_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.commit()

        # Ensure an admin account exists
        cur = conn.execute("SELECT id FROM users WHERE username = ?", ("admin",))
        if cur.fetchone() is None:
            conn.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
                ("admin", generate_password_hash("ChangeMe123!")),
            )
            conn.commit()


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped_view


def admin_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if not session.get("is_admin"):
            abort(403)
        return view_func(*args, **kwargs)

    return wrapped_view


# ---- Flask 3.x-compatible one-time initializer (replaces @before_first_request) ----
def _ensure_db_initialized():
    if not app.config.get("_DB_INIT", False):
        init_db()
        app.config["_DB_INIT"] = True


# Register the guard to run before each request; it will effectively run once.
app.before_request(_ensure_db_initialized)
# -------------------------------------------------------------------------------


@app.route("/")
@login_required
def index():
    with get_db_connection() as conn:
        files = conn.execute(
            """
            SELECT files.id, files.original_name, files.uploaded_at, users.username
            FROM files
            JOIN users ON files.uploader_id = users.id
            ORDER BY files.uploaded_at DESC
            """
        ).fetchall()
    return render_template("dashboard/index.html", files=files)


@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    uploaded_file = request.files.get("file")
    if not uploaded_file or uploaded_file.filename == "":
        flash("Please select a file to upload.", "warning")
        return redirect(url_for("index"))

    original_name = uploaded_file.filename
    safe_name = secure_filename(original_name)
    if not safe_name:
        flash("The selected file name is not allowed.", "danger")
        return redirect(url_for("index"))

    stored_name = f"{uuid4().hex}_{safe_name}"
    file_path = UPLOAD_DIR / stored_name
    try:
        uploaded_file.save(os.fspath(file_path))
    except OSError:
        flash("There was a problem saving the uploaded file.", "danger")
        return redirect(url_for("index"))

    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO files (original_name, stored_name, uploader_id) VALUES (?, ?, ?)",
            (original_name, stored_name, session["user_id"]),
        )
        conn.commit()

    flash("File uploaded successfully.", "success")
    return redirect(url_for("index"))


@app.route("/download/<int:file_id>")
@login_required
def download_file(file_id: int):
    with get_db_connection() as conn:
        file_row = conn.execute(
            "SELECT original_name, stored_name FROM files WHERE id = ?",
            (file_id,),
        ).fetchone()
    if file_row is None:
        abort(404)

    file_path = UPLOAD_DIR / file_row["stored_name"]
    if not file_path.exists():
        abort(404)

    send_kwargs = {"as_attachment": True, "download_name": file_row["original_name"]}

    try:
        return send_from_directory(
            app.config["UPLOAD_FOLDER"], file_row["stored_name"], **send_kwargs
        )
    except TypeError:
        # Flask < 2.0 compatibility
        send_kwargs.pop("download_name", None)
        send_kwargs["attachment_filename"] = file_row["original_name"]
        return send_from_directory(
            app.config["UPLOAD_FOLDER"], file_row["stored_name"], **send_kwargs
        )


@app.route("/delete-file/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id: int):
    with get_db_connection() as conn:
        file_row = conn.execute(
            "SELECT stored_name, uploader_id FROM files WHERE id = ?",
            (file_id,),
        ).fetchone()
        if file_row is None:
            abort(404)
        if not session.get("is_admin") and file_row["uploader_id"] != session["user_id"]:
            abort(403)
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        conn.commit()

    file_path = UPLOAD_DIR / file_row["stored_name"]
    if file_path.exists():
        file_path.unlink()

    flash("File deleted.", "info")
    return redirect(url_for("index"))


@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def manage_users():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required.", "warning")
        else:
            try:
                with get_db_connection() as conn:
                    conn.execute(
                        "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                        (
                            username,
                            generate_password_hash(password),
                            1 if request.form.get("is_admin") == "on" else 0,
                        ),
                    )
                    conn.commit()
                flash("User created successfully.", "success")
            except sqlite3.IntegrityError:
                flash("That username is already taken.", "danger")
    with get_db_connection() as conn:
        users = conn.execute(
            "SELECT id, username, is_admin FROM users ORDER BY username"
        ).fetchall()
    return render_template("admin/manage_users.html", users=users)


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id: int):
    if user_id == session.get("user_id"):
        flash("You cannot delete your own account while logged in.", "danger")
        return redirect(url_for("manage_users"))
    with get_db_connection() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    flash("User removed.", "info")
    return redirect(url_for("manage_users"))


@app.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not new_password:
            flash("Please provide a new password.", "warning")
            return redirect(url_for("change_password"))
        if new_password != confirm_password:
            flash("New password and confirmation do not match.", "danger")
            return redirect(url_for("change_password"))

        with get_db_connection() as conn:
            user = conn.execute(
                "SELECT password_hash FROM users WHERE id = ?",
                (session["user_id"],),
            ).fetchone()
            if not user or not check_password_hash(user["password_hash"], current_password):
                flash("Current password is incorrect.", "danger")
                return redirect(url_for("change_password"))

            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new_password), session["user_id"]),
            )
            conn.commit()

        flash("Your password has been updated.", "success")
        return redirect(url_for("index"))

    return render_template("auth/change_password.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with get_db_connection() as conn:
            user = conn.execute(
                "SELECT id, username, password_hash, is_admin FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            flash("Welcome back!", "success")
            return redirect(url_for("index"))
        flash("Invalid username or password.", "danger")
    return render_template("auth/login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8081, debug=True)
