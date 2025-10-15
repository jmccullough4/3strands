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


TASK_STATUSES = (
    ("todo", "To Do"),
    ("in_progress", "In Progress"),
    ("done", "Completed"),
)
TASK_STATUS_LABELS = {key: label for key, label in TASK_STATUSES}


def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                full_name TEXT,
                email TEXT,
                phone TEXT
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

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL DEFAULT 'todo',
                position INTEGER NOT NULL DEFAULT 0,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )
        conn.commit()

        existing_user_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(users)").fetchall()
        }
        if "full_name" not in existing_user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
        if "email" not in existing_user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
        if "phone" not in existing_user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN phone TEXT")
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
    conn.execute("PRAGMA foreign_keys = ON")
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
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    with get_db_connection() as conn:
        recent_files = conn.execute(
            """
            SELECT files.id, files.original_name, files.uploaded_at, users.username
            FROM files
            JOIN users ON files.uploader_id = users.id
            ORDER BY files.uploaded_at DESC
            LIMIT 5
            """
        ).fetchall()
        task_counts_query = conn.execute(
            "SELECT status, COUNT(*) AS total FROM tasks GROUP BY status"
        ).fetchall()
    task_counts = {key: 0 for key, _ in TASK_STATUSES}
    for row in task_counts_query:
        task_counts[row["status"]] = row["total"]
    return render_template(
        "dashboard/index.html",
        recent_files=recent_files,
        task_counts=task_counts,
        task_status_labels=TASK_STATUS_LABELS,
    )


@app.route("/files")
@login_required
def file_share():
    with get_db_connection() as conn:
        files = conn.execute(
            """
            SELECT files.id, files.original_name, files.uploaded_at, users.username
            FROM files
            JOIN users ON files.uploader_id = users.id
            ORDER BY files.uploaded_at DESC
            """
        ).fetchall()
    return render_template("dashboard/files.html", files=files)


@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    uploaded_file = request.files.get("file")
    if not uploaded_file or uploaded_file.filename == "":
        flash("Please select a file to upload.", "warning")
        return redirect(url_for("file_share"))

    original_name = uploaded_file.filename
    safe_name = secure_filename(original_name)
    if not safe_name:
        flash("The selected file name is not allowed.", "danger")
        return redirect(url_for("file_share"))

    stored_name = f"{uuid4().hex}_{safe_name}"
    file_path = UPLOAD_DIR / stored_name
    try:
        uploaded_file.save(os.fspath(file_path))
    except OSError:
        flash("There was a problem saving the uploaded file.", "danger")
        return redirect(url_for("file_share"))

    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO files (original_name, stored_name, uploader_id) VALUES (?, ?, ?)",
            (original_name, stored_name, session["user_id"]),
        )
        conn.commit()

    flash("File uploaded successfully.", "success")
    return redirect(url_for("file_share"))


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
    return redirect(url_for("file_share"))


@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def manage_users():
    if request.method == "POST":
        action = request.form.get("action", "create")
        if action == "reset_password":
            target_id = request.form.get("user_id", "").strip()
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not target_id.isdigit():
                flash("Unable to identify which user to update.", "danger")
            elif not new_password:
                flash("Please provide a new password.", "warning")
            elif new_password != confirm_password:
                flash("New password and confirmation do not match.", "danger")
            else:
                with get_db_connection() as conn:
                    cursor = conn.execute(
                        "UPDATE users SET password_hash = ? WHERE id = ?",
                        (generate_password_hash(new_password), int(target_id)),
                    )
                    conn.commit()
                if cursor.rowcount:
                    flash("Password updated successfully.", "success")
                else:
                    flash("User could not be found.", "danger")
            return redirect(url_for("manage_users"))

        if action == "update_profile":
            target_id = request.form.get("user_id", "").strip()
            if not target_id.isdigit():
                flash("Unable to identify which user to update.", "danger")
                return redirect(url_for("manage_users"))

            full_name = request.form.get("full_name", "").strip() or None
            email = request.form.get("email", "").strip() or None
            phone = request.form.get("phone", "").strip() or None
            is_admin = 1 if request.form.get("is_admin") == "on" else 0

            with get_db_connection() as conn:
                cursor = conn.execute(
                    """
                    UPDATE users
                    SET full_name = ?, email = ?, phone = ?, is_admin = ?
                    WHERE id = ?
                    """,
                    (full_name, email, phone, is_admin, int(target_id)),
                )
                conn.commit()

            if cursor.rowcount:
                flash("User details updated.", "success")
            else:
                flash("User could not be found.", "danger")
            return redirect(url_for("manage_users"))

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        full_name = request.form.get("full_name", "").strip() or None
        email = request.form.get("email", "").strip() or None
        phone = request.form.get("phone", "").strip() or None
        if not username or not password:
            flash("Username and password are required.", "warning")
        else:
            try:
                with get_db_connection() as conn:
                    conn.execute(
                        """
                        INSERT INTO users (username, password_hash, is_admin, full_name, email, phone)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            username,
                            generate_password_hash(password),
                            1 if request.form.get("is_admin") == "on" else 0,
                            full_name,
                            email,
                            phone,
                        ),
                    )
                    conn.commit()
                flash("User created successfully.", "success")
            except sqlite3.IntegrityError:
                flash("That username is already taken.", "danger")
        return redirect(url_for("manage_users"))
    with get_db_connection() as conn:
        users = conn.execute(
            """
            SELECT id, username, is_admin, full_name, email, phone
            FROM users
            ORDER BY COALESCE(NULLIF(full_name, ''), username)
            """
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
        return redirect(url_for("dashboard"))

    return render_template("auth/change_password.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with get_db_connection() as conn:
            user = conn.execute(
                """
                SELECT id, username, password_hash, is_admin
                FROM users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            session["user_initial"] = user["username"][:1].upper()
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("auth/login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


def _valid_status(status: str) -> bool:
    return status in TASK_STATUS_LABELS


@app.route("/tasks")
@login_required
def tasks_board():
    tasks_by_status = {key: [] for key, _ in TASK_STATUSES}
    with get_db_connection() as conn:
        tasks = conn.execute(
            """
            SELECT tasks.id, tasks.title, tasks.description, tasks.status,
                   tasks.created_at, tasks.position, users.username AS creator
            FROM tasks
            LEFT JOIN users ON tasks.created_by = users.id
            ORDER BY tasks.status, tasks.position, tasks.created_at
            """
        ).fetchall()
    for task in tasks:
        tasks_by_status.setdefault(task["status"], []).append(task)
    return render_template(
        "dashboard/tasks.html",
        tasks_by_status=tasks_by_status,
        task_statuses=TASK_STATUSES,
        status_labels=TASK_STATUS_LABELS,
    )


@app.route("/tasks/new", methods=["POST"])
@login_required
def create_task():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    status = request.form.get("status", "todo").strip()

    if not title:
        flash("Task title is required.", "warning")
        return redirect(url_for("tasks_board"))
    if not _valid_status(status):
        status = "todo"

    with get_db_connection() as conn:
        current_position = conn.execute(
            "SELECT COALESCE(MAX(position), 0) FROM tasks WHERE status = ?",
            (status,),
        ).fetchone()[0]
        conn.execute(
            """
            INSERT INTO tasks (title, description, status, position, created_by)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                title,
                description or None,
                status,
                current_position + 1,
                session.get("user_id"),
            ),
        )
        conn.commit()

    flash("Task added to the board.", "success")
    return redirect(url_for("tasks_board"))


@app.route("/tasks/<int:task_id>/move", methods=["POST"])
@login_required
def move_task(task_id: int):
    new_status = request.form.get("status", "").strip()
    if not _valid_status(new_status):
        flash("That list is not available.", "danger")
        return redirect(url_for("tasks_board"))

    with get_db_connection() as conn:
        max_position = conn.execute(
            "SELECT COALESCE(MAX(position), 0) FROM tasks WHERE status = ?",
            (new_status,),
        ).fetchone()[0]
        cursor = conn.execute(
            "UPDATE tasks SET status = ?, position = ? WHERE id = ?",
            (new_status, max_position + 1, task_id),
        )
        conn.commit()

    if cursor.rowcount:
        flash("Task updated.", "success")
    else:
        flash("Task could not be found.", "danger")
    return redirect(url_for("tasks_board"))


@app.route("/tasks/<int:task_id>/update", methods=["POST"])
@login_required
def update_task(task_id: int):
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()

    if not title:
        flash("Task title cannot be empty.", "warning")
        return redirect(url_for("tasks_board"))

    with get_db_connection() as conn:
        cursor = conn.execute(
            "UPDATE tasks SET title = ?, description = ? WHERE id = ?",
            (title, description or None, task_id),
        )
        conn.commit()

    if cursor.rowcount:
        flash("Task details saved.", "success")
    else:
        flash("Task could not be found.", "danger")
    return redirect(url_for("tasks_board"))


@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
@login_required
def delete_task(task_id: int):
    with get_db_connection() as conn:
        cursor = conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        conn.commit()

    if cursor.rowcount:
        flash("Task removed from the board.", "info")
    else:
        flash("Task could not be found.", "danger")
    return redirect(url_for("tasks_board"))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8081, debug=True)
