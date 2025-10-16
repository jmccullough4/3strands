import os
import sqlite3
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.parse import parse_qs, quote, urlparse
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

app = Flask(__name__, instance_relative_config=True)
app.config.from_mapping(
    SECRET_KEY="change-this-secret-key",  # consider loading from env or instance/config.py
    UPLOAD_FOLDER=str(UPLOAD_DIR),
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,  # 25 MB
    _DB_INIT=False,  # guard to ensure init_db() runs once in Flask 3.x
)
app.config.from_pyfile("config.py", silent=True)

app.config.setdefault(
    "CALENDAR_EMBEDS",
    [
        {
            "title": "3 Strands Operations",
            "url": os.getenv(
                "GOOGLE_CALENDAR_PRIMARY",
                "https://calendar.google.com/calendar/ical/c_5545ea209f164c2ff801f63851bf358a7f85b6115d1162e8a4bcb8db84f391dd%40group.calendar.google.com/public/basic.ics",
            ),
        }
    ],
)
app.config.setdefault("CALENDAR_TIMEZONE", "America/Chicago")
def slugify(value: str) -> str:
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in value)
    slug = "-".join(filter(None, slug.split("-")))
    return slug or "list"


def _is_completed_list(slug: Optional[str], name: str) -> bool:
    normalized = (slug or slugify(name)).lower()
    completed_keywords = (
        "done",
        "complete",
        "completed",
        "ready",
        "deliver",
        "delivered",
        "finish",
    )
    return any(keyword in normalized for keyword in completed_keywords)


def _compute_task_metrics(task_summary: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    total_tasks = 0
    completed_tasks = 0
    for column in task_summary:
        count = int(column.get("count") or 0)
        total_tasks += count
        if _is_completed_list(column.get("slug"), column.get("name", "")):
            completed_tasks += count

    open_tasks = max(total_tasks - completed_tasks, 0)
    return {
        "total": total_tasks,
        "completed": completed_tasks,
        "open": open_tasks,
    }


def _format_calendar_url(raw_url: str, timezone: str) -> str:
    if not raw_url:
        return raw_url

    if "calendar/embed" in raw_url:
        return raw_url

    if "/calendar/ical/" in raw_url and raw_url.endswith(".ics"):
        calendar_id_part = raw_url.split("/calendar/ical/", 1)[1]
        calendar_id = calendar_id_part.split("/public", 1)[0]
        calendar_id = calendar_id.replace("%40", "@")
        return (
            "https://calendar.google.com/calendar/embed?src="
            f"{quote(calendar_id)}&ctz={quote(timezone)}&mode=AGENDA"
        )

    parsed = urlparse(raw_url)
    if parsed.netloc == "calendar.google.com":
        query = parse_qs(parsed.query)
        cid_values = query.get("cid")
        if cid_values:
            calendar_id = cid_values[0]
            return (
                "https://calendar.google.com/calendar/embed?src="
                f"{quote(calendar_id)}&ctz={quote(timezone)}&mode=AGENDA"
            )

    return raw_url


def _resolve_calendar_embeds() -> Iterable[Dict[str, str]]:
    timezone = app.config.get("CALENDAR_TIMEZONE", "UTC")
    resolved = []
    for calendar in app.config.get("CALENDAR_EMBEDS", []):
        if not isinstance(calendar, dict):
            continue
        url = calendar.get("url", "").strip()
        if not url:
            continue
        resolved.append(
            {
                "title": calendar.get("title") or "Calendar",
                "url": _format_calendar_url(url, timezone),
            }
        )
    return resolved


def _ensure_unique_list_slug(conn: sqlite3.Connection, base: str) -> str:
    slug = base
    suffix = 1
    while conn.execute(
        "SELECT 1 FROM task_lists WHERE slug = ?",
        (slug,),
    ).fetchone():
        slug = f"{base}-{suffix}"
        suffix += 1
    return slug


def _normalize_folder_row(folder_row: Optional[sqlite3.Row]) -> Dict[str, Any]:
    if folder_row is None:
        return {"id": None, "name": "Shared Drive", "parent_id": None}
    return {
        "id": folder_row["id"],
        "name": folder_row["name"],
        "parent_id": folder_row["parent_id"],
    }


def _build_folder_breadcrumbs(
    conn: sqlite3.Connection, current_folder: Dict[str, Any]
) -> Iterable[Dict[str, Any]]:
    breadcrumbs = [{"id": None, "name": "Shared Drive"}]
    if current_folder.get("id") is None:
        return breadcrumbs

    lineage = []
    walker = current_folder
    visited: set[int] = set()
    while walker and walker.get("id") is not None:
        folder_id = walker["id"]
        if folder_id in visited:
            break
        visited.add(folder_id)
        lineage.append({"id": folder_id, "name": walker["name"]})
        parent_id = walker.get("parent_id")
        if parent_id is None:
            break
        parent_row = conn.execute(
            "SELECT id, name, parent_id FROM folders WHERE id = ?",
            (parent_id,),
        ).fetchone()
        walker = _normalize_folder_row(parent_row)

    breadcrumbs.extend(reversed(lineage))
    return breadcrumbs


def _fetch_task_lists(conn: sqlite3.Connection) -> Iterable[sqlite3.Row]:
    return conn.execute(
        "SELECT id, name, slug FROM task_lists ORDER BY position, id"
    ).fetchall()


def _set_user_session(user: sqlite3.Row, provider: str = "local") -> None:
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    email_value = user["email"] if "email" in user.keys() else None
    session["email"] = email_value or user["username"]
    session["display_name"] = user["full_name"] or session["email"]
    session["user_initial"] = session["display_name"][0].upper() if session["display_name"] else "?"
    session["is_admin"] = bool(user["is_admin"])
    session["auth_provider"] = provider
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                is_admin INTEGER NOT NULL DEFAULT 0,
                full_name TEXT,
                email TEXT UNIQUE,
                phone TEXT,
                google_sub TEXT UNIQUE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                parent_id INTEGER REFERENCES folders(id) ON DELETE CASCADE,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
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
                folder_id INTEGER REFERENCES folders(id) ON DELETE SET NULL,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (uploader_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS task_lists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                slug TEXT UNIQUE NOT NULL,
                position INTEGER NOT NULL DEFAULT 0
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
                assigned_to INTEGER,
                previous_list_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                list_id INTEGER,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (list_id) REFERENCES task_lists(id) ON DELETE SET NULL,
                FOREIGN KEY (previous_list_id) REFERENCES task_lists(id) ON DELETE SET NULL
            )
            """
        )
        conn.commit()

        existing_file_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(files)").fetchall()
        }
        if "folder_id" not in existing_file_columns:
            conn.execute(
                "ALTER TABLE files ADD COLUMN folder_id INTEGER REFERENCES folders(id) ON DELETE SET NULL"
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
        if "google_sub" not in existing_user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN google_sub TEXT")
        conn.commit()

        existing_tasks_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(tasks)").fetchall()
        }
        if "list_id" not in existing_tasks_columns:
            conn.execute("ALTER TABLE tasks ADD COLUMN list_id INTEGER")
        if "assigned_to" not in existing_tasks_columns:
            conn.execute("ALTER TABLE tasks ADD COLUMN assigned_to INTEGER")
        if "previous_list_id" not in existing_tasks_columns:
            conn.execute("ALTER TABLE tasks ADD COLUMN previous_list_id INTEGER")
        conn.commit()

        existing_indexes = {
            row[1]
            for row in conn.execute("PRAGMA index_list('users')").fetchall()
        }
        if "idx_users_email" not in existing_indexes:
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        if "idx_users_google_sub" not in existing_indexes:
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub ON users(google_sub)"
            )
        conn.commit()

        legacy_completed = conn.execute(
            "SELECT id, name, slug FROM task_lists WHERE slug = ?",
            ("completed-runs",),
        ).fetchone()
        if legacy_completed is not None:
            conn.execute(
                "UPDATE task_lists SET name = ?, slug = ?, position = ? WHERE id = ?",
                ("Completed", "completed", 1000, legacy_completed["id"]),
            )

        completed_exists = conn.execute(
            "SELECT 1 FROM task_lists WHERE slug = ?",
            ("completed",),
        ).fetchone()
        if completed_exists is None:
            conn.execute(
                "INSERT INTO task_lists (name, slug, position) VALUES (?, ?, ?)",
                ("Completed", "completed", 1000),
            )
        conn.commit()

        # Ensure every task references a list and status slug matches the list
        list_lookup = {
            row["id"]: (row["slug"], row["name"])
            for row in conn.execute(
                "SELECT id, slug, name FROM task_lists ORDER BY position"
            ).fetchall()
        }
        default_list_id: Optional[int] = next(iter(list_lookup), None)
        if default_list_id is not None:
            for task in conn.execute(
                "SELECT id, list_id, status FROM tasks"
            ).fetchall():
                if task["list_id"] is None:
                    conn.execute(
                        "UPDATE tasks SET list_id = ?, status = ? WHERE id = ?",
                        (default_list_id, list_lookup[default_list_id][0], task["id"]),
                    )
                else:
                    slug, _ = list_lookup.get(task["list_id"], (None, None))
                    if slug and task["status"] != slug:
                        conn.execute(
                            "UPDATE tasks SET status = ? WHERE id = ?",
                            (slug, task["id"]),
                        )
            conn.commit()

        # Ensure an admin account exists for bootstrap access
        cur = conn.execute("SELECT id FROM users WHERE username = ?", ("admin",))
        if cur.fetchone() is None:
            conn.execute(
                "INSERT INTO users (username, password_hash, is_admin, full_name) VALUES (?, ?, 1, ?)",
                ("admin", generate_password_hash("3strands2025!"), "Ranch Admin"),
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
            SELECT files.id, files.original_name, files.uploaded_at,
                   COALESCE(NULLIF(users.full_name, ''), users.username) AS uploader
            FROM files
            JOIN users ON files.uploader_id = users.id
            ORDER BY files.uploaded_at DESC
            LIMIT 5
            """
        ).fetchall()

        task_lists = list(_fetch_task_lists(conn))
        task_counts_query = conn.execute(
            "SELECT list_id, COUNT(*) AS total FROM tasks GROUP BY list_id"
        ).fetchall()

    task_counts: Dict[int, int] = {
        row["list_id"]: row["total"] for row in task_counts_query
    }
    task_summary = [
        {
            "id": task_list["id"],
            "name": task_list["name"],
            "slug": task_list["slug"],
            "count": task_counts.get(task_list["id"], 0),
        }
        for task_list in task_lists
    ]
    return render_template(
        "index.html",
        recent_files=recent_files,
        task_summary=task_summary,
        task_metrics=_compute_task_metrics(task_summary),
        calendar_embeds=list(_resolve_calendar_embeds()),
    )


@app.route("/files")
@login_required
def file_share():
    folder_id_raw = request.args.get("folder_id", "").strip()
    if folder_id_raw and not folder_id_raw.isdigit():
        flash("That folder could not be found.", "warning")
        return redirect(url_for("file_share"))

    requested_folder_id: Optional[int] = int(folder_id_raw) if folder_id_raw else None

    with get_db_connection() as conn:
        folder_row: Optional[sqlite3.Row] = None
        if requested_folder_id is not None:
            folder_row = conn.execute(
                "SELECT id, name, parent_id FROM folders WHERE id = ?",
                (requested_folder_id,),
            ).fetchone()
            if folder_row is None:
                flash("That folder is no longer available.", "warning")

        current_folder = _normalize_folder_row(folder_row)
        breadcrumbs = list(_build_folder_breadcrumbs(conn, current_folder))

        if current_folder["id"] is None:
            subfolders = conn.execute(
                """
                SELECT id, name, parent_id, created_at
                FROM folders
                WHERE parent_id IS NULL
                ORDER BY name COLLATE NOCASE
                """
            ).fetchall()
        else:
            subfolders = conn.execute(
                """
                SELECT id, name, parent_id, created_at
                FROM folders
                WHERE parent_id = ?
                ORDER BY name COLLATE NOCASE
                """,
                (current_folder["id"],),
            ).fetchall()

        base_query = """
            SELECT files.id, files.original_name, files.uploaded_at,
                   COALESCE(NULLIF(users.full_name, ''), users.username) AS uploader,
                   users.username AS uploader_username
            FROM files
            JOIN users ON files.uploader_id = users.id
        """
        if current_folder["id"] is None:
            files = conn.execute(
                base_query + " WHERE files.folder_id IS NULL ORDER BY files.uploaded_at DESC"
            ).fetchall()
        else:
            files = conn.execute(
                base_query + " WHERE files.folder_id = ? ORDER BY files.uploaded_at DESC",
                (current_folder["id"],),
            ).fetchall()

    return render_template(
        "dashboard/files.html",
        files=files,
        subfolders=subfolders,
        current_folder=current_folder,
        breadcrumbs=breadcrumbs,
    )


@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    folder_id_raw = request.form.get("folder_id", "").strip()
    redirect_kwargs: Dict[str, Any] = {}
    if folder_id_raw and folder_id_raw.isdigit():
        redirect_kwargs["folder_id"] = int(folder_id_raw)

    uploaded_file = request.files.get("file")
    if not uploaded_file or uploaded_file.filename == "":
        flash("Please select a file to upload.", "warning")
        return redirect(url_for("file_share", **redirect_kwargs))

    original_name = uploaded_file.filename
    safe_name = secure_filename(original_name)
    if not safe_name:
        flash("The selected file name is not allowed.", "danger")
        return redirect(url_for("file_share", **redirect_kwargs))

    stored_name = f"{uuid4().hex}_{safe_name}"
    file_path = UPLOAD_DIR / stored_name
    with get_db_connection() as conn:
        folder_id: Optional[int] = None
        if folder_id_raw:
            if folder_id_raw.isdigit():
                candidate = conn.execute(
                    "SELECT id FROM folders WHERE id = ?",
                    (int(folder_id_raw),),
                ).fetchone()
                if candidate is None:
                    flash("Choose a valid destination folder.", "danger")
                    return redirect(url_for("file_share"))
                folder_id = int(folder_id_raw)
                redirect_kwargs["folder_id"] = folder_id
            else:
                flash("Choose a valid destination folder.", "danger")
                return redirect(url_for("file_share"))

        try:
            uploaded_file.save(os.fspath(file_path))
        except OSError:
            flash("There was a problem saving the uploaded file.", "danger")
            return redirect(url_for("file_share", **redirect_kwargs))

        conn.execute(
            """
            INSERT INTO files (original_name, stored_name, uploader_id, folder_id)
            VALUES (?, ?, ?, ?)
            """,
            (original_name, stored_name, session["user_id"], folder_id),
        )
        conn.commit()

    flash("File uploaded successfully.", "success")
    return redirect(url_for("file_share", **redirect_kwargs))


@app.route("/folders/new", methods=["POST"])
@login_required
def create_folder():
    name = request.form.get("name", "").strip()
    parent_id_raw = request.form.get("parent_id", "").strip()

    redirect_kwargs: Dict[str, Any] = {}
    if parent_id_raw and parent_id_raw.isdigit():
        redirect_kwargs["folder_id"] = int(parent_id_raw)

    if not name:
        flash("Name your new folder to organize the shared drive.", "warning")
        return redirect(url_for("file_share", **redirect_kwargs))

    with get_db_connection() as conn:
        parent_id: Optional[int] = None
        if parent_id_raw:
            if parent_id_raw.isdigit():
                parent_row = conn.execute(
                    "SELECT id FROM folders WHERE id = ?",
                    (int(parent_id_raw),),
                ).fetchone()
                if parent_row is None:
                    flash("That parent folder is no longer available.", "danger")
                    return redirect(url_for("file_share"))
                parent_id = int(parent_id_raw)
            else:
                flash("Choose a valid parent folder.", "danger")
                return redirect(url_for("file_share"))

        conflict = conn.execute(
            """
            SELECT 1
            FROM folders
            WHERE name = :name AND (
                (:parent_id IS NULL AND parent_id IS NULL) OR parent_id = :parent_id
            )
            LIMIT 1
            """,
            {"parent_id": parent_id, "name": name},
        ).fetchone()
        if conflict:
            flash("A folder with that name already exists here.", "warning")
            return redirect(url_for("file_share", **redirect_kwargs))

        conn.execute(
            "INSERT INTO folders (name, parent_id, created_by) VALUES (?, ?, ?)",
            (name, parent_id, session.get("user_id")),
        )
        conn.commit()

    flash("Folder created.", "success")
    return redirect(url_for("file_share", **redirect_kwargs))


@app.route("/folders/<int:folder_id>/delete", methods=["POST"])
@admin_required
def delete_folder(folder_id: int):
    with get_db_connection() as conn:
        folder = conn.execute(
            "SELECT id, name, parent_id FROM folders WHERE id = ?",
            (folder_id,),
        ).fetchone()
        if folder is None:
            flash("That folder could not be found.", "danger")
            return redirect(url_for("file_share"))

        child_count = conn.execute(
            "SELECT COUNT(*) FROM folders WHERE parent_id = ?",
            (folder_id,),
        ).fetchone()[0]
        file_count = conn.execute(
            "SELECT COUNT(*) FROM files WHERE folder_id = ?",
            (folder_id,),
        ).fetchone()[0]
        if child_count or file_count:
            flash("Empty the folder before deleting it.", "warning")
            redirect_kwargs = {"folder_id": folder["id"]}
            return redirect(url_for("file_share", **redirect_kwargs))

        conn.execute("DELETE FROM folders WHERE id = ?", (folder_id,))
        conn.commit()

        parent_id = folder["parent_id"]

    flash("Folder removed.", "info")
    redirect_kwargs = {}
    if parent_id is not None:
        redirect_kwargs["folder_id"] = parent_id
    return redirect(url_for("file_share", **redirect_kwargs))


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
@app.route("/admin/access", methods=["GET", "POST"])
@admin_required
def manage_users():
    if request.method == "POST":
        action = request.form.get("action", "create")

        if action == "delete":
            user_id = request.form.get("user_id", "").strip()
            if not user_id.isdigit():
                flash("Unable to determine which account to remove.", "danger")
            elif int(user_id) == session.get("user_id"):
                flash("You cannot remove your own account while signed in.", "danger")
            else:
                with get_db_connection() as conn:
                    conn.execute("DELETE FROM users WHERE id = ?", (int(user_id),))
                    conn.commit()
                flash("User removed from the dashboard.", "info")
            return redirect(url_for("manage_users"))

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip() or None
        full_name = request.form.get("full_name", "").strip() or None
        phone = request.form.get("phone", "").strip() or None
        is_admin = 1 if request.form.get("is_admin") == "on" else 0

        if not username:
            flash("Username is required.", "warning")
            return redirect(url_for("manage_users"))

        if action == "update":
            user_id = request.form.get("user_id", "").strip()
            if not user_id.isdigit():
                flash("Unable to determine which account to update.", "danger")
                return redirect(url_for("manage_users"))

            password_value = request.form.get("password", "").strip()
            with get_db_connection() as conn:
                try:
                    conn.execute(
                        """
                        UPDATE users
                        SET username = ?, full_name = ?, email = ?, phone = ?, is_admin = ?
                        WHERE id = ?
                        """,
                        (username, full_name, email, phone, is_admin, int(user_id)),
                    )
                    if password_value:
                        if len(password_value) < 8:
                            flash("Passwords must be at least 8 characters when resetting an account.", "warning")
                            return redirect(url_for("manage_users"))
                        conn.execute(
                            "UPDATE users SET password_hash = ? WHERE id = ?",
                            (generate_password_hash(password_value), int(user_id)),
                        )
                    conn.commit()
                except sqlite3.IntegrityError:
                    flash(
                        "That username or email is already in use by another account.",
                        "danger",
                    )
                    return redirect(url_for("manage_users"))

            flash("Account details updated.", "success")
            return redirect(url_for("manage_users"))

        password_value = request.form.get("password", "").strip()
        if not password_value:
            flash("Please provide a password for the new account.", "warning")
            return redirect(url_for("manage_users"))
        if len(password_value) < 8:
            flash("Passwords must be at least 8 characters when creating a new account.", "warning")
            return redirect(url_for("manage_users"))

        with get_db_connection() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO users (username, password_hash, is_admin, full_name, email, phone)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        username,
                        generate_password_hash(password_value),
                        is_admin,
                        full_name,
                        email,
                        phone,
                    ),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                flash("That username or email is already in use.", "danger")
                return redirect(url_for("manage_users"))

        flash("Teammate account created.", "success")
        return redirect(url_for("manage_users"))

    with get_db_connection() as conn:
        users = conn.execute(
            """
            SELECT id, username, full_name, email, phone, is_admin
            FROM users
            ORDER BY username
            """
        ).fetchall()
    return render_template("admin/manage_users.html", users=users)


@app.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password", "").strip()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not new_password:
            flash("Please provide a new password.", "warning")
            return redirect(url_for("change_password"))
        if len(new_password) < 8:
            flash("Choose a password that is at least 8 characters long.", "warning")
            return redirect(url_for("change_password"))
        if new_password != confirm_password:
            flash("New password and confirmation do not match.", "danger")
            return redirect(url_for("change_password"))

        with get_db_connection() as conn:
            user = conn.execute(
                "SELECT password_hash FROM users WHERE id = ?",
                (session["user_id"],),
            ).fetchone()
            if not user:
                flash("We couldn't load your account. Please sign in again.", "danger")
                return redirect(url_for("login"))

            stored_hash = user["password_hash"]
            if stored_hash:
                if not current_password or not check_password_hash(stored_hash, current_password):
                    flash("Current password is incorrect.", "danger")
                    return redirect(url_for("change_password"))
            elif not session.get("is_admin"):
                flash("Ask an administrator to set a password for your account first.", "danger")
                return redirect(url_for("dashboard"))

            if stored_hash and check_password_hash(stored_hash, new_password):
                flash("Your new password must be different from your current password.", "warning")
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
        if not username or not password:
            flash("Please provide both username and password.", "warning")
            return redirect(url_for("login"))
        with get_db_connection() as conn:
            user = conn.execute(
                """
                SELECT id, username, password_hash, is_admin, full_name, email
                FROM users
                WHERE username = ? OR email = ?
                """,
                (username, username),
            ).fetchone()
        if user and user["password_hash"] and check_password_hash(user["password_hash"], password):
            _set_user_session(user, provider="local")
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")
        return redirect(url_for("login"))
    return render_template("auth/login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))
@app.route("/tasks")
@login_required
def tasks_board():
    with get_db_connection() as conn:
        task_lists = list(
            conn.execute(
                "SELECT id, name, slug FROM task_lists ORDER BY position, id"
            ).fetchall()
        )
        tasks = conn.execute(
            """
            SELECT tasks.id,
                   tasks.title,
                   tasks.description,
                   tasks.created_at,
                   tasks.position,
                   tasks.list_id,
                   tasks.status,
                   tasks.assigned_to,
                   tasks.previous_list_id,
                   COALESCE(NULLIF(creator.full_name, ''), creator.username) AS creator,
                   COALESCE(NULLIF(assignee.full_name, ''), assignee.username) AS assignee
            FROM tasks
            LEFT JOIN users AS creator ON tasks.created_by = creator.id
            LEFT JOIN users AS assignee ON tasks.assigned_to = assignee.id
            ORDER BY tasks.list_id, tasks.position, tasks.created_at
            """
        ).fetchall()
        assignable_users = conn.execute(
            """
            SELECT id,
                   COALESCE(NULLIF(full_name, ''), username) AS display_name
            FROM users
            WHERE is_admin = 0
            ORDER BY display_name COLLATE NOCASE, id
            """
        ).fetchall()
    lists_by_id = {task_list["id"]: task_list for task_list in task_lists}
    completed_list = next(
        (lst for lst in task_lists if _is_completed_list(lst["slug"], lst["name"])),
        None,
    )
    active_lists = [
        lst for lst in task_lists if not _is_completed_list(lst["slug"], lst["name"])
    ]
    board_lists = list(active_lists)
    if completed_list is not None:
        board_lists.append(completed_list)

    seen_ids = {lst["id"] for lst in board_lists}
    for task in tasks:
        list_id = task["list_id"]
        if list_id is not None and list_id not in seen_ids:
            extra_list = lists_by_id.get(list_id)
            if extra_list is not None:
                board_lists.append(extra_list)
                seen_ids.add(extra_list["id"])

    tasks_by_list: Dict[int, list] = {task_list["id"]: [] for task_list in board_lists}
    for task in tasks:
        tasks_by_list.setdefault(task["list_id"], []).append(task)
    completed_list = next(
        (lst for lst in task_lists if _is_completed_list(lst["slug"], lst["name"])),
        None,
    )
    return render_template(
        "dashboard/tasks.html",
        board_lists=board_lists,
        active_task_lists=active_lists,
        tasks_by_list=tasks_by_list,
        assignable_users=assignable_users,
        completed_list_id=completed_list["id"] if completed_list else None,
    )


@app.route("/tasks/new", methods=["POST"])
@login_required
def create_task():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    list_id_raw = request.form.get("list_id", "").strip()
    assigned_to_raw = request.form.get("assigned_to", "").strip()

    if not title:
        flash("Task title is required.", "warning")
        return redirect(url_for("tasks_board"))
    if not list_id_raw.isdigit():
        flash("Select a valid task list.", "danger")
        return redirect(url_for("tasks_board"))

    list_id = int(list_id_raw)
    assigned_to_id: Optional[int] = None
    with get_db_connection() as conn:
        task_list = conn.execute(
            "SELECT id, slug, name FROM task_lists WHERE id = ?",
            (list_id,),
        ).fetchone()
        if task_list is None:
            flash("That task list no longer exists.", "danger")
            return redirect(url_for("tasks_board"))

        if _is_completed_list(task_list["slug"], task_list["name"]):
            flash("Create or select an active list to add new tasks. Completed is archive-only.", "warning")
            return redirect(url_for("tasks_board"))

        if assigned_to_raw:
            if assigned_to_raw.isdigit():
                candidate = conn.execute(
                    "SELECT id FROM users WHERE id = ? AND is_admin = 0",
                    (int(assigned_to_raw),),
                ).fetchone()
                if candidate is None:
                    flash("Choose a valid team member for this assignment.", "danger")
                    return redirect(url_for("tasks_board"))
                assigned_to_id = int(assigned_to_raw)
            elif assigned_to_raw.lower() not in {"", "none", "null"}:
                flash("Choose a valid team member for this assignment.", "danger")
                return redirect(url_for("tasks_board"))

        current_position = conn.execute(
            "SELECT COALESCE(MAX(position), 0) FROM tasks WHERE list_id = ?",
            (list_id,),
        ).fetchone()[0]
        conn.execute(
            """
            INSERT INTO tasks (title, description, status, position, created_by, assigned_to, list_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                description or None,
                task_list["slug"],
                current_position + 1,
                session.get("user_id"),
                assigned_to_id,
                list_id,
            ),
        )
        conn.commit()

    flash("Task added to the board.", "success")
    return redirect(url_for("tasks_board"))


@app.route("/tasks/<task_id>/toggle", methods=["POST"])
@login_required
def toggle_task_completion(task_id: str):
    completed_raw = request.form.get("completed", "0").strip()
    current_list_raw = request.form.get("current_list_id", "").strip()

    if not task_id.isdigit():
        flash("Task could not be found.", "danger")
        return redirect(url_for("tasks_board"))
    if not current_list_raw.isdigit():
        flash("That task list is not available.", "danger")
        return redirect(url_for("tasks_board"))

    task_id_int = int(task_id)
    current_list_id = int(current_list_raw)
    completed_flag = completed_raw == "1"

    with get_db_connection() as conn:
        task = conn.execute(
            "SELECT id, list_id, previous_list_id FROM tasks WHERE id = ?",
            (task_id_int,),
        ).fetchone()
        if task is None:
            flash("Task could not be found.", "danger")
            return redirect(url_for("tasks_board"))

        task_lists = list(_fetch_task_lists(conn))
        lists_by_id = {lst["id"]: lst for lst in task_lists}
        completed_list = next(
            (lst for lst in task_lists if _is_completed_list(lst["slug"], lst["name"])),
            None,
        )

        if completed_flag:
            if completed_list is None:
                flash("Create a Completed list before marking tasks done.", "warning")
                return redirect(url_for("tasks_board"))
            previous_list_id = (
                task["list_id"]
                if task["list_id"] != completed_list["id"]
                else task["previous_list_id"]
            )
            max_position = conn.execute(
                "SELECT COALESCE(MAX(position), 0) FROM tasks WHERE list_id = ?",
                (completed_list["id"],),
            ).fetchone()[0]
            conn.execute(
                """
                UPDATE tasks
                SET list_id = ?, status = ?, position = ?, previous_list_id = ?
                WHERE id = ?
                """,
                (
                    completed_list["id"],
                    completed_list["slug"],
                    max_position + 1,
                    previous_list_id,
                    task_id_int,
                ),
            )
        else:
            if not task_lists:
                flash("Add a task list to reopen items.", "warning")
                return redirect(url_for("tasks_board"))

            target_list_id = task["previous_list_id"]
            if target_list_id is None or target_list_id not in lists_by_id:
                target_list_id = next(
                    (
                        lst["id"]
                        for lst in task_lists
                        if lst["id"]
                        != (completed_list["id"] if completed_list else None)
                        and not _is_completed_list(lst["slug"], lst["name"])
                    ),
                    None,
                )
            target_list = lists_by_id.get(target_list_id)
            if target_list is None:
                target_list = lists_by_id.get(current_list_id)
            if target_list is None:
                flash("That task list is not available.", "danger")
                return redirect(url_for("tasks_board"))

            max_position = conn.execute(
                "SELECT COALESCE(MAX(position), 0) FROM tasks WHERE list_id = ?",
                (target_list["id"],),
            ).fetchone()[0]
            conn.execute(
                """
                UPDATE tasks
                SET list_id = ?, status = ?, position = ?, previous_list_id = NULL
                WHERE id = ?
                """,
                (
                    target_list["id"],
                    target_list["slug"],
                    max_position + 1,
                    task_id_int,
                ),
            )
        conn.commit()

    flash("Task updated.", "success")
    return redirect(url_for("tasks_board"))


@app.route("/tasks/<task_id>/move", methods=["POST"])
@login_required
def move_task(task_id: str):
    list_id_raw = request.form.get("list_id", "").strip()
    if not list_id_raw.isdigit() or not task_id.isdigit():
        flash("That list is not available.", "danger")
        return redirect(url_for("tasks_board"))

    list_id = int(list_id_raw)
    task_id_int = int(task_id)
    with get_db_connection() as conn:
        task_list = conn.execute(
            "SELECT id, slug FROM task_lists WHERE id = ?",
            (list_id,),
        ).fetchone()
        if task_list is None:
            flash("That list is not available.", "danger")
            return redirect(url_for("tasks_board"))
        max_position = conn.execute(
            "SELECT COALESCE(MAX(position), 0) FROM tasks WHERE list_id = ?",
            (list_id,),
        ).fetchone()[0]
        cursor = conn.execute(
            "UPDATE tasks SET list_id = ?, status = ?, position = ?, previous_list_id = NULL WHERE id = ?",
            (list_id, task_list["slug"], max_position + 1, task_id_int),
        )
        conn.commit()

    if cursor.rowcount:
        flash("Task updated.", "success")
    else:
        flash("Task could not be found.", "danger")
    return redirect(url_for("tasks_board"))


@app.route("/tasks/<task_id>/update", methods=["POST"])
@login_required
def update_task(task_id: str):
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    assigned_to_raw = request.form.get("assigned_to", "").strip()

    if not title:
        flash("Task title cannot be empty.", "warning")
        return redirect(url_for("tasks_board"))

    assigned_to_id: Optional[int] = None
    with get_db_connection() as conn:
        if assigned_to_raw:
            if assigned_to_raw.isdigit():
                candidate = conn.execute(
                    "SELECT id FROM users WHERE id = ? AND is_admin = 0",
                    (int(assigned_to_raw),),
                ).fetchone()
                if candidate is None:
                    flash("Choose a valid team member for this assignment.", "danger")
                    return redirect(url_for("tasks_board"))
                assigned_to_id = int(assigned_to_raw)
            elif assigned_to_raw.lower() not in {"", "none", "null"}:
                flash("Choose a valid team member for this assignment.", "danger")
                return redirect(url_for("tasks_board"))

        cursor = conn.execute(
            "UPDATE tasks SET title = ?, description = ?, assigned_to = ? WHERE id = ?",
            (title, description or None, assigned_to_id, int(task_id)),
        )
        conn.commit()

    if cursor.rowcount:
        flash("Task details saved.", "success")
    else:
        flash("Task could not be found.", "danger")
    return redirect(url_for("tasks_board"))


@app.route("/tasks/<task_id>/delete", methods=["POST"])
@login_required
def delete_task(task_id: str):
    if not task_id.isdigit():
        flash("Task could not be found.", "danger")
        return redirect(url_for("tasks_board"))

    with get_db_connection() as conn:
        cursor = conn.execute("DELETE FROM tasks WHERE id = ?", (int(task_id),))
        conn.commit()

    if cursor.rowcount:
        flash("Task removed from the board.", "info")
    else:
        flash("Task could not be found.", "danger")
    return redirect(url_for("tasks_board"))


@app.route("/tasks/lists/new", methods=["POST"])
@login_required
def create_task_list():
    name = request.form.get("name", "").strip()
    if not name:
        flash("Name your new list to keep the board organized.", "warning")
        return redirect(url_for("tasks_board"))

    with get_db_connection() as conn:
        base_slug = slugify(name)
        slug = _ensure_unique_list_slug(conn, base_slug)
        position = conn.execute(
            "SELECT COALESCE(MAX(position), 0) + 1 FROM task_lists"
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO task_lists (name, slug, position) VALUES (?, ?, ?)",
            (name, slug, position),
        )
        conn.commit()

    flash("New task list added to the board.", "success")
    return redirect(url_for("tasks_board"))


@app.route("/tasks/lists/<list_id>/rename", methods=["POST"])
@login_required
def rename_task_list(list_id: str):
    name = request.form.get("name", "").strip()
    if not name:
        flash("List names cannot be empty.", "warning")
        return redirect(url_for("tasks_board"))

    if not list_id.isdigit():
        flash("That list could not be found.", "danger")
        return redirect(url_for("tasks_board"))

    list_id_int = int(list_id)
    with get_db_connection() as conn:
        current = conn.execute(
            "SELECT slug, name FROM task_lists WHERE id = ?",
            (list_id_int,),
        ).fetchone()
        if current is None:
            flash("That list could not be found.", "danger")
            return redirect(url_for("tasks_board"))
        if _is_completed_list(current["slug"], current["name"]):
            flash("The Completed archive cannot be renamed.", "warning")
            return redirect(url_for("tasks_board"))
        base_slug = slugify(name)
        slug = current["slug"] if current["slug"] == base_slug else _ensure_unique_list_slug(conn, base_slug)
        conn.execute(
            "UPDATE task_lists SET name = ?, slug = ? WHERE id = ?",
            (name, slug, list_id_int),
        )
        conn.execute(
            "UPDATE tasks SET status = ? WHERE list_id = ?",
            (slug, list_id_int),
        )
        conn.commit()

    flash("List updated.", "success")
    return redirect(url_for("tasks_board"))


@app.route("/tasks/lists/<list_id>/delete", methods=["POST"])
@login_required
def delete_task_list(list_id: str):
    if not list_id.isdigit():
        flash("That list could not be found.", "danger")
        return redirect(url_for("tasks_board"))

    list_id_int = int(list_id)
    with get_db_connection() as conn:
        total_lists = conn.execute("SELECT COUNT(*) FROM task_lists").fetchone()[0]
        if total_lists <= 1:
            flash("Keep at least one list on the board.", "warning")
            return redirect(url_for("tasks_board"))

        existing = conn.execute(
            "SELECT id, slug, name FROM task_lists WHERE id = ?",
            (list_id_int,),
        ).fetchone()
        if existing is None:
            flash("That list could not be found.", "danger")
            return redirect(url_for("tasks_board"))
        if _is_completed_list(existing["slug"], existing["name"]):
            flash("The Completed archive cannot be removed.", "warning")
            return redirect(url_for("tasks_board"))

        has_tasks = conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE list_id = ?",
            (list_id_int,),
        ).fetchone()[0]
        if has_tasks:
            flash("Move or archive the tasks before deleting this list.", "danger")
            return redirect(url_for("tasks_board"))

        conn.execute("DELETE FROM task_lists WHERE id = ?", (list_id_int,))
        conn.commit()

    flash("List removed.", "info")
    return redirect(url_for("tasks_board"))


if __name__ == "__main__":
    init_db()
    debug_env = os.environ.get("FLASK_DEBUG", "")
    debug_mode = debug_env.lower() in {"1", "true", "t", "yes", "on"}
    app.run(host="127.0.0.1", port=8081, debug=debug_mode)
