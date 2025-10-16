import os
import sqlite3
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.parse import parse_qs, quote, urlparse
from uuid import uuid4

import requests
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
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,  # 20 MB
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
app.config.setdefault("TRELLO_API_KEY", os.getenv("TRELLO_API_KEY"))
app.config.setdefault("TRELLO_API_TOKEN", os.getenv("TRELLO_API_TOKEN"))
app.config.setdefault("TRELLO_BOARD_ID", os.getenv("TRELLO_BOARD_ID"))
app.config.setdefault(
    "TRELLO_BOARD_URL",
    os.getenv("TRELLO_BOARD_URL", "https://trello.com/b/WLeHBhSM/3-iii"),
)


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


class TrelloError(RuntimeError):
    """Raised when Trello API operations fail."""


class TrelloClient:
    _API_BASE = "https://api.trello.com/1"

    def __init__(self, api_key: str, token: str, board_id: str) -> None:
        self.api_key = api_key
        self.token = token
        self.board_id = board_id

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> Any:
        merged_params = dict(params or {})
        merged_params.update({"key": self.api_key, "token": self.token})
        try:
            response = requests.request(
                method,
                f"{self._API_BASE}{path}",
                params=merged_params,
                json=json,
                timeout=10,
            )
        except requests.RequestException as exc:  # pragma: no cover - network failure
            raise TrelloError("Unable to reach Trello. Please try again shortly.") from exc

        if response.status_code >= 400:
            raise TrelloError(
                f"Trello API error ({response.status_code}): {response.text.strip() or 'Unknown error.'}"
            )

        if not response.text:
            return {}
        try:
            return response.json()
        except ValueError:
            return {}

    def fetch_board_state(self) -> Tuple[Iterable[Dict[str, Any]], Dict[str, Iterable[Dict[str, Any]]]]:
        lists = self._request(
            "GET",
            f"/boards/{self.board_id}/lists",
            params={
                "fields": "name,pos",
                "cards": "open",
                "card_fields": "name,desc,dateLastActivity",
                "card_members": "true",
                "card_member_fields": "fullName,username",
            },
        )

        structured_lists = []
        tasks_by_list: Dict[str, Iterable[Dict[str, Any]]] = {}

        for trello_list in lists:
            list_id = trello_list.get("id")
            if not list_id:
                continue
            list_name = trello_list.get("name", "List")
            structured_lists.append(
                {
                    "id": list_id,
                    "name": list_name,
                    "slug": slugify(list_name),
                    "position": trello_list.get("pos", 0),
                }
            )

            tasks: list[Dict[str, Any]] = []
            for card in trello_list.get("cards", []):
                created_at = card.get("dateLastActivity")
                formatted_date = ""
                if created_at:
                    try:
                        parsed = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                        formatted_date = parsed.strftime("%b %d, %Y %I:%M %p")
                    except ValueError:
                        formatted_date = created_at

                members = card.get("members", []) or []
                member_names = [member.get("fullName") or member.get("username") for member in members]
                creator = ", ".join(filter(None, member_names)) or "Unassigned"

                tasks.append(
                    {
                        "id": card.get("id"),
                        "title": card.get("name", "Untitled"),
                        "description": card.get("desc") or None,
                        "creator": creator,
                        "created_at": formatted_date,
                    }
                )

            tasks_by_list[list_id] = tasks

        structured_lists.sort(key=lambda entry: entry.get("position", 0))
        return structured_lists, tasks_by_list

    def create_card(self, list_id: str, title: str, description: Optional[str] = None) -> None:
        self._request(
            "POST",
            "/cards",
            params={
                "idList": list_id,
                "name": title,
                "desc": description or "",
                "pos": "bottom",
            },
        )

    def update_card(self, card_id: str, *, title: str, description: Optional[str]) -> None:
        self._request(
            "PUT",
            f"/cards/{card_id}",
            params={"name": title, "desc": description or ""},
        )

    def move_card(self, card_id: str, list_id: str) -> None:
        self._request(
            "PUT",
            f"/cards/{card_id}",
            params={"idList": list_id, "pos": "bottom"},
        )

    def delete_card(self, card_id: str) -> None:
        self._request("DELETE", f"/cards/{card_id}")

    def create_list(self, name: str) -> None:
        self._request(
            "POST",
            "/lists",
            params={"name": name, "idBoard": self.board_id, "pos": "bottom"},
        )

    def rename_list(self, list_id: str, name: str) -> None:
        self._request("PUT", f"/lists/{list_id}", params={"name": name})

    def archive_list(self, list_id: str) -> None:
        self._request("PUT", f"/lists/{list_id}/closed", params={"value": "true"})


def _extract_trello_board_id(board_url: Optional[str]) -> Optional[str]:
    if not board_url:
        return None

    parsed = urlparse(board_url)
    netloc = parsed.netloc.lower()
    # Allow standard Trello domains regardless of letter casing or ``www`` prefix.
    host = netloc.split(":", 1)[0]
    if host not in {"trello.com", "www.trello.com"}:
        return None

    path_parts = [segment for segment in parsed.path.split("/") if segment]
    if len(path_parts) >= 2 and path_parts[0] == "b":
        return path_parts[1]

    return None


def get_trello_client() -> Optional[TrelloClient]:
    api_key = app.config.get("TRELLO_API_KEY")
    token = app.config.get("TRELLO_API_TOKEN")
    board_id = app.config.get("TRELLO_BOARD_ID")

    if not board_id:
        derived = _extract_trello_board_id(app.config.get("TRELLO_BOARD_URL"))
        if derived:
            board_id = derived
            app.config["TRELLO_BOARD_ID"] = derived

    if api_key and token and board_id:
        return TrelloClient(api_key, token, board_id)
    return None


def _format_trello_board_embed(raw_url: Optional[str]) -> Optional[str]:
    if not raw_url:
        return None

    url = raw_url.strip()
    if not url:
        return None

    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    host = netloc.split(":", 1)[0]
    if host in {"trello.com", "www.trello.com"}:
        path_parts = [segment for segment in parsed.path.split("/") if segment]
        if len(path_parts) >= 2 and path_parts[0] == "b":
            board_id = path_parts[1]
            slug = path_parts[2] if len(path_parts) >= 3 else ""
            name_param = quote(slug) if slug else ""
            base = f"https://trello.com/embed/board?id={board_id}&display=board"
            if name_param:
                return f"{base}&name={name_param}"
            return base

    return url


def _resolve_trello_board_links() -> Tuple[Optional[str], Optional[str]]:
    board_url = app.config.get("TRELLO_BOARD_URL")
    if not isinstance(board_url, str):
        board_url = ""
    board_url = board_url.strip()
    if not board_url:
        return None, None

    embed_url = _format_trello_board_embed(board_url)
    return board_url, embed_url


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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                list_id INTEGER,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (list_id) REFERENCES task_lists(id) ON DELETE SET NULL
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
        if "google_sub" not in existing_user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN google_sub TEXT")
        conn.commit()

        existing_tasks_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(tasks)").fetchall()
        }
        if "list_id" not in existing_tasks_columns:
            conn.execute("ALTER TABLE tasks ADD COLUMN list_id INTEGER")
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

        default_lists = [
            ("Chute Gate", 1),
            ("On Deck", 2),
            ("Ready to Deliver", 3),
            ("Completed Runs", 4),
        ]
        for name, position in default_lists:
            slug = slugify(name)
            conn.execute(
                "INSERT OR IGNORE INTO task_lists (name, slug, position) VALUES (?, ?, ?)",
                (name, slug, position),
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

    task_summary = []
    trello_client = get_trello_client()
    if trello_client:
        try:
            trello_lists, trello_tasks = trello_client.fetch_board_state()
        except TrelloError as exc:
            flash(str(exc), "danger")
        else:
            task_summary = [
                {
                    "id": task_list["id"],
                    "name": task_list["name"],
                    "slug": task_list.get("slug") or slugify(task_list["name"]),
                    "count": len(trello_tasks.get(task_list["id"], [])),
                }
                for task_list in trello_lists
            ]
    else:
        with get_db_connection() as conn:
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
    trello_board_url, trello_board_embed_url = _resolve_trello_board_links()
    return render_template(
        "index.html",
        recent_files=recent_files,
        task_summary=task_summary,
        task_metrics=_compute_task_metrics(task_summary),
        calendar_embeds=list(_resolve_calendar_embeds()),
        trello_board_url=trello_board_url,
        trello_board_embed_url=trello_board_embed_url,
    )


@app.route("/files")
@login_required
def file_share():
    with get_db_connection() as conn:
        files = conn.execute(
            """
            SELECT files.id, files.original_name, files.uploaded_at,
                   COALESCE(NULLIF(users.full_name, ''), users.username) AS uploader,
                   users.username AS uploader_username
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
    trello_client = get_trello_client()
    trello_board_url, trello_board_embed_url = _resolve_trello_board_links()
    if trello_client:
        try:
            task_lists, trello_tasks = trello_client.fetch_board_state()
        except TrelloError as exc:
            flash(str(exc), "danger")
            task_lists = []
            trello_tasks = {}
        return render_template(
            "dashboard/tasks.html",
            task_lists=task_lists,
            tasks_by_list=trello_tasks,
            trello_enabled=True,
            trello_board_url=trello_board_url,
            trello_board_embed_url=trello_board_embed_url,
            trello_embed_only=False,
        )

    if trello_board_embed_url:
        return render_template(
            "dashboard/tasks.html",
            task_lists=[],
            tasks_by_list={},
            trello_enabled=False,
            trello_board_url=trello_board_url,
            trello_board_embed_url=trello_board_embed_url,
            trello_embed_only=True,
        )

    with get_db_connection() as conn:
        task_lists = list(
            conn.execute(
                "SELECT id, name, slug FROM task_lists ORDER BY position, id"
            ).fetchall()
        )
        tasks = conn.execute(
            """
            SELECT tasks.id, tasks.title, tasks.description, tasks.created_at,
                   tasks.position, tasks.list_id,
                   COALESCE(NULLIF(users.full_name, ''), users.username) AS creator
            FROM tasks
            LEFT JOIN users ON tasks.created_by = users.id
            ORDER BY tasks.list_id, tasks.position, tasks.created_at
            """
        ).fetchall()
    tasks_by_list: Dict[int, list] = {task_list["id"]: [] for task_list in task_lists}
    for task in tasks:
        tasks_by_list.setdefault(task["list_id"], []).append(task)
    return render_template(
        "dashboard/tasks.html",
        task_lists=task_lists,
        tasks_by_list=tasks_by_list,
        trello_enabled=False,
        trello_board_url=trello_board_url,
        trello_board_embed_url=trello_board_embed_url,
        trello_embed_only=False,
    )


@app.route("/tasks/new", methods=["POST"])
@login_required
def create_task():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    list_id_raw = request.form.get("list_id", "").strip()

    if not title:
        flash("Task title is required.", "warning")
        return redirect(url_for("tasks_board"))
    trello_client = get_trello_client()
    trello_board_url, trello_board_embed_url = _resolve_trello_board_links()
    if trello_client:
        if not list_id_raw:
            flash("Select a list on the Trello board.", "danger")
            return redirect(url_for("tasks_board"))
        try:
            trello_client.create_card(list_id_raw, title, description)
        except TrelloError as exc:
            flash(str(exc), "danger")
        else:
            flash("Task added to the shared Trello board.", "success")
        return redirect(url_for("tasks_board"))

    if trello_board_embed_url:
        flash(
            "The Trello board is active. Add cards directly in Trello or configure the API credentials to manage them here.",
            "warning",
        )
        return redirect(url_for("tasks_board"))

    if not list_id_raw.isdigit():
        flash("Select a valid task list.", "danger")
        return redirect(url_for("tasks_board"))

    list_id = int(list_id_raw)
    with get_db_connection() as conn:
        task_list = conn.execute(
            "SELECT id, slug FROM task_lists WHERE id = ?",
            (list_id,),
        ).fetchone()
        if task_list is None:
            flash("That task list no longer exists.", "danger")
            return redirect(url_for("tasks_board"))

        current_position = conn.execute(
            "SELECT COALESCE(MAX(position), 0) FROM tasks WHERE list_id = ?",
            (list_id,),
        ).fetchone()[0]
        conn.execute(
            """
            INSERT INTO tasks (title, description, status, position, created_by, list_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                description or None,
                task_list["slug"],
                current_position + 1,
                session.get("user_id"),
                list_id,
            ),
        )
        conn.commit()

    flash("Task added to the board.", "success")
    return redirect(url_for("tasks_board"))


@app.route("/tasks/<task_id>/move", methods=["POST"])
@login_required
def move_task(task_id: str):
    list_id_raw = request.form.get("list_id", "").strip()
    trello_client = get_trello_client()
    trello_board_url, trello_board_embed_url = _resolve_trello_board_links()
    if trello_client:
        if not list_id_raw:
            flash("That Trello list is not available.", "danger")
            return redirect(url_for("tasks_board"))
        try:
            trello_client.move_card(task_id, list_id_raw)
        except TrelloError as exc:
            flash(str(exc), "danger")
        else:
            flash("Task updated.", "success")
        return redirect(url_for("tasks_board"))

    if trello_board_embed_url:
        flash(
            "The Trello board is active. Move cards directly in Trello or add API credentials to sync from the dashboard.",
            "warning",
        )
        return redirect(url_for("tasks_board"))

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
            "UPDATE tasks SET list_id = ?, status = ?, position = ? WHERE id = ?",
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

    if not title:
        flash("Task title cannot be empty.", "warning")
        return redirect(url_for("tasks_board"))

    trello_client = get_trello_client()
    trello_board_url, trello_board_embed_url = _resolve_trello_board_links()
    if trello_client:
        try:
            trello_client.update_card(
                task_id,
                title=title,
                description=description or None,
            )
        except TrelloError as exc:
            flash(str(exc), "danger")
        else:
            flash("Task details saved.", "success")
        return redirect(url_for("tasks_board"))

    if trello_board_embed_url:
        flash(
            "The Trello board is active. Edit cards directly in Trello or configure the API credentials to manage them here.",
            "warning",
        )
        return redirect(url_for("tasks_board"))

    with get_db_connection() as conn:
        cursor = conn.execute(
            "UPDATE tasks SET title = ?, description = ? WHERE id = ?",
            (title, description or None, int(task_id)),
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
    trello_client = get_trello_client()
    trello_board_url, trello_board_embed_url = _resolve_trello_board_links()
    if trello_client:
        try:
            trello_client.delete_card(task_id)
        except TrelloError as exc:
            flash(str(exc), "danger")
        else:
            flash("Task removed from the board.", "info")
        return redirect(url_for("tasks_board"))

    if trello_board_embed_url:
        flash(
            "The Trello board is active. Remove cards directly in Trello or configure the API credentials to manage them here.",
            "warning",
        )
        return redirect(url_for("tasks_board"))

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

    trello_client = get_trello_client()
    trello_board_url, trello_board_embed_url = _resolve_trello_board_links()
    if trello_client:
        try:
            trello_client.create_list(name)
        except TrelloError as exc:
            flash(str(exc), "danger")
        else:
            flash("New Trello list added to the board.", "success")
        return redirect(url_for("tasks_board"))

    if trello_board_embed_url:
        flash(
            "The Trello board is active. Create lists directly in Trello or configure the API credentials to manage them here.",
            "warning",
        )
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

    trello_client = get_trello_client()
    trello_board_url, trello_board_embed_url = _resolve_trello_board_links()
    if trello_client:
        try:
            trello_client.rename_list(list_id, name)
        except TrelloError as exc:
            flash(str(exc), "danger")
        else:
            flash("List updated.", "success")
        return redirect(url_for("tasks_board"))

    if trello_board_embed_url:
        flash(
            "The Trello board is active. Rename lists directly in Trello or configure the API credentials to manage them here.",
            "warning",
        )
        return redirect(url_for("tasks_board"))

    if not list_id.isdigit():
        flash("That list could not be found.", "danger")
        return redirect(url_for("tasks_board"))

    list_id_int = int(list_id)
    with get_db_connection() as conn:
        current = conn.execute(
            "SELECT slug FROM task_lists WHERE id = ?",
            (list_id_int,),
        ).fetchone()
        if current is None:
            flash("That list could not be found.", "danger")
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
    trello_client = get_trello_client()
    trello_board_url, trello_board_embed_url = _resolve_trello_board_links()
    if trello_client:
        try:
            trello_client.archive_list(list_id)
        except TrelloError as exc:
            flash(str(exc), "danger")
        else:
            flash("List archived on Trello.", "info")
        return redirect(url_for("tasks_board"))

    if trello_board_embed_url:
        flash(
            "The Trello board is active. Archive lists directly in Trello or configure the API credentials to manage them here.",
            "warning",
        )
        return redirect(url_for("tasks_board"))

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
            "SELECT id FROM task_lists WHERE id = ?",
            (list_id_int,),
        ).fetchone()
        if existing is None:
            flash("That list could not be found.", "danger")
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
