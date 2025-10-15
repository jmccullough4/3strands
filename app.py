import ipaddress
import os
import sqlite3
from functools import wraps
from pathlib import Path
from typing import Dict, Iterable, Optional
from urllib.parse import urlparse
from uuid import uuid4

from flask import (
    Flask,
    abort,
    flash,
    make_response,
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
    "EXTERNAL_BASE_URL",
    os.getenv("EXTERNAL_BASE_URL") or "http://dashboard.3strands.co:8081",
)
app.config.setdefault(
    "ALLOW_INSECURE_SAML_REDIRECTS",
    os.getenv("ALLOW_INSECURE_SAML_REDIRECTS", "").lower()
    in {"1", "true", "yes", "on"}
    or bool(app.config["EXTERNAL_BASE_URL"].startswith("http://")),
)
app.config.setdefault(
    "SAML_IDP_ENTITY_ID",
    os.getenv("SAML_IDP_ENTITY_ID")
    or "https://accounts.google.com/o/saml2?idpid=C040clheo",
)
app.config.setdefault(
    "SAML_IDP_SSO_URL",
    os.getenv("SAML_IDP_SSO_URL")
    or "https://accounts.google.com/o/saml2/idp?idpid=C040clheo",
)
app.config.setdefault(
    "SAML_IDP_X509CERT",
    os.getenv("SAML_IDP_X509CERT")
    or (
        "MIIDdDCCAlygAwIBAgIGAZnp2SLbMA0GCSqGSIb3DQEBCwUAMHsxFDASBgNVBAoTC0dvb2dsZSBJbmMuMRYwFAYDVQQHEw1Nb3VudGFpbiBW"
        "aWV3MQ8wDQYDVQQDEwZHb29nbGUxGDAWBgNVBAsTD0dvb2dsZSBGb3IgV29yazELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEw"
        "HhcNMjUxMDE1MjE0OTA1WhcNMzAxMDE0MjE0OTA1WjB7MRQwEgYDVQQKEwtHb29nbGUgSW5jLjEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEP"
        "MA0GA1UEAxMGR29vZ2xlMRgwFgYDVQQLEw9Hb29nbGUgRm9yIFdvcmsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMIIBIjAN"
        "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx0zhfINES7iJ0gnEsKfSikxNwfQ6ltqFlcX8CPFrDnLORh1aP+un05Djx513Qhkqss+CwJJYH"
        "+HYmdHOhoy3HsFMUt6Hj06C/v2dFLzIrhuY9ASzyr75TzAWUztTFWOwtyde1cfQlT+3obzJp1bQcWd7ok0HCOjRProbX61hSDM/uMGuqDUIUS"
        "isctqP40NKYEn3XAu9k98C7dQIJEnlFBSR/OpNUIUAv1ORvjf+fRIlsXIo/TUndmyfp9oul1VvKWGh1F2A1+Ih3jQGTGxUAlNAUT4MnM2/Ew+"
        "gEPummJE4u6GSzqijUT1+3ZJKCEdSn4cnriq9N+z7zebj4aSjBwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCosOuC9TX2XqwrPepEzZEiGlE/"
        "kgq7feBOmefyj0voomj5VxKVyKWKtk0E/qd2ReN7eDZjrTKAuJof9YFcJqS7SeSl/XAW+KwhBvzdX8DN9T+A2Syg/p8tmSB64GWPF4HriHn6g"
        "p/5SnYaAfeX7amADBTzmRbDd6cX8HRryK3Zt+VCGk05vbq+noHVV3WkY7Kxl1+MRMfCBZv3o5Sr3JvlhfVfFd0ccRtvpAepSsC9lkICDiCxde"
        "3tkfG28byooNDYX3eyVy0Q1Ujg/yv/+OarchN058SLsXk3H9Zg/2FjEpe26qZu0jKTEPFK95/VYI4LCZ4gkVj/VDJG7RDHD8Cu"
    ),
)
app.config.setdefault("SAML_SP_ENTITY_ID", os.getenv("SAML_SP_ENTITY_ID", ""))
app.config.setdefault(
    "CALENDAR_EMBEDS",
    [
        {
            "title": "Production Schedule",
            "url": os.getenv(
                "GOOGLE_CALENDAR_PRODUCTION",
                "https://calendar.google.com/calendar/embed?src=your-production-calendar@group.calendar.google.com",
            ),
        },
        {
            "title": "Markets & Deliveries",
            "url": os.getenv(
                "GOOGLE_CALENDAR_DELIVERIES",
                "https://calendar.google.com/calendar/embed?src=your-logistics-calendar@group.calendar.google.com",
            ),
        },
    ],
)


def slugify(value: str) -> str:
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in value)
    slug = "-".join(filter(None, slug.split("-")))
    return slug or "list"
try:  # pragma: no cover - optional dependency checked at runtime
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.settings import OneLogin_Saml2_Settings
except ImportError:  # pragma: no cover - handled at runtime when SAML is used
    OneLogin_Saml2_Auth = None
    OneLogin_Saml2_Settings = None


def _assert_public_https(parsed_url, context: str) -> None:
    allow_insecure = app.config.get("ALLOW_INSECURE_SAML_REDIRECTS", False)
    if allow_insecure:
        return

    host = parsed_url.hostname
    if host:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip and (ip.is_private or ip.is_loopback or ip.is_link_local):
            raise RuntimeError(
                f"{context} cannot point to a private or loopback address. Configure EXTERNAL_BASE_URL with your public HTTPS dashboard domain authorized in Google Cloud."
            )
        if ip and parsed_url.scheme != "https":
            raise RuntimeError(
                f"{context} must use https when referencing a direct IP address."
            )

    if parsed_url.scheme != "https":
        # Permit http:// redirects for publicly routable hostnames when HTTPS isn't
        # available yet, but encourage operators to secure the deployment.
        if parsed_url.scheme == "http" and host and not host.replace(".", "").isdigit():
            return
        raise RuntimeError(
            f"{context} must use https. Update EXTERNAL_BASE_URL to match the public domain registered in Google Cloud."
        )


def _saml_enabled() -> bool:
    return bool(
        OneLogin_Saml2_Auth
        and app.config.get("SAML_IDP_ENTITY_ID")
        and app.config.get("SAML_IDP_SSO_URL")
        and app.config.get("SAML_IDP_X509CERT")
    )


def _require_saml_ready() -> None:
    if OneLogin_Saml2_Auth is None or OneLogin_Saml2_Settings is None:
        raise RuntimeError(
            "SAML login requires the python3-saml package. Install it with 'pip install python3-saml'."
        )
    if not _saml_enabled():
        raise RuntimeError(
            "SAML identity provider details are missing. Update SAML_IDP_* settings in instance/config.py."
        )


def _saml_base_url() -> str:
    base_url = app.config.get("EXTERNAL_BASE_URL")
    if not base_url:
        absolute = url_for("home", _external=True)
        parsed = urlparse(absolute)
        _assert_public_https(parsed, "Generated redirect URL")
        return absolute.rstrip("/")

    parsed_base = urlparse(base_url)
    if not parsed_base.scheme or not parsed_base.netloc:
        raise RuntimeError(
            "EXTERNAL_BASE_URL must include scheme and host, e.g. https://dashboard.example.com"
        )
    _assert_public_https(parsed_base, "EXTERNAL_BASE_URL")
    return base_url.rstrip("/")


def _saml_settings() -> Dict:
    _require_saml_ready()
    base_url = _saml_base_url()
    acs_url = f"{base_url}{url_for('auth_saml_acs', _external=False)}"
    entity_id = (
        app.config.get("SAML_SP_ENTITY_ID") or f"{base_url}{url_for('saml_metadata', _external=False)}"
    )
    return {
        "strict": True,
        "debug": app.debug,
        "sp": {
            "entityId": entity_id,
            "assertionConsumerService": {
                "url": acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": app.config["SAML_IDP_ENTITY_ID"],
            "singleSignOnService": {
                "url": app.config["SAML_IDP_SSO_URL"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": "".join(app.config["SAML_IDP_X509CERT"].split()),
        },
        "security": {
            "authnRequestsSigned": False,
            "logoutRequestSigned": False,
            "logoutResponseSigned": False,
            "wantAssertionsSigned": True,
            "wantMessagesSigned": False,
            "wantNameId": True,
            "wantAttributeStatement": False,
        },
    }


def _prepare_saml_request_data() -> Dict:
    data = {
        "https": "on" if request.scheme == "https" else "off",
        "http_host": request.host,
        "server_port": request.environ.get("SERVER_PORT"),
        "script_name": request.path,
        "get_data": request.args.copy(),
        "post_data": request.form.copy(),
    }
    if request.query_string:
        try:
            data["query_string"] = request.query_string.decode()
        except Exception:  # pragma: no cover - defensive fallback
            data["query_string"] = ""
    return data


def _init_saml_auth():
    settings = _saml_settings()
    request_data = _prepare_saml_request_data()
    return OneLogin_Saml2_Auth(request_data, old_settings=settings)


def _normalize_email(value: str) -> str:
    return value.strip().lower()


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


def _set_user_session(user: sqlite3.Row, provider: str) -> None:
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
            CREATE TABLE IF NOT EXISTS allowed_emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                full_name TEXT,
                phone TEXT,
                is_admin INTEGER NOT NULL DEFAULT 0,
                notes TEXT
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
        ]
        existing_lists = conn.execute("SELECT COUNT(*) FROM task_lists").fetchone()[0]
        if existing_lists == 0:
            for name, position in default_lists:
                slug = slugify(name)
                conn.execute(
                    "INSERT INTO task_lists (name, slug, position) VALUES (?, ?, ?)",
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
                ("admin", generate_password_hash("ChangeMe123!"), "Ranch Admin"),
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
    task_counts: Dict[int, int] = {row["list_id"]: row["total"] for row in task_counts_query}
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
        "dashboard/index.html",
        recent_files=recent_files,
        task_summary=task_summary,
        calendar_embeds=app.config.get("CALENDAR_EMBEDS", []),
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


@app.route("/admin/access", methods=["GET", "POST"])
@admin_required
def manage_users():
    if request.method == "POST":
        action = request.form.get("action", "create")
        email_input = _normalize_email(request.form.get("email", ""))
        full_name = request.form.get("full_name", "").strip() or None
        phone = request.form.get("phone", "").strip() or None
        notes = request.form.get("notes", "").strip() or None
        is_admin = 1 if request.form.get("is_admin") == "on" else 0

        if action == "delete":
            entry_id = request.form.get("entry_id", "").strip()
            if not entry_id.isdigit():
                flash("Unable to determine which email to remove.", "danger")
            else:
                with get_db_connection() as conn:
                    conn.execute("DELETE FROM allowed_emails WHERE id = ?", (int(entry_id),))
                    conn.commit()
                flash("Access removed for that address.", "info")
            return redirect(url_for("manage_users"))

        if not email_input or "@" not in email_input:
            flash("Please provide a valid email address.", "warning")
            return redirect(url_for("manage_users"))

        if action == "update":
            entry_id = request.form.get("entry_id", "").strip()
            if not entry_id.isdigit():
                flash("Unable to determine which email to update.", "danger")
                return redirect(url_for("manage_users"))
            with get_db_connection() as conn:
                conn.execute(
                    """
                    UPDATE allowed_emails
                    SET email = ?, full_name = ?, phone = ?, notes = ?, is_admin = ?
                    WHERE id = ?
                    """,
                    (email_input, full_name, phone, notes, is_admin, int(entry_id)),
                )
                conn.commit()
                conn.execute(
                    """
                    UPDATE users
                    SET full_name = COALESCE(?, full_name),
                        email = COALESCE(?, email),
                        phone = COALESCE(?, phone),
                        is_admin = CASE WHEN ? = 1 THEN 1 ELSE is_admin END
                    WHERE email = ?
                    """,
                    (full_name, email_input, phone, is_admin, email_input),
                )
                conn.commit()
            flash("Access details updated.", "success")
            return redirect(url_for("manage_users"))

        # default: create/update entry
        with get_db_connection() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO allowed_emails (email, full_name, phone, notes, is_admin)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (email_input, full_name, phone, notes, is_admin),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                flash("That email address is already authorized.", "warning")
                return redirect(url_for("manage_users"))
        flash("Team member authorized. They can now sign in with Google Workspace.", "success")
        return redirect(url_for("manage_users"))

    with get_db_connection() as conn:
        allowed = conn.execute(
            """
            SELECT id, email, full_name, phone, notes, is_admin
            FROM allowed_emails
            ORDER BY COALESCE(NULLIF(full_name, ''), email)
            """
        ).fetchall()
    return render_template("admin/manage_users.html", allowed=allowed)


@app.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    if session.get("auth_provider") != "local":
        abort(403)
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
            if not user or not user["password_hash"]:
                flash("Password authentication is not available for this account.", "danger")
                return redirect(url_for("dashboard"))
            if not check_password_hash(user["password_hash"], current_password):
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
        if not username or not password:
            flash("Please provide both username and password.", "warning")
            return redirect(url_for("login"))
        with get_db_connection() as conn:
            user = conn.execute(
                """
                SELECT id, username, password_hash, is_admin, full_name, email
                FROM users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()
        if user and user["password_hash"] and check_password_hash(user["password_hash"], password):
            _set_user_session(user, provider="local")
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")
        return redirect(url_for("login"))
    return render_template(
        "auth/login.html",
        saml_ready=_saml_enabled(),
    )


@app.route("/auth/saml/login")
def auth_saml_login():
    try:
        auth = _init_saml_auth()
    except RuntimeError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("login"))

    return redirect(auth.login())


@app.route("/auth/saml/acs", methods=["POST"])
def auth_saml_acs():
    try:
        auth = _init_saml_auth()
    except RuntimeError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("login"))

    auth.process_response()
    errors = auth.get_errors()
    if errors:
        flash(", ".join(errors) or "The identity provider rejected the request.", "danger")
        return redirect(url_for("login"))
    if not auth.is_authenticated():
        flash("We couldn't verify your Google Workspace login.", "danger")
        return redirect(url_for("login"))

    attributes = auth.get_attributes()
    nameid = auth.get_nameid() or ""
    email = _normalize_email(nameid)
    if not email:
        email_attrs = attributes.get("email") or attributes.get("Email")
        if email_attrs:
            email = _normalize_email(email_attrs[0])
    if not email:
        flash("Your Google Workspace identity must include an email address.", "danger")
        return redirect(url_for("login"))

    with get_db_connection() as conn:
        allowed = conn.execute(
            "SELECT id, full_name, phone, is_admin FROM allowed_emails WHERE email = ?",
            (email,),
        ).fetchone()
    if allowed is None:
        flash("That email address hasn't been authorized yet. Please ask the admin for access.", "danger")
        return redirect(url_for("login"))

    full_name = allowed["full_name"] or attributes.get("displayName", [None])[0]
    with get_db_connection() as conn:
        existing = conn.execute(
            "SELECT id, username, full_name, email, phone, is_admin FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if existing:
            conn.execute(
                """
                UPDATE users
                SET full_name = ?, phone = COALESCE(?, phone), google_sub = ?, username = ?, email = ?,
                    is_admin = CASE WHEN ? = 1 THEN 1 ELSE is_admin END
                WHERE id = ?
                """,
                (
                    full_name or existing["full_name"],
                    allowed["phone"],
                    nameid,
                    email,
                    email,
                    int(allowed["is_admin"]),
                    existing["id"],
                ),
            )
            conn.commit()
            user = conn.execute(
                "SELECT id, username, full_name, email, is_admin FROM users WHERE id = ?",
                (existing["id"],),
            ).fetchone()
        else:
            cursor = conn.execute(
                """
                INSERT INTO users (username, full_name, email, phone, is_admin, google_sub)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    email,
                    full_name,
                    email,
                    allowed["phone"],
                    int(allowed["is_admin"]),
                    nameid,
                ),
            )
            conn.commit()
            user = conn.execute(
                "SELECT id, username, full_name, email, is_admin FROM users WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()

    _set_user_session(user, provider="saml")
    session["display_name"] = full_name or session.get("display_name")
    session["saml_nameid"] = nameid
    session["saml_session_index"] = auth.get_session_index()
    flash("Signed in with Google Workspace.", "success")
    return redirect(url_for("dashboard"))


@app.route("/auth/saml/metadata")
def saml_metadata():
    try:
        settings = OneLogin_Saml2_Settings(_saml_settings(), None)
    except RuntimeError as exc:
        return make_response(str(exc), 500)

    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    if errors:
        return make_response("; ".join(errors), 500)

    response = make_response(metadata, 200)
    response.headers["Content-Type"] = "application/samlmetadata+xml"
    return response


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


@app.route("/tasks/<int:task_id>/move", methods=["POST"])
@login_required
def move_task(task_id: int):
    list_id_raw = request.form.get("list_id", "").strip()
    if not list_id_raw.isdigit():
        flash("That list is not available.", "danger")
        return redirect(url_for("tasks_board"))

    list_id = int(list_id_raw)
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
            (list_id, task_list["slug"], max_position + 1, task_id),
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


@app.route("/tasks/lists/<int:list_id>/rename", methods=["POST"])
@login_required
def rename_task_list(list_id: int):
    name = request.form.get("name", "").strip()
    if not name:
        flash("List names cannot be empty.", "warning")
        return redirect(url_for("tasks_board"))

    with get_db_connection() as conn:
        current = conn.execute(
            "SELECT slug FROM task_lists WHERE id = ?",
            (list_id,),
        ).fetchone()
        if current is None:
            flash("That list could not be found.", "danger")
            return redirect(url_for("tasks_board"))
        base_slug = slugify(name)
        slug = current["slug"] if current["slug"] == base_slug else _ensure_unique_list_slug(conn, base_slug)
        conn.execute(
            "UPDATE task_lists SET name = ?, slug = ? WHERE id = ?",
            (name, slug, list_id),
        )
        conn.execute(
            "UPDATE tasks SET status = ? WHERE list_id = ?",
            (slug, list_id),
        )
        conn.commit()

    flash("List updated.", "success")
    return redirect(url_for("tasks_board"))


@app.route("/tasks/lists/<int:list_id>/delete", methods=["POST"])
@login_required
def delete_task_list(list_id: int):
    with get_db_connection() as conn:
        total_lists = conn.execute("SELECT COUNT(*) FROM task_lists").fetchone()[0]
        if total_lists <= 1:
            flash("Keep at least one list on the board.", "warning")
            return redirect(url_for("tasks_board"))

        existing = conn.execute(
            "SELECT id FROM task_lists WHERE id = ?",
            (list_id,),
        ).fetchone()
        if existing is None:
            flash("That list could not be found.", "danger")
            return redirect(url_for("tasks_board"))

        has_tasks = conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE list_id = ?",
            (list_id,),
        ).fetchone()[0]
        if has_tasks:
            flash("Move or archive the tasks before deleting this list.", "danger")
            return redirect(url_for("tasks_board"))

        conn.execute("DELETE FROM task_lists WHERE id = ?", (list_id,))
        conn.commit()

    flash("List removed.", "info")
    return redirect(url_for("tasks_board"))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8081, debug=True)
