import os
import re
import sqlite3
import uuid
import pyotp
from functools import wraps
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "database.db"
UPLOAD_FOLDER = BASE_DIR / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "488e28aff633feda7f2e9bef7aec39a6b72b60a949733831c0b7a6a569db06ec"),
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[]
)
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    return response
ALLOWED_EXTENSIONS = {
    "py", "c", "h", "cpp", "hpp", "java", "js", "ts", "html", "css",
    "json", "xml", "sql", "md", "txt", "yml", "yaml", "sh", "bat",
    "cs", "php", "go", "rs", "kt", "swift", "ipynb", "toml", "ini"
}

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db

def create_database():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                two_factor_secret TEXT,
                two_factor_enabled INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS repositories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL,
                repository_id INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_repositories_user ON repositories(user_id);
            CREATE INDEX IF NOT EXISTS idx_files_repository ON files(repository_id);
        """)

        for table, column in (
            ("users", "created_at"),
            ("users", "two_factor_secret"),
            ("users", "two_factor_enabled"),
            ("repositories", "created_at"),
            ("files", "uploaded_at"),
        ):
            existing = {
                row["name"]
                for row in db.execute(f"PRAGMA table_info({table})")
            }

            if column not in existing:
                if column == "two_factor_enabled":
                    db.execute(
                        "ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 0"
                    )
                else:
                    db.execute(
                        f"ALTER TABLE {table} ADD COLUMN {column} TEXT"
                    )

                if column in ("created_at", "uploaded_at"):
                    db.execute(
                        f"UPDATE {table} SET {column} = CURRENT_TIMESTAMP WHERE {column} IS NULL"
                    )

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Сначала войдите в аккаунт.", "info")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

def repository_or_404(db, repository_id):
    repository = db.execute("""
        SELECT r.*, u.username,
               (SELECT COUNT(*) FROM files f WHERE f.repository_id = r.id) AS file_count
        FROM repositories r JOIN users u ON u.id = r.user_id
        WHERE r.id = ?
    """, (repository_id,)).fetchone()
    if repository is None:
        abort(404)
    return repository

def owns_repository(repository):
    if repository["user_id"] != session.get("user_id"):
        abort(403)

@app.errorhandler(413)
def too_large(_error):
    flash("Файл слишком большой. Максимальный размер — 20 МБ.", "error")
    return redirect(request.referrer or url_for("index"))

@app.route("/")
def index():
    search = request.args.get("q", "").strip()
    with get_db() as db:
        query = """
            SELECT r.*, u.username,
                   (SELECT COUNT(*) FROM files f WHERE f.repository_id = r.id) AS file_count
            FROM repositories r JOIN users u ON u.id = r.user_id
        """
        params = []
        if search:
            query += " WHERE r.name LIKE ? OR r.description LIKE ? OR u.username LIKE ?"
            params = [f"%{search}%"] * 3
        query += " ORDER BY r.id DESC"
        repositories = db.execute(query, params).fetchall()
        stats = {
            "repositories": db.execute("SELECT COUNT(*) FROM repositories").fetchone()[0],
            "users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "files": db.execute("SELECT COUNT(*) FROM files").fetchone()[0],
        }
    return render_template("index.html", repositories=repositories, stats=stats, search=search)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not re.fullmatch(r"[A-Za-zА-Яа-яЁё0-9_-]{3,24}", username):
            flash("Логин: 3–24 символа, только буквы, цифры, _ и -.", "error")
        elif len(password) < 8:
            flash("Пароль должен содержать минимум 8 символов.", "error")
        else:
            try:
                with get_db() as db:
                    db.execute(
                        "INSERT INTO users (username, password) VALUES (?, ?)",
                        (username, generate_password_hash(password))
                    )
                flash("Аккаунт создан. Теперь войдите.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Этот логин уже занят.", "error")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if user and check_password_hash(user["password"], password):
            destination = request.args.get("next", "")

            if not destination.startswith("/") or destination.startswith("//"):
                destination = url_for("index")

            session.clear()

            # Если двухфакторная защита включена
            if user["two_factor_enabled"]:
                session["pending_2fa_user_id"] = user["id"]
                session["pending_2fa_next"] = destination
                return redirect(url_for("verify_2fa"))

            # Обычный вход, если 2FA не включена
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            return redirect(destination)

        flash("Неверный логин или пароль.", "error")

    return render_template("login.html")
@app.route("/verify-2fa", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def verify_2fa():
    user_id = session.get("pending_2fa_user_id")

    if not user_id:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()

        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()

        if user and user["two_factor_enabled"] and user["two_factor_secret"]:
            totp = pyotp.TOTP(user["two_factor_secret"])

            if totp.verify(code, valid_window=1):
                destination = session.pop("pending_2fa_next", url_for("index"))

                session.pop("pending_2fa_user_id", None)
                session["user_id"] = user["id"]
                session["username"] = user["username"]

                return redirect(destination)

        flash("Неверный код подтверждения.", "error")

    return render_template("verify_2fa.html")


@app.route("/setup-2fa", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per minute")
def setup_2fa():
    with get_db() as db:
        user = db.execute(
            "SELECT * FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

    if user["two_factor_enabled"]:
        flash("Двухфакторная защита уже включена.", "info")
        return redirect(url_for("index"))

    secret = user["two_factor_secret"]

    if not secret or not re.fullmatch(r"[A-Z2-7]{16,64}", secret):
        secret = pyotp.random_base32()

        with get_db() as db:
            db.execute(
                "UPDATE users SET two_factor_secret = ?, two_factor_enabled = 0 WHERE id = ?",
                (secret, user["id"])
            )

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        totp = pyotp.TOTP(secret)

        if totp.verify(code, valid_window=1):
            with get_db() as db:
                db.execute(
                    "UPDATE users SET two_factor_enabled = 1 WHERE id = ?",
                    (user["id"],)
                )

            flash("Двухфакторная защита успешно включена.", "success")
            return redirect(url_for("index"))

        flash("Неверный код. Попробуйте ещё раз.", "error")

    return render_template("setup_2fa.html", secret=secret)
@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("Вы вышли из аккаунта.", "info")
    return redirect(url_for("index"))


@app.route("/create_repository", methods=["GET", "POST"])
@login_required
def create_repository():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        if not name or len(name) > 60:
            flash("Название обязательно и должно быть не длиннее 60 символов.", "error")
        elif len(description) > 300:
            flash("Описание должно быть не длиннее 300 символов.", "error")
        else:
            with get_db() as db:
                db.execute(
                    "INSERT INTO repositories (name, description, user_id) VALUES (?, ?, ?)",
                    (name, description, session["user_id"])
                )
            flash("Репозиторий создан.", "success")
            return redirect(url_for("index"))
    return render_template("create_repository.html")

@app.route("/repository/<int:repository_id>")
def repository(repository_id):
    with get_db() as db:
        repo = repository_or_404(db, repository_id)
        files = db.execute(
            "SELECT * FROM files WHERE repository_id = ? ORDER BY id DESC",
            (repository_id,)
        ).fetchall()
    return render_template("repository.html", repository=repo, files=files)

@app.route("/upload/<int:repository_id>", methods=["POST"])
@login_required
def upload_file(repository_id):
    with get_db() as db:
        repo = repository_or_404(db, repository_id)
        owns_repository(repo)
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            flash("Сначала выберите файл.", "error")
            return redirect(url_for("repository", repository_id=repository_id))
        filename = secure_filename(uploaded.filename)
        if not filename or "." not in filename:
            flash("Не удалось определить имя или тип файла.", "error")
            return redirect(url_for("repository", repository_id=repository_id))
        extension = filename.rsplit(".", 1)[1].lower()
        if extension not in ALLOWED_EXTENSIONS:
            flash("Этот тип файла пока не поддерживается.", "error")
            return redirect(url_for("repository", repository_id=repository_id))
        stored_filename = f"{uuid.uuid4().hex}_{filename}"
        target = UPLOAD_FOLDER / stored_filename
        uploaded.save(target)
        try:
            db.execute(
                "INSERT INTO files (filename, stored_filename, repository_id) VALUES (?, ?, ?)",
                (filename, stored_filename, repository_id)
            )
        except Exception:
            target.unlink(missing_ok=True)
            raise
    flash("Файл добавлен в репозиторий.", "success")
    return redirect(url_for("repository", repository_id=repository_id))

@app.route("/download/<int:file_id>")
def download_file(file_id):
    with get_db() as db:
        file_record = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if file_record is None:
        abort(404)
    path = UPLOAD_FOLDER / file_record["stored_filename"]
    if not path.is_file():
        abort(404)
    return send_from_directory(
        UPLOAD_FOLDER, file_record["stored_filename"],
        as_attachment=True, download_name=file_record["filename"]
    )

@app.route("/delete_file/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    with get_db() as db:
        record = db.execute("""
            SELECT f.*, r.user_id FROM files f
            JOIN repositories r ON r.id = f.repository_id WHERE f.id = ?
        """, (file_id,)).fetchone()
        if record is None:
            abort(404)
        if record["user_id"] != session["user_id"]:
            abort(403)
        db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        repository_id = record["repository_id"]
    (UPLOAD_FOLDER / record["stored_filename"]).unlink(missing_ok=True)
    flash("Файл удалён.", "success")
    return redirect(url_for("repository", repository_id=repository_id))

@app.route("/delete_repository/<int:repository_id>", methods=["POST"])
@login_required
def delete_repository(repository_id):
    with get_db() as db:
        repo = repository_or_404(db, repository_id)
        owns_repository(repo)
        stored_files = db.execute(
            "SELECT stored_filename FROM files WHERE repository_id = ?", (repository_id,)
        ).fetchall()
        db.execute("DELETE FROM repositories WHERE id = ?", (repository_id,))
    for item in stored_files:
        (UPLOAD_FOLDER / item["stored_filename"]).unlink(missing_ok=True)
    flash("Репозиторий удалён.", "success")
    return redirect(url_for("index"))

@app.context_processor
def inject_globals():
    return {"current_year": __import__("datetime").datetime.now().year}

if __name__ == "__main__":
    create_database()
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
