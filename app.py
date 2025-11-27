# === LIBRERIE BASE ===
import base64
import os
from datetime import timedelta
from io import BytesIO
import io
import secrets
import sqlite3
import csv
import hmac

# === PACCHETTI TERZI ===
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv
import pyotp
import qrcode

# === MONDO FLASK ===
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
    Response,
    send_file,
)
from flask_session import Session
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from functools import wraps

# === FORM ===
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired


# === CONFIGURAZIONE BASE ===
load_dotenv()
app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or secrets.token_urlsafe(32)
if not os.getenv("SECRET_KEY"):
    with open(".env", "a") as f:
        f.write(f"\nSECRET_KEY={app.config['SECRET_KEY']}")

app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(os.getcwd(), "flask_session")
os.makedirs(app.config["SESSION_FILE_DIR"], exist_ok=True)
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

Session(app)
csrf = CSRFProtect(app)
ph = PasswordHasher()

TOTP_SECRET = os.getenv("TOTP_SECRET")
if not TOTP_SECRET:
    TOTP_SECRET = pyotp.random_base32()
    with open(".env", "a") as f:
        f.write(f"\nTOTP_SECRET={TOTP_SECRET}")


# === HELPERS CRYPTO / KDF ===
def kdf_pbkdf2(
    password: bytes, salt: bytes, length: int = 32, iterations: int = 390000
) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)

# Deriva una chiave di crittografia dalla master password e dal sale
def derive_key(password, salt: bytes) -> bytes:
    if isinstance(password, str):
        password_bytes = password.encode()
    else:
        password_bytes = password
    return kdf_pbkdf2(password_bytes, salt, length=32, iterations=390000)

# == HELPERS ENCRYPTION / DECRYPTION (AES-GCM) ===
def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    """AES-GCM encrypt: ritorna nonce + ciphertext"""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    """Inverse di encrypt_bytes: blob = nonce + ciphertext"""
    try:
        nonce = blob[:12]
        ct = blob[12:]
        aesgcm = AESGCM(key)
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt
    except Exception:
        raise


# === FORM ===
class LoginForm(FlaskForm):
    password = PasswordField("Master Password", validators=[DataRequired()])
    submit = SubmitField("Accedi")


class AddPasswordForm(FlaskForm):
    site = StringField("Sito", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("Aggiungi")


class MFAForm(FlaskForm):
    token = StringField("Codice MFA", validators=[DataRequired()])
    submit = SubmitField("Verifica")


class RecoveryForm(FlaskForm):
    recovery_key = StringField("Chiave di Recupero", validators=[DataRequired()])
    new_password = PasswordField("Nuova Master Password", validators=[DataRequired()])
    submit = SubmitField("Reimposta Password")


# === DATABASE ===
DB_PATH = "passwords.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # master table (leave mostly as-is)
    c.execute(
        """CREATE TABLE IF NOT EXISTS master (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        password_hash TEXT NOT NULL,
        salt BLOB
    )"""
    )
    # vault table
    c.execute(
        """CREATE TABLE IF NOT EXISTS vault (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site TEXT,
        username TEXT,
        password BLOB,
        nonce BLOB,
        salt BLOB
    )"""
    )
    # recovery: extend columns for salt, key_hash, backup (encrypted master_key)
    c.execute(
        """CREATE TABLE IF NOT EXISTS recovery (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT
    )"""
    )
    conn.commit()

    # Migrate recovery table: if missing columns, add them.
    c.execute("PRAGMA table_info(recovery)")
    rec_cols = [r[1] for r in c.fetchall()]
    # If old 'key' exists and new columns not present, we will add new columns and migrate if possible.
    if "salt" not in rec_cols:
        try:
            c.execute("ALTER TABLE recovery ADD COLUMN salt BLOB")
        except Exception:
            pass
    if "key_hash" not in rec_cols:
        try:
            c.execute("ALTER TABLE recovery ADD COLUMN key_hash BLOB")
        except Exception:
            pass
    if "backup" not in rec_cols:
        try:
            c.execute("ALTER TABLE recovery ADD COLUMN backup BLOB")
        except Exception:
            pass

    # ensure master table has salt column (you had code for this earlier)
    c.execute("PRAGMA table_info(master)")
    cols = [r[1] for r in c.fetchall()]
    if "salt" not in cols:
        try:
            c.execute("ALTER TABLE master ADD COLUMN salt BLOB")
            conn.commit()
        except Exception:
            pass

    conn.commit()
    conn.close()


init_db()


# === CRITTOGRAFIA STORAGE (compatibile con il tuo codice originale) ===
def encrypt(password: str, master_key) -> tuple:
    """
    Encrypt a single password string with a derived key.
    Returns (ciphertext, nonce, salt) matching your previous schema.
    """
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(master_key, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, password.encode(), None)
    return ciphertext, nonce, salt


def decrypt(ciphertext: bytes, nonce: bytes, salt: bytes, master_key) -> str:
    try:
        key = derive_key(master_key, salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode()
    except Exception:
        return "[DECRYPT FAILED]"


# === DECORATOR login_required ===
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Controllo master key
        if "master_key" not in session:
            flash("Sessione scaduta. Effettua nuovamente il login.", "warning")
            return redirect(url_for("login"))

        # Controllo MFA
        if not session.get("mfa_ok"):
            flash("Devi completare l'autenticazione MFA.", "warning")
            return redirect(url_for("mfa"))

        return f(*args, **kwargs)

    return decorated_function


# === ROTTE ===
@app.route("/", methods=["GET", "POST"])
def login():
    form = LoginForm()

    # --- Controllo se esiste già la master password ---
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash, salt FROM master LIMIT 1")
    result = c.fetchone()
    conn.close()

    # --- Se l'utente ha inviato il form ---
    if form.validate_on_submit():
        pw = form.password.data

        # -------------------------------------------------------
        #  PRIMO AVVIO: master password non esiste ancora
        # -------------------------------------------------------
        if result is None:
            # Genera hash e sale
            hash_pw = ph.hash(pw)
            master_salt = os.urandom(16)

            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(
                "INSERT INTO master (password_hash, salt) VALUES (?, ?)",
                (hash_pw, master_salt),
            )

            # --- Generazione Recovery Key (plaintext temporaneo) ---
            recovery_key = secrets.token_urlsafe(32)

            # Compute recovery salt + hash for verification, and also store a backup of the derived master_key encrypted with recovery key
            recovery_salt = os.urandom(16)
            # compute hash for later verification (PBKDF2)
            recovery_key_hash = kdf_pbkdf2(
                recovery_key.encode(), recovery_salt, length=32, iterations=200000
            )

            # Deriva la chiave per l'apertura del vault (master_key raw bytes)
            derived_key = derive_key(pw, master_salt)  # 32 bytes
            session.permanent = True
            session["master_key"] = base64.b64encode(derived_key).decode()
            session["mfa_ok"] = False

            # Backup del master key cifrato con una chiave derivata dalla recovery key
            recovery_enc_key = kdf_pbkdf2(
                recovery_key.encode(), recovery_salt, length=32, iterations=200000
            )
            backup_blob = encrypt_bytes(derived_key, recovery_enc_key)  # nonce + ct

            # Inserisci entry recovery (salta inserimento plaintext 'key' per compatibilità: aggiorniamo le colonne)
            # Se esiste già una row nella tabella recovery, facciamo UPDATE, altrimenti INSERT
            c.execute("SELECT id FROM recovery LIMIT 1")
            r = c.fetchone()
            if r:
                c.execute(
                    "UPDATE recovery SET key=?, salt=?, key_hash=?, backup=? WHERE id=?",
                    (
                        session["recovery_key"],
                        recovery_salt,
                        recovery_key_hash,
                        backup_blob,
                        r[0],
                    ),
                )
            else:
                c.execute(
                    "INSERT INTO recovery (key, salt, key_hash, backup) VALUES (?, ?, ?, ?)",
                    (None, recovery_salt, recovery_key_hash, backup_blob),
                )

            conn.commit()
            conn.close()

            # Salva la recovery key in sessione per mostrarla nella pagina dedicata
            session["recovery_key"] = recovery_key

            # Redirect alla pagina che obbliga a salvare la recovery key
            return redirect(url_for("first_setup_recovery"))

        # -------------------------------------------------------
        #  LOGIN NORMALE: master password già esiste
        # -------------------------------------------------------
        else:
            try:
                stored_hash, stored_salt = result[0], result[1]
                ph.verify(stored_hash, pw)
            except Exception:
                flash("Master password errata.", "danger")
                return redirect(url_for("login"))

            # login riuscito
            derived_key = derive_key(pw, stored_salt)
            session.permanent = True
            session["master_key"] = base64.b64encode(derived_key).decode()
            session["mfa_ok"] = False

            return redirect(url_for("dashboard"))

    # --- GET: carica la pagina di login ---
    return render_template("login.html", form=form, pw=result is not None)


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    form = AddPasswordForm()
    master_key = base64.b64decode(session["master_key"])

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if form.validate_on_submit():
        site = form.site.data
        username = form.username.data
        password = form.password.data
        ciphertext, nonce, salt = encrypt(password, master_key)
        c.execute(
            "INSERT INTO vault (site, username, password, nonce, salt) VALUES (?, ?, ?, ?, ?)",
            (site, username, ciphertext, nonce, salt),
        )
        conn.commit()
        flash("Password salvata!", "success")
    c.execute("SELECT id, site, username, password, nonce, salt FROM vault")
    rows = c.fetchall()
    conn.close()

    decrypted = []
    for row in rows:
        pid, site, username, pw, nonce, salt = row
        dec = decrypt(pw, nonce, salt, master_key)
        decrypted.append((pid, site, username, dec))

    return render_template("dashboard.html", add_form=form, passwords=decrypted)


@app.route("/add_password", methods=["POST"])
@login_required
def add_password():
    form = AddPasswordForm()
    if form.validate_on_submit():
        try:
            master_key = base64.b64decode(session["master_key"])
            site = form.site.data
            username = form.username.data
            password = form.password.data
            ciphertext, nonce, salt = encrypt(password, master_key)
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(
                "INSERT INTO vault (site, username, password, nonce, salt) VALUES (?, ?, ?, ?, ?)",
                (site, username, ciphertext, nonce, salt),
            )
            conn.commit()
            conn.close()
            flash("Password aggiunta con successo!", "success")
        except Exception as e:
            app.logger.error(f"Errore durante l'aggiunta della password: {e}")
            flash("Errore durante l'aggiunta della password", "danger")
    else:
        flash("Errore nei dati inseriti.", "danger")

    return redirect(url_for("dashboard"))


@app.route("/delete/<int:password_id>", methods=["POST"])
@login_required
def delete_password(password_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM vault WHERE id=?", (password_id,))
    conn.commit()
    conn.close()
    flash("Password eliminata!", "info")
    return redirect(url_for("dashboard"))


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Logout effettuato", "info")
    return redirect(url_for("login"))


@app.route("/generate_password")
@login_required
def generate_password():
    chars = (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    )
    pw = "".join(secrets.choice(chars) for _ in range(20))
    return pw


@app.route("/setup_mfa")
def setup_mfa():
    if "master_key" not in session:
        return redirect(url_for("login"))
    totp = pyotp.TOTP(TOTP_SECRET)
    uri = totp.provisioning_uri(name="Vault", issuer_name="SecureVault")
    qr = qrcode.make(uri)
    buf = BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
    return render_template("setup_mfa.html", qr_b64=qr_b64)


@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    if "master_key" not in session:
        return redirect(url_for("login"))

    form = MFAForm()
    totp = pyotp.TOTP(TOTP_SECRET)
    if form.validate_on_submit():
        token = form.token.data.strip()
        if totp.verify(token):
            session["mfa_ok"] = True
            flash("Autenticazione MFA riuscita!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Codice MFA non valido.", "danger")
    return render_template("mfa.html", form=form)


@app.route("/reveal_password", methods=["POST"])
@login_required
def reveal_password():
    if "master_key" not in session or not session.get("mfa_ok"):
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json() or {}
    pid = data.get("id")
    try:
        pid = int(pid)
    except Exception:
        return jsonify({"error": "bad_request"}), 400
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password, nonce, salt FROM vault WHERE id=?", (pid,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not_found"}), 404
    ciphertext, nonce, salt = row
    try:
        master_key = base64.b64decode(session["master_key"])
        plaintext = decrypt(ciphertext, nonce, salt, master_key)
    except Exception:
        return jsonify({"error": "decrypt_failed"}), 500
    if plaintext == "[DECRYPT FAILED]":
        return jsonify({"error": "decrypt_failed"}), 500
    return jsonify({"password": plaintext})


# === ROUTE RECOVERY KEY ===
@app.route("/recovery", methods=["GET", "POST"])
def recovery():
    form = RecoveryForm()
    if form.validate_on_submit():
        rkey = form.recovery_key.data.strip()
        new_pw = form.new_password.data

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # Pull stored salt + key_hash + backup
        c.execute("SELECT salt, key_hash, backup FROM recovery LIMIT 1")
        row = c.fetchone()

        if not row:
            flash("Chiave di recupero non valida.", "danger")
            conn.close()
            return redirect(url_for("recovery"))

        rec_salt, rec_hash, backup_blob = row
        if rec_salt is None or rec_hash is None or backup_blob is None:
            flash("Sistema di recovery non configurato correttamente.", "danger")
            conn.close()
            return redirect(url_for("recovery"))

        # Verifica recovery key confrontando il PBKDF2 hash
        try:
            derived = kdf_pbkdf2(rkey.encode(), rec_salt, length=32, iterations=200000)
        except Exception:
            flash("Errore durante la verifica della chiave di recupero.", "danger")
            conn.close()
            return redirect(url_for("recovery"))

        if not hmac.compare_digest(derived, rec_hash):
            flash("Chiave di recupero non valida.", "danger")
            conn.close()
            return redirect(url_for("recovery"))

        # Ora possiamo usare la recovery key per decifrare il backup del master_key
        try:
            rec_enc_key = kdf_pbkdf2(
                rkey.encode(), rec_salt, length=32, iterations=200000
            )
            master_key_bytes = decrypt_bytes(
                backup_blob, rec_enc_key
            )  # raw derived master key
        except Exception:
            flash("Impossibile decifrare il backup del master key.", "danger")
            conn.close()
            return redirect(url_for("recovery"))

        # Aggiorna master password e re-critta il vault con la nuova derived key
        master_salt = os.urandom(16)
        hash_pw = ph.hash(new_pw)
        c.execute(
            "UPDATE master SET password_hash=?, salt=? WHERE id=1",
            (hash_pw, master_salt),
        )

        # Deriva la nuova master key
        new_derived_key = derive_key(new_pw, master_salt)

        # Decripta e ricripta vault usando master_key_bytes (l'old derived key) per decifrare
        c.execute("SELECT id, password, nonce, salt FROM vault")
        vault_rows = c.fetchall()
        for vid, ciphertext, nonce, salt in vault_rows:
            # decrypt with old derived key (master_key_bytes)
            try:
                # master_key_bytes is raw derived key from earlier, but our encrypt/decrypt scheme expects derive_key(master_key, salt)
                # We used derived_key previously as the "master_key" argument to encrypt(), so this should work:
                plaintext = decrypt(ciphertext, nonce, salt, master_key_bytes)
            except Exception:
                plaintext = "[DECRYPT FAILED]"

            if plaintext == "[DECRYPT FAILED]":
                # if a row cannot be decrypted, leave it as-is (or optionally delete). We'll keep it unchanged.
                app.logger.warning(
                    f"Could not decrypt vault id {vid} during recovery re-encrypt. Leaving unchanged."
                )
                continue

            # re-encrypt with new derived key
            new_ct, new_nonce, new_salt = encrypt(plaintext, new_derived_key)
            c.execute(
                "UPDATE vault SET password=?, nonce=?, salt=? WHERE id=?",
                (new_ct, new_nonce, new_salt, vid),
            )

        # Rigenera nuovo backup per la nuova recovery key:
        new_recovery = secrets.token_urlsafe(32)
        new_recovery_salt = os.urandom(16)
        new_recovery_hash = kdf_pbkdf2(
            new_recovery.encode(), new_recovery_salt, length=32, iterations=200000
        )
        new_backup_blob = encrypt_bytes(
            new_derived_key,
            kdf_pbkdf2(
                new_recovery.encode(), new_recovery_salt, length=32, iterations=200000
            ),
        )

        # Aggiorna tabella recovery con nuovo hash/salt/backup (lasciamo la colonna 'key' a NULL)
        c.execute("SELECT id FROM recovery LIMIT 1")
        r = c.fetchone()
        if r:
            c.execute(
                "UPDATE recovery SET key=NULL, salt=?, key_hash=?, backup=? WHERE id=?",
                (new_recovery_salt, new_recovery_hash, new_backup_blob, r[0]),
            )
        else:
            c.execute(
                "INSERT INTO recovery (key, salt, key_hash, backup) VALUES (?, ?, ?, ?)",
                (None, new_recovery_salt, new_recovery_hash, new_backup_blob),
            )

        conn.commit()
        conn.close()

        # Salva in sessione per mostrarla nella nuova pagina la nuova recovery key in chiaro (l'utente deve salvarla)
        session["recovery_key"] = new_recovery
        flash(
            "Master password reimpostata correttamente. Conserva la nuova recovery key mostrata.",
            "success",
        )
        return redirect(url_for("show_recovery"))

    return render_template("recovery.html", form=form)


@app.route("/show_recovery", methods=["GET", "POST"])
def show_recovery():
    recovery_key = session.get("recovery_key")
    if not recovery_key:
        flash("Nessuna recovery key disponibile.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        if request.form.get("confirm_save"):
            session.pop("recovery_key", None)
            flash("Recovery key salvata correttamente!", "success")
            return redirect(url_for("login"))
        else:
            flash("Devi confermare di aver salvato la recovery key.", "danger")

    return render_template("show_recovery.html", recovery_key=recovery_key)


@app.route("/first_setup_recovery", methods=["GET", "POST"])
def first_setup_recovery():
    recovery_key = session.get("recovery_key")

    if not recovery_key:
        flash("Nessuna recovery key disponibile.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        if request.form.get("confirm_save"):
            # rimuoviamo la key dalla sessione
            session.pop("recovery_key", None)
            flash("Recovery key salvata correttamente!", "success")
            return redirect(url_for("setup_mfa"))
        else:
            flash("Devi confermare di aver salvato la recovery key.", "danger")

    return render_template("first_setup_recovery.html", recovery_key=recovery_key)


# === ROUTE EXPORT PASSWORDS ===
@app.route("/export", methods=["GET"])
@login_required
def export_page():
    return render_template("export.html")


@app.route("/export", methods=["POST"])
@login_required
def export_passwords():
    """
    Exporta le password in CSV, cifra il CSV con una chiave derivata dalla recovery key (AES-GCM),
    e restituisce un file binario (nonce + ciphertext).
    Requisiti: utente loggato (session master_key) e MFA completata (login_required gestisce).
    """
    user_key = request.form.get("recovery_key", "").strip()
    if not user_key:
        flash("Inserisci la recovery key.", "danger")
        return redirect(url_for("export_page"))

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Recupera salt + key_hash + (eventuale) backup
    c.execute("SELECT salt, key_hash FROM recovery LIMIT 1")
    row = c.fetchone()
    if not row:
        conn.close()
        flash("Sistema di recovery non configurato.", "danger")
        return redirect(url_for("export_page"))

    rec_salt, rec_hash = row
    if rec_salt is None or rec_hash is None:
        conn.close()
        flash("Sistema di recovery non configurato correttamente.", "danger")
        return redirect(url_for("export_page"))

    # Verifica recovery key (PBKDF2)
    try:
        derived = kdf_pbkdf2(user_key.encode(), rec_salt, length=32, iterations=200000)
    except Exception:
        conn.close()
        flash("Errore durante la verifica della recovery key.", "danger")
        return redirect(url_for("export_page"))

    if not hmac.compare_digest(derived, rec_hash):
        conn.close()
        flash("Recovery key non valida!", "error")
        return redirect(url_for("export_page"))

    # Recupera tutte le password dal vault e le decripta con la master_key in sessione
    c.execute("SELECT site, username, password, nonce, salt FROM vault")
    rows = c.fetchall()
    conn.close()

    master_key = base64.b64decode(session["master_key"])

    # Crea CSV in memoria
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["site", "username", "password"])
    for site, username, pw_blob, nonce, salt in rows:
        # pw_blob may be None if something went wrong; decrypt as possible
        try:
            plaintext = decrypt(pw_blob, nonce, salt, master_key)
        except Exception:
            plaintext = "[DECRYPT FAILED]"
        writer.writerow([site, username, plaintext])

    csv_bytes = output.getvalue().encode()

    # Cifra il CSV con una chiave derivata dalla recovery key (stessa derivazione usata per backup)
    rec_enc_key = kdf_pbkdf2(user_key.encode(), rec_salt, length=32, iterations=200000)
    encrypted_blob = encrypt_bytes(csv_bytes, rec_enc_key)  # nonce + ciphertext

    # Restituisci il file binario: nonce + ciphertext
    mem = BytesIO()
    mem.write(encrypted_blob)
    mem.seek(0)

    # Nome file consigliato
    filename = "passwords_encrypted.bin"

    return send_file(
        mem,
        as_attachment=True,
        download_name=filename,
        mimetype="application/octet-stream",
    )


# === ROUTE IMPORT PASSWORDS ===
@app.route("/import", methods=["GET"])
@login_required
def import_page():
    if "master_key" not in session or not session.get("mfa_ok"):
        return redirect(url_for("login"))
    return render_template("import.html")


@app.route("/import", methods=["POST"])
@login_required
def import_passwords():
    if "master_key" not in session or not session.get("mfa_ok"):
        flash("Sessione non valida. Effettua nuovamente il login.", "warning")
        return redirect(url_for("login"))

    # --- Controllo recovery key e file ---
    user_key = request.form.get("recovery_key", "").strip()
    file = request.files.get("file")

    if not file:
        flash("Nessun file selezionato.", "danger")
        return redirect(url_for("import_page"))

    # Recupero salt e hash dal DB
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT salt, key_hash FROM recovery LIMIT 1")
    row = c.fetchone()
    conn.close()

    if not row or not row[0]:
        flash("Sistema di recovery non configurato correttamente.", "danger")
        return redirect(url_for("import_page"))

    rec_salt, rec_hash = row

    # Deriva chiave dalla recovery key
    try:
        derived = kdf_pbkdf2(user_key.encode(), rec_salt, length=32, iterations=200000)
    except Exception:
        flash("Errore durante la derivazione della chiave di recovery.", "danger")
        return redirect(url_for("import_page"))

    # Verifica recovery key
    if not hmac.compare_digest(derived, rec_hash):
        flash("Recovery key non valida!", "danger")
        return redirect(url_for("import_page"))

    # --- Lettura e decifratura del file .bin ---
    try:
        encrypted_blob = file.read()  # nonce + ciphertext
        csv_bytes = decrypt_bytes(
            encrypted_blob, derived
        )  # funzione che decifra AES-GCM
        content = csv_bytes.decode("utf-8")
        reader = csv.reader(io.StringIO(content))
        header = next(reader)

        if header != ["site", "username", "password"]:
            flash("Formato CSV non valido. Intestazioni errate.", "danger")
            return redirect(url_for("import_page"))

    except Exception:
        flash("Errore nella decifratura o nella lettura del file CSV.", "danger")
        return redirect(url_for("import_page"))

    # --- Import dati nel vault ---
    master_key = base64.b64decode(session["master_key"])
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    imported = 0
    for row in reader:
        if len(row) != 3:
            continue

        site, username, pwd_plain = row
        ciphertext, nonce, salt = encrypt(pwd_plain, master_key)

        c.execute(
            """
            INSERT INTO vault (site, username, password, nonce, salt)
            VALUES (?, ?, ?, ?, ?)
        """,
            (site, username, ciphertext, nonce, salt),
        )

        imported += 1

    conn.commit()
    conn.close()

    flash(f"Import completato: {imported} password aggiunte al vault.", "success")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(port=5000, debug=True)
