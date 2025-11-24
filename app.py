# === LIBRERIE BASE ===
import base64
import os
from datetime import timedelta
from io import BytesIO
import secrets
import sqlite3

# === PACCHETTI TERZI ===
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv
import pyotp
import qrcode

# === MONDO FLASK ===
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect

# === FORM ===
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired


# === CONFIGURAZIONE BASE ===
load_dotenv()
app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY") or secrets.token_urlsafe(32)
if not os.getenv("SECRET_KEY"):
    with open(".env", "a") as f:
        f.write(f"\nSECRET_KEY={app.config['SECRET_KEY']}")

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.getcwd(), 'flask_session')
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

Session(app)
csrf = CSRFProtect(app)
ph = PasswordHasher()

TOTP_SECRET = os.getenv("TOTP_SECRET")
if not TOTP_SECRET:
    TOTP_SECRET = pyotp.random_base32()
    with open(".env", "a") as f:
        f.write(f"\nTOTP_SECRET={TOTP_SECRET}")

# === FORM ===
class LoginForm(FlaskForm):
    password = PasswordField('Master Password', validators=[DataRequired()])
    submit = SubmitField('Accedi')

class AddPasswordForm(FlaskForm):
    site = StringField('Sito', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    submit = SubmitField('Aggiungi')

class MFAForm(FlaskForm):
    token = StringField('Codice MFA', validators=[DataRequired()])
    submit = SubmitField('Verifica')

class RecoveryForm(FlaskForm):
    recovery_key = StringField('Chiave di Recupero', validators=[DataRequired()])
    new_password = PasswordField('Nuova Master Password', validators=[DataRequired()])
    submit = SubmitField('Reimposta Password')

# === DATABASE ===
DB_PATH = "passwords.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS master (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        password_hash TEXT NOT NULL,
        salt BLOB
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS vault (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site TEXT,
        username TEXT,
        password BLOB,
        nonce BLOB,
        salt BLOB
    )""")
    # === RECOVERY KEY ===
    c.execute("""CREATE TABLE IF NOT EXISTS recovery (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL
    )""")
    conn.commit()
    c.execute("PRAGMA table_info(master)")
    cols = [r[1] for r in c.fetchall()]
    if 'salt' not in cols:
        c.execute("ALTER TABLE master ADD COLUMN salt BLOB")
        conn.commit()
    conn.close()

init_db()

# === CRITTOGRAFIA ===
def derive_key(password, salt: bytes) -> bytes:
    if isinstance(password, str):
        password_bytes = password.encode()
    else:
        password_bytes = password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return kdf.derive(password_bytes)

def encrypt(password: str, master_key) -> tuple:
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

# === ROTTE ===
@app.route('/', methods=['GET', 'POST'])
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
            c.execute("INSERT INTO master (password_hash, salt) VALUES (?, ?)", (hash_pw, master_salt))

            # --- Generazione Recovery Key ---
            recovery_key = secrets.token_urlsafe(32)
            c.execute("INSERT INTO recovery (key) VALUES (?)", (recovery_key,))

            conn.commit()
            conn.close()

            # Salva la recovery key in sessione per mostrarla nella pagina dedicata
            session['recovery_key'] = recovery_key

            # Deriva la chiave per l'apertura del vault
            derived_key = derive_key(pw, master_salt)
            session.permanent = True
            session['master_key'] = base64.b64encode(derived_key).decode()
            session['mfa_ok'] = False

            # Redirect alla pagina che obbliga a salvare la recovery key
            return redirect(url_for('first_setup_recovery'))

        # -------------------------------------------------------
        #  LOGIN NORMALE: master password già esiste
        # -------------------------------------------------------
        else:
            try:
                stored_hash, stored_salt = result[0], result[1]
                ph.verify(stored_hash, pw)
            except Exception:
                flash("Master password errata.", "danger")
                return redirect(url_for('login'))

            # login riuscito
            derived_key = derive_key(pw, stored_salt)
            session.permanent = True
            session['master_key'] = base64.b64encode(derived_key).decode()
            session['mfa_ok'] = False

            return redirect(url_for('dashboard'))

    # --- GET: carica la pagina di login ---
    return render_template('login.html', form=form, pw=result is not None)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'master_key' not in session:
        return redirect(url_for('login'))
    if not session.get('mfa_ok'):
        return redirect(url_for('mfa'))

    form = AddPasswordForm()
    master_key = base64.b64decode(session['master_key'])

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if form.validate_on_submit():
        site = form.site.data
        username = form.username.data
        password = form.password.data
        ciphertext, nonce, salt = encrypt(password, master_key)
        c.execute("INSERT INTO vault (site, username, password, nonce, salt) VALUES (?, ?, ?, ?, ?)",
                  (site, username, ciphertext, nonce, salt))
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

    return render_template('dashboard.html', add_form=form, passwords=decrypted)

@app.route('/add_password', methods=['POST'])
def add_password():
    if 'master_key' not in session:
        flash("Sessione scaduta. Effettua di nuovo il login.", "warning")
        return redirect(url_for('logout'))

    form = AddPasswordForm()
    if form.validate_on_submit():
        try:
            master_key = base64.b64decode(session['master_key'])
            site = form.site.data
            username = form.username.data
            password = form.password.data
            ciphertext, nonce, salt = encrypt(password, master_key)
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("INSERT INTO vault (site, username, password, nonce, salt) VALUES (?, ?, ?, ?, ?)",
                      (site, username, ciphertext, nonce, salt))
            conn.commit()
            conn.close()
            flash("Password aggiunta con successo!", "success")
        except Exception as e:
            app.logger.error("Errore durante l'aggiunta della password")
            flash("Errore durante l'aggiunta della password", "danger")
    else:
        flash("Errore nei dati inseriti.", "danger")

    return redirect(url_for('dashboard'))

@app.route('/delete/<int:password_id>', methods=['POST'])
def delete_password(password_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM vault WHERE id=?", (password_id,))
    conn.commit()
    conn.close()
    flash("Password eliminata!", "info")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logout effettuato", "info")
    return redirect(url_for('login'))

@app.route('/generate_password')
def generate_password():
    if 'master_key' not in session or not session.get('mfa_ok'):
        return redirect(url_for('login'))
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    pw = ''.join(secrets.choice(chars) for _ in range(20))
    return pw

@app.route('/setup_mfa')
def setup_mfa():
    if 'master_key' not in session:
        return redirect(url_for('login'))
    totp = pyotp.TOTP(TOTP_SECRET)
    uri = totp.provisioning_uri(name="Vault", issuer_name="SecureVault")
    qr = qrcode.make(uri)
    buf = BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
    return render_template('setup_mfa.html', qr_b64=qr_b64)

@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if 'master_key' not in session:
        return redirect(url_for('login'))

    form = MFAForm()
    totp = pyotp.TOTP(TOTP_SECRET)
    if form.validate_on_submit():
        token = form.token.data.strip()
        if totp.verify(token):
            session['mfa_ok'] = True
            flash("Autenticazione MFA riuscita!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Codice MFA non valido.", "danger")
    return render_template('mfa.html', form=form)

@app.route('/reveal_password', methods=['POST'])
def reveal_password():
    if 'master_key' not in session or not session.get('mfa_ok'):
        return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json() or {}
    pid = data.get('id')
    try:
        pid = int(pid)
    except Exception:
        return jsonify({'error': 'bad_request'}), 400
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password, nonce, salt FROM vault WHERE id=?", (pid,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'not_found'}), 404
    ciphertext, nonce, salt = row
    try:
        master_key = base64.b64decode(session['master_key'])
        plaintext = decrypt(ciphertext, nonce, salt, master_key)
    except Exception:
        return jsonify({'error': 'decrypt_failed'}), 500
    if plaintext == "[DECRYPT FAILED]":
        return jsonify({'error': 'decrypt_failed'}), 500
    return jsonify({'password': plaintext})

# === ROUTE RECOVERY KEY ===
@app.route('/recovery', methods=['GET', 'POST'])
def recovery():
    form = RecoveryForm()
    if form.validate_on_submit():
        rkey = form.recovery_key.data.strip()
        new_pw = form.new_password.data

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT key FROM recovery LIMIT 1")
        row = c.fetchone()

        if not row or row[0] != rkey:
            flash("Chiave di recupero non valida.", "danger")
            conn.close()
            return redirect(url_for('recovery'))

        # Aggiorna master password
        master_salt = os.urandom(16)
        hash_pw = ph.hash(new_pw)
        c.execute("UPDATE master SET password_hash=?, salt=? WHERE id=1", (hash_pw, master_salt))

        # Genera nuova Recovery Key
        new_recovery = secrets.token_urlsafe(32)
        c.execute("UPDATE recovery SET key=? WHERE id=1", (new_recovery,))

        # Decripta e ricripta vault
        c.execute("SELECT id, password, nonce, salt FROM vault")
        vault_rows = c.fetchall()
        derived_old_key = derive_key(new_pw, master_salt)
        for vid, ciphertext, nonce, salt in vault_rows:
            plaintext = decrypt(ciphertext, nonce, salt, derived_old_key)
            new_ct, new_nonce, new_salt = encrypt(plaintext, derived_old_key)
            c.execute("UPDATE vault SET password=?, nonce=?, salt=? WHERE id=?", (new_ct, new_nonce, new_salt, vid))

        conn.commit()
        conn.close()

        # Salva in sessione per mostrarla nella nuova pagina
        session['recovery_key'] = new_recovery
        return redirect(url_for('show_recovery'))

    return render_template('recovery.html', form=form)

@app.route('/show_recovery', methods=['GET', 'POST'])
def show_recovery():
    recovery_key = session.get('recovery_key')
    if not recovery_key:
        flash("Nessuna recovery key disponibile.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        if request.form.get('confirm_save'):
            session.pop('recovery_key', None)
            flash("Recovery key salvata correttamente!", "success")
            return redirect(url_for('login'))
        else:
            flash("Devi confermare di aver salvato la recovery key.", "danger")

    return render_template('show_recovery.html', recovery_key=recovery_key)

@app.route('/first_setup_recovery', methods=['GET', 'POST'])
def first_setup_recovery():
    recovery_key = session.get('recovery_key')

    if not recovery_key:
        flash("Nessuna recovery key disponibile.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        if request.form.get('confirm_save'):
            # rimuoviamo la key dalla sessione
            session.pop('recovery_key', None)
            flash("Recovery key salvata correttamente!", "success")
            return redirect(url_for('setup_mfa'))
        else:
            flash("Devi confermare di aver salvato la recovery key.", "danger")

    return render_template('first_setup_recovery.html', recovery_key=recovery_key)

if __name__ == "__main__":
    app.run(port=5000, debug=True)
