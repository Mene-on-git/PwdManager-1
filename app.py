import os
import sqlite3
from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import pyotp
import qrcode
from io import BytesIO
import base64
from datetime import timedelta
from flask_session import Session

# === CONFIGURAZIONE BASE ===
load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY") or secrets.token_urlsafe(32)

# Session lato server per non mettere segreti nel cookie firmato
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

# MFA - se non esiste, ne genera uno e lo salva nel file .env
TOTP_SECRET = os.getenv("TOTP_SECRET")
if not TOTP_SECRET:
    TOTP_SECRET = pyotp.random_base32()
    with open(".env", "a") as f:
        f.write(f"\nTOTP_SECRET={TOTP_SECRET}")

class MFAForm(FlaskForm):
    token = StringField('Codice MFA', validators=[DataRequired()])
    submit = SubmitField('Verifica')

# === DATABASE ===
DB_PATH = "passwords.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # crea master con campo salt; se la tabella esiste senza salt, aggiunge la colonna
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
    conn.commit()
    # migrazione: assicurarsi che la colonna 'salt' esista (compat con DB preesistenti)
    c.execute("PRAGMA table_info(master)")
    cols = [r[1] for r in c.fetchall()]
    if 'salt' not in cols:
        c.execute("ALTER TABLE master ADD COLUMN salt BLOB")
        conn.commit()
    conn.close()

init_db()

# === CRITTOGRAFIA ===
def derive_key(password, salt: bytes) -> bytes:
    """Deriva una chiave AES-256. 'password' può essere str o bytes."""
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
    """Cripta password con AES-GCM.
       master_key può essere str o bytes (usato come input per derive_key con salt per entry)."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(master_key, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, password.encode(), None)
    return ciphertext, nonce, salt

def decrypt(ciphertext: bytes, nonce: bytes, salt: bytes, master_key) -> str:
    """Decripta password con AES-GCM. Ritorna stringa o un messaggio neutro se fallisce."""
    try:
        key = derive_key(master_key, salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode()
    except Exception:
        return "[DECRYPT FAILED]"

# === FORM ===
class LoginForm(FlaskForm):
    password = PasswordField('Master Password', validators=[DataRequired()])
    submit = SubmitField('Accedi')

class AddPasswordForm(FlaskForm):
    site = StringField('Sito', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    submit = SubmitField('Aggiungi')

# === ROTTE ===
@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash, salt FROM master LIMIT 1")
    result = c.fetchone()
    conn.close()

    if form.validate_on_submit():
        pw = form.password.data
        # Se non esiste master password, la crea (salva anche un salt)
        if result is None:
            hash_pw = ph.hash(pw)
            master_salt = os.urandom(16)
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("INSERT INTO master (password_hash, salt) VALUES (?, ?)", (hash_pw, master_salt))
            conn.commit()
            conn.close()
            flash("Master password creata!", "success")
            derived_key = derive_key(pw, master_salt)
            session.permanent = True
            session['master_key'] = base64.b64encode(derived_key).decode()
        else:
            try:
                stored_hash, stored_salt = result[0], result[1]
                ph.verify(stored_hash, pw)
            except Exception:
                flash("Master password errata.", "danger")
                return redirect(url_for('login'))

            derived_key = derive_key(pw, stored_salt)
            session.permanent = True
            session['master_key'] = base64.b64encode(derived_key).decode()

        session['mfa_ok'] = False
        return redirect(url_for('dashboard'))

    return render_template('login.html', form=form, pw=result is not None)

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
            c.execute(
                "INSERT INTO vault (site, username, password, nonce, salt) VALUES (?, ?, ?, ?, ?)",
                (site, username, ciphertext, nonce, salt)
            )
            conn.commit()
            conn.close()

            flash("Password aggiunta con successo!", "success")
        except Exception as e:
            app.logger.error("Errore durante l'aggiunta della password")
            flash("Errore durante l'aggiunta della password", "danger")
    else:
        flash("Errore nei dati inseriti.", "danger")

    return redirect(url_for('dashboard'))

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
    # richiede autenticazione e MFA
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

# assume che session['master_key'] e session['mfa_ok'] siano gestiti nel flusso di login/MFA
@app.route('/reveal_password', methods=['POST'])
def reveal_password():
    # controllo sessione e MFA
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

    # non includere ulteriori dati sensibili nella risposta
    return jsonify({'password': plaintext})


if __name__ == "__main__":
    # in produzione disabilitare debug ed usare WSGI server
    app.run(debug=True)
