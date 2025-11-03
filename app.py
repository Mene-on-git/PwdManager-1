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
# Carica variabili d'ambiente dal file .env (se presente).
load_dotenv()
app = Flask(__name__)

# Chiave segreta per sessioni e CSRF (se non esiste, ne genera una e la salva nel file .env)
# Nota: qui si assegna SECRET_KEY con il valore di env o con un valore generato.
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY") or secrets.token_urlsafe(32)
if not os.getenv("SECRET_KEY"):
    with open(".env", "a") as f:
        f.write(f"\nSECRET_KEY={app.config['SECRET_KEY']}")

# Session lato server per non mettere segreti nel cookie firmato
# Qui si configura Flask-Session per memorizzare le sessioni su filesystem.
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.getcwd(), 'flask_session')
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Inizializza estensioni Flask: sessione, CSRF e il verificatore Argon2 per la master password.
Session(app)
csrf = CSRFProtect(app)
ph = PasswordHasher()

# MFA - se non esiste, ne genera uno e lo salva nel file .env
# TOTP_SECRET è la secret usata per generare i codici TOTP (Google Authenticator, ecc).
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
    # Inizializza il database SQLite se non esiste, crea tabelle master e vault.
    # Se ci sono vecchie versioni della tabella master senza la colonna 'salt', tenta di aggiungerla.
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
        # Se la colonna non esiste, viene aggiunta. Operazione compatibile con DB preesistenti.
        c.execute("ALTER TABLE master ADD COLUMN salt BLOB")
        conn.commit()
    conn.close()

init_db()

# === CRITTOGRAFIA ===
# Deriva una chiave AES-256. 'password' può essere str o bytes (usato come input per PBKDF2HMAC).
def derive_key(password, salt: bytes) -> bytes:
    # Se l'input è stringa viene convertito in bytes.
    if isinstance(password, str):
        password_bytes = password.encode()
    else:
        password_bytes = password
    # PBKDF2HMAC con SHA256: genera una chiave lunga 32 byte (AES-256) usando il salt e iterations specificate.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    # derive() produce la chiave crittografica a partire dalla password/secret
    return kdf.derive(password_bytes)

# Cripta password con AES-GCM usando la master key derivata.
# master_key può essere str o bytes (usato come input per derive_key con salt per entry)
def encrypt(password: str, master_key) -> tuple:
    # Genera un salt unico per questa voce (usato come salt nella derivazione della chiave)
    salt = os.urandom(16)
    # Nonce per AES-GCM (12 byte consigliati)
    nonce = os.urandom(12)
    # Deriva la chiave AES a partire dalla master_key e dal salt generato
    key = derive_key(master_key, salt)
    aesgcm = AESGCM(key)
    # cifra la password (associata a nessun dato aggiuntivo)
    ciphertext = aesgcm.encrypt(nonce, password.encode(), None)
    # Restituisce il ciphertext, il nonce e il salt necessari per decriptare in seguito
    return ciphertext, nonce, salt

# Decripta password con AES-GCM. Ritorna stringa o un messaggio neutro se fallisce.
def decrypt(ciphertext: bytes, nonce: bytes, salt: bytes, master_key) -> str:
    try:
        # Deriva la stessa chiave usata in encrypt partendo dalla master_key e dal salt salvato
        key = derive_key(master_key, salt)
        aesgcm = AESGCM(key)
        # Decripta e ritorna il plaintext in formato stringa
        return aesgcm.decrypt(nonce, ciphertext, None).decode()
    except Exception:
        # In caso di errore (chiave sbagliata, tampering, dati corrotti) ritorna una stringa indicativa
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
    # Route di login che gestisce sia la creazione della master password (al primo avvio)
    # sia la verifica della master password esistente.
    form = LoginForm()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Recupera l'hash della master password e il salt salvato (se esistono)
    c.execute("SELECT password_hash, salt FROM master LIMIT 1")
    result = c.fetchone()
    conn.close()

    if form.validate_on_submit():
        pw = form.password.data
        # Se non esiste master password, la crea (salva anche un salt)
        if result is None:
            # Crea hash Argon2 della password e genera un salt per l'uso nella derivazione delle chiavi
            hash_pw = ph.hash(pw)
            master_salt = os.urandom(16)
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            # Salva hash e salt nella tabella master
            c.execute("INSERT INTO master (password_hash, salt) VALUES (?, ?)", (hash_pw, master_salt))
            conn.commit()
            conn.close()
            flash("Master password creata!", "success")
            # Deriva la chiave dalla password appena creata e la salva nella sessione (base64-encoded)
            derived_key = derive_key(pw, master_salt)
            session.permanent = True
            session['master_key'] = base64.b64encode(derived_key).decode()
            # Dopo la creazione guidiamo direttamente alla configurazione MFA
            session['mfa_ok'] = False
            return redirect(url_for('setup_mfa'))
        else:
            try:
                # Se esiste un record master, verifica la password con Argon2
                stored_hash, stored_salt = result[0], result[1]
                ph.verify(stored_hash, pw)
            except Exception:
                # Se la verifica fallisce, notifica l'utente
                flash("Master password errata.", "danger")
                return redirect(url_for('login'))

            # Se la verifica riesce, deriva la chiave e la salva in sessione
            derived_key = derive_key(pw, stored_salt)
            session.permanent = True
            session['master_key'] = base64.b64encode(derived_key).decode()

        # Dopo il login la MFA non è ancora stata verificata: imposta mfa_ok a False
        session['mfa_ok'] = False
        return redirect(url_for('dashboard'))

    # Mostra la pagina di login; pw=True se esiste già una master password (per UI)
    return render_template('login.html', form=form, pw=result is not None)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    # Dashboard principale che mostra le voci del vault decriptate per l'utente autenticato.
    if 'master_key' not in session:
        return redirect(url_for('login'))
    if not session.get('mfa_ok'):
        # Se MFA non è stata verificata, reindirizza alla pagina di MFA
        return redirect(url_for('mfa'))

    form = AddPasswordForm()
    # Recupera la chiave derivata dalla sessione (base64 -> bytes)
    master_key = base64.b64decode(session['master_key'])

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Supporta l'inserimento diretto dalla dashboard (form POST)
    if form.validate_on_submit():
        site = form.site.data
        username = form.username.data
        password = form.password.data

        ciphertext, nonce, salt = encrypt(password, master_key)
        c.execute("INSERT INTO vault (site, username, password, nonce, salt) VALUES (?, ?, ?, ?, ?)",
                  (site, username, ciphertext, nonce, salt))
        conn.commit()
        flash("Password salvata!", "success")

    # Recupera tutte le voci salvate (i dati sensibili sono ciphertext, nonce, salt)
    c.execute("SELECT id, site, username, password, nonce, salt FROM vault")
    rows = c.fetchall()
    conn.close()

    # Decripta ogni voce per mostrarla nella UI; se decrittazione fallisce mostra il marker [DECRYPT FAILED]
    decrypted = []
    for row in rows:
        pid, site, username, pw, nonce, salt = row
        dec = decrypt(pw, nonce, salt, master_key)
        decrypted.append((pid, site, username, dec))

    # Render della dashboard con la lista delle password decriptate (usata dalla UI)
    return render_template('dashboard.html', add_form=form, passwords=decrypted)

@app.route('/add_password', methods=['POST'])
def add_password():
    # Aggiunge una voce al vault. Richiede che la sessione contenga la master_key.
    if 'master_key' not in session:
        flash("Sessione scaduta. Effettua di nuovo il login.", "warning")
        return redirect(url_for('logout'))

    form = AddPasswordForm()
    if form.validate_on_submit():
        try:
            # Recupera la master_key (derivata) dalla sessione, la decodifica da base64
            master_key = base64.b64decode(session['master_key'])
            site = form.site.data
            username = form.username.data
            password = form.password.data

            # Cripta la password con la master_key (viene generato salt e nonce specifici per la voce)
            ciphertext, nonce, salt = encrypt(password, master_key)

            # Salva i dati cifrati nel DB (ciphertext, nonce, salt)
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
            # Log dell'errore lato server e messaggio generico all'utente
            app.logger.error("Errore durante l'aggiunta della password")
            flash("Errore durante l'aggiunta della password", "danger")
    else:
        flash("Errore nei dati inseriti.", "danger")

    return redirect(url_for('dashboard'))

@app.route('/delete/<int:password_id>', methods=['POST'])
def delete_password(password_id):
    # Elimina la voce con l'id specificato dal DB
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM vault WHERE id=?", (password_id,))
    conn.commit()
    conn.close()
    flash("Password eliminata!", "info")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    # Cancella la sessione utente e reindirizza al login
    session.clear()
    flash("Logout effettuato", "info")
    return redirect(url_for('login'))

@app.route('/generate_password')
def generate_password():
    # Endpoint che genera una password casuale e la ritorna in chiaro.
    # Richiede autenticazione e MFA; altrimenti rimanda al login.
    if 'master_key' not in session or not session.get('mfa_ok'):
        return redirect(url_for('login'))

    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    pw = ''.join(secrets.choice(chars) for _ in range(20))
    return pw

@app.route('/setup_mfa')
def setup_mfa():
    # Mostra il QR code per la configurazione del TOTP (Google Authenticator).
    if 'master_key' not in session:
        return redirect(url_for('login'))

    # Crea un oggetto TOTP con la secret condivisa e genera l'URI di provisioning
    totp = pyotp.TOTP(TOTP_SECRET)
    uri = totp.provisioning_uri(name="Vault", issuer_name="SecureVault")
    # Genera un QR code PNG dall'URI e lo codifica in base64 per l'inclusione in una pagina HTML
    qr = qrcode.make(uri)
    buf = BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return render_template('setup_mfa.html', qr_b64=qr_b64)

@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    # Pagina di verifica MFA: l'utente inserisce il codice TOTP ottenuto dall'app Authenticator
    if 'master_key' not in session:
        return redirect(url_for('login'))

    form = MFAForm()
    totp = pyotp.TOTP(TOTP_SECRET)

    if form.validate_on_submit():
        token = form.token.data.strip()
        # Verifica il token TOTP usando la secret condivisa
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
    # Endpoint AJAX che ritorna la password in chiaro per una voce specificata dall'id.
    # Controlla che la sessione sia valida e che la MFA sia stata effettuata.
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
    app.run(port=5000, debug=True) #quando si usa in produzione, debug deve essere False e quando farò il server mettere host='0.0.0.0'
