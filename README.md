# PwdManager

PwdManager è una semplice applicazione Flask per gestire un vault locale di password cifrate. È pensata come progetto didattico/personale: salva le password cifrate in un database SQLite e protegge l'accesso con una master password + 2FA TOTP (Google Authenticator).

## Caratteristiche principali
- Verifica della master password con Argon2 — vedi [`LoginForm`](app.py) e la route [`login`](app.py).
- Crittografia per voce con AES‑GCM e derivazione della chiave tramite PBKDF2 — funzioni: [`derive_key`](app.py), [`encrypt`](app.py), [`decrypt`](app.py).
- 2FA TOTP per autenticazione aggiuntiva e provisioning QR — route [`setup_mfa`](app.py) e [`mfa`](app.py).
- Sessioni lato server tramite flask-session per non mettere il master key nei cookie — configurazione in [app.py](app.py).
- Interfaccia minimale con template e script JS per le operazioni principali.

## Requisiti
- Python 3.8+
- Dipendenze elencate in [requirements.txt](requirements.txt)

## Installazione rapida (sviluppo)
1. Posizionati nella cartella del progetto.
2. Crea e attiva un virtualenv:
   - Windows:
     - python -m venv venv
     - venv\Scripts\activate
   - macOS / Linux:
     - python -m venv venv
     - source venv/bin/activate
3. Installa le dipendenze:
   - pip install -r requirements.txt

## Avvio (sviluppo)
Avvia l'app in sviluppo eseguendo:
- python app.py

Note: il file principale è [app.py](app.py). In produzione disabilita il debug e usa un server WSGI.

## Come usarla
1. Apri l'app (es. http://127.0.0.1:5000) — la pagina iniziale è gestita dalla route [`login`](app.py) e dal template [templates/login.html](templates/login.html).
2. Se non esiste una master password, il primo accesso la crea.
3. Dopo il login verrai guidato alla verifica MFA tramite [`mfa`](app.py) (template [templates/mfa.html](templates/mfa.html)). Se vuoi configurare Google Authenticator, usa [`setup_mfa`](app.py) (template [templates/setup_mfa.html](templates/setup_mfa.html)) che mostra il QR.
4. Dopo autenticazione MFA, vai alla dashboard ([templates/dashboard.html](templates/dashboard.html)):
   - Aggiungi nuove voci (site, username, password).
   - Genera password casuali con il pulsante di generazione (chiamata a [`/generate_password`](app.py)); il comportamento JS è in [static/js/dashboard.js](static/js/dashboard.js).
   - Copia la password negli appunti con il pulsante "Copia" (il plaintext non viene inserito nel DOM; la chiamata server è [`/reveal_password`](app.py)).
   - Elimina voci tramite il form di eliminazione (route [`delete_password`](app.py) / `/delete/<id>`).

## File principali
- Applicazione e logica: [app.py](app.py) — vedi in particolare [`LoginForm`](app.py), [`AddPasswordForm`](app.py), [`MFAForm`](app.py), e le funzioni di crittografia [`derive_key`](app.py), [`encrypt`](app.py), [`decrypt`](app.py).
- Template:
  - [templates/login.html](templates/login.html)
  - [templates/mfa.html](templates/mfa.html)
  - [templates/setup_mfa.html](templates/setup_mfa.html)
  - [templates/dashboard.html](templates/dashboard.html)
- Static:
  - CSS: [static/styles.css](static/styles.css)
  - JS: [static/js/login.js](static/js/login.js), [static/js/dashboard.js](static/js/dashboard.js)
- Database: `passwords.db` (creato automaticamente) — schema inizializzato in [app.py](app.py).
- Session files: cartella [flask_session/](flask_session/).
- Requisiti: [requirements.txt](requirements.txt)
- Licenza: [LICENSE](LICENSE)
- Ignora file sensibili: [.gitignore](.gitignore)

## Comportamento e dettagli tecnici
- La master password è salvata come hash Argon2 (non è recuperabile).
- Per ogni voce del vault viene generato un salt e un nonce e la password viene cifrata con AES‑GCM; la chiave è derivata via PBKDF2 dallo "master key".
- La variabile TOTP secret viene generata automaticamente e aggiunta a `.env` se non presente (gestita in [app.py](app.py)).
- Le sessioni sono persistenti lato server: il valore derivato della master key viene memorizzato nella sessione in forma base64 (vedi [app.py](app.py)).

## Sicurezza & produzione
- Non lasciare `.env` o il database `passwords.db` esposti in un repository pubblico.
- Disabilita `debug=True` in produzione e usa HTTPS.
- Valuta l'uso di un backend per sessioni più robusto (es. Redis) se distribuisci l'app su più istanze.
- Proteggi e fai backup sicuro del TOTP secret se lo usi in produzione.

## Debug e note di sviluppo
- Controlla i log dell'app se incontri errori di crittografia o DB.
- Le animazioni di alert e comportamenti client sono in [static/js/login.js](static/js/login.js) e [static/js/dashboard.js](static/js/dashboard.js).
- Lo stile è gestito in [static/styles.css](static/styles.css).

## Licenza
Questo progetto è rilasciato sotto MIT License — vedi [LICENSE](LICENSE).

---
Per approfondimenti implementativi apri il file principale [app.py](app.py) e i template in [templates/](templates/).