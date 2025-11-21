document.addEventListener('DOMContentLoaded', () => {
    const genBtn = document.getElementById('btn-generate');
    const toggleGenBtn = document.getElementById('btn-toggle-gen');
    const genInput = document.getElementById('genpw');
    const genIcon = document.getElementById('toggle-gen-icon');
    const container = document.querySelector('.container') || document.body;
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';

    function showToast(message, category = 'success', timeout = 3000) {
        const toast = document.createElement('div');
        toast.className = `alert alert-${category}`;
        toast.textContent = message;
        container.insertBefore(toast, container.firstChild);

        requestAnimationFrame(() => {
            toast.style.transition = 'opacity 0.35s ease, max-height 0.35s ease';
            toast.style.opacity = '1';
            toast.style.maxHeight = toast.scrollHeight + 'px';
        });
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.maxHeight = '0';
            setTimeout(() => toast.remove(), 400);
        }, timeout);
    }

    if (genBtn) {
        genBtn.addEventListener('click', async () => {
            try {
                const r = await fetch('/generate_password', { credentials: 'same-origin' });
                if (!r.ok) {
                    showToast('Errore nella generazione della password.', 'danger');
                    return;
                }
                const pw = await r.text();
                genInput.value = pw;
                genInput.type = 'password';
                if (genIcon) genIcon.textContent = '👁️';
            } catch (e) {
                showToast('Errore nella generazione della password.', 'danger');
            }
        });
    }

    if (toggleGenBtn) {
        toggleGenBtn.addEventListener('click', () => {
            if (!genInput) return;
            if (genInput.type === 'password') {
                genInput.type = 'text';
                if (genIcon) genIcon.textContent = '🙈';
            } else {
                genInput.type = 'password';
                if (genIcon) genIcon.textContent = '👁️';
            }
        });
    }

    // copia password: NON inserire il plaintext nel DOM.
    document.querySelectorAll('.btn-copy').forEach(btn => {
        btn.addEventListener('click', async () => {
            const id = btn.dataset.id;
            if (!id) return;

            try {
                const res = await fetch('/reveal_password', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken
                    },
                    body: JSON.stringify({ id })
                });

                if (!res.ok) {
                    if (res.status === 401) showToast('Non autorizzato. Effettua il login/MFA.', 'danger');
                    else if (res.status === 404) showToast('Voce non trovata.', 'warning');
                    else showToast('Errore durante il recupero della password.', 'danger');
                    return;
                }

                const data = await res.json();
                const pwd = data.password;
                if (!pwd) {
                    showToast('Errore: password non disponibile', 'danger');
                    return;
                }

                // copia senza esporre il testo nel DOM
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    await navigator.clipboard.writeText(pwd);
                } else {
                    const ta = document.createElement('textarea');
                    ta.value = pwd;
                    ta.style.position = 'fixed';
                    ta.style.left = '-9999px';
                    document.body.appendChild(ta);
                    ta.select();
                    document.execCommand('copy');
                    ta.remove();
                }

                showToast('Password copiata negli appunti', 'success');
            } catch (err) {
                showToast('Errore durante la copia', 'danger');
            }
        });
    });

    // Auto-dismiss alerts già presenti nella pagina: fade out dopo 5s
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(a => {
        a.style.opacity = '1';
        a.style.maxHeight = a.scrollHeight + 'px';
        setTimeout(() => {
            a.style.transition = 'opacity 0.5s ease, max-height 0.5s ease';
            a.style.opacity = '0';
            a.style.maxHeight = '0';
            setTimeout(() => a.remove(), 600);
        }, 5000);
    });
});

// conferma eliminazione password tramite toast inline (tema dark)
document.querySelectorAll('.form-delete').forEach(form => {
    form.addEventListener('submit', function(e) {
        e.preventDefault();

        if (form.querySelector('.inline-toast')) return;

        const row = form.closest('tr');
        const toast = document.createElement('div');
        toast.className = 'alert inline-toast d-flex justify-content-between align-items-center';
        toast.style.marginTop = '5px';
        toast.style.opacity = '0';
        toast.style.maxHeight = '0';
        toast.style.transition = 'opacity 0.35s ease, max-height 0.35s ease';
        toast.innerHTML = `
            <span>Sei sicuro di voler eliminare questa password?</span>
            <div>
                <button class="btn btn-sm btn-danger me-2">Sì</button>
                <button class="btn btn-sm btn-secondary">No</button>
            </div>
        `;

        row.parentNode.insertBefore(toast, row.nextSibling);

        requestAnimationFrame(() => {
            toast.style.opacity = '1';
            toast.style.maxHeight = toast.scrollHeight + 'px';
        });

        const yesBtn = toast.querySelector('button.btn-danger');
        const noBtn = toast.querySelector('button.btn-secondary');

        yesBtn.addEventListener('click', () => {
            form.submit();
        });

        noBtn.addEventListener('click', () => {
            toast.style.opacity = '0';
            toast.style.maxHeight = '0';
            setTimeout(() => toast.remove(), 400);
        });
    });
});

// Override dei pulsanti "Elimina" per usare toast di conferma overlay
document.querySelectorAll('form[action^="/delete/"]').forEach(form => {
    const btn = form.querySelector('button[type="submit"]');
    if (!btn) return;

    btn.addEventListener('click', (e) => {
        e.preventDefault(); // blocca submit

        // Evita più toast per lo stesso form
        if (form.querySelector('.confirm-toast')) return;

        // Crea overlay semitrasparente
        const overlay = document.createElement('div');
        overlay.style.position = 'fixed';
        overlay.style.top = 0;
        overlay.style.left = 0;
        overlay.style.width = '100%';
        overlay.style.height = '100%';
        overlay.style.background = 'rgba(0,0,0,0.4)';
        overlay.style.zIndex = 9998;

        // Toast vero e proprio
        const toast = document.createElement('div');
        toast.className = 'alert alert-warning confirm-toast';
        toast.style.position = 'absolute';
        toast.style.zIndex = 9999;
        toast.style.minWidth = '220px';
        toast.style.padding = '10px 14px';
        toast.style.borderRadius = '6px';
        toast.style.fontSize = '0.9em';
        toast.style.display = 'flex';
        toast.style.alignItems = 'center';
        toast.style.justifyContent = 'space-between';
        toast.style.flexWrap = 'wrap';
        toast.style.gap = '6px';
        toast.style.backgroundColor = '#f57f17';
        toast.style.color = '#000';
        toast.style.boxShadow = '0 4px 12px rgba(0,0,0,0.3)';
        toast.textContent = 'Sei sicuro di voler eliminare questa password?';

        const yesBtn = document.createElement('button');
        yesBtn.className = 'btn btn-sm btn-danger';
        yesBtn.textContent = 'Sì';

        const noBtn = document.createElement('button');
        noBtn.className = 'btn btn-sm btn';
        noBtn.textContent = 'No';

        toast.appendChild(yesBtn);
        toast.appendChild(noBtn);
        document.body.appendChild(overlay);
        document.body.appendChild(toast);

        // Posiziona sopra il pulsante, centrato orizzontalmente rispetto alla riga
        function positionToast() {
            const rect = btn.getBoundingClientRect();
            const scrollTop = window.scrollY || document.documentElement.scrollTop;
            const scrollLeft = window.scrollX || document.documentElement.scrollLeft;
            
            toast.style.top = (rect.top + scrollTop - toast.offsetHeight - 8) + 'px';
            toast.style.left = (rect.left + scrollLeft + rect.width / 2 - toast.offsetWidth / 2) + 'px';
        }

        positionToast();
        window.addEventListener('resize', positionToast);
        window.addEventListener('scroll', positionToast);

        requestAnimationFrame(() => {
            toast.style.opacity = '1';
            toast.style.transform = 'translateY(0)';
        });

        const timeoutId = setTimeout(() => {
            toast.remove();
            overlay.remove();
        }, 6000);

        noBtn.addEventListener('click', () => {
            clearTimeout(timeoutId);
            toast.remove();
            overlay.remove();
        });

        yesBtn.addEventListener('click', () => {
            clearTimeout(timeoutId);
            form.submit();
        });
    });
});
