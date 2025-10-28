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