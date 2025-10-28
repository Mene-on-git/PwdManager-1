document.addEventListener('DOMContentLoaded', () => {
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