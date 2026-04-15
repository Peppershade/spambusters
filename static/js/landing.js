// Spambusters - Landing page JS

// Sticky nav background on scroll
const nav = document.getElementById('topNav');
window.addEventListener('scroll', () => {
    nav.classList.toggle('scrolled', window.scrollY > 40);
}, { passive: true });

// Scroll-reveal with IntersectionObserver
const revealEls = document.querySelectorAll('.reveal');
if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.15, rootMargin: '0px 0px -40px 0px' });
    revealEls.forEach(el => observer.observe(el));
} else {
    revealEls.forEach(el => el.classList.add('visible'));
}

// Easter egg: click the ghost
(function() {
    const ghost = document.getElementById('heroGhost');
    const audio = document.getElementById('easterEggAudio');
    let isPlaying = false;

    function spawnParticles() {
        const rect = ghost.getBoundingClientRect();
        const cx = rect.left + rect.width / 2;
        const cy = rect.top + rect.height / 2;
        const emojis = ['👻', '💀', '🔥', '✨', '⚡', '🚫', '📧', '🛡️'];
        const count = 12;

        for (let i = 0; i < count; i++) {
            const particle = document.createElement('span');
            particle.className = 'ghost-particle';
            particle.textContent = emojis[i % emojis.length];

            const angle = (i / count) * Math.PI * 2;
            const dist = 120 + Math.random() * 80;
            const tx = Math.cos(angle) * dist;
            const ty = Math.sin(angle) * dist - 40;
            const rot = (Math.random() - 0.5) * 360;

            particle.style.cssText = `
                left: ${cx - 14}px;
                top: ${cy - 14}px;
                --tx: ${tx}px;
                --ty: ${ty}px;
                --rot: ${rot}deg;
                animation-delay: ${i * 0.04}s;
            `;

            document.body.appendChild(particle);
            setTimeout(() => particle.remove(), 1400);
        }
    }

    function flashScreen() {
        const flash = document.createElement('div');
        flash.className = 'hero-flash';
        document.body.appendChild(flash);
        setTimeout(() => flash.remove(), 700);
    }

    ghost.addEventListener('click', function() {
        if (isPlaying) {
            // Stop
            audio.pause();
            audio.currentTime = 0;
            isPlaying = false;
            ghost.classList.remove('playing');
            return;
        }

        // Play
        audio.play().then(() => {
            isPlaying = true;

            // Burst animation
            ghost.classList.remove('activated', 'playing');
            void ghost.offsetWidth; // reflow
            ghost.classList.add('activated');
            spawnParticles();
            flashScreen();

            // Transition to vibing after burst
            setTimeout(() => {
                ghost.classList.remove('activated');
                ghost.classList.add('playing');
            }, 800);
        }).catch(() => {
            // Autoplay blocked — no-op
        });

        audio.onended = function() {
            isPlaying = false;
            ghost.classList.remove('playing');
        };
    });
})();
