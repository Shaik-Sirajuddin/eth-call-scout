const slides = [...document.querySelectorAll('[data-slide]')];
const dots = [...document.querySelectorAll('[data-go-to]')];
const current = document.querySelector('[data-slide-current]');
const carousel = document.querySelector('[data-carousel]');
const carouselStage = carousel?.querySelector('.carousel-stage');
const carouselTrack = carousel?.querySelector('[data-track]');
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
let activeSlide = 1;
let autoDirection = -1;
let autoplayTimer;

function centerActiveSlide() {
  const slide = slides[activeSlide];
  if (!slide || !carouselStage || !carouselTrack) return;
  const offset = (carouselStage.clientWidth - slide.offsetWidth) / 2 - slide.offsetLeft;
  carouselTrack.style.transform = `translate3d(${offset}px, 0, 0)`;
}

function showSlide(index) {
  if (!slides.length) return;
  activeSlide = (index + slides.length) % slides.length;
  slides.forEach((slide, i) => {
    const active = i === activeSlide;
    slide.classList.toggle('active', active);
    slide.setAttribute('aria-hidden', String(!active));
    slide.inert = !active;
  });
  dots.forEach((dot, i) => {
    const active = i === activeSlide;
    dot.classList.toggle('selected', active);
    dot.setAttribute('aria-selected', String(active));
  });
  if (current) current.textContent = String(activeSlide + 1).padStart(2, '0');
  requestAnimationFrame(centerActiveSlide);
}

function stopAutoplay() {
  window.clearInterval(autoplayTimer);
  autoplayTimer = undefined;
}

function startAutoplay() {
  stopAutoplay();
  if (reducedMotion || slides.length < 2 || document.hidden) return;
  autoplayTimer = window.setInterval(() => {
    if (activeSlide === slides.length - 1) autoDirection = -1;
    if (activeSlide === 0) autoDirection = 1;
    showSlide(activeSlide + autoDirection);
  }, 4800);
}

dots.forEach((dot) => dot.addEventListener('click', () => showSlide(Number(dot.dataset.goTo))));
document.querySelector('[data-prev]')?.addEventListener('click', () => { autoDirection = -1; showSlide(activeSlide - 1); });
document.querySelector('[data-next]')?.addEventListener('click', () => { autoDirection = 1; showSlide(activeSlide + 1); });
carousel?.addEventListener('pointerenter', stopAutoplay);
carousel?.addEventListener('pointerleave', startAutoplay);
carousel?.addEventListener('focusin', stopAutoplay);
carousel?.addEventListener('focusout', (event) => {
  if (!carousel.contains(event.relatedTarget)) startAutoplay();
});
document.addEventListener('visibilitychange', () => document.hidden ? stopAutoplay() : startAutoplay());
window.addEventListener('resize', centerActiveSlide, { passive: true });
showSlide(activeSlide);
startAutoplay();

const menuToggle = document.querySelector('[data-menu-toggle]');
const mobileNav = document.querySelector('[data-mobile-nav]');
menuToggle?.addEventListener('click', () => {
  const open = menuToggle.getAttribute('aria-expanded') !== 'true';
  menuToggle.setAttribute('aria-expanded', String(open));
  mobileNav?.classList.toggle('open', open);
});
mobileNav?.querySelectorAll('a').forEach((link) => link.addEventListener('click', () => {
  menuToggle?.setAttribute('aria-expanded', 'false');
  mobileNav.classList.remove('open');
}));

document.querySelectorAll('[data-copy-code]').forEach((button) => button.addEventListener('click', async () => {
  const code = button.closest('.guide-code')?.querySelector('code')?.innerText ?? '';
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(code);
    button.textContent = 'Copied';
  } catch {
    button.textContent = 'Copy unavailable';
  }
  window.setTimeout(() => { button.textContent = original; }, 1400);
}));
