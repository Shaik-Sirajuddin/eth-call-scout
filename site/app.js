const slides = [...document.querySelectorAll('[data-slide]')];
const dots = [...document.querySelectorAll('[data-go-to]')];
const current = document.querySelector('[data-slide-current]');
let activeSlide = 0;

function showSlide(index) {
  if (!slides.length) return;
  activeSlide = (index + slides.length) % slides.length;
  slides.forEach((slide, i) => {
    const active = i === activeSlide;
    slide.classList.toggle('active', active);
    slide.setAttribute('aria-hidden', String(!active));
  });
  dots.forEach((dot, i) => {
    const active = i === activeSlide;
    dot.classList.toggle('selected', active);
    dot.setAttribute('aria-selected', String(active));
  });
  if (current) current.textContent = String(activeSlide + 1).padStart(2, '0');
}

dots.forEach((dot) => dot.addEventListener('click', () => showSlide(Number(dot.dataset.goTo))));
document.querySelector('[data-prev]')?.addEventListener('click', () => showSlide(activeSlide - 1));
document.querySelector('[data-next]')?.addEventListener('click', () => showSlide(activeSlide + 1));
showSlide(0);

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
