const scenarios = {
  safe: {
    decision: 'ALLOW',
    icon: '✓',
    block: 'BLOCK 23,804,912',
    policy: '8e4f01…c291',
    state: '11ad90…7bc2',
    trace: '0d7ac2…e810',
    explanation: 'Every deterministic check passed. The exact copied request may reach the wallet.',
    checks: [
      ['pass', 'Executable policy', 'target · selector · spender · amount'],
      ['pass', 'Authenticated live state', 'operational · 2/2 signatures · fresh'],
      ['pass', 'Full simulation quorum', '2/2 identical effect fingerprints'],
      ['pass', 'Wallet boundary', 'exact request preserved'],
    ],
  },
  compromised: {
    decision: 'DENY',
    icon: '×',
    block: 'BLOCK 23,804,917',
    policy: '8e4f01…c291',
    state: 'f3b802…019d',
    trace: '—',
    explanation: 'The target is allowlisted, but live bytecode no longer matches its monitored invariant. Simulation is unnecessary because live state already vetoed.',
    checks: [
      ['pass', 'Executable policy', 'target and method are allowlisted'],
      ['fail', 'Authenticated live state', 'runtime code hash changed · compromised'],
      ['skip', 'Full simulation quorum', 'not reached after deterministic denial'],
      ['fail', 'Wallet boundary', 'request was not forwarded'],
    ],
  },
  internal: {
    decision: 'DENY',
    icon: '×',
    block: 'BLOCK 23,804,921',
    policy: '8e4f01…c291',
    state: '11ad90…7bc2',
    trace: '7fd299…ab41',
    explanation: 'The top-level call looked valid, but both simulators observed an internal call to an unapproved contract. The wallet never received it.',
    checks: [
      ['pass', 'Executable policy', 'top-level request is bounded'],
      ['pass', 'Authenticated live state', 'operational · target bound'],
      ['fail', 'Full simulation quorum', 'hidden target 0x3333…3333'],
      ['fail', 'Wallet boundary', 'request was not forwarded'],
    ],
  },
  delegation: {
    decision: 'DENY',
    icon: '×',
    block: 'BLOCK 23,804,925',
    policy: '72c817…0a44',
    state: '11ad90…7bc2',
    trace: '—',
    explanation: 'The 7702 authorization was signed, but the delegate runtime code hash differed from the approved identity. Delegation and execution both stopped.',
    checks: [
      ['pass', 'Authorization authority', 'signer · chain · next nonce verified'],
      ['pass', 'Authenticated live state', 'operational · fresh'],
      ['fail', 'EIP-7702 delegate identity', 'runtime hash mismatch on 2/2 sources'],
      ['fail', 'Wallet boundary', 'type-4 request was not forwarded'],
    ],
  },
};

const decision = document.querySelector('[data-receipt-decision]');
const checks = document.querySelector('[data-receipt-checks]');
const explanation = document.querySelector('[data-receipt-explanation]');
const policyHash = document.querySelector('[data-policy-hash]');
const stateHash = document.querySelector('[data-state-hash]');
const traceHash = document.querySelector('[data-trace-hash]');
const receiptTime = document.querySelector('[data-receipt-time]');
const scenarioButtons = [...document.querySelectorAll('[data-scenario]')];
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function renderScenario(name) {
  const scenario = scenarios[name];
  if (!scenario || !decision || !checks) return;

  decision.classList.toggle('denied', scenario.decision === 'DENY');
  decision.querySelector('.decision-icon').textContent = scenario.icon;
  decision.querySelector('strong').textContent = scenario.decision;
  receiptTime.textContent = scenario.block;
  policyHash.textContent = scenario.policy;
  stateHash.textContent = scenario.state;
  traceHash.textContent = scenario.trace;
  explanation.textContent = scenario.explanation;

  checks.replaceChildren(...scenario.checks.map(([status, title, detail]) => {
    const row = document.createElement('div');
    row.className = `receipt-check ${status === 'pass' ? '' : status}`.trim();

    const symbol = document.createElement('span');
    symbol.className = 'check-symbol';
    symbol.textContent = status === 'pass' ? '✓' : status === 'fail' ? '×' : '–';

    const copy = document.createElement('div');
    const strong = document.createElement('strong');
    strong.textContent = title;
    const code = document.createElement('code');
    code.textContent = detail;
    copy.append(strong, document.createElement('br'), code);

    const result = document.createElement('span');
    result.className = 'check-status';
    result.textContent = status === 'pass' ? 'PASS' : status === 'fail' ? 'DENY' : 'SKIP';
    row.append(symbol, copy, result);
    return row;
  }));

  scenarioButtons.forEach((button) => button.setAttribute('aria-selected', String(button.dataset.scenario === name)));
}

scenarioButtons.forEach((button) => button.addEventListener('click', () => renderScenario(button.dataset.scenario)));
renderScenario('safe');

const tour = document.querySelector('[data-tour]');
const tourSlides = [...document.querySelectorAll('[data-tour-slide]')];
const tourDots = [...document.querySelectorAll('[data-tour-dot]')];
const tourCount = document.querySelector('[data-tour-count]');
const tourPrev = document.querySelector('[data-tour-prev]');
const tourNext = document.querySelector('[data-tour-next]');
let activeTourSlide = 0;
let tourTimer;

function showTourSlide(index) {
  if (!tourSlides.length) return;
  activeTourSlide = (index + tourSlides.length) % tourSlides.length;
  tourSlides.forEach((slide, slideIndex) => {
    const active = slideIndex === activeTourSlide;
    slide.classList.toggle('active', active);
    slide.setAttribute('aria-hidden', String(!active));
  });
  tourDots.forEach((dot, dotIndex) => {
    const active = dotIndex === activeTourSlide;
    dot.classList.toggle('active', active);
    dot.setAttribute('aria-selected', String(active));
    dot.tabIndex = active ? 0 : -1;
  });
  if (tourCount) {
    tourCount.textContent = `${String(activeTourSlide + 1).padStart(2, '0')} / ${String(tourSlides.length).padStart(2, '0')}`;
  }
}

function stopTourAutoplay() {
  window.clearInterval(tourTimer);
  tourTimer = undefined;
}

function startTourAutoplay() {
  if (reducedMotion || !tourSlides.length || tourTimer) return;
  tourTimer = window.setInterval(() => showTourSlide(activeTourSlide + 1), 7000);
}

tourPrev?.addEventListener('click', () => showTourSlide(activeTourSlide - 1));
tourNext?.addEventListener('click', () => showTourSlide(activeTourSlide + 1));
tourDots.forEach((dot) => dot.addEventListener('click', () => showTourSlide(Number(dot.dataset.tourDot))));
tour?.addEventListener('keydown', (event) => {
  if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
  event.preventDefault();
  showTourSlide(activeTourSlide + (event.key === 'ArrowRight' ? 1 : -1));
});
tour?.addEventListener('mouseenter', stopTourAutoplay);
tour?.addEventListener('mouseleave', startTourAutoplay);
tour?.addEventListener('focusin', stopTourAutoplay);
tour?.addEventListener('focusout', (event) => {
  if (!tour.contains(event.relatedTarget)) startTourAutoplay();
});
showTourSlide(0);
startTourAutoplay();

const header = document.querySelector('[data-header]');
const nav = document.querySelector('[data-nav]');
const navToggle = document.querySelector('[data-nav-toggle]');

function closeNav() {
  nav?.classList.remove('open');
  navToggle?.setAttribute('aria-expanded', 'false');
}

navToggle?.addEventListener('click', () => {
  const open = !nav.classList.contains('open');
  nav.classList.toggle('open', open);
  navToggle.setAttribute('aria-expanded', String(open));
});
nav?.querySelectorAll('a').forEach((link) => link.addEventListener('click', closeNav));
document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closeNav(); });

function updateHeader() { header?.classList.toggle('scrolled', window.scrollY > 18); }
updateHeader();
window.addEventListener('scroll', updateHeader, { passive: true });

const revealItems = [...document.querySelectorAll('.reveal')];
if (reducedMotion || !('IntersectionObserver' in window)) {
  revealItems.forEach((item) => item.classList.add('visible'));
} else {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      entry.target.classList.add('visible');
      observer.unobserve(entry.target);
    });
  }, { threshold: 0.12, rootMargin: '0px 0px -40px' });
  revealItems.forEach((item) => observer.observe(item));
}

const copyButton = document.querySelector('[data-copy]');
copyButton?.addEventListener('click', async () => {
  const label = copyButton.querySelector('span');
  const original = label.textContent;
  try {
    await navigator.clipboard.writeText(copyButton.dataset.copy);
    label.textContent = 'Copied';
  } catch {
    label.textContent = 'Copy unavailable';
  }
  window.setTimeout(() => { label.textContent = original; }, 1600);
});
