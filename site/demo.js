const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const state = { live: false, health: null, runs: [], activeId: null, polling: null, busy: false };
const addresses = {
  wallet: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
  router: '0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9',
  unsafe: '0x0165878A594ca255338adfa4d48449f69242Eb8F',
};
const sampleTx = {
  chainId: 31337, from: addresses.wallet, to: addresses.router, value: '0', gas: '350000',
  maxFeePerGas: '10000000000', maxPriorityFeePerGas: '1000000000', nonce: '0', type: '2',
  data: '0x5a47ddc30000000000000000000000000000000000000000000000056bc75e2d63100000000000000000000000000000000000000000000000000a4c966cdd1e1600000000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8',
};

function sampleRun(scenario, index) {
  const allowed = scenario === 'safe';
  const liveDenied = scenario === 'compromised';
  const title = { safe: 'Swap 100 dUSD for at least 190 dETH to my wallet', compromised: 'Swap 80 dUSD while the router is paused', 'hidden-call': 'Swap 60 dUSD through the router with hidden unsafe mode', slippage: 'Swap 50 dUSD with an impossible minimum output' }[scenario];
  const reason = liveDenied ? 'The router pause invariant returned 1 on both authenticated monitor sources.' : scenario === 'hidden-call' ? 'Both full traces reached an internal target that the policy did not approve.' : scenario === 'slippage' ? 'The exact transaction reverted on both independent execution sources.' : 'Both full traces produced the same bounded effect fingerprint.';
  const at = `2026-11-06T10:2${index}:00.000Z`;
  const parsed = { action: 'swapExactTokensForTokens', tokenIn: 'dUSD', tokenOut: 'dETH', amountIn: `${100 - index * 10}000000000000000000`, minimumOut: '190000000000000000000', recipient: addresses.wallet, summary: title };
  const protocolData = { sequence: 41 + index, signatures: ['operations', 'security'], blockNumber: 18, evidence: [{ source: 'anvil-primary', status: liveDenied ? 'compromised' : 'operational', blockNumber: 18 }, { source: 'anvil-secondary', status: liveDenied ? 'compromised' : 'operational', blockNumber: 18 }] };
  const checks = [
    { id: 'policy:chain', status: 'pass', detail: 'Chain 31337 is authorized.' },
    { id: 'policy:contract', status: 'pass', detail: 'Router and selector match executable policy.' },
    { id: 'policy:constraints', status: 'pass', detail: 'Input, minimum output, and recipient are bounded.' },
    { id: 'state:operational', status: liveDenied ? 'deny' : 'pass', detail: liveDenied ? reason : 'Threshold-signed state is fresh and operational.' },
    { id: 'simulation:quorum', status: allowed ? 'pass' : liveDenied ? 'skip' : 'deny', detail: liveDenied ? 'Not reached after live-state veto.' : reason },
  ];
  const simulation = liveDenied ? null : {
    blockNumber: 18, blockHash: '0x79af65f1967e0c8a0f3deff3d89791be5ad77b4dc228b9222a92b60a01284ed0',
    fingerprint: allowed ? '0x0d7a38c4834c610f822e1d6595593d84ae718a15c95d1efe4a4f152eb493e810' : null,
    agreeingSources: allowed ? ['anvil-primary', 'anvil-secondary'] : [],
    metrics: allowed ? { internalCalls: 3, maxCallDepth: 1, gasEstimate: '98392', stateAccounts: 4, storageWrites: 5, codeChanges: 0 } : null,
    failures: allowed ? [] : [{ source: 'anvil-primary', reason }, { source: 'anvil-secondary', reason }],
  };
  const events = [
    ['request', 'pass', 'Prompt received', 'The agent received a user goal, not wallet authority.', { prompt: title, scenario }],
    ['chain', 'pass', 'Dual-Anvil state restored', 'Two independent nodes began from the same deterministic snapshot.', { sources: ['anvil-primary', 'anvil-secondary'] }],
    ['agent', 'pass', 'Agent built structured intent', title, parsed],
    ['agent', 'pass', 'Exact transaction proposed', 'Calldata, fees, gas, chain, and nonce were fixed before authorization.', sampleTx],
    ['live-state', liveDenied ? 'deny' : 'pass', `Protocol ${liveDenied ? 'compromised' : 'operational'}`, liveDenied ? reason : '2-of-2 signed observations passed.', protocolData],
    ['policy', liveDenied ? 'deny' : 'pass', liveDenied ? 'Live-state invariant vetoed' : 'Executable policy passed', liveDenied ? 'No wallet call or simulation was made.' : 'All static constraints and protocol evidence passed.', { checks }],
    ['simulation', liveDenied ? 'skip' : allowed ? 'pass' : 'deny', liveDenied ? 'Simulation not reached' : allowed ? 'Full simulation quorum matched' : 'Simulation vetoed the proposal', liveDenied ? 'An earlier deterministic veto stopped the request.' : reason, simulation],
    ['audit', 'pass', 'Receipt appended to hash chain', `${index + 1} decision receipts verified.`, { valid: true, count: index + 1, headHash: `0x${String(index + 1).repeat(64).slice(0,64)}` }],
    ['wallet', allowed ? 'pass' : 'deny', allowed ? 'Wallet forwarded one exact request' : 'Wallet never received the transaction', allowed ? 'The transaction was mined on the primary local node.' : 'The guarded provider failed closed before eth_sendTransaction.', allowed ? { transactionHash: '0x8b219bfb12cad0564a0334bfa8fc51af90f0ce966a34a21a040e6d9526733e57', blockNumber: 19 } : null],
  ].map(([phase, status, eventTitle, detail, data], eventIndex) => ({ index: eventIndex + 1, at, phase, status, title: eventTitle, detail, data }));
  return {
    id: `example_${scenario.replace('-', '_')}`, createdAt: at, updatedAt: at, prompt: title, scenario,
    status: 'complete', decision: allowed ? 'allow' : 'deny', agent: parsed, transaction: sampleTx,
    transactionHash: allowed ? events.at(-1).data.transactionHash : null,
    chainReceipt: allowed ? { blockNumber: 19, status: 1, gasUsed: '95488' } : null,
    receipt: { decision: allowed ? 'allow' : 'deny', policyHash: '8e4f01c4e3d5c199f65bda99a8a39e7907d73da96880d91c9a51ee52edb7c291', checks, protocolState: { payload: { sequence: protocolData.sequence } }, simulation }, events,
  };
}

const samples = ['safe', 'compromised', 'hidden-call', 'slippage'].map(sampleRun);

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character]);
}
function short(value, start = 10, end = 6) {
  const text = String(value ?? '—');
  return text.length > start + end + 1 ? `${text.slice(0, start)}…${text.slice(-end)}` : text;
}
function timestamp(value) {
  try { return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(value)); } catch { return '—'; }
}
function statusOf(run) { return run.decision ?? run.status ?? 'queued'; }
function eventFor(run, phase) { return run.events?.find((event) => event.phase === phase); }
function asJson(value) { return JSON.stringify(value ?? null, null, 2); }

function setMode() {
  const badge = $('[data-mode-badge]');
  const notice = $('[data-mode-notice]');
  badge.className = `mode-badge ${state.live ? 'live' : 'example'}`;
  badge.innerHTML = `<i></i><span>${state.live ? 'LIVE DUAL-ANVIL' : 'EXAMPLE EVIDENCE'}</span>`;
  $('[data-chain-id]').textContent = state.health?.chainId ?? '31337';
  notice.hidden = state.live;
  notice.textContent = 'Stored example evidence — no chain or wallet is connected on this deployment. Run npm run demo:serve locally to execute fresh dual-Anvil simulations.';
  $('[data-run-button-label]').textContent = state.live ? 'Run guarded trade' : 'Open example run';
}

function renderRuns() {
  const list = $('[data-run-list]');
  $('[data-run-count]').textContent = state.runs.length;
  if (!state.runs.length) {
    list.innerHTML = '<p class="run-list-empty">No runs yet. Start the first guarded trade.</p>';
    return;
  }
  list.innerHTML = state.runs.map((run) => {
    const status = statusOf(run);
    return `<button class="run-item ${run.id === state.activeId ? 'active' : ''}" type="button" data-run-id="${escapeHtml(run.id)}">
      <span class="run-item-top"><span class="run-id">${escapeHtml(short(run.id, 16, 4))}</span><span class="decision-pill ${escapeHtml(status)}">${escapeHtml(status.toUpperCase())}</span></span>
      <span class="run-prompt">${escapeHtml(run.prompt)}</span>
      <span class="run-meta"><span>${escapeHtml(run.scenario)}</span><span>${escapeHtml(timestamp(run.updatedAt))} · ${run.eventCount ?? run.events?.length ?? 0}/9</span></span>
    </button>`;
  }).join('');
  $$('[data-run-id]', list).forEach((button) => button.addEventListener('click', () => selectRun(button.dataset.runId)));
}

function checkMarkup(check) {
  return `<div class="check ${escapeHtml(check.status)}"><i></i><b>${escapeHtml(check.id)}</b><span>${escapeHtml(check.detail)}</span></div>`;
}

function renderDetail(run) {
  const detail = $('[data-run-detail]');
  if (!run) return;
  const verdict = statusOf(run);
  const liveState = eventFor(run, 'live-state');
  const simulationEvent = eventFor(run, 'simulation');
  const audit = eventFor(run, 'audit');
  const wallet = eventFor(run, 'wallet');
  const simulation = run.receipt?.simulation ?? simulationEvent?.data ?? null;
  const checks = run.receipt?.checks ?? eventFor(run, 'policy')?.data?.checks ?? [];
  const passCount = checks.filter((check) => check.status === 'pass').length;
  const denyCount = checks.filter((check) => check.status === 'deny').length;
  const tx = run.transaction;
  detail.innerHTML = `<header class="detail-head">
      <div><span class="section-label">${state.live ? 'LIVE RUN' : 'STORED EXAMPLE'} · ${escapeHtml(run.id)}</span><h2>${escapeHtml(run.prompt)}</h2><p>${escapeHtml(run.scenario)} · updated ${escapeHtml(timestamp(run.updatedAt))} · ${run.events?.length ?? 0} recorded stages</p></div>
      <div class="verdict ${escapeHtml(verdict)}"><span>FINAL DECISION</span><strong>${escapeHtml(verdict.toUpperCase())}</strong></div>
    </header>
    <div class="metric-grid">
      <div class="metric"><span>POLICY CHECKS</span><strong>${passCount} pass · ${denyCount} deny</strong></div>
      <div class="metric"><span>LIVE STATE</span><strong>${escapeHtml(liveState?.status === 'pass' ? '2 / 2 signed' : liveState?.status ?? 'pending')}</strong></div>
      <div class="metric"><span>SIMULATION</span><strong>${escapeHtml(simulation?.agreeingSources?.length != null ? `${simulation.agreeingSources.length} / 2 agree` : simulationEvent?.status ?? 'pending')}</strong></div>
      <div class="metric"><span>WALLET OUTCOME</span><strong>${escapeHtml(run.transactionHash ? `mined ${short(run.transactionHash)}` : wallet?.status === 'deny' ? 'never called' : 'pending')}</strong></div>
    </div>
    <section class="detail-section">
      <div class="section-row"><div><span class="section-label">EXECUTION LOG</span><h3>End-to-end decision path</h3></div><span>${run.events?.length ?? 0} / 9 stages</span></div>
      <div class="timeline">${(run.events ?? []).map((event) => `<div class="event ${escapeHtml(event.status)}"><span class="event-index">${String(event.index).padStart(2,'0')}</span><span class="event-phase">${escapeHtml(event.phase)}</span><div class="event-copy"><strong>${escapeHtml(event.title)}</strong><p>${escapeHtml(event.detail)}</p></div></div>`).join('')}</div>
    </section>
    <section class="detail-section">
      <div class="section-row"><div><span class="section-label">BOUND EVIDENCE</span><h3>What the system actually checked</h3></div><button class="copy-json" type="button" data-copy-run>Copy run JSON</button></div>
      <div class="evidence-grid">
        <article class="evidence-card"><div class="evidence-card-head"><span>AGENT PROPOSAL</span><b>UNTRUSTED</b></div>
          <dl class="kv-list"><div><dt>action</dt><dd>${escapeHtml(run.agent?.action ?? '—')}</dd></div><div><dt>input</dt><dd>${escapeHtml(run.agent?.amountIn ?? '—')}</dd></div><div><dt>minimum out</dt><dd>${escapeHtml(run.agent?.minimumOut ?? '—')}</dd></div><div><dt>recipient</dt><dd>${escapeHtml(run.agent?.recipient ?? '—')}</dd></div></dl>
        </article>
        <article class="evidence-card"><div class="evidence-card-head"><span>EXACT TRANSACTION</span><b>FIXED BEFORE CHECKS</b></div>
          <dl class="kv-list"><div><dt>to</dt><dd>${escapeHtml(tx?.to ?? 'not built')}</dd></div><div><dt>selector</dt><dd>${escapeHtml(tx?.data?.slice(0,10) ?? '—')}</dd></div><div><dt>nonce / gas</dt><dd>${escapeHtml(tx ? `${tx.nonce} / ${tx.gas}` : '—')}</dd></div><div><dt>type / value</dt><dd>${escapeHtml(tx ? `${tx.type} / ${tx.value} wei` : '—')}</dd></div></dl>
        </article>
        <article class="evidence-card wide"><div class="evidence-card-head"><span>EXECUTABLE POLICY</span><b class="${denyCount ? 'deny' : ''}">${denyCount ? 'VETOED' : 'PASSED'}</b></div><div class="check-list">${checks.length ? checks.map(checkMarkup).join('') : '<p class="run-list-empty">Policy checks are not available yet.</p>'}</div></article>
        <article class="evidence-card"><div class="evidence-card-head"><span>SIGNED LIVE PROTOCOL STATE</span><b class="${liveState?.status === 'deny' ? 'deny' : ''}">${escapeHtml((liveState?.status ?? 'pending').toUpperCase())}</b></div>
          <dl class="kv-list"><div><dt>sequence</dt><dd>${escapeHtml(liveState?.data?.sequence ?? '—')}</dd></div><div><dt>signers</dt><dd>${escapeHtml(liveState?.data?.signatures?.join(', ') ?? '—')}</dd></div><div><dt>block</dt><dd>${escapeHtml(liveState?.data?.blockNumber ?? '—')}</dd></div><div><dt>evidence</dt><dd>${escapeHtml(liveState?.data?.evidence?.length != null ? `${liveState.data.evidence.length} monitor results` : '—')}</dd></div></dl>
        </article>
        <article class="evidence-card"><div class="evidence-card-head"><span>FULL EVM SIMULATION</span><b class="${simulationEvent?.status === 'deny' ? 'deny' : ''}">${escapeHtml((simulationEvent?.status ?? 'pending').toUpperCase())}</b></div>
          <dl class="kv-list"><div><dt>sources</dt><dd>${escapeHtml(simulation?.agreeingSources?.join(', ') || simulationEvent?.status || '—')}</dd></div><div><dt>fingerprint</dt><dd>${escapeHtml(short(simulation?.fingerprint, 14, 8))}</dd></div><div><dt>calls / depth</dt><dd>${escapeHtml(simulation?.metrics ? `${simulation.metrics.internalCalls ?? simulation.metrics.calls ?? '—'} / ${simulation.metrics.maxCallDepth ?? '—'}` : '—')}</dd></div><div><dt>storage writes</dt><dd>${escapeHtml(simulation?.metrics?.storageWrites ?? '—')}</dd></div></dl>
        </article>
        <article class="evidence-card"><div class="evidence-card-head"><span>WALLET RESULT</span><b class="${wallet?.status === 'deny' ? 'deny' : ''}">${escapeHtml(run.transactionHash ? 'MINED' : wallet?.status === 'deny' ? 'NOT CALLED' : 'PENDING')}</b></div>
          <dl class="kv-list"><div><dt>tx hash</dt><dd>${escapeHtml(run.transactionHash ?? 'none')}</dd></div><div><dt>block</dt><dd>${escapeHtml(run.chainReceipt?.blockNumber ?? '—')}</dd></div><div><dt>gas used</dt><dd>${escapeHtml(run.chainReceipt?.gasUsed ?? '—')}</dd></div><div><dt>status</dt><dd>${escapeHtml(run.chainReceipt?.status ?? (run.decision === 'deny' ? 'denied before send' : '—'))}</dd></div></dl>
        </article>
        <article class="evidence-card"><div class="evidence-card-head"><span>AUDIT RECEIPT CHAIN</span><b>${escapeHtml(audit?.data?.valid === false ? 'INVALID' : 'VERIFIED')}</b></div>
          <dl class="kv-list"><div><dt>receipts</dt><dd>${escapeHtml(audit?.data?.count ?? '—')}</dd></div><div><dt>head hash</dt><dd>${escapeHtml(short(audit?.data?.headHash, 14, 8))}</dd></div><div><dt>policy hash</dt><dd>${escapeHtml(short(run.receipt?.policyHash ?? run.receipt?.policy?.hash, 14, 8))}</dd></div><div><dt>decision</dt><dd>${escapeHtml(run.receipt?.decision ?? run.decision ?? '—')}</dd></div></dl>
        </article>
        <article class="evidence-card wide"><div class="evidence-card-head"><span>EXACT CALLDATA</span><b>${escapeHtml(tx?.data ? `${(tx.data.length - 2) / 2} BYTES` : 'PENDING')}</b></div><pre class="code-box">${escapeHtml(tx?.data ?? 'Transaction calldata has not been built yet.')}</pre></article>
      </div>
    </section>`;
  $('[data-copy-run]', detail)?.addEventListener('click', () => copyRun(run));
}

async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { 'content-type': 'application/json', ...(options.headers ?? {}) } });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error ?? `Request failed with ${response.status}`);
  return payload;
}

async function selectRun(id) {
  state.activeId = id;
  renderRuns();
  let run = state.runs.find((entry) => entry.id === id);
  if (state.live) {
    try { run = await api(`/api/runs/${encodeURIComponent(id)}`); } catch (error) { notify(error.message); return; }
  }
  if (run) {
    const index = state.runs.findIndex((entry) => entry.id === id);
    if (index >= 0) state.runs[index] = { ...state.runs[index], ...run, eventCount: run.events?.length };
    renderDetail(run);
  }
}

async function refreshRuns() {
  if (!state.live) return;
  const payload = await api('/api/runs');
  state.runs = payload.runs;
  renderRuns();
}

async function pollRun(id) {
  clearTimeout(state.polling);
  try {
    const run = await api(`/api/runs/${encodeURIComponent(id)}`);
    const index = state.runs.findIndex((entry) => entry.id === id);
    const summary = { ...run, eventCount: run.events?.length };
    if (index >= 0) state.runs[index] = summary; else state.runs.unshift(summary);
    renderRuns();
    renderDetail(run);
    if (!['complete', 'error'].includes(run.status)) {
      state.polling = setTimeout(() => pollRun(id), 250);
    } else {
      state.busy = false;
      $('[data-run-button]').disabled = false;
      $('[data-form-status]').textContent = run.decision === 'allow' ? 'All gates passed. One exact transaction was mined.' : 'The request was denied before the wallet boundary.';
    }
  } catch (error) {
    state.busy = false;
    $('[data-run-button]').disabled = false;
    showFormError(error.message);
  }
}

async function submitRun(event) {
  event.preventDefault();
  if (state.busy) return;
  const form = new FormData(event.currentTarget);
  const prompt = String(form.get('prompt') ?? '').trim();
  const scenario = String(form.get('scenario') ?? 'safe');
  if (!prompt) return showFormError('Enter a trading request first.');
  $('[data-form-status]').classList.remove('error');
  if (!state.live) {
    const run = samples.find((entry) => entry.scenario === scenario) ?? samples[0];
    state.activeId = run.id;
    renderRuns();
    renderDetail(run);
    notify('Stored evidence opened. Start the local engine to execute a fresh run.');
    document.querySelector('.runs-layout')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    return;
  }
  state.busy = true;
  $('[data-run-button]').disabled = true;
  $('[data-form-status]').textContent = 'Agent is building one exact transaction…';
  try {
    const run = await api('/api/runs', { method: 'POST', body: JSON.stringify({ prompt, scenario }) });
    state.activeId = run.id;
    state.runs.unshift({ ...run, eventCount: run.events?.length });
    renderRuns();
    renderDetail(run);
    pollRun(run.id);
  } catch (error) {
    state.busy = false;
    $('[data-run-button]').disabled = false;
    showFormError(error.message);
  }
}

function showFormError(message) {
  const target = $('[data-form-status]');
  target.textContent = message;
  target.classList.add('error');
}
function notify(message) {
  const toast = $('[data-toast]');
  toast.textContent = message;
  toast.classList.add('show');
  clearTimeout(notify.timer);
  notify.timer = setTimeout(() => toast.classList.remove('show'), 2600);
}
async function copyRun(run) {
  try { await navigator.clipboard.writeText(asJson(run)); notify('Run JSON copied.'); } catch { notify('Clipboard access is unavailable in this browser.'); }
}

async function boot() {
  $$('input[name="scenario"]').forEach((input) => input.addEventListener('change', () => {
    $$('.scenario').forEach((label) => label.classList.toggle('active', label.contains(input) && input.checked));
  }));
  $('[data-run-form]').addEventListener('submit', submitRun);
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1800);
    state.health = await api('/api/health', { signal: controller.signal });
    clearTimeout(timeout);
    if (!state.health.ready) throw new Error('Runtime is not ready.');
    state.live = true;
    await refreshRuns();
  } catch {
    state.live = false;
    state.health = { chainId: 31337 };
    state.runs = samples;
  }
  setMode();
  renderRuns();
  if (state.runs.length) selectRun(state.runs[0].id);
}

boot();
