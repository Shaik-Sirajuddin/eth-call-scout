'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';

const scenarios = [
  { value: 'safe', title: 'Safe path', detail: 'All gates pass; one tx is mined', verdict: 'ALLOW' },
  { value: 'exploiter', title: 'Exploiter recipient', detail: 'Bot pays the Binance bridge exploiter', verdict: 'DENY' },
  { value: 'block-limit', title: 'Block spend limit', detail: 'Second swap in one block goes over', verdict: 'DENY' },
  { value: 'compromised', title: 'Protocol paused', detail: 'Signed live state vetoes first', verdict: 'DENY' },
  { value: 'hidden-call', title: 'Hidden call', detail: 'Full trace finds unsafe target', verdict: 'DENY' },
  { value: 'slippage', title: 'Slippage revert', detail: 'Exact call fails on both nodes', verdict: 'DENY' },
];

async function requestJson(url, options) {
  const response = await fetch(url, { cache: 'no-store', ...options });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error ?? `Request failed with ${response.status}`);
  return data;
}

function short(value, start = 10, end = 6) {
  const text = String(value ?? '—');
  return text.length > start + end + 1 ? `${text.slice(0, start)}…${text.slice(-end)}` : text;
}

function time(value) {
  try { return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(value)); } catch { return '—'; }
}

function json(value) {
  return JSON.stringify(value ?? null, null, 2);
}

function eventFor(run, phase) {
  return run?.events?.findLast?.((event) => event.phase === phase) ?? [...(run?.events ?? [])].reverse().find((event) => event.phase === phase);
}

function statusClass(value) {
  return ['deny', 'error', 'running', 'queued', 'skip'].includes(value) ? value : '';
}

export default function RunExplorer({ initialRunId = null }) {
  const router = useRouter();
  const [health, setHealth] = useState(null);
  const [runs, setRuns] = useState([]);
  const [activeId, setActiveId] = useState(initialRunId);
  const [activeRun, setActiveRun] = useState(null);
  const [prompt, setPrompt] = useState('Swap 100 dUSD for at least 190 dETH to my wallet');
  const [scenario, setScenario] = useState('safe');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [toast, setToast] = useState('');

  const refresh = useCallback(async () => {
    const [{ runs: latest }, current] = await Promise.all([
      requestJson('/api/runs'),
      activeId ? requestJson(`/api/runs/${encodeURIComponent(activeId)}`).catch(() => null) : Promise.resolve(null),
    ]);
    setRuns(latest);
    if (current) setActiveRun(current);
    if (!activeId && latest.length) setActiveId(latest[0].id);
  }, [activeId]);

  useEffect(() => {
    let cancelled = false;
    requestJson('/api/health')
      .then((value) => { if (!cancelled) setHealth(value); })
      .catch((cause) => { if (!cancelled) setError(cause.message); });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try { if (!cancelled) await refresh(); } catch (cause) { if (!cancelled) setError(cause.message); }
    };
    tick();
    const timer = window.setInterval(tick, activeRun && ['queued', 'running'].includes(activeRun.status) ? 600 : 1800);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [refresh, activeRun?.status]);

  useEffect(() => {
    if (!activeId) return;
    requestJson(`/api/runs/${encodeURIComponent(activeId)}`)
      .then(setActiveRun)
      .catch((cause) => setError(cause.message));
  }, [activeId]);

  const selectRun = (id) => {
    setActiveId(id);
    router.replace(`/runs/${encodeURIComponent(id)}`, { scroll: false });
  };

  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const run = await requestJson('/api/runs', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ prompt, scenario }),
      });
      setActiveRun(run);
      setActiveId(run.id);
      router.push(`/runs/${encodeURIComponent(run.id)}`, { scroll: false });
      await refresh();
    } catch (cause) {
      setError(cause.message);
    } finally {
      setBusy(false);
    }
  };

  const copy = async () => {
    if (!activeRun) return;
    try {
      await navigator.clipboard.writeText(json(activeRun));
      setToast('Run JSON copied.');
    } catch {
      setToast('Clipboard access is unavailable.');
    }
    window.setTimeout(() => setToast(''), 2200);
  };

  return (
    <>
      <main id="demo-main" className="workspace">
        <header className="topbar">
          <div><span className="topbar-kicker">WALLET POLICY GATEWAY / TRANSACTION CONTROL</span><h1>Agent transaction runs</h1></div>
          <div className="environment" aria-live="polite">
            <div className={`mode-badge ${health?.ready ? 'live' : 'checking'}`}><i></i><span>{health?.ready ? 'LIVE DUAL-ANVIL' : 'STARTING ENGINE'}</span></div>
            <div className="chain-badge"><span>CHAIN</span><strong>{health?.chainId ?? '—'}</strong></div>
          </div>
        </header>

        {error && <div className="mode-notice">{error}</div>}

        <section className="command-panel" aria-labelledby="command-title">
          <div className="command-copy">
            <span className="section-label">UNTRUSTED AGENT INPUT</span>
            <h2 id="command-title">Tell the agent what to trade.</h2>
            <p>It may construct one exact transaction. It never receives the signer or direct provider access.</p>
          </div>
          <form className="prompt-form" onSubmit={submit}>
            <label htmlFor="trade-prompt">Trading request</label>
            <div className="prompt-row">
              <textarea id="trade-prompt" rows="3" maxLength="500" value={prompt} onChange={(event) => setPrompt(event.target.value)} />
              <button className="run-button" type="submit" disabled={busy || !health?.ready}><span>{busy ? 'Submitting…' : 'Run guarded trade'}</span><b aria-hidden="true">→</b></button>
            </div>
            <fieldset className="scenario-picker">
              <legend>Choose the chain condition</legend>
              {scenarios.map((entry) => <label key={entry.value} className={`scenario ${scenario === entry.value ? 'active' : ''}`}><input type="radio" name="scenario" value={entry.value} checked={scenario === entry.value} onChange={() => setScenario(entry.value)} /><span><b>{entry.title}</b><small>{entry.detail}</small></span><i>{entry.verdict}</i></label>)}
            </fieldset>
            <p className={`form-status ${error ? 'error' : ''}`}>{busy ? 'The proposal is entering the deterministic boundary…' : ''}</p>
          </form>
        </section>

        <section className="engine-strip" aria-label="Active security gates">
          <div><i className="green"></i><span>POLICY</span><strong>Executable</strong></div>
          <div><i className="aqua"></i><span>LIVE STATE</span><strong>2 / 2 signed</strong></div>
          <div><i className="amber"></i><span>SIMULATION</span><strong>2 independent traces</strong></div>
          <div><i className="green"></i><span>HISTORY</span><strong>Persistent snapshots</strong></div>
        </section>

        <section className="runs-layout" aria-label="Run explorer">
          <aside className="run-rail">
            <div className="rail-heading"><div><span className="section-label">ALL SESSIONS</span><h2>Runs</h2></div><span className="run-count">{runs.length}</span></div>
            <div className="run-list" aria-live="polite">
              {!runs.length && <p className="run-list-empty">No stored runs yet.</p>}
              {runs.map((run) => <button key={run.id} type="button" className={`run-item ${activeId === run.id ? 'active' : ''}`} onClick={() => selectRun(run.id)}><span className="run-item-top"><span className="run-id">{run.id}</span><span className={`decision-pill ${statusClass(run.decision ?? run.status)}`}>{String(run.decision ?? run.status).toUpperCase()}</span></span><p className="run-prompt">{run.prompt}</p><span className="run-meta"><span>{run.source === 'agent-api' ? 'AGENT API' : run.scenario}</span><span>{time(run.updatedAt)}</span></span></button>)}
            </div>
          </aside>
          <RunDetail run={activeRun} onCopy={copy} />
        </section>
      </main>
      <div className={`toast ${toast ? 'show' : ''}`} role="status" aria-live="polite">{toast}</div>
    </>
  );
}

function RunDetail({ run, onCopy }) {
  const checks = run?.receipt?.checks ?? [];
  const simulation = run?.receipt?.simulation ?? eventFor(run, 'simulation')?.data;
  const liveState = eventFor(run, 'live-state');
  const wallet = eventFor(run, 'wallet');
  const audit = eventFor(run, 'audit');
  const passed = useMemo(() => checks.filter((check) => check.status === 'pass').length, [checks]);
  if (!run) return <article className="run-detail"><div className="empty-state"><span>NO RUN SELECTED</span><h2>Evidence will appear here.</h2><p>Start a guarded trade or select a stored run to inspect every deterministic decision.</p></div></article>;

  const verdict = run.decision ?? run.status;
  return (
    <article className="run-detail" aria-live="polite">
      <header className="detail-head"><div><span className="section-label">{run.source === 'agent-api' ? 'EXTERNAL AGENT API' : 'BUNDLED INTENT PLANNER'}</span><h2>{run.prompt}</h2><p>{run.id} · {new Date(run.createdAt).toLocaleString()}</p></div><div className={`verdict ${statusClass(verdict)}`}><span>FINAL DECISION</span><strong>{String(verdict).toUpperCase()}</strong></div></header>
      <div className="metric-grid">
        <div className="metric"><span>POLICY CHECKS</span><strong>{passed} pass / {checks.filter((check) => check.status === 'deny').length} deny</strong></div>
        <div className="metric"><span>LIVE STATE</span><strong>{liveState?.status === 'deny' ? 'vetoed' : liveState ? '2 / 2 signed' : 'pending'}</strong></div>
        <div className="metric"><span>SIMULATION</span><strong>{simulation?.agreeingSources?.length != null ? `${simulation.agreeingSources.length} agreeing` : eventFor(run, 'simulation')?.status ?? 'pending'}</strong></div>
        <div className="metric"><span>WALLET OUTCOME</span><strong>{run.transactionHash ? `mined ${short(run.transactionHash)}` : wallet?.status === 'deny' ? 'never called' : 'pending'}</strong></div>
      </div>

      <section className="detail-section"><div className="section-row"><div><span className="section-label">END-TO-END FLOW</span><h3>Decision timeline</h3></div><span>{run.events?.length ?? 0} events</span></div><div className="timeline">{(run.events ?? []).map((event) => <div key={`${event.index}-${event.at}`} className={`event ${statusClass(event.status)}`}><span className="event-index">{String(event.index).padStart(2, '0')}</span><span className="event-phase">{event.phase}</span><div className="event-copy"><strong>{event.title}</strong><p>{event.detail}</p></div></div>)}</div></section>

      <section className="detail-section"><div className="section-row"><div><span className="section-label">VERIFIABLE EVIDENCE</span><h3>What the system saw</h3></div><button className="copy-json" type="button" onClick={onCopy}>Copy run JSON</button></div><div className="evidence-grid">
        <Evidence title="AGENT PROPOSAL" state={run.transaction ? 'FIXED' : 'PENDING'}><KeyValue rows={[['source', run.source ?? 'bundled-agent'], ['request id', run.requestId ?? '—'], ['to', short(run.transaction?.to, 14, 8)], ['selector', run.transaction?.data?.slice(0, 10) ?? '—'], ['nonce', run.transaction?.nonce ?? '—'], ['type', run.transaction?.type ?? '—']]} /></Evidence>
        <Evidence title="LIVE PROTOCOL STATE" state={liveState?.status === 'deny' ? 'VETO' : liveState ? 'SIGNED' : 'PENDING'} deny={liveState?.status === 'deny'}><KeyValue rows={[['sequence', liveState?.data?.sequence ?? '—'], ['signers', liveState?.data?.signatures?.join(', ') ?? '—'], ['block', liveState?.data?.blockNumber ?? '—'], ['evidence', liveState?.data?.evidence?.length != null ? `${liveState.data.evidence.length} monitor results` : '—']]} /></Evidence>
        <Evidence title="POLICY + INVARIANTS" state={checks.some((check) => check.status === 'deny') ? 'DENY' : checks.length ? 'PASS' : 'PENDING'} deny={checks.some((check) => check.status === 'deny')} wide><div className="check-list">{checks.map((check) => <div key={check.id} className={`check ${statusClass(check.status)}`}><i></i><b>{check.id}</b><span>{check.detail}</span></div>)}</div></Evidence>
        <Evidence title="FULL EVM SIMULATION" state={eventFor(run, 'simulation')?.status?.toUpperCase() ?? 'PENDING'} deny={eventFor(run, 'simulation')?.status === 'deny'}><KeyValue rows={[['fingerprint', short(simulation?.fingerprint, 14, 8)], ['sources', simulation?.agreeingSources?.join(', ') || '—'], ['call frames', simulation?.metrics?.calls ?? '—'], ['storage writes', simulation?.metrics?.storageWrites ?? '—'], ['gas estimate', simulation?.metrics?.gasEstimate ?? '—']]} /></Evidence>
        <Evidence title="WALLET + AUDIT" state={run.transactionHash ? 'MINED' : wallet?.status === 'deny' ? 'NOT CALLED' : 'PENDING'} deny={wallet?.status === 'deny'}><KeyValue rows={[['transaction', short(run.transactionHash, 14, 8)], ['block', run.chainReceipt?.blockNumber ?? '—'], ['audit valid', audit?.data?.valid == null ? '—' : String(audit.data.valid)], ['receipt count', audit?.data?.count ?? '—']]} /></Evidence>
        <Evidence title="ON-CHAIN VERIFICATION" state={run.verification?.status?.toUpperCase() ?? 'NOT SENT'} deny={Boolean(run.verification) && run.verification.status !== 'verified'}><KeyValue rows={[['block', run.verification?.blockNumber ?? '—'], ['gas used', run.verification?.gasUsed ?? '—'], ...(run.verification?.checks ?? []).map((check) => [check.id.replace('onchain:', ''), check.status])]} /></Evidence>
        <Evidence title="ALERTS" state={run.alerts?.length ? `${run.alerts.length} RAISED` : 'NONE'} deny={Boolean(run.alerts?.length)}><KeyValue rows={(run.alerts ?? []).length ? run.alerts.map((alert) => [alert.code, alert.message]) : [['log', 'No alerts for this run']]} /></Evidence>
        <Evidence title="EXACT TRANSACTION ENVELOPE" state="JSON" wide><pre className="code-box">{json(run.transaction)}</pre></Evidence>
        <Evidence title="AUTHORIZATION RECEIPT" state={run.receipt?.decision?.toUpperCase() ?? 'PENDING'} deny={run.receipt?.decision === 'deny'} wide><pre className="code-box">{json(run.receipt)}</pre></Evidence>
      </div></section>
    </article>
  );
}

function Evidence({ title, state, deny = false, wide = false, children }) {
  return <article className={`evidence-card ${wide ? 'wide' : ''}`}><div className="evidence-card-head"><span>{title}</span><b className={deny ? 'deny' : ''}>{state}</b></div>{children}</article>;
}

function KeyValue({ rows }) {
  return <dl className="kv-list">{rows.map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{String(value ?? '—')}</dd></div>)}</dl>;
}
