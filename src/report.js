const esc = (v = '') => String(v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = (v) => v == null ? '—' : typeof v === 'string' ? v : JSON.stringify(v);
const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
function addressesIn(value, out = []) {
  if (typeof value === 'string' && ADDRESS.test(value)) out.push(value);
  else if (Array.isArray(value)) value.forEach((x) => addressesIn(x, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((x) => addressesIn(x, out));
  return [...new Set(out)];
}
function short(value, max = 132) { const s = String(value ?? '—'); return s.length > max ? `${s.slice(0, max - 1)}…` : s; }
function actionFor(f) {
  const name = String(f.functionName ?? '').toLowerCase();
  if (/flashloan|flashborrow|flash_loan/.test(name)) return { kind: 'flash-loan', label: 'Flash loan', glyph: 'ϟ' };
  if (/swap|exactinput|exactoutput|multiswap/.test(name) || (name === 'execute' && (/swap-router/i.test(f.registryMatch?.role ?? '') || /dex|exchange/i.test(f.registryMatch?.category ?? '')))) return { kind: 'swap', label: 'Swap', glyph: '⇄' };
  if (/bridge|sendmessage|finalizewithdrawal|relaymessage/.test(name)) return { kind: 'bridge', label: 'Bridge', glyph: '↗' };
  if (/borrow|supply|deposit|withdraw|repay|liquidat/.test(name)) return { kind: 'lending', label: 'Lending', glyph: '▤' };
  if (/stake|unstake|delegate/.test(name)) return { kind: 'staking', label: 'Staking', glyph: '◇' };
  if (/vote|proposal|castvote|queue/.test(name)) return { kind: 'governance', label: 'Governance', glyph: '▣' };
  if (/transfer|approve|permit|balanceof|totalsupply/.test(name)) return { kind: 'token', label: 'Token', glyph: '◉' };
  if (/latestanswer|latestrounddata|getprice|pricefeed/.test(name)) return { kind: 'oracle', label: 'Oracle', glyph: '⌁' };
  return { kind: 'contract', label: 'Contract call', glyph: '◆' };
}
function safeImageUrl(value) {
  if (typeof value !== 'string') return null;
  const candidate = value.startsWith('ipfs://') ? `https://ipfs.io/ipfs/${value.slice(7)}` : value;
  try { const url = new URL(candidate); return url.protocol === 'https:' ? url.href : null; } catch { return null; }
}
function protocolFor(f) {
  const m = f.registryMatch;
  return m ? { id: m.protocolId ?? m.id ?? m.name ?? m.symbol ?? f.address, label: m.type === 'token' ? `${m.symbol ?? m.name} · token` : m.name ?? 'Mapped protocol', logo: m.logo ?? m.logoURI ?? null, known: true }
    : { id: f.address ?? 'unresolved', label: f.address ? 'Unmapped contract' : 'Unresolved target', logo: null, known: false };
}
function colorFor(value) {
  let hash = 0;
  for (const ch of String(value)) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
  return `hsl(${hash % 360} 57% 41%)`;
}
function analyzeRisk(findings) {
  const targets = new Map();
  for (const f of findings.filter((x) => x.kind !== 'parse error')) {
    const address = f.address ?? f.transaction?.to;
    const involved = f.involvedAddresses ?? addressesIn([address, f.parameters]);
    for (const entry of involved) {
      const value = typeof entry === 'string' ? entry : entry.address;
      if (!ADDRESS.test(String(value ?? ''))) continue;
      const key = value.toLowerCase();
      const current = targets.get(key) ?? { known: false, unresolved: false };
      if (typeof entry === 'object' ? entry.known : address && value.toLowerCase() === address.toLowerCase() && f.registryMatch) current.known = true;
      targets.set(key, current);
    }
    if (!involved.length && !address) targets.set(`unresolved:${f.file}:${f.line}`, { known: false, unresolved: true });
  }
  const values = [...targets.values()];
  const unknown = values.filter((x) => !x.known && !x.unresolved).length;
  const unresolved = values.filter((x) => x.unresolved).length;
  const total = values.length;
  const score = total ? Math.min(100, Math.round(100 * (unknown + unresolved * 0.6) / total)) : 0;
  const risk = score >= 60 ? 'high' : score >= 30 ? 'mid' : 'low';
  const safety = score >= 60 ? 'Low' : score >= 30 ? 'Mid' : 'High';
  return { score, risk, safety, unknown, unresolved, total, mapped: values.filter((x) => x.known).length };
}

function renderFlow(findings) {
  const calls = findings.filter((x) => x.kind !== 'parse error').sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.column - b.column);
  if (!calls.length) return '<div class="empty">No call sites found for this scan.</div>';
  const groups = new Map();
  for (const call of calls) {
    const key = `${call.file}\u0000${call.function}`;
    if (!groups.has(key)) groups.set(key, { file: call.file, fn: call.function, calls: [] });
    groups.get(key).calls.push(call);
  }
  let number = 0;
  return [...groups.values()].map((group, groupIndex) => {
    const nodes = group.calls.map((f, index) => {
      const order = ++number;
      const protocol = protocolFor(f);
      const tone = colorFor(protocol.id);
      const action = actionFor(f);
      const target = f.address ?? f.transaction?.to ?? 'Address unresolved';
      const logo = safeImageUrl(protocol.logo);
      const participants = [...new Set([f.transaction?.from, ...addressesIn(f.parameters), ...addressesIn(f.transaction)].filter((x) => x && x.toLowerCase() !== String(target).toLowerCase()))];
      const search = [protocol.label, f.file, f.function, f.functionName, f.address, action.label, f.rpcMethod, f.library, f.kind].join(' ').toLowerCase();
      return `<div class="flow-step" data-search="${esc(search)}" data-protocol="${esc(protocol.label)}" data-known="${protocol.known}">
        <div class="order-mark"><span>${order}</span><i>${index < group.calls.length - 1 ? '↓' : '·'}</i></div>
        <article class="protocol-box" style="--tone:${tone}">
          <div class="protocol-heading">${logo ? `<img src="${esc(logo)}" alt="" referrerpolicy="no-referrer" onerror="this.hidden=true">` : `<span class="protocol-avatar">${esc(protocol.label.slice(0, 1).toUpperCase())}</span>`}<div class="protocol-title"><strong>${esc(protocol.label)}</strong><small>${esc(f.registryMatch?.contractName ?? f.registryMatch?.category ?? f.library)} · ${esc(f.file)}:${f.line}</small></div><span class="action-pill action-${action.kind}">${action.glyph} ${action.label}</span></div>
          <div class="call-meta"><b>${esc(f.functionName ?? 'Raw / unresolved call')}</b><span>${esc(f.rpcMethod ?? f.kind)}${f.decoded ? ` · decoded via ${esc(f.decoded.source)}` : ''}</span></div>
          <div class="address-line"><code>${esc(target)}</code>${f.transaction?.from ? `<span>from ${esc(f.transaction.from)}</span>` : ''}</div>
          <details><summary>Call details</summary><dl><dt>Arguments / calldata</dt><dd><code>${esc(fmt(f.parameters))}</code></dd>${f.calldata ? `<dt>Raw calldata</dt><dd><code>${esc(f.calldata)}</code></dd>` : ''}<dt>Other addresses</dt><dd><code>${esc(participants.length ? participants.join(', ') : 'None resolved')}</code></dd><dt>Source excerpt</dt><dd><pre>${esc(f.snippet)}</pre></dd>${f.notes?.length ? `<dt>Notes</dt><dd>${esc(f.notes.join(' '))}</dd>` : ''}</dl></details>
        </article>
      </div>`;
    }).join('');
    return `<section class="transaction-group" data-group="${groupIndex}"><div class="group-heading"><span class="group-index">FLOW ${String(groupIndex + 1).padStart(2, '0')}</span><strong>${esc(short(`${group.file} · ${group.fn}`, 150))}</strong><span>${group.calls.length} ordered call${group.calls.length === 1 ? '' : 's'}</span></div><div class="flow-lane">${nodes}</div></section>`;
  }).join('');
}

export function renderReport(data) {
  const risk = analyzeRisk(data.findings);
  const protocols = [...new Set(data.findings.filter((f) => f.kind !== 'parse error').map((f) => protocolFor(f).label))].sort();
  const protocolOptions = protocols.map((name) => `<option value="${esc(name)}">${esc(name)}</option>`).join('');
  const parseErrors = data.findings.filter((x) => x.kind === 'parse error').length;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ethereum interaction map</title>
<style>
:root{color-scheme:light;--ink:#18231f;--muted:#718079;--line:#dce5df;--green:#156b4d;--paper:#f2f6f3;--white:#fff;--navy:#102b21}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}header{background:var(--navy);color:#f4fff7;padding:22px 30px;display:flex;align-items:center;justify-content:space-between;gap:20px}header h1{font-size:21px;letter-spacing:-.03em;margin:0}header p{margin:3px 0 0;color:#b7cbbf;font-size:12px}.header-actions{display:flex;gap:8px;align-items:center}.header-actions a{color:#d5e9db;text-decoration:none;border:1px solid #49685b;border-radius:8px;padding:7px 10px;font-size:12px}.layout{max-width:1500px;margin:0 auto;padding:24px;display:grid;grid-template-columns:290px minmax(0,1fr);gap:22px;align-items:start}.risk-panel{position:sticky;top:18px}.risk-card,.graph-card,.transaction-group{background:var(--white);border:1px solid var(--line);border-radius:15px}.risk-card{padding:20px}.eyebrow{font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);font-weight:750}.score-row{display:flex;align-items:end;justify-content:space-between;margin:13px 0 6px}.score{font-size:48px;line-height:1;font-weight:750;letter-spacing:-.06em}.score small{font-size:14px;color:var(--muted);letter-spacing:0}.risk-level,.safety-level{font-weight:750;text-transform:uppercase;font-size:11px;padding:5px 9px;border-radius:99px}.risk-high{background:#ffe6e2;color:#a23124}.risk-mid{background:#fff0d9;color:#875700}.risk-low{background:#e3f4e9;color:#176344}.meter{height:8px;background:#edf1ee;border-radius:9px;overflow:hidden;margin:12px 0 18px}.meter span{height:100%;display:block;border-radius:inherit;background:#39a271;transition:width .3s}.risk-high~.meter span{background:#df665b}.risk-mid~.meter span{background:#d39a39}.risk-stats{display:grid;grid-template-columns:1fr 1fr;gap:8px}.risk-stat{border:1px solid var(--line);border-radius:10px;padding:10px}.risk-stat b{font-size:18px;display:block}.risk-stat span{font-size:10px;color:var(--muted)}.safety-row{display:flex;align-items:center;justify-content:space-between;padding:13px 0;border-top:1px solid var(--line);margin-top:14px}.safety-row span:first-child{font-size:12px;color:var(--muted)}.safety-high{color:#176344;background:#e3f4e9}.safety-mid{color:#875700;background:#fff0d9}.safety-low{color:#a23124;background:#ffe6e2}.risk-note{font-size:11px;color:var(--muted);margin:14px 0 0}.legend{margin-top:14px;border-top:1px solid var(--line);padding-top:14px}.legend p{font-size:10px;color:var(--muted);margin:6px 0}.legend-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#2d9671;margin-right:6px}.legend-dot.unknown{background:#d78149}.graph-card{overflow:hidden}.graph-top{padding:19px 20px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:15px}.graph-top h2{font-size:17px;margin:0}.graph-top p{font-size:11px;color:var(--muted);margin:3px 0 0}.scan-count{font-size:11px;color:var(--muted);white-space:nowrap}.controls{display:flex;gap:8px;padding:12px 18px;border-bottom:1px solid var(--line);background:#fbfcfb}.controls input,.controls select{font:inherit;border:1px solid var(--line);border-radius:8px;background:white;padding:9px 11px;color:var(--ink)}.controls input{flex:1;min-width:100px}.flow-canvas{padding:16px 18px 22px;max-height:calc(100vh - 245px);overflow:auto;background-image:linear-gradient(to right,transparent 49px,#e7ede9 50px,transparent 51px)}.transaction-group{border:1px solid #cddbd2;border-left:3px solid #4b9874;margin:0 0 14px;padding:12px 12px 5px;background:#fbfdfb}.group-heading{display:flex;gap:10px;align-items:center;padding:0 2px 10px;border-bottom:1px solid #e6ede8}.group-heading strong{font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1}.group-heading>span:last-child{font-size:10px;color:var(--muted);white-space:nowrap}.group-index{font-size:9px;font-weight:800;letter-spacing:.1em;color:var(--green);background:#e6f2eb;padding:4px 6px;border-radius:5px;white-space:nowrap}.flow-lane{padding-top:12px}.flow-step{display:grid;grid-template-columns:30px minmax(0,1fr);gap:10px;max-width:950px;margin:0 auto 9px}.order-mark{display:flex;flex-direction:column;align-items:center;color:#82948a;font-size:10px}.order-mark span{width:22px;height:22px;background:#1d7655;color:white;border-radius:50%;display:grid;place-items:center;font-weight:750}.order-mark i{font-style:normal;flex:1;font-size:16px;line-height:22px;color:#8bac98}.protocol-box{border:1px solid color-mix(in srgb,var(--tone) 50%,white);border-left:4px solid var(--tone);border-radius:11px;background:white;padding:11px 13px;box-shadow:0 2px 7px #18231f08}.protocol-heading{display:flex;align-items:center;gap:9px}.protocol-heading img,.protocol-avatar{width:28px;height:28px;border-radius:8px;object-fit:contain;background:#f4f6f4}.protocol-avatar{display:grid;place-items:center;font-weight:800;color:white;background:var(--tone)}.protocol-title{min-width:0;flex:1}.protocol-title strong{display:block;font-size:12px}.protocol-title small{display:block;color:var(--muted);font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.action-pill{white-space:nowrap;border-radius:99px;padding:4px 8px;background:#edf2f6;color:#394e60;font-size:10px;font-weight:700}.action-swap{background:#e6f4ed;color:#146240}.action-flash-loan{background:#fff0dc;color:#875000}.action-lending{background:#e8efff;color:#294e9b}.action-bridge{background:#f0eaff;color:#6441a5}.action-staking{background:#e7f6f7;color:#1c6d72}.action-governance{background:#f7eaf0;color:#8e345b}.action-token{background:#eef2f4;color:#425660}.action-oracle{background:#fff4d9;color:#815f00}.call-meta{margin:9px 0 6px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}.call-meta b{font-size:12px}.call-meta span{font-size:10px;color:var(--muted);font-family:ui-monospace,monospace}.address-line{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.address-line code{font-size:10px;color:#435249;overflow-wrap:anywhere}.address-line span{color:var(--muted);font-size:10px}.protocol-box details{margin-top:7px;border-top:1px solid #edf1ee;padding-top:5px}.protocol-box summary{font-size:10px;color:var(--green);cursor:pointer}.protocol-box dl{display:grid;grid-template-columns:125px minmax(0,1fr);gap:5px 10px;font-size:10px;margin:8px 0 2px}.protocol-box dt{color:var(--muted)}.protocol-box dd{margin:0;overflow-wrap:anywhere}.protocol-box dd code{font-family:ui-monospace,monospace}.protocol-box pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f6f4;padding:8px;border-radius:6px;margin:0;font-size:10px}.empty{padding:45px;text-align:center;color:var(--muted)}.empty[hidden],.flow-step[hidden],.transaction-group[hidden]{display:none}.footnote{font-size:10px;color:var(--muted);padding:12px 20px 18px;border-top:1px solid var(--line)}@media(max-width:850px){.layout{grid-template-columns:1fr;padding:12px}.risk-panel{position:static}.risk-card{padding:14px}.risk-stats{grid-template-columns:repeat(4,1fr)}.graph-top{align-items:flex-start}.flow-canvas{max-height:none}}@media(max-width:570px){header{padding:16px;align-items:flex-start}.header-actions{display:none}.risk-stats{grid-template-columns:1fr 1fr}.controls{flex-wrap:wrap}.controls input,.controls select{width:100%}.group-heading{flex-wrap:wrap}.group-heading strong{flex-basis:70%}.protocol-heading{align-items:flex-start}.action-pill{margin-left:auto}.protocol-box dl{grid-template-columns:1fr}.flow-canvas{padding:12px 8px}.transaction-group{padding:9px 7px 3px}}
</style></head><body>
<header><div><h1>Ethereum interaction map</h1><p>Static call graph · generated ${esc(new Date(data.generatedAt).toLocaleString())}</p></div><div class="header-actions"><a href="ruleset.html">Ruleset builder</a><a href="https://etherscan.io" target="_blank" rel="noreferrer">Ethereum mainnet</a></div></header>
<main class="layout"><aside class="risk-panel"><section class="risk-card"><div class="eyebrow">Address coverage · exposure</div><div class="score-row"><div class="score">${risk.score}<small> / 100</small></div><span class="risk-level risk-${risk.risk}">${risk.risk} risk</span></div><div class="meter meter-${risk.risk}"><span style="width:${risk.score}%;background:${risk.risk==='high'?'#df665b':risk.risk==='mid'?'#d39a39':'#39a271'}"></span></div><div class="risk-stats"><div class="risk-stat"><b>${risk.mapped}</b><span>mapped addresses</span></div><div class="risk-stat"><b>${risk.unknown}</b><span>unmapped addresses</span></div><div class="risk-stat"><b>${risk.unresolved}</b><span>unresolved targets</span></div><div class="risk-stat"><b>${risk.total}</b><span>unique addresses</span></div></div><div class="safety-row"><span>Catalog safety indicator</span><span class="safety-level safety-${risk.safety.toLowerCase()}">${risk.safety}</span></div><p class="risk-note">This measures registry coverage for detected targets and address arguments. It is not a contract security audit. Unmapped addresses increase exposure; unresolved targets count as partial exposure. Address arguments may be wallets as well as tokens.</p><div class="legend"><div class="eyebrow">Map key</div><p><span class="legend-dot"></span>Mapped token or protocol</p><p><span class="legend-dot unknown"></span>Unmapped or unresolved target</p><p>Vertical position shows source order, not confirmed on-chain timing.</p></div></section></aside>
<section class="graph-card"><div class="graph-top"><div><h2>Call sequence</h2><p>Protocol-colored boxes · source groups are outlined together</p></div><div class="scan-count">${data.findings.length} detections · ${data.scannedFiles} files${parseErrors ? ` · ${parseErrors} parse notices` : ''}</div></div>
<div class="controls"><input id="search" type="search" placeholder="Search protocol, address, function, or source…"><select id="protocol"><option value="">All protocols</option>${protocolOptions}</select><select id="scope"><option value="all">All targets</option><option value="mapped">Mapped only</option><option value="unknown">Unknown only</option></select></div>
<div class="flow-canvas" id="flow">${renderFlow(data.findings)}</div><div class="footnote">Each outlined group represents calls found in the same source function and ordered by line number. Static analysis cannot prove that these calls execute together in one transaction or recover runtime timestamps. Colors stay consistent per protocol or token within this report.</div></section></main>
<script>
const search=document.querySelector('#search'),protocol=document.querySelector('#protocol'),scope=document.querySelector('#scope');
function applyFilters(){const query=search.value.trim().toLowerCase(),selected=protocol.value,kind=scope.value;document.querySelectorAll('.flow-step').forEach(node=>{const matches=node.dataset.search.includes(query)&&(!selected||node.dataset.protocol===selected)&&(kind==='all'||(kind==='mapped'?node.dataset.known==='true':node.dataset.known==='false'));node.hidden=!matches});document.querySelectorAll('.transaction-group').forEach(group=>{group.hidden=!group.querySelector('.flow-step:not([hidden])')})}
search.addEventListener('input',applyFilters);protocol.addEventListener('change',applyFilters);scope.addEventListener('change',applyFilters);
</script></body></html>`;
}
