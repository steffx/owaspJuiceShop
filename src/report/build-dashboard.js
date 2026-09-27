#!/usr/bin/env node
/**
 * Builds the security dashboard (site/index.html) from the run artifacts:
 *   results/findings.jsonl  security findings recorded by the specs
 *   results/coverage.json   score board coverage report
 *   results/results.json    Playwright JSON report (test pass/fail)
 */
import fs from 'node:fs';
import path from 'node:path';
import { readFindings } from '../report/findings.js';
import { FOCUS_AREAS, SEVERITY, severityRank } from '../security/owasp.js';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..');
const R = (f) => path.join(ROOT, 'results', f);
const readJson = (f, fallback) => (fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : fallback);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const findings = readFindings();
const coverage = readJson(R('coverage.json'), null);
const report = readJson(R('results.json'), null);

// ---------- test totals from the Playwright JSON report ----------
let passed = 0;
let failed = 0;
(function walk(suites = []) {
  for (const s of suites) {
    for (const spec of s.specs ?? []) for (const t of spec.tests) t.status === 'expected' || t.status === 'skipped' ? passed++ : failed++;
    walk(s.suites);
  }
})(report?.suites);

// ---------- findings by area and severity ----------
const detected = findings.filter((f) => f.detected);
const severityCounts = Object.fromEntries(SEVERITY.map((s) => [s, detected.filter((f) => f.severity === s).length]));

const SEV_STYLE = {
  critical: '--sev-critical',
  high: '--sev-high',
  medium: '--sev-medium',
  low: '--sev-low',
  info: '--sev-info',
};
const sevBadge = (s) => `<span class="sev" style="background:var(${SEV_STYLE[s]})">${s}</span>`;

const areaSections = FOCUS_AREAS.map((area) => {
  const rows = findings
    .filter((f) => f.area === area.key)
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
    .map(
      (f) => `<tr>
        <td><code>${esc(f.id)}</code></td>
        <td>${esc(f.title)}</td>
        <td>${esc(f.owasp)}</td>
        <td>${sevBadge(f.severity)}</td>
        <td>${f.detected ? '<span class="yes">observed</span>' : '<span class="muted">not present</span>'}</td>
        <td class="ev">${esc(f.evidence ?? '')}</td>
      </tr>`,
    )
    .join('');
  const cov = coverage?.areas.find((a) => a.key === area.key);
  const chip = cov ? `<span class="chip">${cov.challengeCount} score board challenges</span>` : '';
  return `<section class="card">
    <h2>${esc(area.label)} <span class="owasp">${area.categories.map(esc).join(' ')}</span> ${chip}</h2>
    <div class="table-wrap"><table>
      <thead><tr><th>ID</th><th>Check</th><th>OWASP</th><th>Severity</th><th>On target</th><th>Evidence</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="6" class="muted">No findings recorded.</td></tr>'}</tbody>
    </table></div>
  </section>`;
}).join('');

const coverageBar = coverage
  ? `<div class="cov">${coverage.areas
      .map(
        (a) => `<div class="cov-item ${a.exercised ? 'on' : 'off'}"><span>${esc(a.label)}</span><b>${a.exercised ? '✔ exercised' : '– not exercised'}</b><small>${a.challengeCount} challenges</small></div>`,
      )
      .join('')}</div>`
  : '<p class="muted">Run the coverage project to populate score board coverage.</p>';

const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Juice Shop Security Suite</title>
<style>
:root{ color-scheme:light; --surface:#fcfcfb; --card:#fff; --border:#e3e2de; --text:#0b0b0b; --muted:#52514e;
  --sev-info:#5b6675; --sev-low:#1baf7a; --sev-medium:#eda100; --sev-high:#eb6834; --sev-critical:#e34948; --on:#0b6b3a;
  font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif; }
@media (prefers-color-scheme:dark){ :root:where(:not([data-theme="light"])){ color-scheme:dark; --surface:#1a1a19; --card:#232322; --border:#3a3936; --text:#fff; --muted:#c3c2b7;
  --sev-info:#8a93a1; --sev-low:#199e70; --sev-medium:#c98500; --sev-high:#d95926; --sev-critical:#e66767; --on:#5cc98b; } }
:root[data-theme="dark"]{ color-scheme:dark; --surface:#1a1a19; --card:#232322; --border:#3a3936; --text:#fff; --muted:#c3c2b7;
  --sev-info:#8a93a1; --sev-low:#199e70; --sev-medium:#c98500; --sev-high:#d95926; --sev-critical:#e66767; --on:#5cc98b; }
*{box-sizing:border-box} body{margin:0;background:var(--surface);color:var(--text)}
main{max-width:1000px;margin:0 auto;padding:24px 16px 48px;display:grid;gap:16px}
h1{margin:0;font-size:1.6rem} h2{margin:0 0 12px;font-size:1.1rem;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
p,.muted{color:var(--muted)} p{margin:4px 0 0}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;min-width:0}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.tile{border:1px solid var(--border);border-radius:10px;padding:12px} .tile span{color:var(--muted);font-size:.85rem} .tile b{display:block;font-size:1.5rem;margin-top:4px}
.sevrow{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.sev{color:#fff;font-size:.72rem;font-weight:700;padding:2px 8px;border-radius:999px;text-transform:capitalize}
.owasp{color:var(--muted);font-size:.8rem;font-weight:500} .chip{margin-left:auto;font-size:.75rem;color:var(--muted);border:1px solid var(--border);border-radius:999px;padding:2px 8px}
.table-wrap{overflow-x:auto} table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{text-align:left;padding:8px;border-bottom:1px solid var(--border);vertical-align:top} th{color:var(--muted);font-size:.82rem;white-space:nowrap}
td.ev{color:var(--muted);font-family:ui-monospace,monospace;font-size:.8rem} .yes{color:var(--sev-high);font-weight:600} .muted{color:var(--muted)}
code{font-size:.85rem}
.cov{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}
.cov-item{border:1px solid var(--border);border-radius:10px;padding:12px;display:grid;gap:2px}
.cov-item.on b{color:var(--on)} .cov-item span{font-weight:600} .cov-item small{color:var(--muted)}
</style></head>
<body><main>
<header><h1>OWASP Juice Shop — security regression suite</h1>
<p>${esc(new Date().toISOString().slice(0, 16).replace('T', ' '))} UTC · target: intentionally vulnerable training app</p></header>

<section class="card"><div class="tiles">
  <div class="tile"><span>Tests</span><b>${passed} passed${failed ? `, ${failed} failed` : ''}</b></div>
  <div class="tile"><span>Security checks</span><b>${findings.length}</b></div>
  <div class="tile"><span>Weaknesses on target</span><b>${detected.length}</b></div>
  <div class="tile"><span>Focus areas covered</span><b>${coverage ? `${coverage.areasExercised}/${coverage.areasTotal}` : '–'}</b></div>
  <div class="tile"><span>Score board challenges</span><b>${coverage ? coverage.totalChallenges : '–'}</b></div>
</div>
<div class="sevrow">${SEVERITY.slice().reverse().map((s) => `${sevBadge(s)} ${severityCounts[s]}`).join(' &nbsp; ')}</div>
</section>

<section class="card"><h2>Score board coverage</h2>
<p>Each focus area mapped to Juice Shop's own challenge categories. "Exercised" means the suite recorded at least one finding there.</p>
${coverageBar}</section>

${areaSections}

<section class="card"><h2>About this suite</h2>
<p>Every check is a detector validated against a target whose weaknesses are documented, so the detector is trusted before it runs against a real service. "On target" shows whether the weakness or misconfiguration is present on this training app; the same checks assert the secure state when pointed at a hardened deployment.</p></section>
</main></body></html>`;

fs.mkdirSync(path.join(ROOT, 'site'), { recursive: true });
fs.writeFileSync(path.join(ROOT, 'site', 'index.html'), html);
console.log(`Dashboard written to site/index.html (${findings.length} findings, ${detected.length} weaknesses on target, coverage ${coverage ? `${coverage.areasExercised}/${coverage.areasTotal}` : 'n/a'})`);
