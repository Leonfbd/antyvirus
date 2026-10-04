/* Panel sterowania AntyVirus - czysty JS, bez frameworków i buildu. */

const state = {
  status: null,
  job: null,
  pollTimer: null,
  jobTimer: null,
  detectionFilter: '',
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const api = async (url, options) => {
  const res = await fetch(url, options);
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`${res.status}: ${detail.slice(0, 200)}`);
  }
  return res.json();
};

const post = (url, body) => api(url, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

const fmtTime = (ts) => {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString('pl-PL', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
};
const fmtSize = (bytes) => {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / Math.pow(1024, i)).toFixed(i ? 1 : 0)} ${units[i]}`;
};
const verdictPL = (v) => ({ malicious: 'ZŁOŚLIWY', suspicious: 'PODEJRZANY', clean: 'CZYSTY',
  error: 'BŁĄD', skipped: 'POMINIĘTY' }[v] || v);

/* ------------------------------- zakładki ------------------------------- */
$$('.tab').forEach((tab) => tab.addEventListener('click', () => {
  $$('.tab').forEach((t) => t.classList.remove('active'));
  $$('.tab-panel').forEach((p) => p.classList.remove('active'));
  tab.classList.add('active');
  $(`#${tab.dataset.tab}`).classList.add('active');
  if (tab.dataset.tab === 'threats') loadDetections();
  if (tab.dataset.tab === 'quarantine') loadQuarantine();
  if (tab.dataset.tab === 'sigs') loadSigs();
  if (tab.dataset.tab === 'settings') loadSettings();
}));

/* -------------------------------- status -------------------------------- */
async function loadStatus() {
  try {
    state.status = await api('/api/status');
    renderStatus();
  } catch (err) {
    $('#footerStatus').textContent = `błąd połączenia: ${err.message}`;
  }
}

function renderStatus() {
  const s = state.status;
  if (!s) return;

  const on = s.protection === 'on';
  const pill = $('#protectionPill');
  pill.textContent = on ? 'OCHRONA AKTYWNA' : 'OCHRONA NIEAKTYWNA';
  pill.className = `pill ${on ? 'pill-on' : 'pill-off'}`;
  $('#toggleProtection').textContent = on ? 'Wyłącz ochronę' : 'Włącz ochronę';

  $('#statProtection').textContent = on ? 'AKTYWNA' : 'WYŁĄCZONA';
  $('#statProtection').className = on ? '' : 'danger';
  const watched = s.realtime?.paths || [];
  $('#statWatched').textContent = watched.length
    ? `obserwowane: ${watched.length} katalogów`
    : 'brak obserwowanych katalogów';

  const sig = s.signatures || {};
  const total = (sig.hashes || 0) + (sig.yara_rules || 0) + (sig.clamav_sigs || 0);
  $('#statSigs').textContent = total.toLocaleString('pl-PL');
  $('#statSigsHint').textContent =
    `YARA: ${sig.yara_rules || 0} plików · hasze: ${(sig.hashes || 0).toLocaleString('pl-PL')} · ClamAV: ${(sig.clamav_sigs || 0).toLocaleString('pl-PL')}`;

  const db = s.database || {};
  $('#statThreats').textContent = (db.threats || 0).toLocaleString('pl-PL');
  $('#statThreatsHint').textContent = `przeskanowanych plików: ${(db.files_scanned || 0).toLocaleString('pl-PL')}`;
  $('#statQuarantine').textContent = s.quarantine_count || 0;

  $('#thrSusp').textContent = state.config?.suspicious_threshold ?? 25;
  $('#thrMal').textContent = state.config?.malicious_threshold ?? 60;

  $('#footerStatus').textContent =
    `AntyVirus v${s.version} · ${s.hostname} · sygnatury z ${sig.updated_at_human || '—'}`;
}

/* -------------------------------- zdarzenia ------------------------------ */
async function loadEvents() {
  const events = await api('/api/events?limit=60');
  const feed = $('#eventFeed');
  if (!events.length) { feed.innerHTML = '<p class="muted">Brak zdarzeń.</p>'; return; }
  feed.innerHTML = events.map((e) => `
    <div class="feed-item">
      <span class="time">${fmtTime(e.ts)}</span>
      <span class="kind kind-${e.kind}">${e.kind}</span>
      <span class="msg">${escapeHtml(e.message || '')}
        ${e.path ? `<br><small class="muted">${escapeHtml(e.path)}</small>` : ''}
      </span>
    </div>`).join('');
}

/* -------------------------------- skanowanie ----------------------------- */
$('#btnScan').addEventListener('click', () => {
  const value = $('#scanPath').value.trim();
  if (!value) { $('#scanStatus').textContent = 'Podaj ścieżkę.'; return; }
  startScan([value]);
});

$$('[data-quick]').forEach((btn) => btn.addEventListener('click', () => {
  const kind = btn.dataset.quick;
  const s = state.status;
  const home = s?.home_dir || '/home/user';
  const map = {
    home: home,
    downloads: `${home}/Downloads`,
    samples: s?.samples_dir || './samples',
  };
  const path = map[kind];
  $('#quickNote').textContent = `Uruchamiam skan: ${path}`;
  $$('.tab').forEach((t) => t.classList.remove('active'));
  $$('.tab-panel').forEach((p) => p.classList.remove('active'));
  document.querySelector('.tab[data-tab="scan"]').classList.add('active');
  $('#scan').classList.add('active');
  $('#scanPath').value = path;
  startScan([path]);
}));

async function startScan(paths) {
  try {
    const quarantine = $('#scanQuarantine').checked;
    const res = await post('/api/scan', { paths, quarantine });
    state.job = res.job_id;
    $('#scanProgressWrap').classList.remove('hidden');
    $('#scanResults').classList.add('hidden');
    $('#scanResults').innerHTML = '';
    if (state.jobTimer) clearInterval(state.jobTimer);
    state.jobTimer = setInterval(pollJob, 700);
    pollJob();
  } catch (err) {
    $('#scanStatus').textContent = `Błąd: ${err.message}`;
  }
}

async function pollJob() {
  if (!state.job) return;
  const job = await api(`/api/scan/${state.job}`);
  $('#scanBar').style.width = `${job.percent}%`;
  $('#scanStatus').textContent = job.state === 'done'
    ? `Zakończono w ${(job.elapsed_ms / 1000).toFixed(1)} s`
    : `Skanowanie… ${job.done}/${job.total} plików`;
  const s = job.summary;
  $('#scanCounts').textContent = s
    ? `złośliwe: ${s.malicious} · podejrzane: ${s.suspicious} · czyste: ${s.clean} · błędy: ${s.errors}`
    : (job.current ? `${job.current.slice(0, 90)}…` : '');

  if (job.state !== 'running') {
    clearInterval(state.jobTimer);
    state.job = null;
    renderResults(job);
    loadStatus();
    loadEvents();
    loadDetections();
  }
}

function renderResults(job) {
  const box = $('#scanResults');
  box.classList.remove('hidden');
  const results = (job.summary && job.summary.results) || [];
  const interesting = results
    .filter((r) => r.verdict === 'malicious' || r.verdict === 'suspicious' || r.error)
    .sort((a, b) => b.score - a.score);
  const clean = results.filter((r) => r.verdict === 'clean');

  if (!results.length) {
    box.innerHTML = '<p class="muted">Brak wyników.</p>';
    return;
  }

  const renderRow = (r) => `
    <div class="res-row ${r.verdict}">
      <div class="res-head">
        <span class="res-path">${escapeHtml(r.path)}</span>
        <span class="badge ${r.verdict}">${verdictPL(r.verdict)} · ${r.score} pkt</span>
      </div>
      <div class="muted" style="font-size:.78rem;margin-top:4px">
        ${r.file_type} · ${fmtSize(r.size)} · ${r.elapsed_ms} ms
        ${r.sha256 ? `· sha256: ${r.sha256.slice(0, 16)}…` : ''}
        ${r.quarantined ? '· <b style="color:var(--warn)">odizolowany</b>' : ''}
      </div>
      ${r.error ? `<div class="finding">Błąd: ${escapeHtml(r.error)}</div>` : ''}
      ${(r.findings || []).map((f) => `
        <div class="finding">
          <span class="sev sev-${f.severity}">${f.severity}</span>
          <span class="rule">${escapeHtml(f.detector)}/${escapeHtml(f.rule)}</span>
          <span>+${f.weight}</span>
          <div>${escapeHtml(f.description)}</div>
          ${f.evidence ? `<div class="ev">↳ ${escapeHtml(f.evidence.slice(0, 300))}</div>` : ''}
        </div>`).join('')}
    </div>`;

  box.innerHTML = `
    <div class="card-head">
      <h2>Wyniki (${interesting.length} do przejrzenia z ${results.length})</h2>
      <label class="chip"><input type="checkbox" id="showClean"> pokaż czyste</label>
    </div>
    ${interesting.map(renderRow).join('') || '<p class="muted">Nie wykryto zagrożeń.</p>'}
    <div id="cleanRows" class="hidden">${clean.map(renderRow).join('')}</div>`;

  const toggle = $('#showClean');
  if (toggle) toggle.addEventListener('change', (e) => {
    $('#cleanRows').classList.toggle('hidden', !e.target.checked);
  });
}

/* ------------------------------- przeglądarka ---------------------------- */
$('#btnBrowse').addEventListener('click', browse);
async function browse(path) {
  const box = $('#browseList');
  box.classList.remove('hidden');
  try {
    const entries = await api(`/api/browse?path=${encodeURIComponent(path || $('#scanPath').value || '')}`);
    box.innerHTML = entries.map((e) => `
      <div class="browse-item ${e.type}" data-path="${escapeHtml(e.path)}" data-type="${e.type}">
        ${e.type === 'dir' ? '📁' : '📄'} ${escapeHtml(e.name)}
      </div>`).join('') || '<div class="browse-item muted">(pusty katalog)</div>';
    $$('.browse-item').forEach((item) => item.addEventListener('click', () => {
      if (item.dataset.type === 'dir') {
        $('#scanPath').value = item.dataset.path;
        browse(item.dataset.path);
      } else {
        $('#scanPath').value = item.dataset.path;
      }
    }));
  } catch (err) {
    box.innerHTML = `<div class="browse-item muted">${escapeHtml(err.message)}</div>`;
  }
}

/* -------------------------------- wykrycia ------------------------------- */
$$('.chip[data-filter]').forEach((chip) => chip.addEventListener('click', () => {
  $$('.chip[data-filter]').forEach((c) => c.classList.remove('active'));
  chip.classList.add('active');
  state.detectionFilter = chip.dataset.filter;
  loadDetections();
}));

async function loadDetections() {
  const url = state.detectionFilter
    ? `/api/detections?limit=200&verdict=${state.detectionFilter}`
    : '/api/detections?limit=200';
  try {
    const rows = await api(url);
    const box = $('#detectionsTable');
    if (!rows.length) { box.innerHTML = '<p class="muted">Brak wykryć.</p>'; return; }
    box.innerHTML = `
      <table>
        <thead><tr><th>Czas</th><th>Werdykt</th><th>Punkty</th><th>Reguła</th><th>Plik</th><th>Opis</th></tr></thead>
        <tbody>
        ${rows.map((r) => `
          <tr>
            <td>${fmtTime(r.detected_at)}</td>
            <td><span class="badge ${r.verdict}">${verdictPL(r.verdict)}</span></td>
            <td>${r.score}</td>
            <td><span class="rule">${escapeHtml(r.detector)}/${escapeHtml(r.rule)}</span></td>
            <td class="path">${escapeHtml(r.path)}</td>
            <td>${escapeHtml((r.description || '').slice(0, 160))}</td>
          </tr>`).join('')}
        </tbody>
      </table>`;
  } catch (err) {
    $('#detectionsTable').innerHTML = `<p class="muted">${escapeHtml(err.message)}</p>`;
  }
}

/* ------------------------------- kwarantanna ----------------------------- */
async function loadQuarantine() {
  try {
    const items = await api('/api/quarantine');
    const box = $('#quarantineList');
    if (!items.length) { box.innerHTML = '<p class="muted">Kwarantanna jest pusta.</p>'; return; }
    box.innerHTML = items.map((it) => `
      <div class="list-item">
        <div class="meta">
          <b>${escapeHtml(it.name || it.original_path)}</b>
          <small>${escapeHtml(it.original_path)}</small>
          <small>${it.verdict} · ${it.score} pkt · ${fmtSize(it.size)} · ${it.quarantined_at_human || ''}</small>
          <small>${escapeHtml((it.reason || '').slice(0, 140))}</small>
        </div>
        <div class="ops">
          <button class="btn btn-sm" data-restore="${escapeHtml(it.id)}">Przywróć</button>
          <button class="btn btn-sm btn-danger" data-delete="${escapeHtml(it.id)}">Usuń</button>
        </div>
      </div>`).join('');

    $$('[data-restore]').forEach((b) => b.addEventListener('click', async () => {
      const res = await post(`/api/quarantine/${b.dataset.restore}/restore`, {});
      await loadQuarantine(); loadStatus(); loadEvents();
      alert(`Przywrócono do: ${res.path}`);
    }));
    $$('[data-delete]').forEach((b) => b.addEventListener('click', async () => {
      if (!confirm('Usunąć plik trwale z kwarantanny?')) return;
      await api(`/api/quarantine/${b.dataset.delete}`, { method: 'DELETE' });
      await loadQuarantine(); loadStatus();
    }));
  } catch (err) {
    $('#quarantineList').innerHTML = `<p class="muted">${escapeHtml(err.message)}</p>`;
  }
}
$('#btnRefreshQuarantine').addEventListener('click', loadQuarantine);

/* -------------------------------- sygnatury ------------------------------ */
async function loadSigs() {
  try {
    const [status, manifest] = await Promise.all([
      api('/api/status'),
      api('/api/sigs/status'),
    ]);
    const sig = status.signatures || {};
    $('#sigStats').innerHTML = `
      <span class="k">Skróty plików</span><span class="v">${(sig.hashes || 0).toLocaleString('pl-PL')}</span>
      <span class="k">Import-hashe</span><span class="v">${(sig.imphash || 0).toLocaleString('pl-PL')}</span>
      <span class="k">Pliki reguł YARA</span><span class="v">${(sig.yara_rules || 0).toLocaleString('pl-PL')}</span>
      <span class="k">Błędne reguły</span><span class="v">${sig.yara_errors || 0}</span>
      <span class="k">Sygnatury ClamAV</span><span class="v">${(sig.clamav_sigs || 0).toLocaleString('pl-PL')}</span>
      <span class="k">Ostatnia aktualizacja</span><span class="v">${sig.updated_at_human || '—'}</span>`;

    const sources = manifest.sources || [];
    $('#sigSources').innerHTML = sources.length
      ? `<h3 style="margin-top:16px">Źródła</h3>` + sources.map((s) => `
          <div class="src">
            <span>${escapeHtml(s.name)} <small class="muted">${escapeHtml(s.url || '')}</small></span>
            <span class="${s.status === 'error' ? 'err' : 'ok'}">${escapeHtml(s.status)}${s.rules ? ` · ${s.rules} reguł` : ''}</span>
          </div>`).join('')
      : '<p class="muted">Bazy nie były jeszcze aktualizowane.</p>';
  } catch (err) {
    $('#sigSources').innerHTML = `<p class="muted">${escapeHtml(err.message)}</p>`;
  }
}

async function updateSigs() {
  const btn = $('#btnUpdateSigs');
  btn.disabled = true;
  btn.textContent = 'Aktualizuję…';
  try {
    const res = await post('/api/sigs/update', {});
    await loadSigs(); loadStatus(); loadEvents();
    const ok = (res.manifest.sources || []).filter((s) => s.status !== 'error').length;
    alert(`Zaktualizowano ${ok}/${res.manifest.sources.length} źródeł.`);
  } catch (err) {
    alert(`Aktualizacja nie powiodła się: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Aktualizuj sygnatury';
  }
}
$('#btnUpdateSigs').addEventListener('click', updateSigs);
$('#btnUpdateSigs2').addEventListener('click', updateSigs);

$('#btnAddIoc').addEventListener('click', async () => {
  const hash = $('#iocHash').value.trim();
  const name = $('#iocName').value.trim() || 'dodane ręcznie';
  if (!hash) { $('#iocNote').textContent = 'Podaj skrót.'; return; }
  try {
    const res = await post('/api/ioc', { hash_value: hash, name });
    $('#iocNote').textContent = `Dodano. Baza zawiera teraz ${res.total} skrótów.`;
    $('#iocHash').value = '';
    loadStatus();
  } catch (err) {
    $('#iocNote').textContent = `Błąd: ${err.message}`;
  }
});

/* -------------------------------- ustawienia ----------------------------- */
const SETTINGS = [
  ['suspicious_threshold', 'Próg „podejrzany” (pkt)', 'number'],
  ['malicious_threshold', 'Próg „złośliwy” (pkt)', 'number'],
  ['max_file_size', 'Maksymalny rozmiar pliku (B)', 'number'],
  ['max_workers', 'Liczba wątków skanowania', 'number'],
  ['entropy_file_threshold', 'Próg entropii pliku', 'number'],
  ['quarantine_enabled', 'Kwarantanna włączona', 'bool'],
  ['quarantine_on_malicious', 'Izoluj złośliwe automatycznie', 'bool'],
  ['quarantine_on_suspicious', 'Izoluj podejrzane automatycznie', 'bool'],
  ['watched_paths', 'Obserwowane katalogi (po przecinku)', 'list'],
];

async function loadSettings() {
  state.config = await api('/api/config');
  $('#settingsForm').innerHTML = SETTINGS.map(([key, label, type]) => {
    const value = state.config[key];
    if (type === 'bool') {
      return `<div class="field"><label>${label}</label>
        <select data-key="${key}"><option value="true" ${value ? 'selected' : ''}>tak</option>
        <option value="false" ${!value ? 'selected' : ''}>nie</option></select></div>`;
    }
    if (type === 'list') {
      return `<div class="field"><label>${label}</label>
        <input data-key="${key}" value="${escapeHtml((value || []).join(','))}"></div>`;
    }
    return `<div class="field"><label>${label}</label>
      <input type="number" data-key="${key}" value="${value}"></div>`;
  }).join('');
}

$('#btnSaveSettings').addEventListener('click', async () => {
  const payload = {};
  $$('#settingsForm [data-key]').forEach((el) => {
    const key = el.dataset.key;
    const meta = SETTINGS.find((s) => s[0] === key);
    if (meta[2] === 'bool') payload[key] = el.value === 'true';
    else if (meta[2] === 'list') payload[key] = el.value.split(',').map((s) => s.trim()).filter(Boolean);
    else payload[key] = Number(el.value);
  });
  try {
    await post('/api/config', payload);
    $('#settingsNote').textContent = 'Zapisano.';
    await loadStatus();
    renderStatus();
  } catch (err) {
    $('#settingsNote').textContent = `Błąd: ${err.message}`;
  }
});

/* ------------------------------ ochrona RT ------------------------------- */
$('#toggleProtection').addEventListener('click', async () => {
  const on = state.status?.protection === 'on';
  try {
    await post('/api/realtime', { enabled: !on });
    await loadStatus(); loadEvents();
  } catch (err) {
    alert(`Nie udało się przełączyć ochrony: ${err.message}`);
  }
});

/* ------------------------------- narzędzia ------------------------------- */
function escapeHtml(text) {
  return String(text ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/* --------------------------------- start --------------------------------- */
(async function init() {
  await loadStatus();
  state.config = await api('/api/config');
  $('#scanQuarantine').checked =
    Boolean(state.config.quarantine_enabled && state.config.quarantine_on_malicious);
  renderStatus();
  await loadEvents();
  loadDetections();
  setInterval(() => { loadStatus(); loadEvents(); }, 5000);
})();
