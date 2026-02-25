/**
 * Frontend: view only. All state from backend API.
 * Scan view: 4 panels (Controls, Progress, Stages, Output). Log: separate page.
 */
// When on localhost, always talk to backend on 12001 so we don't depend on proxy.
const API_BASE = (typeof location !== 'undefined' && (location.hostname === 'localhost' || location.hostname === '127.0.0.1'))
  ? 'http://127.0.0.1:12001'
  : '';

const POLL_INTERVAL_MS = 1500;
const POLL_INTERVAL_WHILE_RUNNING_MS = 500; // faster updates for live output
const POLL_INTERVAL_STREAM_BURST_MS = 200; // first few polls when step is running (to catch first line)
const POLL_STREAM_BURST_COUNT = 8; // poll at 200ms for ~1.6s, then 500ms
const STATUS_FETCH_TIMEOUT_MS = 25000;

const targetEl = document.getElementById('target');
const goalEl = document.getElementById('goal');
const executeBtn = document.getElementById('execute');
const statusLineEl = document.getElementById('status-line');
const progressEl = document.getElementById('progress-text');
const stagesListEl = document.getElementById('stages-list');
const outputEl = document.getElementById('output-text');
const logEl = document.getElementById('log-text');
const apiStatusEl = document.getElementById('api-status');
const currentActivityEl = document.getElementById('current-activity');
const copyReportBtn = document.getElementById('copy-report');
const scanCompleteBanner = document.getElementById('scan-complete-banner');
const panelResults = document.getElementById('panel-results');
const resultsContent = document.getElementById('results-content');
const goalDescriptionEl = document.getElementById('goal-description');

let goalsWithDescriptions = [];

async function pingBackend() {
  const url = `${API_BASE}/api/ping`;
  try {
    const res = await fetch(url);
    const data = await res.json();
    return data;
  } catch (e) {
    return { ok: false, error: String(e.message || e) };
  }
}

async function postScan(target, goal) {
  const url = `${API_BASE}/api/scan`;
  if (apiStatusEl) apiStatusEl.textContent = `Sending POST to ${url}…`;
  console.log('[ProbeScout] POST', url, 'goal=', goal);
  const params = new URLSearchParams();
  params.set('target', target.trim());
  if (goal) params.set('goal', goal);
  const body = params.toString();
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
    signal: controller.signal,
  });
  clearTimeout(timeoutId);
  if (!res.ok) {
    const t = await res.text();
    throw new Error(t || `Scan start failed: ${res.status}`);
  }
  if (apiStatusEl) apiStatusEl.textContent = `API: ${API_BASE || '(same origin)'} • Backend connected`;
  return res.json();
}

async function getStatus() {
  const url = `${API_BASE}/api/scan/status`;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), STATUS_FETCH_TIMEOUT_MS);
  const res = await fetch(url, { signal: controller.signal });
  clearTimeout(timeoutId);
  if (!res.ok) throw new Error(`Status failed: ${res.status}`);
  return res.json();
}

function humanLabel(actionId) {
  const labels = {
    host_reachability: 'Host reachability',
    port_scan: 'Port scan',
    service_detect: 'Service detection',
    os_fingerprint: 'OS fingerprint',
    wait: 'Wait',
    done: 'Done',
  };
  return labels[actionId] || actionId;
}

function setStatusLine(status, step, currentAction, errorMsg, lastLog, maxSteps) {
  statusLineEl.className = 'status-line';
  if (status === 'idle') {
    statusLineEl.textContent = 'Idle';
    if (currentActivityEl) currentActivityEl.textContent = '';
  } else if (status === 'running') {
    statusLineEl.classList.add('running');
    const stepPart = (step != null && maxSteps != null) ? `step ${step}/${maxSteps}` : (step != null ? `step ${step}` : '');
    const actionPart = currentAction ? humanLabel(currentAction) : '';
    const parts = [stepPart, actionPart].filter(Boolean);
    statusLineEl.textContent = parts.length ? `Running — ${parts.join(' · ')}` : 'Running…';
  } else if (status === 'done') {
    statusLineEl.classList.add('done');
    const doneStep = (step != null && maxSteps != null) ? ` (${step}/${maxSteps} steps)` : '';
    statusLineEl.textContent = `Scan complete${doneStep}`;
    if (scanCompleteBanner) scanCompleteBanner.hidden = false;
  } else if (status === 'error') {
    statusLineEl.classList.add('error');
    statusLineEl.textContent = errorMsg ? `Error: ${errorMsg}` : 'Error';
    if (scanCompleteBanner) scanCompleteBanner.hidden = true;
  } else {
    statusLineEl.textContent = status || '—';
    if (scanCompleteBanner) scanCompleteBanner.hidden = true;
  }
  if (status === 'idle' || status === 'running') {
    if (scanCompleteBanner) scanCompleteBanner.hidden = true;
  }
}

function setProgress(data) {
  if (currentActivityEl) {
    currentActivityEl.textContent = data.last_log || '';
  }
  const stepStr = (data.step != null && data.max_steps != null)
    ? `${data.step} / ${data.max_steps}`
    : (data.step != null ? String(data.step) : '—');
  const stageCount = (data.stages && data.stages.length) || 0;
  const lines = [
    `Target:    ${data.target || '—'}`,
    `Status:    ${data.status || '—'}`,
    `Steps:     ${stepStr}  (LLM turns, max ${data.max_steps ?? '?'})`,
    `Action:    ${data.current_action ? humanLabel(data.current_action) : '—'}`,
    `Stages:    ${stageCount}  (actions completed)`,
    `Last:      ${data.last_log || '—'}`,
  ];
  if (data.status === 'done' && data.step != null && stageCount < data.step) {
    lines.push(`Note:     Step ${data.step} was "done" (end scan), so it's not in Stages.`);
  }
  if (data.error) lines.push(`Error:     ${data.error}`);
  progressEl.textContent = lines.join('\n');
}

function renderStagesList(stages = [], currentAction, onSelectStage, inProgressActionId) {
  stagesListEl.innerHTML = '';
  const hasInProgress = inProgressActionId && !stages.some((s) => s.action_id === inProgressActionId);
  if (!stages.length && !hasInProgress) {
    stagesListEl.innerHTML = '<span class="muted">No stages yet.</span>';
    return;
  }
  for (let i = 0; i < stages.length; i++) {
    const s = stages[i];
    const div = document.createElement('div');
    div.className =
      'stage-item' +
      (s.action_id === currentAction ? ' current' : '') +
      (s.done ? ' done' : '');
    const started = s.started_at ? ` <span class="stage-started">${escapeHtml(s.started_at)}</span>` : '';
    div.innerHTML = `
      <span class="stage-label">${humanLabel(s.action_id)}</span>
      <span class="stage-id">${s.action_id}</span>${started}
    `;
    div.dataset.index = i;
    if (onSelectStage) {
      div.style.cursor = 'pointer';
      div.addEventListener('click', () => onSelectStage(i));
    }
    stagesListEl.appendChild(div);
  }
  if (hasInProgress) {
    const div = document.createElement('div');
    div.className = 'stage-item stage-item-in-progress current';
    div.innerHTML = `
      <span class="stage-label">${humanLabel(inProgressActionId)}</span>
      <span class="stage-id">${inProgressActionId}</span>
      <span class="stage-started">(running…)</span>
    `;
    div.dataset.index = stages.length;
    if (onSelectStage) {
      div.style.cursor = 'pointer';
      div.addEventListener('click', () => onSelectStage(stages.length));
    }
    stagesListEl.appendChild(div);
  }
}

function setOutput(text) {
  const next = text || '';
  const current = (outputEl.textContent ?? '');
  if (next !== current) {
    outputEl.textContent = next;
  }
  outputEl.classList.toggle('empty', !next || next.trim() === '');
}

function setResults(results) {
  if (!panelResults || !resultsContent) return;
  if (!results) {
    panelResults.hidden = true;
    resultsContent.textContent = '';
    return;
  }
  panelResults.hidden = false;
  const lines = [];
  lines.push(`Target:        ${results.target || '—'}`);
  lines.push(`Host:          ${results.host_addr || results.hostname || '—'}`);
  if (results.hostname && results.hostname !== (results.host_addr || '')) {
    lines.push(`Hostname:      ${results.hostname}`);
  }
  lines.push(`Reachability:  ${results.host_reachability || '—'}`);
  lines.push(`OS fingerprint: ${results.os_fingerprint_done ? 'done' : '—'}`);
  if (results.os_guess) {
    lines.push(`OS guess:      ${results.os_guess}`);
  }
  lines.push('');
  lines.push('Open ports:');
  if (results.open_ports && results.open_ports.length > 0) {
    for (const p of results.open_ports) {
      lines.push(`  ${p.port}/${p.proto || 'tcp'}`);
    }
  } else {
    lines.push('  (none)');
  }
  lines.push('');
  lines.push('Services:');
  if (results.services && results.services.length > 0) {
    for (const s of results.services) {
      const svc = (s.service || '').trim() || '—';
      const ver = (s.version || '').trim();
      lines.push(`  ${s.port}/${s.proto || 'tcp'}: ${svc}${ver ? ' ' + ver : ''}`);
    }
  } else {
    lines.push('  (none)');
  }
  resultsContent.textContent = lines.length ? lines.join('\n') : '—';
}

function setLog(logLines) {
  const text = Array.isArray(logLines) && logLines.length ? logLines.join('') : '';
  logEl.textContent = text || '';
  logEl.classList.toggle('empty', !text || text.trim() === '');
}

function escapeHtml(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

function copyReportToClipboard() {
  const progressText = (progressEl && progressEl.textContent) ? progressEl.textContent.trim() : '—';
  const stageItems = stagesListEl ? stagesListEl.querySelectorAll('.stage-item') : [];
  const stagesText = stageItems.length
    ? Array.from(stageItems).map((el) => el.textContent.trim()).join('\n')
    : 'No stages yet.';
  const outputText = (outputEl && outputEl.textContent) ? outputEl.textContent.trim() : '—';
  const resultsText = (resultsContent && resultsContent.textContent) ? resultsContent.textContent.trim() : '';
  const logText = (logEl && logEl.textContent) ? logEl.textContent.trim() : '—';
  const reportParts = [
    '2. Progress',
    '---',
    progressText,
    '',
    '3. Stages (completed actions)',
    '---',
    stagesText,
    '',
    '4. Output',
    '---',
    outputText,
  ];
  if (resultsText) {
    reportParts.push('', '5. Results', '---', resultsText, '');
  }
  reportParts.push(
    reportParts.length > 1 && resultsText ? '6. Log (step = LLM turn)' : '5. Log (step = LLM turn)',
    '---',
    logText
  );
  const report = reportParts.join('\n');
  navigator.clipboard.writeText(report).then(
    () => {
      if (copyReportBtn) {
        const orig = copyReportBtn.textContent;
        copyReportBtn.textContent = 'Copied!';
        setTimeout(() => { copyReportBtn.textContent = orig; }, 2000);
      }
    },
    () => {
      if (copyReportBtn) copyReportBtn.textContent = 'Copy failed';
    }
  );
}

let pollTimer = null;
let selectedStageIndex = -1;
let pollCount = 0;

function stopPolling() {
  if (pollTimer) {
    clearTimeout(pollTimer);
    pollTimer = null;
  }
  pollCount = 0;
}

function startPolling() {
  stopPolling();
  selectedStageIndex = -1;
  pollCount = 0;
  function poll() {
    pollCount += 1;
    console.log('[ProbeScout] GET /api/scan/status');
    getStatus()
      .then((data) => {
        try {
          setStatusLine(
            data.status,
            data.step,
            data.current_action,
            data.error,
            data.last_log,
            data.max_steps
          );
          setProgress(data);
          setLog(data.log_lines);
          const stages = data.stages || [];
        const inProgress =
          data.status === 'running' &&
          data.current_action &&
          !stages.some((s) => s.action_id === data.current_action);
        const stepDetail = (inProgress && data.current_step_detail) ? ` (${data.current_step_detail})` : '';
        const commandBlock = (inProgress && data.current_command) ? `$ ${data.current_command}\n\n` : '';
        const runningMessage =
          inProgress &&
          `${commandBlock}Running: ${humanLabel(data.current_action)}${stepDetail}…\n\nOutput will appear when this step completes.`;
        const stepOutput = typeof data.current_step_output === 'string' ? data.current_step_output : '';
        const hasLiveOutput = inProgress && stepOutput.trim().length > 0;
        if (inProgress && stepOutput.length > 0) {
          console.log('[ProbeScout] status: running, current_step_output length=', stepOutput.length);
        }
        const liveOutput =
          hasLiveOutput
            ? `${commandBlock}Running: ${humanLabel(data.current_action)}${stepDetail}…\n\n${stepOutput}`
            : runningMessage;
          renderStagesList(stages, data.current_action, (index) => {
            selectedStageIndex = index;
          if (inProgress && index === stages.length) {
            const cmd = (data.current_command) ? `$ ${data.current_command}\n\n` : '';
            const live = stepOutput.trim();
            setOutput(
              live
                ? `${cmd}Running: ${humanLabel(data.current_action)}…\n\n${stepOutput}`
                : runningMessage
            );
          } else {
              setOutput(stages[index]?.output ?? '');
            }
          }, inProgress ? data.current_action : null);
          if (inProgress) {
            selectedStageIndex = stages.length;
            setOutput(liveOutput);
          } else if (stages.length > 0) {
            const idx =
              selectedStageIndex >= 0 && selectedStageIndex < stages.length
                ? selectedStageIndex
                : stages.length - 1;
            selectedStageIndex = idx;
            setOutput(stages[idx].output ?? '');
          } else {
            setOutput('');
          }
          if (data.status === 'done' && data.results) {
            setResults(data.results);
          } else {
            setResults(null);
          }
        } finally {
          if (data && data.status === 'running') {
            const interval = pollCount <= POLL_STREAM_BURST_COUNT
              ? POLL_INTERVAL_STREAM_BURST_MS
              : POLL_INTERVAL_WHILE_RUNNING_MS;
            pollTimer = setTimeout(poll, interval);
          } else {
            stopPolling();
            executeBtn.disabled = false;
          }
        }
      })
      .catch((err) => {
        setStatusLine('error', null, null, err.message);
        setProgress({ target: targetEl.value?.trim() || '—', status: 'error', error: err.message });
        setOutput(`Error: ${err.message}`);
        stopPolling();
        executeBtn.disabled = false;
      });
  }
  poll();
}

executeBtn.addEventListener('click', async () => {
  const target = targetEl.value?.trim();
  if (!target) return;
  const goal = goalEl?.value?.trim() || '';
  executeBtn.disabled = true;
  setStatusLine('running');
  setProgress({ target, status: 'running', step: 0 });
  renderStagesList([]);
  setOutput('Starting scan…');
  setLog([]);
  if (currentActivityEl) currentActivityEl.textContent = 'Starting scan…';
  try {
    await postScan(target, goal);
    startPolling();
  } catch (err) {
    console.error('Execute failed:', err);
    const msg = err && err.name === 'AbortError'
      ? 'Request timed out (15s). Backend may not have received the POST — check backend terminal for ">>> POST /api/scan".'
      : (err && (err.message || String(err)));
    setStatusLine('error', null, null, msg);
    setProgress({ target, status: 'error', error: msg });
    setOutput(`Error: ${msg}\n\nIf you see "Failed to fetch", the backend may be down or CORS blocking. Backend must run on http://127.0.0.1:12001`);
    executeBtn.disabled = false;
    if (apiStatusEl) apiStatusEl.textContent = `API error: ${msg}`;
  }
});

// Show API base and test backend on load
function setApiStatus(text, isError) {
  if (!apiStatusEl) return;
  apiStatusEl.textContent = text;
  apiStatusEl.className = 'api-status' + (isError ? ' api-status-error' : '');
}

// Tab navigation: Scan | Log
const viewScan = document.getElementById('view-scan');
const viewLog = document.getElementById('view-log');
const tabScan = document.getElementById('tab-scan');
const tabLog = document.getElementById('tab-log');
const backToScanBtn = document.getElementById('back-to-scan-btn');
const copyLogBtn = document.getElementById('copy-log-btn');

function showView(name) {
  const isScan = name === 'scan';
  if (viewScan) viewScan.hidden = !isScan;
  if (viewLog) viewLog.hidden = isScan;
  if (tabScan) {
    tabScan.classList.toggle('nav-tab-active', isScan);
    tabScan.setAttribute('aria-selected', isScan);
  }
  if (tabLog) {
    tabLog.classList.toggle('nav-tab-active', !isScan);
    tabLog.setAttribute('aria-selected', !isScan);
  }
}

if (tabScan) tabScan.addEventListener('click', () => showView('scan'));
if (tabLog) tabLog.addEventListener('click', () => showView('log'));
if (backToScanBtn) backToScanBtn.addEventListener('click', () => showView('scan'));
if (copyReportBtn) copyReportBtn.addEventListener('click', copyReportToClipboard);
if (copyLogBtn) copyLogBtn.addEventListener('click', copyReportToClipboard);

function updateGoalDescription() {
  if (!goalDescriptionEl || !goalEl) return;
  const id = goalEl.value || '';
  const g = goalsWithDescriptions.find((x) => x.id === id);
  goalDescriptionEl.textContent = g && g.description ? g.description : '';
}

async function fetchGoalsAndPopulateDropdown() {
  const url = `${API_BASE}/api/goals`;
  try {
    const res = await fetch(url);
    if (!res.ok) return;
    const data = await res.json();
    const goals = data.goals;
    if (goalEl && Array.isArray(goals) && goals.length > 0) {
      goalsWithDescriptions = goals;
      goalEl.innerHTML = goals.map((g) => `<option value="${escapeHtml(g.id)}">${escapeHtml(g.label)}</option>`).join('');
      updateGoalDescription();
    }
  } catch (_) {
    // Keep static options from HTML
  }
}

if (goalEl) goalEl.addEventListener('change', updateGoalDescription);

(async function init() {
  setStatusLine('idle');
  setProgress({ target: targetEl.value?.trim() || '—', status: 'idle' });
  renderStagesList([]);
  setOutput('');
  updateGoalDescription();

  if (API_BASE) {
    setApiStatus(`API: ${API_BASE} — checking…`, false);
    const ping = await pingBackend();
    if (ping && ping.ok && ping.pid) {
      setApiStatus(`API: ${API_BASE} • Backend connected (PID ${ping.pid})`, false);
      await fetchGoalsAndPopulateDropdown();
    } else {
      setApiStatus(`API: ${API_BASE} • Backend not reachable. Start backend on port 12001.`, true);
    }
  } else {
    setApiStatus('API: same origin', false);
    await fetchGoalsAndPopulateDropdown();
  }
})();
