/**
 * Frontend: view only. All state from backend API.
 * 5-panel layout: Controls & status | Progress | Stages | Output | Log (timestamps & log from backend)
 */
// When on localhost, always talk to backend on 12001 so we don't depend on proxy.
const API_BASE = (typeof location !== 'undefined' && (location.hostname === 'localhost' || location.hostname === '127.0.0.1'))
  ? 'http://127.0.0.1:12001'
  : '';

const targetEl = document.getElementById('target');
const executeBtn = document.getElementById('execute');
const statusLineEl = document.getElementById('status-line');
const progressEl = document.getElementById('progress-text');
const stagesListEl = document.getElementById('stages-list');
const outputEl = document.getElementById('output-text');
const logEl = document.getElementById('log-text');
const apiStatusEl = document.getElementById('api-status');
const currentActivityEl = document.getElementById('current-activity');
const copyReportBtn = document.getElementById('copy-report');

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

async function postScan(target) {
  const url = `${API_BASE}/api/scan`;
  if (apiStatusEl) apiStatusEl.textContent = `Sending POST to ${url}…`;
  console.log('[ProbeScout] POST', url);
  // Form-encoded body avoids CORS preflight (OPTIONS); JSON POST triggers preflight which may not reach backend.
  const body = 'target=' + encodeURIComponent(target.trim());
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
  const res = await fetch(`${API_BASE}/api/scan/status`);
  if (!res.ok) throw new Error(`Status failed: ${res.status}`);
  return res.json();
}

function humanLabel(actionId) {
  const labels = {
    host_reachability: 'Host reachability',
    port_scan_1_100: 'Port scan 1–100',
    port_scan_1_1000: 'Port scan 1–1000',
    port_scan_1_65535: 'Port scan 1–65535',
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
    const logPart = lastLog || '';
    const parts = [stepPart, actionPart, logPart].filter(Boolean);
    statusLineEl.textContent = parts.length ? `Running — ${parts.join(' · ')}` : 'Running…';
  } else if (status === 'done') {
    statusLineEl.classList.add('done');
    const doneStep = (step != null && maxSteps != null) ? ` (${step}/${maxSteps} steps)` : '';
    statusLineEl.textContent = `Done${doneStep}`;
  } else if (status === 'error') {
    statusLineEl.classList.add('error');
    statusLineEl.textContent = errorMsg ? `Error: ${errorMsg}` : 'Error';
  } else {
    statusLineEl.textContent = status || '—';
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

function renderStagesList(stages = [], currentAction, onSelectStage) {
  stagesListEl.innerHTML = '';
  if (!stages.length) {
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
}

function setOutput(text) {
  outputEl.textContent = text || '';
  outputEl.classList.toggle('empty', !text || text.trim() === '');
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
  const logText = (logEl && logEl.textContent) ? logEl.textContent.trim() : '—';
  const report = [
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
    '',
    '5. Log (step = LLM turn)',
    '---',
    logText,
  ].join('\n');
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

function stopPolling() {
  if (pollTimer) {
    clearTimeout(pollTimer);
    pollTimer = null;
  }
}

function startPolling() {
  stopPolling();
  selectedStageIndex = -1;
  function poll() {
    getStatus()
      .then((data) => {
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
        renderStagesList(stages, data.current_action, (index) => {
          selectedStageIndex = index;
          setOutput(stages[index]?.output ?? '');
        });
        if (stages.length > 0) {
          const idx =
            selectedStageIndex >= 0 && selectedStageIndex < stages.length
              ? selectedStageIndex
              : stages.length - 1;
          setOutput(stages[idx].output ?? '');
        } else {
          setOutput('');
        }
        if (data.status === 'running') {
          pollTimer = setTimeout(poll, 1500);
        } else {
          stopPolling();
          executeBtn.disabled = false;
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
  executeBtn.disabled = true;
  setStatusLine('running');
  setProgress({ target, status: 'running', step: 0 });
  renderStagesList([]);
  setOutput('Starting scan…');
  setLog([]);
  if (currentActivityEl) currentActivityEl.textContent = 'Starting scan…';
  try {
    await postScan(target);
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

(function setupLogPanelResize() {
  const handle = document.getElementById('resize-handle-log');
  const panel = document.getElementById('panel-log');
  if (!handle || !panel) return;
  const MIN_H = 160;
  const MAX_H = 600;
  let startY = 0;
  let startH = 0;

  handle.addEventListener('mousedown', (e) => {
    e.preventDefault();
    startY = e.clientY;
    startH = panel.offsetHeight;
    const onMove = (e2) => {
      const dy = e2.clientY - startY;
      let h = Math.round(startH + dy);
      h = Math.max(MIN_H, Math.min(MAX_H, h));
      panel.style.height = h + 'px';
    };
    const onUp = () => {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  });
})();

if (copyReportBtn) {
  copyReportBtn.addEventListener('click', copyReportToClipboard);
}

(async function init() {
  setStatusLine('idle');
  setProgress({ target: targetEl.value?.trim() || '—', status: 'idle' });
  renderStagesList([]);
  setOutput('');

  if (API_BASE) {
    setApiStatus(`API: ${API_BASE} — checking…`, false);
    const ping = await pingBackend();
    if (ping && ping.ok && ping.pid) {
      setApiStatus(`API: ${API_BASE} • Backend connected (PID ${ping.pid})`, false);
    } else {
      setApiStatus(`API: ${API_BASE} • Backend not reachable. Start backend on port 12001.`, true);
    }
  } else {
    setApiStatus('API: same origin', false);
  }
})();
