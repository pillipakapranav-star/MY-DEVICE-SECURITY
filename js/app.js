/**
 * AEGIS SENTINEL - CYBER DEFENSE WEB APP & SIMULATION ENGINE
 * Interactive biometric HUD, PIN shield simulator, audio synthesizer, and telemetry.
 */

// --- Web Audio API High-Tech Sound Synthesizer ---
class SoundFX {
  constructor() {
    this.ctx = null;
  }

  init() {
    if (!this.ctx) {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (AudioContext) {
        this.ctx = new AudioContext();
      }
    }
  }

  playBeep(freq = 800, type = 'sine', duration = 0.08) {
    this.init();
    if (!this.ctx) return;
    try {
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = type;
      osc.frequency.setValueAtTime(freq, this.ctx.currentTime);
      gain.gain.setValueAtTime(0.12, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + duration);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start();
      osc.stop(this.ctx.currentTime + duration);
    } catch (e) {
      // Audio autoplay policy fallback
    }
  }

  playSuccess() {
    this.playBeep(523.25, 'sine', 0.1);
    setTimeout(() => this.playBeep(659.25, 'sine', 0.1), 100);
    setTimeout(() => this.playBeep(783.99, 'sine', 0.2), 200);
  }

  playAlarm() {
    this.init();
    if (!this.ctx) return;
    try {
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(400, this.ctx.currentTime);
      osc.frequency.linearRampToValueAtTime(900, this.ctx.currentTime + 0.3);
      osc.frequency.linearRampToValueAtTime(400, this.ctx.currentTime + 0.6);
      gain.gain.setValueAtTime(0.2, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, this.ctx.currentTime + 0.7);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start();
      osc.stop(this.ctx.currentTime + 0.7);
    } catch (e) {}
  }
}

const sfx = new SoundFX();

// --- State Management ---
const state = {
  currentPin: '',
  demoPin: '1234',
  failedAttempts: 0,
  maxAttempts: 3,
  faceMode: 'owner', // 'owner', 'unknown', 'absent'
  logs: [
    {
      timestamp: '2026-10-08 10:14:02',
      type: 'PIN Verified (Access Granted)',
      location: 'Local Workstation (Console)',
      bursts: '0 photos',
      status: 'SECURE',
      badgeClass: 'badge-auth'
    },
    {
      timestamp: '2026-10-08 09:42:18',
      type: 'Biometric Face Match Verified',
      location: 'Webcam CAM-01',
      bursts: '0 photos',
      status: 'AUTHORIZED',
      badgeClass: 'badge-auth'
    }
  ]
};

// --- DOM Elements ---
document.addEventListener('DOMContentLoaded', () => {
  setupTabs();
  setupPinPad();
  setupHUD();
  setupTelemetry();
  renderLogs();
  setupCopyBtn();
  setupModal();
});

// --- Tab Controller ---
function setupTabs() {
  const tabs = document.querySelectorAll('.sim-tab');
  const panels = document.querySelectorAll('.sim-content');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      sfx.playBeep(600, 'sine', 0.05);
      const target = tab.getAttribute('data-tab');

      tabs.forEach(t => t.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      const targetPanel = document.getElementById(target);
      if (targetPanel) targetPanel.classList.add('active');
    });
  });
}

// --- PIN Shield Simulator ---
function setupPinPad() {
  const dots = document.querySelectorAll('.pin-dot');
  const statusMsg = document.getElementById('pin-status-msg');
  const attemptsBadge = document.getElementById('attempts-badge');
  const keyBtns = document.querySelectorAll('.key-btn[data-key]');
  const clearBtn = document.getElementById('key-clear');
  const enterBtn = document.getElementById('key-enter');
  const simStrikeBtn = document.getElementById('btn-simulate-strike');
  const simBreachBtn = document.getElementById('btn-trigger-breach');

  function updateDots() {
    dots.forEach((dot, idx) => {
      if (idx < state.currentPin.length) {
        dot.classList.add('filled');
      } else {
        dot.classList.remove('filled');
      }
    });
  }

  keyBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      sfx.playBeep(450, 'triangle', 0.05);
      if (state.currentPin.length < 4) {
        state.currentPin += btn.getAttribute('data-key');
        updateDots();
      }
    });
  });

  clearBtn.addEventListener('click', () => {
    sfx.playBeep(350, 'sine', 0.05);
    state.currentPin = '';
    updateDots();
    statusMsg.textContent = 'Cleared input.';
    statusMsg.className = 'audit-status text-muted';
  });

  enterBtn.addEventListener('click', () => {
    if (state.currentPin.length === 0) return;

    if (state.currentPin === state.demoPin) {
      // SUCCESS
      sfx.playSuccess();
      statusMsg.textContent = '>>> [SUCCESS] Master PIN Verified! Access Granted.';
      statusMsg.className = 'audit-status text-emerald font-bold';
      state.failedAttempts = 0;
      attemptsBadge.textContent = '3 ATTEMPTS REMAINING';
      attemptsBadge.style.color = 'var(--accent-cyan)';

      addLog('PIN Authentication Success', 'Web Console', '0 photos', 'ACCESS GRANTED', 'badge-auth');
    } else {
      // FAILURE
      state.failedAttempts++;
      sfx.playBeep(220, 'sawtooth', 0.15);
      const remaining = state.maxAttempts - state.failedAttempts;

      if (remaining <= 0) {
        triggerBreach('3 Consecutive Failed PIN Attempts');
      } else {
        statusMsg.textContent = `>>> [DENIED] Invalid PIN! Strike ${state.failedAttempts}/${state.maxAttempts}.`;
        statusMsg.className = 'audit-status text-danger font-bold';
        attemptsBadge.textContent = `${remaining} ATTEMPTS REMAINING`;
        attemptsBadge.style.color = 'var(--accent-warning)';
      }
    }
    state.currentPin = '';
    updateDots();
  });

  simStrikeBtn.addEventListener('click', () => {
    state.failedAttempts++;
    sfx.playBeep(220, 'sawtooth', 0.15);
    const remaining = Math.max(0, state.maxAttempts - state.failedAttempts);

    if (remaining === 0) {
      triggerBreach('Simulated 3-Strike Breach Event');
    } else {
      statusMsg.textContent = `Simulated strike recorded: ${state.failedAttempts}/3`;
      statusMsg.className = 'audit-status text-warning';
      attemptsBadge.textContent = `${remaining} ATTEMPTS REMAINING`;
    }
  });

  simBreachBtn.addEventListener('click', () => {
    triggerBreach('Emergency Defense Override Triggered');
  });
}

function triggerBreach(reason) {
  sfx.playAlarm();
  const modal = document.getElementById('breach-modal');
  const modalReason = document.getElementById('modal-breach-reason');
  const statusMsg = document.getElementById('pin-status-msg');
  const telemetryStatus = document.getElementById('telemetry-status');

  if (modalReason) modalReason.textContent = reason;
  if (modal) modal.classList.add('active');

  if (statusMsg) {
    statusMsg.textContent = `>>> [BREACH PROTOCOL] LockWorkStation() executed! 5 photos captured.`;
    statusMsg.className = 'audit-status text-danger font-bold';
  }

  if (telemetryStatus) {
    telemetryStatus.textContent = 'BREACH TRIGGERED (LOCKED)';
    telemetryStatus.className = 'telemetry-value text-danger';
  }

  addLog(`BREACH: ${reason}`, 'Host System (Win+L)', '5 Burst Photos', 'DISPATCHED', 'badge-breach');

  state.failedAttempts = 0;
  const attemptsBadge = document.getElementById('attempts-badge');
  if (attemptsBadge) {
    attemptsBadge.textContent = 'HOST LOCKDOWN ENGAGED';
    attemptsBadge.style.color = 'var(--accent-danger)';
  }
}

function setupModal() {
  const modal = document.getElementById('breach-modal');
  const dismissBtn = document.getElementById('btn-dismiss-modal');

  if (dismissBtn) {
    dismissBtn.addEventListener('click', () => {
      sfx.playBeep(500, 'sine', 0.08);
      modal.classList.remove('active');
      const telemetryStatus = document.getElementById('telemetry-status');
      if (telemetryStatus) {
        telemetryStatus.textContent = 'ARMED & VIGILANT';
        telemetryStatus.className = 'telemetry-value text-success';
      }
      const attemptsBadge = document.getElementById('attempts-badge');
      if (attemptsBadge) {
        attemptsBadge.textContent = '3 ATTEMPTS REMAINING';
        attemptsBadge.style.color = 'var(--accent-cyan)';
      }
    });
  }
}

// --- Biometric Sentry HUD Canvas Animation ---
function setupHUD() {
  const canvas = document.getElementById('hud-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const targetName = document.getElementById('hud-target-name');
  const confidence = document.getElementById('hud-confidence');
  const threatLevel = document.getElementById('stat-threat-level');
  const modeTag = document.getElementById('hud-mode-tag');

  const radios = document.querySelectorAll('input[name="face-mode"]');
  radios.forEach(radio => {
    radio.addEventListener('change', (e) => {
      state.faceMode = e.target.value;
      sfx.playBeep(700, 'sine', 0.08);

      if (state.faceMode === 'owner') {
        targetName.textContent = 'TARGET: AUTHORIZED OWNER';
        confidence.textContent = 'CONFIDENCE: 94.8%';
        confidence.className = 'hud-tag text-emerald';
        threatLevel.textContent = 'SECURE';
        threatLevel.className = 'stat-num text-success';
        modeTag.textContent = 'MODE: OWNER VERIFIED';
      } else if (state.faceMode === 'unknown') {
        sfx.playAlarm();
        targetName.textContent = 'TARGET: UNRECOGNIZED INTRUDER';
        confidence.textContent = 'CONFIDENCE: 28.1% (FAIL)';
        confidence.className = 'hud-tag text-danger';
        threatLevel.textContent = 'ELEVATED (ALERT)';
        threatLevel.className = 'stat-num text-danger';
        modeTag.textContent = 'MODE: INTRUDER DETECTED';
        addLog('Biometric Intruder Flagged', 'Webcam CAM-01', '5 Burst Photos', 'EVIDENCE SAVED', 'badge-breach');
      } else {
        targetName.textContent = 'TARGET: NO FACE DETECTED';
        confidence.textContent = 'CONFIDENCE: N/A';
        confidence.className = 'hud-tag text-muted';
        threatLevel.textContent = 'ABSENCE PATROL';
        threatLevel.className = 'stat-num text-warning';
        modeTag.textContent = 'MODE: IDLE VIGIL';
      }
    });
  });

  // Animated Scan Line & Grid HUD Loop
  let scanY = 0;
  let scanDir = 1;

  function renderFrame() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Dark grid background
    ctx.strokeStyle = 'rgba(0, 242, 254, 0.06)';
    ctx.lineWidth = 1;
    for (let x = 0; x < canvas.width; x += 30) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, canvas.height);
      ctx.stroke();
    }
    for (let y = 0; y < canvas.height; y += 30) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(canvas.width, y);
      ctx.stroke();
    }

    // Face Simulation Box
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const boxSize = 160;

    let boxColor = '#10b981';
    if (state.faceMode === 'unknown') boxColor = '#ef4444';
    if (state.faceMode === 'absent') boxColor = 'rgba(100, 116, 139, 0.4)';

    if (state.faceMode !== 'absent') {
      // Draw Bounding Reticle
      ctx.strokeStyle = boxColor;
      ctx.lineWidth = 2;
      const corner = 24;

      // Top-Left
      ctx.beginPath();
      ctx.moveTo(centerX - boxSize/2, centerY - boxSize/2 + corner);
      ctx.lineTo(centerX - boxSize/2, centerY - boxSize/2);
      ctx.lineTo(centerX - boxSize/2 + corner, centerY - boxSize/2);
      ctx.stroke();

      // Top-Right
      ctx.beginPath();
      ctx.moveTo(centerX + boxSize/2 - corner, centerY - boxSize/2);
      ctx.lineTo(centerX + boxSize/2, centerY - boxSize/2);
      ctx.lineTo(centerX + boxSize/2, centerY - boxSize/2 + corner);
      ctx.stroke();

      // Bottom-Left
      ctx.beginPath();
      ctx.moveTo(centerX - boxSize/2, centerY + boxSize/2 - corner);
      ctx.lineTo(centerX - boxSize/2, centerY + boxSize/2);
      ctx.lineTo(centerX - boxSize/2 + corner, centerY + boxSize/2);
      ctx.stroke();

      // Bottom-Right
      ctx.beginPath();
      ctx.moveTo(centerX + boxSize/2 - corner, centerY + boxSize/2);
      ctx.lineTo(centerX + boxSize/2, centerY + boxSize/2);
      ctx.lineTo(centerX + boxSize/2, centerY + boxSize/2 - corner);
      ctx.stroke();

      // Center crosshairs
      ctx.strokeStyle = boxColor;
      ctx.beginPath();
      ctx.moveTo(centerX - 10, centerY);
      ctx.lineTo(centerX + 10, centerY);
      ctx.moveTo(centerX, centerY - 10);
      ctx.lineTo(centerX, centerY + 10);
      ctx.stroke();

      // Label
      ctx.fillStyle = boxColor;
      ctx.font = '12px "JetBrains Mono", monospace';
      const label = state.faceMode === 'owner' ? '[ ID: 1 // AUTHORIZED OWNER ]' : '[ ALERT // UNKNOWN SUBJECT ]';
      ctx.fillText(label, centerX - boxSize/2, centerY - boxSize/2 - 10);
    }

    // Moving Scan Line
    scanY += 2 * scanDir;
    if (scanY > canvas.height || scanY < 0) scanDir *= -1;

    ctx.strokeStyle = 'rgba(0, 242, 254, 0.35)';
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(0, scanY);
    ctx.lineTo(canvas.width, scanY);
    ctx.stroke();

    requestAnimationFrame(renderFrame);
  }

  renderFrame();
}

// --- Geolocation Telemetry ---
function setupTelemetry() {
  const locElem = document.getElementById('telemetry-location');
  if (!locElem) return;

  fetch('https://ipapi.co/json/')
    .then(res => res.json())
    .then(data => {
      if (data && data.city) {
        locElem.textContent = `${data.city}, ${data.region_code || data.region} (Approx)`;
      } else {
        locElem.textContent = 'Connected (Approx Network Area)';
      }
    })
    .catch(() => {
      locElem.textContent = 'Local Subnet Area (Protected)';
    });
}

// --- Evidence Vault Logs ---
function renderLogs() {
  const tbody = document.getElementById('logs-tbody');
  if (!tbody) return;

  tbody.innerHTML = '';
  state.logs.forEach(log => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${log.timestamp}</code></td>
      <td><strong>${log.type}</strong></td>
      <td>${log.location}</td>
      <td>${log.bursts}</td>
      <td><span class="badge-tag ${log.badgeClass}">${log.status}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function addLog(type, location, bursts, status, badgeClass) {
  const now = new Date();
  const timeStr = now.toISOString().replace('T', ' ').substring(0, 19);
  state.logs.unshift({
    timestamp: timeStr,
    type,
    location,
    bursts,
    status,
    badgeClass
  });
  if (state.logs.length > 8) state.logs.pop();
  renderLogs();
}

const clearLogsBtn = document.getElementById('btn-clear-logs');
if (clearLogsBtn) {
  clearLogsBtn.addEventListener('click', () => {
    sfx.playBeep(400, 'sine', 0.05);
    state.logs = [];
    renderLogs();
  });
}

// --- Copy Terminal Commands ---
function setupCopyBtn() {
  const btn = document.getElementById('btn-copy-code');
  if (!btn) return;

  btn.addEventListener('click', () => {
    const code = `git clone https://github.com/pillipakapranav-star/MY-DEVICE-SECURITY.git\ncd MY-DEVICE-SECURITY\npython -m pip install -r requirements.txt\npython main.py`;
    navigator.clipboard.writeText(code).then(() => {
      sfx.playSuccess();
      btn.textContent = 'Copied!';
      setTimeout(() => btn.textContent = 'Copy', 2000);
    });
  });
}
