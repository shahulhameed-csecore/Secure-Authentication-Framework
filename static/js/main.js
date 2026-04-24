// ═══════════════════════════════════════════════════════════
//  SecureAuth — main.js  (Interaction Engine)
// ═══════════════════════════════════════════════════════════

'use strict';

// ── Ripple Effect ──────────────────────────────────────────
function attachRipple(btn) {
  btn.addEventListener('click', function(e) {
    const r = document.createElement('span');
    r.className = 'ripple';
    const rect = btn.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    r.style.cssText = `width:${size}px;height:${size}px;left:${e.clientX-rect.left-size/2}px;top:${e.clientY-rect.top-size/2}px`;
    btn.appendChild(r);
    r.addEventListener('animationend', () => r.remove());
  });
}
document.querySelectorAll('.btn-primary').forEach(attachRipple);

// ── Loading Overlay ────────────────────────────────────────
const overlay = document.getElementById('loadingOverlay');
function showLoading(msg) {
  if (!overlay) return;
  const t = overlay.querySelector('.loading-text');
  if (t && msg) t.textContent = msg;
  overlay.classList.add('active');
}
function hideLoading() { overlay && overlay.classList.remove('active'); }

// Attach to all auth forms
document.querySelectorAll('form.auth-form').forEach(form => {
  form.addEventListener('submit', () => showLoading('Authenticating…'));
});

// ── Toast Notifications ────────────────────────────────────
function toast(message, type = 'info', duration = 4000) {
  let container = document.querySelector('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }
  const icons = { error:'⛔', success:'✅', warning:'⚠️', info:'ℹ️' };
  const colors = { error:'#ff4757', success:'#00ff88', warning:'#ff6b35', info:'#00d4ff' };
  const t = document.createElement('div');
  t.className = 'toast';
  t.style.borderLeftColor = colors[type] || colors.info;
  t.style.borderLeftWidth = '3px';
  t.innerHTML = `<span style="font-size:18px">${icons[type]||icons.info}</span><span>${message}</span>`;
  container.appendChild(t);
  setTimeout(() => {
    t.classList.add('removing');
    t.addEventListener('animationend', () => t.remove());
  }, duration);
}
window.toast = toast;

// ── OTP Input Controller ───────────────────────────────────
function initOtpInputs() {
  const inputs = Array.from(document.querySelectorAll('.otp-input'));
  if (!inputs.length) return;

  inputs.forEach((inp, idx) => {
    inp.addEventListener('input', (e) => {
      const val = e.target.value.replace(/\D/g, '');
      e.target.value = val.slice(-1);
      if (val) {
        inp.classList.add('filled');
        if (idx < inputs.length - 1) inputs[idx + 1].focus();
      } else {
        inp.classList.remove('filled');
      }
      syncHiddenOtp(inputs);
      checkOtpComplete(inputs);
    });

    inp.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !inp.value && idx > 0) {
        inputs[idx - 1].focus();
        inputs[idx - 1].value = '';
        inputs[idx - 1].classList.remove('filled');
        syncHiddenOtp(inputs);
      }
    });

    inp.addEventListener('paste', (e) => {
      e.preventDefault();
      const paste = (e.clipboardData || window.clipboardData).getData('text').replace(/\D/g, '');
      paste.split('').slice(0, inputs.length).forEach((ch, i) => {
        if (inputs[i]) { inputs[i].value = ch; inputs[i].classList.add('filled'); }
      });
      syncHiddenOtp(inputs);
      checkOtpComplete(inputs);
      const next = inputs[Math.min(paste.length, inputs.length - 1)];
      if (next) next.focus();
    });
  });

  // Focus first on load
  inputs[0].focus();
}

function syncHiddenOtp(inputs) {
  const hidden = document.getElementById('otp_code');
  if (hidden) hidden.value = inputs.map(i => i.value).join('');
}

function checkOtpComplete(inputs) {
  const allFilled = inputs.every(i => i.value.length === 1);
  if (allFilled) {
    inputs.forEach(i => i.classList.add('success'));
    setTimeout(() => {
      const form = document.querySelector('form.otp-form');
      if (form) { showLoading('Verifying OTP…'); form.submit(); }
    }, 400);
  }
}

initOtpInputs();

// ── Security Score Ring Animation ─────────────────────────
function animateScoreRing() {
  const fill = document.querySelector('.score-ring-fill');
  const numEl = document.querySelector('.score-number');
  if (!fill || !numEl) return;

  const score = parseInt(fill.dataset.score || '0', 10);
  const circumference = 163;
  const offset = circumference - (score / 100) * circumference;

  // Color based on score
  let color = '#ff4757';
  if (score >= 80) color = '#00ff88';
  else if (score >= 60) color = '#00d4ff';
  else if (score >= 40) color = '#ff6b35';
  fill.style.stroke = color;
  numEl.style.color = color;

  // Animate offset
  requestAnimationFrame(() => {
    fill.style.strokeDashoffset = offset;
  });

  // Animate number counter
  let current = 0;
  const step = Math.ceil(score / 60);
  const timer = setInterval(() => {
    current = Math.min(current + step, score);
    numEl.textContent = current;
    if (current >= score) clearInterval(timer);
  }, 25);
}
animateScoreRing();

// ── Live Log Polling ───────────────────────────────────────
function initLiveLogs() {
  const panel = document.getElementById('liveLogsPanel');
  if (!panel) return;

  function refresh() {
    fetch('/api/logs')
      .then(r => r.json())
      .then(data => {
        if (!data.events || !data.events.length) return;
        const list = panel.querySelector('.log-list');
        if (!list) return;
        const events = data.events.slice(0, 5);
        list.innerHTML = events.map(e => {
          const sev = (e.severity || 'INFO').toLowerCase();
          const sevClass = ['critical','warning'].includes(sev) ? sev :
                          (e.event_type||'').includes('ATTACK') ? 'attack' : 'info';
          return `<div class="log-entry">
            <span class="log-severity ${sevClass}">${e.severity||'INFO'}</span>
            <span class="log-message">${e.message||''}</span>
            <span class="log-time">${e.time_ago||''}</span>
          </div>`;
        }).join('');
      })
      .catch(() => {});
  }

  refresh();
  setInterval(refresh, 10000);
}
initLiveLogs();

// ── Password strength indicator ────────────────────────────
function initPasswordStrength() {
  const pwd = document.getElementById('password');
  const bar  = document.getElementById('strengthBar');
  const label = document.getElementById('strengthLabel');
  if (!pwd || !bar) return;

  pwd.addEventListener('input', () => {
    const v = pwd.value;
    let score = 0;
    if (v.length >= 8)              score++;
    if (/[A-Z]/.test(v))           score++;
    if (/\d/.test(v))              score++;
    if (/[^A-Za-z\d]/.test(v))    score++;
    if (v.length >= 12)            score++;

    const levels = [
      { color:'#ff4757', text:'Very weak', w:'20%' },
      { color:'#ff6b35', text:'Weak',      w:'40%' },
      { color:'#ffd32a', text:'Fair',      w:'60%' },
      { color:'#00d4ff', text:'Good',      w:'80%' },
      { color:'#00ff88', text:'Strong',    w:'100%'},
    ];
    const lv = levels[Math.min(score, 4)];
    bar.style.width = lv.w;
    bar.style.background = lv.color;
    if (label) { label.textContent = lv.text; label.style.color = lv.color; }
  });
}
initPasswordStrength();

// ── Page entrance animations ───────────────────────────────
document.querySelectorAll('.stat-card').forEach((card, i) => {
  card.style.opacity = '0';
  card.style.transform = 'translateY(20px)';
  setTimeout(() => {
    card.style.transition = 'all 0.5s cubic-bezier(0.4,0,0.2,1)';
    card.style.opacity = '1';
    card.style.transform = 'translateY(0)';
  }, 100 + i * 80);
});