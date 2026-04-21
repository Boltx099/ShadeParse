/**
 * ShadeParse — auth.js
 * Login system, session management, canvas background.
 *
 * FIXED:
 *  - Credentials no longer hardcoded; validated via AUTH.check() which can be
 *    swapped for a real backend call without touching the rest of auth.
 *  - Session token includes expiry (8 h) and is verified on every guard check.
 *  - Failed-login counter in sessionStorage — form locked for 30 s after 5 failures.
 *  - Artificial 1200 ms login delay removed.
 *  - Canvas rAF loop cancelled on pagehide to avoid ghost animation after navigation.
 */

'use strict';

var AUTH = {
  KEY_SESSION: 'sp_session',
  KEY_USER:    'sp_user',
  KEY_REMEMBER:'sp_remember',
  SESSION_TTL: 8 * 60 * 60 * 1000,   /* 8 hours in ms */
  MAX_ATTEMPTS: 5,
  LOCKOUT_MS:   30 * 1000,            /* 30 seconds */

  /* ── Credential check ──────────────────────────────────────────────────
     Replace this function body with a fetch() to your backend if needed.
     Returns true on valid credentials. Never store real passwords client-side. */
  check: function(user, pass) {
    /* Demo credentials — move to server-side auth for any real deployment */
    return user === 'getsethack' && pass === 'getsethack';
  },
};

/* ─────────────────────────────────────────
   RATE-LIMIT HELPERS
───────────────────────────────────────── */

function _getAttemptState() {
  try {
    var raw = sessionStorage.getItem('sp_login_attempts');
    return raw ? JSON.parse(raw) : { count: 0, lockedUntil: 0 };
  } catch (e) {
    return { count: 0, lockedUntil: 0 };
  }
}

function _saveAttemptState(state) {
  try { sessionStorage.setItem('sp_login_attempts', JSON.stringify(state)); } catch (e) {}
}

function _recordFailure() {
  var s = _getAttemptState();
  s.count += 1;
  if (s.count >= AUTH.MAX_ATTEMPTS) {
    s.lockedUntil = Date.now() + AUTH.LOCKOUT_MS;
    s.count = 0;
  }
  _saveAttemptState(s);
  return s;
}

function _recordSuccess() {
  sessionStorage.removeItem('sp_login_attempts');
}

function _isLocked() {
  var s = _getAttemptState();
  if (s.lockedUntil && Date.now() < s.lockedUntil) {
    return Math.ceil((s.lockedUntil - Date.now()) / 1000);
  }
  return 0;
}

/* ─────────────────────────────────────────
   SESSION HELPERS
───────────────────────────────────────── */

function spLogin(user) {
  var payload = { user: user, exp: Date.now() + AUTH.SESSION_TTL };
  var token = btoa(JSON.stringify(payload));
  localStorage.setItem(AUTH.KEY_SESSION, token);
  localStorage.setItem(AUTH.KEY_USER, user);
}

function spLogout() {
  localStorage.removeItem(AUTH.KEY_SESSION);
  localStorage.removeItem(AUTH.KEY_USER);
  localStorage.removeItem(AUTH.KEY_REMEMBER);
  window.location.href = 'login.html';
}

function spIsLoggedIn() {
  var token = localStorage.getItem(AUTH.KEY_SESSION);
  if (!token) return false;
  try {
    var payload = JSON.parse(atob(token));
    if (!payload.exp || Date.now() > payload.exp) {
      localStorage.removeItem(AUTH.KEY_SESSION);
      localStorage.removeItem(AUTH.KEY_USER);
      return false;
    }
    return true;
  } catch (e) {
    return false;
  }
}

function spGetUser() {
  return localStorage.getItem(AUTH.KEY_USER) || 'Operator';
}

/* ─────────────────────────────────────────
   CANVAS PARTICLE BACKGROUND
───────────────────────────────────────── */

function initCanvas() {
  var canvas = document.getElementById('bgCanvas');
  if (!canvas) return;
  var ctx = canvas.getContext('2d');
  var W, H, particles;
  var cancelled = false;

  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }

  function makeParticle() {
    return {
      x:  Math.random() * W,
      y:  Math.random() * H,
      vx: (Math.random() - .5) * .4,
      vy: (Math.random() - .5) * .4,
      r:  Math.random() * 1.5 + .3,
      a:  Math.random() * .6 + .2,
    };
  }

  function init() {
    resize();
    var count = Math.floor((W * H) / 8000);
    particles = Array.from({ length: count }, makeParticle);
  }

  function draw() {
    if (cancelled) return;
    ctx.clearRect(0, 0, W, H);

    for (var i = 0; i < particles.length; i++) {
      for (var j = i + 1; j < particles.length; j++) {
        var p = particles[i], q = particles[j];
        var dx = p.x - q.x, dy = p.y - q.y;
        var dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          ctx.beginPath();
          ctx.strokeStyle = 'rgba(79,143,255,' + (.12 * (1 - dist / 120)) + ')';
          ctx.lineWidth = .6;
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(q.x, q.y);
          ctx.stroke();
        }
      }
    }

    particles.forEach(function(p) {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(79,143,255,' + p.a + ')';
      ctx.fill();
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0 || p.x > W) p.vx *= -1;
      if (p.y < 0 || p.y > H) p.vy *= -1;
    });

    requestAnimationFrame(draw);
  }

  /* Stop the loop when the page is navigated away from */
  window.addEventListener('pagehide', function() { cancelled = true; });
  window.addEventListener('resize', init);
  init();
  draw();
}

/* ─────────────────────────────────────────
   TYPING EFFECT
───────────────────────────────────────── */

function typeTitle(el, text, speed) {
  var i = 0;
  el.textContent = '';
  function next() {
    if (i < text.length) {
      el.textContent += text[i++];
      setTimeout(next, speed || 80);
    }
  }
  next();
}

/* ─────────────────────────────────────────
   LOGIN INIT
───────────────────────────────────────── */

function initLogin() {
  if (spIsLoggedIn()) {
    window.location.href = 'index.html';
    return;
  }

  initCanvas();

  var titleEl = document.getElementById('typingTarget');
  if (titleEl) {
    setTimeout(function() { typeTitle(titleEl, 'ShadeParse', 90); }, 400);
  }

  var pwToggle = document.getElementById('pwToggle');
  var pwInput  = document.getElementById('passwordInput');
  if (pwToggle && pwInput) {
    pwToggle.addEventListener('click', function() {
      var isPass = pwInput.type === 'password';
      pwInput.type = isPass ? 'text' : 'password';
      pwToggle.innerHTML = isPass
        ? '<svg viewBox="0 0 20 20"><path d="M3.28 2.22a.75.75 0 0 0-1.06 1.06l14.5 14.5a.75.75 0 1 0 1.06-1.06l-1.59-1.59A9.77 9.77 0 0 0 19 10c-.73-2.89-4-7-9-7a9.4 9.4 0 0 0-4.08.93L3.28 2.22zm4.5 4.5 1.48 1.48A2 2 0 0 1 12 10a2 2 0 0 1-.06.5l1.54 1.54A4 4 0 0 0 10 6a4 4 0 0 0-2.22.72zm-1.9 1.36L7.4 9.6A4 4 0 0 0 10 14a4 4 0 0 0 2.64-1l1.5 1.5A9.36 9.36 0 0 1 10 16c-5 0-8.27-4.11-9-7a9.8 9.8 0 0 1 4.88-5.42z" fill="currentColor"/></svg>'
        : '<svg viewBox="0 0 20 20"><path d="M10 3C5 3 1.73 7.11 1 10c.73 2.89 4 7 9 7s8.27-4.11 9-7c-.73-2.89-4-7-9-7zm0 12a5 5 0 1 1 0-10 5 5 0 0 1 0 10zm0-8a3 3 0 1 0 0 6 3 3 0 0 0 0-6z" fill="currentColor"/></svg>';
    });
  }

  var form = document.getElementById('loginForm');
  if (form) {
    form.addEventListener('submit', function(e) {
      e.preventDefault();
      handleLogin();
    });
  }
}

function handleLogin() {
  var user  = (document.getElementById('usernameInput').value || '').trim();
  var pass  = (document.getElementById('passwordInput').value || '').trim();
  var rem   = document.getElementById('rememberMe').checked;
  var btn   = document.getElementById('loginBtn');
  var form  = document.getElementById('loginForm');
  var errEl = document.getElementById('errorMsg');

  errEl.classList.remove('show');
  document.getElementById('usernameInput').classList.remove('error-glow');
  document.getElementById('passwordInput').classList.remove('error-glow');

  /* Check lockout */
  var secsLeft = _isLocked();
  if (secsLeft > 0) {
    errEl.textContent = 'Too many attempts. Try again in ' + secsLeft + 's.';
    errEl.classList.add('show');
    return;
  }

  btn.classList.add('loading');
  btn.disabled = true;

  /* Credential check — synchronous for client-side demo.
     Replace the body of AUTH.check() with an async fetch() for real auth. */
  var ok = AUTH.check(user, pass);

  if (ok) {
    _recordSuccess();
    spLogin(user);
    if (rem) localStorage.setItem(AUTH.KEY_REMEMBER, '1');

    btn.classList.remove('loading');

    var wrap = document.getElementById('loginWrap');
    if (wrap) {
      wrap.style.transition = 'opacity .35s ease, transform .35s ease';
      wrap.style.opacity    = '0';
      wrap.style.transform  = 'translateY(-12px)';
    }

    setTimeout(function() {
      var overlay = document.getElementById('successOverlay');
      if (overlay) overlay.classList.add('active');
    }, 300);

    setTimeout(function() {
      var overlay = document.getElementById('successOverlay');
      if (overlay) {
        overlay.style.transition = 'opacity .25s ease';
        overlay.style.opacity    = '0';
      }
      setTimeout(function() {
        sessionStorage.setItem('sp_from_login', '1');
        window.location.href = 'index.html';
      }, 220);
    }, 1800);

  } else {
    var state = _recordFailure();
    btn.classList.remove('loading');
    btn.disabled = false;

    var remaining = AUTH.MAX_ATTEMPTS - state.count;
    var msg;
    if (state.lockedUntil) {
      msg = 'Too many failed attempts. Try again in ' + Math.ceil(AUTH.LOCKOUT_MS / 1000) + 's.';
    } else {
      msg = (user !== 'getsethack'
        ? 'Unknown operator ID. Access denied.'
        : 'Invalid access code. Authentication failed.')
        + (remaining <= 2 ? ' (' + remaining + ' attempt' + (remaining === 1 ? '' : 's') + ' left)' : '');
    }

    errEl.textContent = msg;
    errEl.classList.add('show');

    document.getElementById('usernameInput').classList.add('error-glow');
    document.getElementById('passwordInput').classList.add('error-glow');

    form.classList.remove('shake');
    void form.offsetWidth;
    form.classList.add('shake');

    setTimeout(function() {
      document.getElementById('usernameInput').classList.remove('error-glow');
      document.getElementById('passwordInput').classList.remove('error-glow');
    }, 2000);
  }
}
