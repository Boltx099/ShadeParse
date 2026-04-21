/**
 * ShadeParse — app.js
 * Bootstrap & initialization — final glue layer.
 * FIXED:
 *  - loadTheme() called before DOMContentLoaded so no flash of wrong theme
 *  - Auth guard redirects to login.html if no session
 *  - applySettingsToUI() deferred to after DOM ready
 *  - startClock / setGreeting / renderHistoryTable all wired correctly
 */

'use strict';

/* Theme applied synchronously in <head> script — nothing needed here */

document.addEventListener('DOMContentLoaded', function() {

  /* ── Auth guard ── */
  if (typeof spIsLoggedIn === 'function' && !spIsLoggedIn()) {
    window.location.href = 'login.html';
    return;
  }

  /* ── Smooth page entry — reveal html, fade body in ── */
  document.documentElement.classList.add('sp-visible');
  var fromLogin = sessionStorage.getItem('sp_from_login');
  sessionStorage.removeItem('sp_from_login');
  if (fromLogin) {
    /* Came from login — show instantly, login already had exit animation */
    document.body.style.transition = 'none';
    document.body.classList.add('sp-ready');
    requestAnimationFrame(function() {
      document.body.style.transition = '';   /* re-enable for future toggles */
    });
  } else {
    requestAnimationFrame(function() {
      requestAnimationFrame(function() {
        document.body.classList.add('sp-ready');
      });
    });
  }

  /* ── Load persisted data ── */
  loadSettings();
  loadHistory();
  loadBaseline();

  /* ── Apply settings to UI toggles ── */
  applySettingsToUI();

  /* ── Apply theme icon ── */
  var theme = localStorage.getItem('sp_theme') || 'light';
  if (typeof _applyThemeIcon === 'function') _applyThemeIcon(theme);

  /* ── Init UI components ── */
  initDropZone();
  initShortcuts();
  if (typeof initResizers === 'function') initResizers();

  /* ── Scanner view: source mode by default ── */
  setScanMode('source');

  /* ── Load sample code ── */
  loadSample('mega');

  /* ── Dashboard widgets ── */
  startClock();
  setGreeting();
  updateDashboard(APP.state);
  renderHistoryTable();

  /* ── Initial pipeline render ── */
  renderPipe(null, [], 'src');

  /* ── Log ready ── */
  logEvent(APP.state, 'ShadeParse v4.0 ready — session: ' + (typeof spGetUser === 'function' ? spGetUser() : 'Operator'), 'ok');

  console.log('%cShadeParse v4.0 — all systems nominal', 'color:#4f8fff;font-family:monospace;font-size:11px;font-weight:bold');
});

/* log() shim removed — use logEvent(APP.state, msg, type) directly */
