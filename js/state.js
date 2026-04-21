/**
 * ShadeParse — state.js
 * Global app state, config, and persistence.
 *
 * FIXED:
 *  - clearHistory guard for renderHistoryTable load-order issue.
 *  - saveSettings now also persists aiRemediation.
 *  - localStorage errors surface via showToast so users know when persistence fails.
 *  - saveHistory trims to 50 entries in memory too, preventing unbounded session growth.
 */

'use strict';

var APP = {

  state: {
    allFindings:  [],
    baseline:     null,
    logCount:     0,
    scanCount:    0,
    scanHistory:  [],
    currentMode:  'source',   /* 'source' | 'domain' | 'ip' */
  },

  cfg: {
    snipLen:       120,
    aiRemediation: true,
    sound:         false,
    toasts:        true,
    modules: {
      secrets:   true,
      xss:       true,
      endpoints: true,
      proto:     true,
      crypto:    true,
      supply:    true,
      logic:     true,
      config:    true,
    },
  },

};

/* ─── HISTORY PERSISTENCE ─── */

var HISTORY_MAX = 50;

function loadHistory() {
  try {
    var raw = localStorage.getItem('sp_scan_history');
    if (raw) APP.state.scanHistory = JSON.parse(raw);
  } catch (e) { APP.state.scanHistory = []; }
}

function saveHistory() {
  /* Trim in-memory array AND the persisted copy */
  if (APP.state.scanHistory.length > HISTORY_MAX) {
    APP.state.scanHistory = APP.state.scanHistory.slice(-HISTORY_MAX);
  }
  try {
    localStorage.setItem('sp_scan_history', JSON.stringify(APP.state.scanHistory));
  } catch (e) {
    if (typeof showToast === 'function') showToast('Storage full — scan history could not be saved.', 'warn');
  }
}

function addHistoryEntry(entry) {
  APP.state.scanHistory.push(entry);
  saveHistory();
}

function clearHistory() {
  APP.state.scanHistory = [];
  saveHistory();
  if (typeof renderHistoryTable === 'function') renderHistoryTable();
  if (typeof showToast === 'function') showToast('Scan history cleared.', 'info');
}

/* ─── SETTINGS PERSISTENCE ─── */

function loadSettings() {
  try {
    var raw = localStorage.getItem('sp_cfg');
    if (raw) {
      var saved = JSON.parse(raw);
      if (saved.modules)                        Object.assign(APP.cfg.modules, saved.modules);
      if (typeof saved.snipLen       === 'number')  APP.cfg.snipLen       = saved.snipLen;
      if (typeof saved.sound         === 'boolean') APP.cfg.sound         = saved.sound;
      if (typeof saved.toasts        === 'boolean') APP.cfg.toasts        = saved.toasts;
      if (typeof saved.aiRemediation === 'boolean') APP.cfg.aiRemediation = saved.aiRemediation;
    }
  } catch (e) {}
}

function saveSettings() {
  try {
    localStorage.setItem('sp_cfg', JSON.stringify({
      modules:       APP.cfg.modules,
      snipLen:       APP.cfg.snipLen,
      sound:         APP.cfg.sound,
      toasts:        APP.cfg.toasts,
      aiRemediation: APP.cfg.aiRemediation,
    }));
  } catch (e) {
    if (typeof showToast === 'function') showToast('Storage full — settings could not be saved.', 'warn');
  }
}

/* ─── TOGGLE HANDLERS ─── */

function toggleModule(el) {
  var key   = el.dataset.key;
  var isAI  = (key === 'aiRemediation');
  var newVal;

  if (isAI) {
    newVal = !APP.cfg.aiRemediation;
    APP.cfg.aiRemediation = newVal;
  } else {
    if (APP.cfg.modules[key] === undefined) APP.cfg.modules[key] = true;
    newVal = !APP.cfg.modules[key];
    APP.cfg.modules[key] = newVal;
  }

  if (newVal) {
    el.classList.add('on');
  } else {
    el.classList.remove('on');
  }

  saveSettings();
}

function togglePref(el) {
  var key    = el.dataset.key;
  var newVal = !APP.cfg[key];
  APP.cfg[key] = newVal;

  if (newVal) {
    el.classList.add('on');
  } else {
    el.classList.remove('on');
  }

  saveSettings();
}

function updateSnipLen(val) {
  APP.cfg.snipLen = parseInt(val, 10);
  var el = document.getElementById('snipVal');
  if (el) el.textContent = val + ' chars';
  saveSettings();
}

/* ─── APPLY SAVED SETTINGS TO UI TOGGLES ─── */

function applySettingsToUI() {
  var moduleMap = {
    togSecrets:   'secrets',
    togXss:       'xss',
    togEndpoints: 'endpoints',
    togProto:     'proto',
    togCrypto:    'crypto',
    togSupply:    'supply',
    togLogic:     'logic',
    togConfig:    'config',
  };

  Object.keys(moduleMap).forEach(function(id) {
    var el = document.getElementById(id);
    if (!el) return;
    var key = moduleMap[id];
    var isOn = !!APP.cfg.modules[key];
    el.classList.toggle('on', isOn);
  });

  var togAI = document.getElementById('togAI');
  if (togAI) togAI.classList.toggle('on', !!APP.cfg.aiRemediation);

  var togSound  = document.getElementById('togSound');
  var togToasts = document.getElementById('togToasts');
  if (togSound)  togSound.classList.toggle('on',  !!APP.cfg.sound);
  if (togToasts) togToasts.classList.toggle('on', !!APP.cfg.toasts);

  var snipRange = document.getElementById('snipRange');
  var snipVal   = document.getElementById('snipVal');
  if (snipRange) snipRange.value = APP.cfg.snipLen;
  if (snipVal)   snipVal.textContent = APP.cfg.snipLen + ' chars';
}
