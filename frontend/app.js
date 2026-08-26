/* ══════════════════════════════════════════════════════════
   GIGACL — Frontend v9
   ══════════════════════════════════════════════════════════ */
'use strict';

const S = {
  token:    localStorage.getItem('giga_token')    || null,
  username: localStorage.getItem('giga_username') || null,
  role:     localStorage.getItem('giga_role')     || null,
  maga:     localStorage.getItem('giga_mega') || localStorage.getItem('giga_maga') || 'byte',
  theme:    localStorage.getItem('giga_theme') || 'dark',
  megaVisible: false,
  switches: [],
  swIds:    JSON.parse(localStorage.getItem('giga_swIds') || '[]'),
  sites:    [],
  builtinSites: [],
  customSites:  [],
  siteOrder:    [],
  switchOrder:  [],
  roles:    [],
  logs:     [],
  logsView: [],
  dataGen:  0,
};

const isAdmin = () => S.role === 'admin' || S.role === 'super_admin';
const isSuper = () => S.role === 'super_admin';

/* ── DOM shortcuts ── */
const $  = id => document.getElementById(id);
const el = (sel, root = document) => root.querySelector(sel);
const els = (sel, root = document) => [...root.querySelectorAll(sel)];

/* ── escaping ── */
function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
                  .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
                  .replace(/'/g, '&#39;');
}
/* Safe for use inside a single-quoted JS string in an onclick attribute */
function jsq(s) {
  return String(s === null || s === undefined ? '' : s)
    .replace(/\\/g, '\\\\').replace(/'/g, "\\'")
    .replace(/"/g, '&quot;').replace(/</g, '\\u003c').replace(/\r?\n/g, ' ');
}

/* ── API ── */
const appActivities = new Map();
let appActivitySeq = 0;

function describeActivity(method, path) {
  if (path.includes('/acl/check-ip')) return [
    'Validating the IP lookup…', 'Finding the IP gateway on your switches…',
    'Reading ACLs applied to the gateway interface…', 'Preparing the matching ACL results…'];
  if (path.includes('/acl/check')) return [
    'Validating the access policy…', 'Finding source and destination gateways…',
    'Reading the applied ACLs on each side…', 'Evaluating ACL rules in first-match order…',
    'Preparing the permit or deny result…'];
  if (path.includes('/write/save-config') || path.includes('/write/bulk-save-config')) return [
    'Preparing the selected switches…', 'Saving running-config to startup-config…',
    'Confirming each switch saved successfully…'];
  if (path.includes('/write/rule-preview')) return [
    'Validating the requested ACL rule…', 'Reading the affected ACLs…',
    'Checking existing permits and effective denies…', 'Selecting safe sequence numbers…',
    'Building the rule preview…'];
  if (path.includes('/write/time-range-preview')) return [
    'Validating the time range…', 'Checking the selected switches…',
    'Building the time-range preview…'];
  if (path.includes('/dashboard/health/scan')) return [
    'Reading every switch…', 'Checking rules and TCAM use…',
    'Storing the results…'];
  if (path.includes('/dashboard/')) return ['Gathering the overview…'];
  if (path.includes('/write/') && path.includes('undo')) return [
    'Preparing the undo commands…', 'Restoring the previous switch state…',
    'Verifying the undo result…'];
  if (path.includes('/write/')) return [
    'Validating the requested change…', 'Sending configuration commands to the switch…',
    'Reading the switch response…', 'Verifying the requested configuration…'];
  if (path.includes('/analysis/redundant')) return [
    'Reading ACL rules from the switch…', 'Comparing rule coverage…',
    'Preparing redundant-rule findings…'];
  if (path.includes('/analysis/suggest-summary')) return [
    'Reading ACL rules from the switch…', 'Grouping compatible policies…',
    'Checking safer summary candidates…'];
  if (path.includes('/analysis/object-groups')) return [
    'Requesting object groups from the switch…', 'Identifying address and port groups…',
    'Preparing object-group members…'];
  if (path.includes('/analysis/view') || path.includes('/analysis/list-acls')) return [
    'Connecting to the selected switches…', 'Reading access lists and bindings…',
    'Preparing ACLs for the viewer…'];
  if (path.includes('/analysis/time-ranges')) return [
    'Reading configured time ranges…', 'Checking active and inactive states…',
    'Preparing time-range details…'];
  if (path.includes('/terminal/sessions')) return [method === 'POST'
    ? 'Connecting the switch terminal…' : 'Closing the switch terminal…'];
  if (path.includes('/switches/order')) return ['Saving your switch and label order…'];
  if (path.includes('/switches')) return [method === 'GET'
    ? 'Loading your switches…' : 'Updating switch management…'];
  if (path.includes('/auth/users')) return [method === 'GET'
    ? 'Loading user management…' : 'Updating the user account…'];
  if (path.includes('/auth/me/mega')) return ['Saving your Mega choice…'];
  if (path.includes('/auth/me/password')) return ['Updating your password…'];
  if (path.includes('/logs')) return ['Loading activity history…'];
  if (path.includes('/sites')) return ['Updating locations…'];
  if (path.includes('/meta') || path.includes('/auth/me')) return ['Preparing your workspace…'];
  return ['Preparing the request…', 'Waiting for the server response…', 'Processing the result…'];
}

function updateMegaActivityBubble() {
  const stage = $('maga-stage');
  if (!stage) return;
  const active = [...appActivities.values()].at(-1) || null;
  const message = active?.message || '';
  const status = el('[data-mega-status]', stage);
  if (status) {
    status.textContent = message;
    status.hidden = !message;
  }
  stage.classList.toggle('has-activity', Boolean(message));
  const rect = stage.getBoundingClientRect();
  const center = rect.left + stage.offsetWidth / 2;
  stage.classList.toggle('bubble-from-left', center < 175);
  stage.classList.toggle('bubble-from-right', center > window.innerWidth - 175);
  stage.classList.toggle('bubble-below', rect.top < 82);
  const picker = $('maga-options');
  if (picker) {
    picker.setAttribute('aria-busy', message ? 'true' : 'false');
    els('[data-maga-choice]', picker).forEach(button => { button.disabled = Boolean(message); });
  }
}

function beginAppActivity(messages) {
  const id = ++appActivitySeq;
  const steps = (Array.isArray(messages) ? messages : [messages]).filter(Boolean);
  const entry = { steps, index: 0, message: steps[0] || 'Working…', timer: null };
  appActivities.set(id, entry);
  if (steps.length > 1) {
    entry.timer = setInterval(() => {
      if (entry.index >= steps.length - 1) return;
      entry.index += 1;
      entry.message = `Step ${entry.index + 1} of ${steps.length} · ${steps[entry.index]}`;
      updateMegaActivityBubble();
    }, 2200);
    entry.message = `Step 1 of ${steps.length} · ${steps[0]}`;
  }
  updateMegaActivityBubble();
  return id;
}

function endAppActivity(id) {
  const entry = appActivities.get(id);
  if (entry?.timer) clearInterval(entry.timer);
  appActivities.delete(id);
  updateMegaActivityBubble();
}

class ApiError extends Error {
  constructor(message, status, kind) {
    super(message);
    this.status = status;
    this.kind = kind;
  }
}

async function api(method, path, body) {
  const activityId = beginAppActivity(describeActivity(method, path));
  const headers = {};
  if (S.token) headers.Authorization = `Bearer ${S.token}`;
  let payload;
  if (body instanceof URLSearchParams) {
    payload = body;
  } else if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }

  let res;
  try {
    res = await fetch(path, { method, headers, body: payload });
  } catch {
    endAppActivity(activityId);
    throw new ApiError('Cannot reach the server. Check that it is running.', 0, 'network');
  }

  if (res.status === 401 && S.token) {
    endAppActivity(activityId);
    clearAuth();
    showLogin();
    throw new ApiError('Your session expired. Please sign in again.', 401, 'auth');
  }

  let data = null;
  try { data = await res.json(); } catch { /* no body */ }

  if (!res.ok) {
    const detail = data && data.detail;
    const msg = typeof detail === 'string' ? detail
              : Array.isArray(detail) ? detail.map(d => d.msg).join(' ')
              : `Request failed (HTTP ${res.status}).`;
    const kind = res.status === 423 ? 'locked'
               : (data && data.kind) || 'api';
    endAppActivity(activityId);
    throw new ApiError(msg, res.status, kind);
  }
  endAppActivity(activityId);
  return data;
}

/* ── auth state ── */
function setAuth(token, username, role, maga = 'byte', megaVisible = false) {
  S.token = token; S.username = username; S.role = role; S.maga = maga || 'byte';
  S.megaVisible = !!megaVisible;
  localStorage.setItem('giga_token', token);
  localStorage.setItem('giga_username', username);
  localStorage.setItem('giga_role', role);
  localStorage.setItem('giga_mega', S.maga);
  localStorage.setItem(megaVisibilityKey(), String(S.megaVisible));
}
/* Tell the server we are going, so the account stops counting as active on
   the dashboard. Deliberately fire-and-forget: a failure here must never
   leave someone stuck in a signed-in UI, and the token is being discarded
   either way. */
function releasePresence() {
  if (!S.token) return;
  try {
    api('POST', '/api/auth/logout').catch(() => {});
  } catch (e) { /* nothing to do — we are signing out regardless */ }
}

function clearAuth() {
  closeAllTerminalWindows();
  /* Everything on screen describes the account that is leaving. Cleared here
     as well as in resetAllSectionState(), because that one spares the command
     bar unless it is showing a save result -- a distinction that matters
     between pages and not at all between people. */
  const bar = $('save-bar');
  if (bar) { bar.innerHTML = ''; delete bar.dataset.kind; delete bar.dataset.busy; }
  accessRequestCache = [];
  pendingRequestBlockers = [];
  pendingRequestAccess = null;
  // Switch-management state describes the account that is leaving.
  GRANT.users = []; GRANT.granted = [];
  if ($('sw-add-results')) $('sw-add-results').innerHTML = '';
  if ($('sw-granted-list')) $('sw-granted-list').innerHTML = '';
  if ($('sw-grant-users')) $('sw-grant-users').innerHTML = '';
  clearIdleTimer();
  stopSessionWatch();
  S.token = S.username = S.role = null; S.maga = 'byte'; S.megaVisible = false;
  S.switches = []; S.swIds = []; S.logs = []; S.logsView = [];
  S.sites = []; S.siteOrder = []; S.switchOrder = [];
  localStorage.removeItem('giga_token');
  localStorage.removeItem('giga_username');
  localStorage.removeItem('giga_role');
  localStorage.removeItem('giga_mega');
  localStorage.removeItem('giga_maga');
  localStorage.removeItem('giga_swIds');
  localStorage.removeItem('giga_page');
}

/* ── session heartbeat ── */
/* A browser that is simply sitting there makes no requests, so an account that
   was deleted (or renamed, or had its access revoked) would keep showing a
   working page until its owner happened to click something. This asks quietly
   whether the token is still good. Deliberately a bare fetch rather than api():
   a background poll is not the user doing anything, so it should not light up
   the Mega's activity bubble, and a server that is down or restarting is not a
   reason to throw somebody out of a page they are working in. */
const SESSION_CHECK_MS = 60000;
let sessionCheckTimer = null;

function stopSessionWatch() {
  if (sessionCheckTimer) { clearInterval(sessionCheckTimer); sessionCheckTimer = null; }
}

function startSessionWatch() {
  stopSessionWatch();
  if (!S.token) return;
  sessionCheckTimer = setInterval(checkSession, SESSION_CHECK_MS);
}

async function checkSession() {
  if (!S.token) return;
  let res;
  try {
    res = await fetch('/api/auth/session',
                      { headers: { Authorization: `Bearer ${S.token}` } });
  } catch { return; }
  if (res.status !== 401 || !S.token) return;
  clearAuth();
  showLogin();
  warn('Signed out', 'This account is no longer available. Please sign in again.');
}

/* ── idle-timeout auto-logout (super-admin-configured, applies to everyone) ── */
let idleTimerId = null;
let idleListenersAttached = false;
const IDLE_ACTIVITY_EVENTS = ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart', 'click'];

function clearIdleTimer() {
  if (idleTimerId) { clearTimeout(idleTimerId); idleTimerId = null; }
}

function resetIdleTimer() {
  clearIdleTimer();
  if (!S.token || !S.idleTimeoutMinutes) return;
  idleTimerId = setTimeout(idleLogout, S.idleTimeoutMinutes * 60 * 1000);
}

function idleLogout() {
  idleTimerId = null;
  if (!S.token) return;
  releasePresence();
  clearAuth();
  showLogin();
  info('Signed out', 'You were signed out after a period of inactivity.');
}

/* Wires the activity listeners once; safe to call again after every login
   since it re-applies the (possibly changed) S.idleTimeoutMinutes value. */
function armIdleTimer() {
  if (!idleListenersAttached) {
    idleListenersAttached = true;
    IDLE_ACTIVITY_EVENTS.forEach(evt =>
      document.addEventListener(evt, resetIdleTimer, { passive: true }));
  }
  resetIdleTimer();
}

/* ── toasts ── */
const TOAST_ICON = { success: '✓', error: '✕', warn: '!', info: 'i' };
function toast(kind, title, msg = '', ms = 5000, undoData = null) {
  const box = $('toasts');
  if (!box) return;
  while (box.children.length >= 3) {
    const oldest = box.firstElementChild;
    if (!oldest) break;
    if (oldest._killTimer) clearTimeout(oldest._killTimer);
    oldest.remove();
  }
  const t = document.createElement('div');
  t.className = `toast t-${kind}`;
  
  let undoBtn = '';
  if (undoData) {
    const uid = `u${Date.now()}${Math.floor(Math.random() * 1000)}`;
    window.__undo = window.__undo || {};
    window.__undo[uid] = undoData;
    undoBtn = `<button class="toast-undo" onclick="runUndoFromToast('${uid}', this)">Undo</button>`;
  }
  
  t.innerHTML = `
    <span class="toast-ico">${TOAST_ICON[kind] || 'i'}</span>
    <div class="toast-body">
      <div class="toast-title">${esc(title)}</div>
      ${msg ? `<div class="toast-msg">${esc(msg)}</div>` : ''}
      ${undoBtn}
    </div>
    <button class="toast-x" aria-label="Dismiss">✕</button>
    <span class="toast-bar" style="animation-duration:${ms}ms"></span>`;
  const kill = () => {
    t.classList.add('out');
    setTimeout(() => t.remove(), 200);
  };
  el('.toast-x', t).onclick = kill;
  box.appendChild(t);
  const timer = setTimeout(kill, ms);
  t._killTimer = timer;
}
const ok    = (t, m, undo) => toast('success', t, m, 5000, undo);
const bad   = (t, m) => toast('error',  t, m, 8000);
const warn  = (t, m) => toast('warn',   t, m, 6500);
const info  = (t, m) => toast('info',   t, m);

/* Report an error object with switch-vs-app context */
function reportError(e, fallbackTitle = 'Something went wrong') {
  if (e instanceof ApiError && e.kind === 'switch') {
    bad('Switch error', e.message);
  } else if (e instanceof ApiError && e.kind === 'network') {
    bad('Connection problem', e.message);
  } else {
    bad(fallbackTitle, e && e.message ? e.message : String(e));
  }
}

/* ── small helpers ── */
function spinner(msg = 'Working…') {
  return `<div class="loading"><span class="spinner"></span>${esc(msg)}</div>`;
}
function switchOutputBlock(output, title = 'Switch output') {
  const text = String(output || '').trim() || '(The switch returned no output.)';
  return `<details class="switch-output-block">
    <summary>Show ${esc(title.toLowerCase())}</summary>
    <div class="cli">${esc(text)}</div>
  </details>`;
}
function switchCommandResult(message, output, title = 'Switch output') {
  return `<div class="command-result"><span aria-hidden="true">✓</span>${esc(message)}</div>`
    + switchOutputBlock(output, title);
}
function setSwitchCommandResult(targetId, message, output, title = 'Switch output') {
  const target = $(targetId);
  if (target) target.innerHTML = switchCommandResult(message, output, title);
}
function revealResult(container) {
  if (!container) return;
  requestAnimationFrame(() => requestAnimationFrame(() => {
    const rect = container.getBoundingClientRect();
    if (!rect.height) return;
    const sideScroller = container.closest('.side-workspace-body');
    if (sideScroller) {
      const viewport = sideScroller.getBoundingClientRect();
      if (rect.top > viewport.bottom - 110 || rect.bottom > viewport.bottom) {
        sideScroller.scrollTo({
          top: sideScroller.scrollTop + rect.top - viewport.top - 72,
          behavior: 'smooth',
        });
      }
      return;
    }
    const mainScroller = container.closest('main.main');
    if (mainScroller) {
      const viewport = mainScroller.getBoundingClientRect();
      if (rect.top > viewport.bottom - 110 || rect.bottom > viewport.bottom) {
        mainScroller.scrollTo({
          top: Math.max(0, mainScroller.scrollTop + rect.top - viewport.top - 86),
          behavior: 'smooth',
        });
      }
      return;
    }
    if (rect.top > window.innerHeight - 130 || rect.bottom > window.innerHeight) {
      window.scrollTo({
        top: Math.max(0, window.scrollY + rect.top - 86),
        behavior: 'smooth',
      });
    }
  }));
}
function skeleton(rows = 3) {
  return `<div class="card">${'<div class="skel"></div>'.repeat(rows)}</div>`;
}
function fmtTime(iso) {
  if (!iso) return '';
  const d = new Date(/[zZ]|[+-]\d\d:\d\d$/.test(iso) ? iso : iso + 'Z');
  if (isNaN(d)) return iso;
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} `
       + `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
function setBusy(btn, busy, busyText = 'Working…') {
  if (!btn) return;
  if (busy) {
    btn.dataset.label = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span>${esc(busyText)}`;
  } else {
    btn.disabled = false;
    if (btn.dataset.label) btn.innerHTML = btn.dataset.label;
  }
}
function fieldError(elm, msg) {
  if (!elm) return;
  elm.textContent = msg;
  elm.hidden = !msg;
}

/* ── collapsible switch result builder ── */
function switchResult(switchInfo, bodyHtml, collapsed = false) {
  const { hostname, ip, type, meta = '' } = switchInfo;
  const label = hostname || ip;
  const collapsedClass = collapsed ? ' collapsed' : '';
  return `<div class="sw-result${collapsedClass}" data-switch="${esc(ip)}">
    <div class="sw-result-header">
      <div style="flex:1">
        <div class="sw-result-title">
          <svg class="sw-result-icon" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd"/>
          </svg>
          <span>${esc(label)}</span>
        </div>
        <div class="sw-result-meta">${esc(ip)} · ${esc(switchTypeLabel(type))}${meta ? ' · ' + meta : ''}</div>
      </div>
    </div>
    <div class="sw-result-body">${bodyHtml}</div>
  </div>`;
}

/* toggle switch result collapse */
function setupCollapsibleResults(container) {
  container.addEventListener('click', e => {
    const header = e.target.closest('.sw-result-header');
    if (!header) return;
    const result = header.closest('.sw-result');
    if (!result) return;
    result.classList.toggle('collapsed');
  });
}

/* ══════════ CLIENT-SIDE VALIDATION (mirrors the backend) ══════════ */
const V = {
  unsafe: /[;|&`$<>\r\n]/,

  cliSafe(v, field) {
    if (V.unsafe.test(v)) {
      throw new Error(`${field} contains characters that are not allowed (; | & \` $ < > or newlines).`);
    }
    return v.trim();
  },

  ident(v, field) {
    const s = V.cliSafe(v || '', field);
    if (!s) throw new Error(`${field} is required.`);
    if (!/^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$/.test(s)) {
      throw new Error(`${field} "${s}" is not valid. Use letters, digits, dot, dash or underscore.`);
    }
    return s;
  },

  groupIdent(v, field) {
    const s = V.cliSafe(v || '', field);
    if (!s) throw new Error(`${field} is required.`);
    if (!/^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,63}$/.test(s)) {
      throw new Error(`${field} "${s}" is not valid. Use letters, digits, dot, dash, underscore or slash.`);
    }
    return s;
  },

  ipv4(v) {
    const p = v.split('.');
    if (p.length !== 4) return false;
    return p.every(x => /^\d{1,3}$/.test(x) && +x >= 0 && +x <= 255);
  },

  addr(v, field, { any = true, group = true } = {}) {
    const s = V.cliSafe(v || '', field);
    if (!s) throw new Error(`${field} is required.`);
    const low = s.toLowerCase();
    if (low === 'any') {
      if (!any) throw new Error(`${field} cannot be "any" here.`);
      return 'any';
    }
    if (low.startsWith('addrgroup')) {
      if (!group) throw new Error(`${field} cannot be an object group here.`);
      const parts = s.split(/\s+/);
      if (parts.length !== 2) throw new Error(`${field}: use "addrgroup NAME".`);
      V.groupIdent(parts[1], `${field} group name`);
      return `addrgroup ${parts[1]}`;
    }
    if (s.includes('/')) {
      const [ip, pfx] = s.split('/');
      if (!V.ipv4(ip) || !/^\d{1,2}$/.test(pfx) || +pfx > 32) {
        throw new Error(`${field} "${s}" is not a valid subnet. Example: 10.0.0.0/24`);
      }
      return s;
    }
    if (!V.ipv4(s)) {
      const options = ['an IP (10.0.0.1)', 'a subnet (10.0.0.0/24)'];
      if (any) options.push('"any"');
      if (group) options.push('"addrgroup NAME"');
      throw new Error(`${field} "${s}" is not valid. Use ${options.join(', ')}.`);
    }
    return s;
  },

  port(v, proto) {
    if (!v || !v.trim()) return null;
    const s = V.cliSafe(v, 'Port');
    if (proto !== 'tcp' && proto !== 'udp') {
      throw new Error('A port only applies to TCP or UDP. Clear the port or change the protocol.');
    }
    if (s.toLowerCase().startsWith('portgroup')) {
      const parts = s.split(/\s+/);
      if (parts.length !== 2) throw new Error('Use "portgroup NAME".');
      V.groupIdent(parts[1], 'Port group name');
      return `portgroup ${parts[1]}`;
    }
    const one = x => {
      if (!/^\d+$/.test(x.trim())) throw new Error(`Port "${x.trim()}" must be a number.`);
      const n = +x;
      if (n < 1 || n > 65535) throw new Error(`Port ${n} is out of range (1–65535).`);
      return n;
    };
    if (s.includes('-')) {
      const [a, b] = s.split('-');
      const lo = one(a), hi = one(b);
      if (lo >= hi) throw new Error(`Port range ${lo}-${hi} is invalid: the first port must be lower.`);
      return `${lo}-${hi}`;
    }
    return String(one(s));
  },

  icmpTypes: new Set(['echo', 'echo-reply', 'unreachable', 'administratively-prohibited',
    'packet-too-big', 'time-exceeded', 'redirect', 'traceroute']),

  icmpType(v, proto) {
    if (!v || !v.trim()) return null;
    const s = V.cliSafe(v, 'ICMP type').toLowerCase();
    if (proto !== 'icmp') {
      throw new Error('An ICMP type can only be specified when the protocol is ICMP. Clear the ICMP type or change the protocol.');
    }
    if (!V.icmpTypes.has(s)) {
      throw new Error('ICMP type must be one of: echo, echo-reply, unreachable, administratively-prohibited, packet-too-big, time-exceeded, redirect, traceroute.');
    }
    return s;
  },

  prefix(v, field) {
    const s = V.cliSafe(v || '', field);
    if (!s) throw new Error(`${field} is required.`);
    if (s.includes('/')) {
      const [ip, pfx] = s.split('/');
      if (!V.ipv4(ip) || !/^\d{1,2}$/.test(pfx) || +pfx > 32) {
        throw new Error(`${field} is not a valid network prefix. Use A.B.C.D/LEN.`);
      }
      return s;
    }
    if (!V.ipv4(s)) {
      throw new Error(`${field} is not a valid network prefix. Use A.B.C.D/LEN or a bare IP.`);
    }
    return s;
  },

  portOnly(v, field = 'Port') {
    const s = V.cliSafe(v || '', field);
    if (!s) throw new Error(`${field} is required.`);
    const one = x => {
      if (!/^\d+$/.test(x.trim())) throw new Error(`${field} must be a number between 1 and 65535.`);
      const n = +x;
      if (n < 1 || n > 65535) throw new Error(`${field} must be a number between 1 and 65535.`);
      return n;
    };
    if (s.includes('-')) {
      const [a, b] = s.split('-');
      const lo = one(a), hi = one(b);
      if (lo >= hi) throw new Error(`${field} range is invalid: the first port must be lower.`);
      return `${lo}-${hi}`;
    }
    return String(one(s));
  },

  // Named port keywords Cisco IOS accepts in place of a number, mirroring
  // backend/validators.py's _IOS_*_PORTS sets. NX-OS ports stay numeric-only
  // (see V.portOnly) — the switch itself would reject a keyword there.
  iosNamedPorts: {
    tcp: new Set(['bgp','chargen','cmd','daytime','discard','domain','echo','exec','finger',
      'ftp','ftp-data','gopher','hostname','ident','irc','klogin','kshell','login','lpd','msrpc',
      'nntp','onep-plain','onep-tls','pim-auto-rp','pop2','pop3','smtp','sunrpc','tacacs','talk',
      'telnet','time','uucp','whois','www']),
    udp: new Set(['biff','bootpc','bootps','discard','dnsix','domain','echo','isakmp','mobile-ip',
      'nameserver','netbios-dgm','netbios-ns','netbios-ss','non500-isakmp','ntp','pim-auto-rp',
      'rip','ripv6','snmp','snmptrap','sunrpc','syslog','tacacs','talk','tftp','time','who','xdmcp']),
    'tcp-udp': new Set(['discard','domain','echo','pim-auto-rp','sunrpc','syslog','tacacs','talk']),
  },

  iosPort(v, protocol, field = 'Port') {
    const s = V.cliSafe(v || '', field);
    if (!s) throw new Error(`${field} is required.`);
    const named = V.iosNamedPorts[protocol] || new Set();
    const one = x => {
      const n = +x.trim();
      if (n < 1 || n > 65535) throw new Error(`${field} must be a number between 1 and 65535.`);
      return n;
    };
    // Only a strictly numeric 'LO-HI' is a range — keywords like 'ftp-data'
    // contain a hyphen themselves and must not be mistaken for one.
    const rangeM = s.match(/^(\d+)-(\d+)$/);
    if (rangeM) {
      const lo = one(rangeM[1]), hi = one(rangeM[2]);
      if (lo >= hi) throw new Error(`${field} range is invalid: the first port must be lower.`);
      return `${lo}-${hi}`;
    }
    if (s.includes('-') && !named.has(s.toLowerCase())) {
      throw new Error(`${field} must use numeric ports for a range (e.g. 8080-9000); named keywords cannot be used in a range.`);
    }
    if (/^\d+$/.test(s)) return String(one(s));
    if (named.has(s.toLowerCase())) return s.toLowerCase();
    throw new Error(`${field} must be a number between 1 and 65535, or a valid ${protocol.toUpperCase()} keyword.`);
  },

  seq(v) {
    if (!v || !v.trim()) return null;
    if (!/^\d+$/.test(v.trim())) throw new Error('Sequence number must be a whole number.');
    const n = +v;
    if (n < 1 || n > 4294967294) throw new Error('Sequence number must be between 1 and 4294967294.');
    return n;
  },

  password(v) {
    if (!v || v.length < 12) return 'Password must be at least 12 characters.';
    if (!/[A-Z]/.test(v))    return 'Password must include an uppercase letter.';
    if (!/[a-z]/.test(v))    return 'Password must include a lowercase letter.';
    if (!/\d/.test(v))       return 'Password must include a digit.';
    if (!/[^A-Za-z0-9]/.test(v)) return 'Password must include a special character.';
    return null;
  },

  time(v, field) {
    if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(v || '')) {
      throw new Error(`${field} must be in HH:MM 24-hour format.`);
    }
    return v;
  },
};

/* ══════════ SWITCH HELPERS ══════════ */
const swById   = id => S.switches.find(s => s.id === id) || null;
const aclContextForSwitch = (id, aclName, kind = 'extended') => {
  const sw = swById(id);
  const type = (sw?.switch_type || 'ios').toLowerCase();
  if (type === 'nexus' || type === 'nxos') return `ip access-list ${aclName}`;
  return `ip access-list ${kind === 'standard' ? 'standard' : 'extended'} ${aclName}`;
};
const selected = () => S.swIds.map(swById).filter(Boolean);
const primary  = () => selected()[0] || null;

function withConfiguredVpcPeer(ids) {
  const expanded = [...ids];
  if (expanded.length === 1) {
    const sw = swById(expanded[0]);
    if (sw?.vpc_peer_id && swById(sw.vpc_peer_id)) {
      expanded.push(sw.vpc_peer_id);
    }
  }
  return expanded;
}

function needSwitch() {
  if (!S.swIds.length) {
    warn('No switch selected', 'Choose a switch from the sidebar first.');
    return false;
  }
  return true;
}

function siteLabel(site) {
  return site ? site.toUpperCase() : 'UNASSIGNED';
}

/* Display only. The stored/API value stays 'nexus' or 'ios' -- every switch
   type check elsewhere compares against those, so only the label changes. */
function switchTypeLabel(type) {
  return (type || 'ios').toLowerCase() === 'nexus' ? 'NX-OS' : 'IOS';
}

function mergeOrder(preferred, fallback) {
  const available = new Set(fallback);
  return [...new Set([...(preferred || []), ...fallback])]
    .filter(value => available.has(value));
}

function orderedSiteKeys(groups = null) {
  const ordered = mergeOrder(S.siteOrder, [...S.sites, '']);
  return groups ? ordered.filter(site => groups.has(site)) : ordered;
}

function orderedSwitches(rows) {
  const positions = new Map(mergeOrder(
    S.switchOrder, S.switches.map(sw => sw.id)).map((id, index) => [id, index]));
  return [...rows].sort((a, b) => {
    const ai = positions.get(a.id);
    const bi = positions.get(b.id);
    if (ai !== bi) return (ai ?? Number.MAX_SAFE_INTEGER) - (bi ?? Number.MAX_SAFE_INTEGER);
    return (a.hostname || a.ip_address).localeCompare(b.hostname || b.ip_address);
  });
}

/* ══════════ THEME ══════════ */
/* The ids are what `data-theme` carries and what the account stores. 'dark'
   and 'light' keep the ids they have always had, so a browser that already
   holds one in localStorage keeps its colours when the choice moves to the
   account. `swatch` is only for the picker's preview chip -- the palette
   itself lives entirely in style.css. */
const THEME_CATALOG = {
  dark:    { name: 'Midnight', note: 'Indigo over near-black. Deep, low-glare, the default.',
             swatch: ['#0d1424', '#6d7cff', '#a78bfa'] },
  slate:   { name: 'Slate', note: 'Cool graphite and steel blue. Dark, with the colour dialled back.',
             swatch: ['#12161c', '#5b93c4', '#4fc3b0'] },
  carbon:  { name: 'Carbon', note: 'True black and bright white. The sharpest contrast on offer.',
             swatch: ['#0b0b0d', '#59a5ff', '#a68bff'] },
  light:   { name: 'Daylight', note: 'Midnight turned over: the same indigo on clean white.',
             swatch: ['#eef2f9', '#4f57e8', '#7c4ddb'] },
  glacier: { name: 'Glacier', note: 'Pale blue right through, so nothing on screen is pure white.',
             swatch: ['#cfe3ec', '#08697d', '#2b7fa6'] },
  evermore:{ name: 'Evermore', note: 'Warm paper and deep teal. Built for the long afternoon.',
             swatch: ['#efe7d7', '#0f7168', '#a4622b'] },
};
const DEFAULT_THEME = 'dark';

let themeSwapTimer = null;
function applyTheme(theme) {
  const safe = THEME_CATALOG[theme] ? theme : DEFAULT_THEME;
  const root = document.documentElement;
  /* Crossfade the surfaces, but only when the scheme actually changes -- the
     first paint on load must not fade in from nothing. */
  if (root.getAttribute('data-theme') && root.getAttribute('data-theme') !== safe) {
    root.classList.add('theme-swapping');
    clearTimeout(themeSwapTimer);
    themeSwapTimer = setTimeout(() => root.classList.remove('theme-swapping'), 360);
  }
  root.setAttribute('data-theme', safe);
  S.theme = safe;
  // Still mirrored to localStorage: it is what paints the login screen before
  // anyone has signed in and told us whose account this is.
  localStorage.setItem('giga_theme', safe);
  renderThemeSelector();
}

function renderThemeSelector() {
  const box = $('theme-options');
  if (!box) return;
  box.innerHTML = Object.entries(THEME_CATALOG).map(([id, theme]) => {
    const selected = (S.theme || DEFAULT_THEME) === id;
    return `<button class="theme-option ${selected ? 'is-selected' : ''}" type="button"
              role="radio" aria-checked="${selected}" data-theme-choice="${id}"
              title="${esc(theme.note)}">
      <span class="theme-swatch" aria-hidden="true">${theme.swatch.map(c =>
        `<i style="background:${esc(c)}"></i>`).join('')}</span>
      <span class="theme-option-copy">
        <strong>${esc(theme.name)}</strong>
        <small>${esc(theme.note)}</small>
      </span>
      <span class="maga-check" aria-hidden="true">✓</span>
    </button>`;
  }).join('');
}

async function chooseTheme(id) {
  if (!THEME_CATALOG[id] || id === S.theme) return;
  const previous = S.theme;
  const state = $('theme-save-state');
  // Painted first: the whole point of a theme picker is seeing the change,
  // and the request is only persisting a decision already made.
  applyTheme(id);
  if (state) state.textContent = 'Saving your theme…';
  try {
    const result = await api('PUT', '/api/auth/me/theme', { theme: id });
    applyTheme(result.theme);
    if (state) state.textContent = `${THEME_CATALOG[result.theme].name} is now your theme.`;
  } catch (error) {
    applyTheme(previous);
    reportError(error, 'Could not save your theme');
    if (state) state.textContent = 'Your selection could not be saved.';
  }
}

/* ══════════ CUSTOM SELECT ══════════
   Wraps a native <select> so the option list can be themed.
   The original element stays in the DOM, so .value and change
   events continue to work exactly as before.

   SELECT_EXTRAS lets a specific select gain an inline "add new"
   footer and per-option delete buttons.
   ==================================== */
const SELECT_EXTRAS = {};

function registerSiteSelect(id) {
  SELECT_EXTRAS[id] = {
    actionLabel: 'Add a location',
    placeholder: 'New location name',
    optionMeta(value) {
      if (!value) return null;
      // Built-ins are deletable too, but only from your own list -- the
      // server hides them per-user rather than removing them for everyone.
      if ((S.builtinSites || []).includes(value)) return { tag: 'built-in', deletable: true };
      if ((S.customSites || []).includes(value)) return { tag: 'yours', deletable: true };
      return null;
    },
    async onAdd(name) {
      if (!name) throw new Error('Enter a name.');
      if (!/^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,31}$/.test(name)) {
        throw new Error('Letters, digits, spaces, dot, dash or underscore only.');
      }
      const r = await api('POST', '/api/sites', { name });
      await refreshMeta();
      ok('Location added', r.message);
      return r.name;
    },
    async onDelete(value) {
      const using = S.switches.filter(s => s.site === value).length;
      const builtin = (S.builtinSites || []).includes(value);
      const freed = using
        ? ` ${using} switch${using === 1 ? '' : 'es'} using it will become unassigned.`
        : '';
      const proceed = await confirmDialog({
        title: builtin ? 'Remove location' : 'Delete location',
        message: builtin
          ? `Remove the built-in location "${value}" from your list?`
            + ` Other users keep it, and you can add it back later.${freed}`
          : `Delete the location "${value}"?${freed}`,
        okLabel: builtin ? 'Remove' : 'Delete', okClass: 'btn-danger',
      });
      if (!proceed) return;
      try {
        const r = await api('DELETE', `/api/sites/${encodeURIComponent(value)}`);
        ok('Location deleted', r.message);
        await refreshMeta();
        await loadSwitches();
        buildSwitchManager();
      } catch (e) { reportError(e, 'Could not delete the location'); }
    },
  };
}
function enhanceSelect(sel) {
  if (!sel || sel.dataset.enhanced === '1' || sel.multiple) return;
  sel.dataset.enhanced = '1';

  const wrap = document.createElement('div');
  wrap.className = 'sel' + (sel.classList.contains('sel-sm') ? ' sel-sm' : '');
  sel.parentNode.insertBefore(wrap, sel);
  wrap.appendChild(sel);

  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'sel-btn';
  btn.innerHTML = '<span class="sel-btn-txt"></span><span class="sel-btn-caret">▼</span>';
  wrap.appendChild(btn);

  let menu = null;
  let cursor = -1;

  const opts = () => [...sel.options];

  const syncLabel = () => {
    const o = sel.options[sel.selectedIndex];
    const txt = el('.sel-btn-txt', btn);
    txt.textContent = o ? o.textContent : '';
    txt.classList.toggle('placeholder', !!o && o.value === '');
    wrap.classList.toggle('disabled', sel.disabled);
  };

  /* Position the fixed menu against the button, flipping up when short of room
     and clamping to the viewport so it is always fully visible. */
  const placeMenu = () => {
    if (!menu) return;
    const r = btn.getBoundingClientRect();
    const gap = 5, pad = 8;
    const mw = Math.max(menu.offsetWidth, r.width);
    menu.style.minWidth = `${r.width}px`;

    let left = r.left;
    if (left + mw + pad > window.innerWidth) left = window.innerWidth - mw - pad;
    if (left < pad) left = pad;
    menu.style.left = `${Math.round(left)}px`;

    const mh = menu.offsetHeight;
    const below = window.innerHeight - r.bottom - gap - pad;
    const above = r.top - gap - pad;
    if (mh <= below || below >= above) {
      menu.style.top = `${Math.round(r.bottom + gap)}px`;
      menu.style.maxHeight = `${Math.max(120, Math.min(270, below))}px`;
    } else {
      menu.style.top = `${Math.round(Math.max(pad, r.top - gap - Math.min(mh, above)))}px`;
      menu.style.maxHeight = `${Math.max(120, Math.min(270, above))}px`;
    }
  };

  const close = () => {
    if (menu) { menu.remove(); menu = null; }
    window.removeEventListener('scroll', placeMenu, true);
    window.removeEventListener('resize', placeMenu);
    wrap.classList.remove('open');
    cursor = -1;
  };

  const paintCursor = () => {
    if (!menu) return;
    els('.sel-opt', menu).forEach((n, i) => n.classList.toggle('cursor', i === cursor));
    const active = el('.sel-opt.cursor', menu);
    if (active) active.scrollIntoView({ block: 'nearest' });
  };

  const choose = i => {
    if (i < 0 || i >= sel.options.length) return;
    if (sel.selectedIndex !== i) {
      sel.selectedIndex = i;
      sel.dispatchEvent(new Event('change', { bubbles: true }));
    }
    syncLabel();
    close();
    btn.focus();
  };

  const open = () => {
    if (sel.disabled || menu) return;
    closeAllSelects();
    const cfg = SELECT_EXTRAS[sel.id] || null;

    menu = document.createElement('div');
    menu.className = 'sel-menu';

    const rows = opts().map((o, i) => {
      const meta = cfg && cfg.optionMeta ? cfg.optionMeta(o.value) : null;
      const tag = meta && meta.tag
        ? `<span class="sel-opt-tag">${esc(meta.tag)}</span>` : '';
      const del = meta && meta.deletable
        ? `<button class="sel-opt-del" data-del="${esc(o.value)}" title="Delete">✕</button>` : '';
      /* No tick: .sel-opt.on already tints the row, colours the text and
         bolds it, and reserving a column for a mark that is absent on every
         other row pushed all the labels in from the edge. */
      return `<div class="sel-opt${i === sel.selectedIndex ? ' on' : ''}" data-i="${i}">
         <span class="sel-opt-txt">${esc(o.textContent)}</span>${tag}${del}
       </div>`;
    }).join('') || '<div class="sel-opt" style="cursor:default;opacity:.6">No options</div>';

    const footer = cfg && cfg.actionLabel
      ? `<div class="sel-sep"></div>
         <div class="sel-action" data-act="1">＋ ${esc(cfg.actionLabel)}</div>
         <div class="sel-newwrap" data-newwrap hidden>
           <div class="sel-newrow">
             <input type="text" data-newinput placeholder="${esc(cfg.placeholder || 'New value')}"
                    maxlength="32" spellcheck="false">
             <button type="button" class="btn btn-primary" data-newsave>Add</button>
           </div>
           <div class="sel-newerr" data-newerr hidden></div>
         </div>` : '';

    const searchable = sel.dataset.searchable === '1';
    const searchRow = searchable
      ? `<div class="sel-search-wrap"><input type="text" class="sel-search"
           placeholder="Search…" spellcheck="false" autocomplete="off"></div>` : '';

    menu.innerHTML = searchRow + rows + footer;
    // Attached to <body> so no ancestor with overflow can clip it
    document.body.appendChild(menu);
    wrap.classList.add('open');
    placeMenu();
    window.addEventListener('scroll', placeMenu, true);
    window.addEventListener('resize', placeMenu);

    cursor = sel.selectedIndex;
    paintCursor();

    if (searchable) {
      const search = el('.sel-search', menu);
      search.addEventListener('mousedown', ev => ev.stopPropagation());
      search.addEventListener('keydown', ev => {
        ev.stopPropagation();
        if (ev.key === 'Escape') { ev.preventDefault(); close(); btn.focus(); }
        if (ev.key === 'Enter') {
          ev.preventDefault();
          const first = els('.sel-opt[data-i]', menu).find(o => !o.hidden);
          if (first) choose(+first.dataset.i);
        }
      });
      search.addEventListener('input', () => {
        const q = search.value.trim().toLowerCase();
        els('.sel-opt[data-i]', menu).forEach(o => {
          const txt = el('.sel-opt-txt', o)?.textContent.toLowerCase() || '';
          o.hidden = Boolean(q) && !txt.includes(q);
        });
        placeMenu();
      });
      setTimeout(() => search.focus(), 10);
    }

    menu.addEventListener('mousedown', async e => {
      // delete a value
      const del = e.target.closest('[data-del]');
      if (del) {
        e.preventDefault(); e.stopPropagation();
        if (cfg && cfg.onDelete) await cfg.onDelete(del.dataset.del);
        return;
      }
      // reveal the inline add row
      if (e.target.closest('[data-act]')) {
        e.preventDefault();
        const w = el('[data-newwrap]', menu);
        w.hidden = false;
        el('[data-act]', menu).hidden = true;
        setTimeout(() => el('[data-newinput]', menu)?.focus(), 20);
        return;
      }
      // save a new value
      if (e.target.closest('[data-newsave]')) {
        e.preventDefault();
        await submitNew();
        return;
      }
      if (e.target.closest('[data-newwrap]')) { e.stopPropagation(); return; }

      const o = e.target.closest('.sel-opt[data-i]');
      if (o) { e.preventDefault(); choose(+o.dataset.i); }
    });

    // Typing inside the add row must not be hijacked by menu navigation
    const inp = el('[data-newinput]', menu);
    if (inp) {
      inp.addEventListener('keydown', ev => {
        ev.stopPropagation();
        if (ev.key === 'Enter') { ev.preventDefault(); submitNew(); }
        if (ev.key === 'Escape') { ev.preventDefault(); close(); btn.focus(); }
      });
      inp.addEventListener('mousedown', ev => ev.stopPropagation());
    }

    async function submitNew() {
      const cfg2 = SELECT_EXTRAS[sel.id];
      if (!cfg2 || !cfg2.onAdd) return;
      const input = el('[data-newinput]', menu);
      const errEl = el('[data-newerr]', menu);
      const val = (input?.value || '').trim();
      errEl.hidden = true;
      try {
        const added = await cfg2.onAdd(val);
        if (added) { close(); if (sel._selRefresh) sel._selRefresh(); sel.value = added;
                     sel.dispatchEvent(new Event('change', { bubbles: true }));
                     syncLabel(); }
      } catch (err) {
        errEl.textContent = err.message || String(err);
        errEl.hidden = false;
      }
    }
  };

  btn.addEventListener('click', e => {
    e.stopPropagation();
    menu ? close() : open();
  });

  btn.addEventListener('keydown', e => {
    const n = sel.options.length;
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      menu ? choose(cursor) : open();
    } else if (e.key === 'Escape') {
      close();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (!menu) return open();
      cursor = Math.min(n - 1, cursor + 1); paintCursor();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (!menu) return open();
      cursor = Math.max(0, cursor - 1); paintCursor();
    } else if (e.key === 'Tab') {
      close();
    }
  });

  // Keep the button label in sync when code changes the value or options
  sel.addEventListener('change', syncLabel);
  sel._selRefresh = () => { close(); syncLabel(); };
  wrap._selClose = close;
  syncLabel();
}

function closeAllSelects() {
  els('.sel.open').forEach(w => { if (w._selClose) w._selClose(); });
}

/* Enhance every select in a subtree, and refresh ones already enhanced. */
function enhanceSelects(root = document) {
  els('select', root).forEach(s => {
    if (s.dataset.enhanced === '1') { if (s._selRefresh) s._selRefresh(); }
    else enhanceSelect(s);
  });
}

/* ══════════ MODALS ══════════ */
function openModal(id)  {
  const m = $(id);
  if (!m) return;
  m.hidden = false;
  enhanceSelects(m);
}
function closeModal(id) {
  const m = $(id);
  if (!m) return;
  closeAllSelects();
  m.hidden = true;
}

/* Generic confirm dialog. Returns a Promise<boolean>. */
function confirmDialog({ title, message, commands = null, okLabel = 'Confirm',
                         okClass = 'btn-primary', extraHTML = '' }) {
  return new Promise(resolve => {
    $('cf-title').textContent = title;
    $('cf-msg').textContent = message || '';
    const wrap = $('cf-cli-wrap');
    if (commands && commands.length) {
      wrap.hidden = false;
      $('cf-cli').textContent = commands.join('\n');
    } else {
      wrap.hidden = true;
      $('cf-cli').textContent = '';
    }
    $('cf-extra').innerHTML = extraHTML || '';

    const btn = $('btn-cf-ok');
    btn.className = `btn ${okClass}`;
    btn.textContent = okLabel;

    let done = false;
    const finish = val => {
      if (done) return;
      done = true;
      btn.onclick = null;
      closeModal('m-confirm');
      resolve(val);
    };
    btn.onclick = () => finish(true);
    // Cancel handlers are wired globally via [data-close]; watch for close
    const mo = new MutationObserver(() => {
      if ($('m-confirm').hidden) { mo.disconnect(); finish(false); }
    });
    mo.observe($('m-confirm'), { attributes: true, attributeFilter: ['hidden'] });
    openModal('m-confirm');
  });
}

/* ══════════ SWITCH PICKER ══════════ */
function pickerRules() {
  const first = primary();
  const firstIsIos = first && (first.switch_type || 'ios').toLowerCase() !== 'nexus';
  return { first, firstIsIos };
}

let pickerCursor = -1;

function buildPicker() {
  pickerCursor = -1;
  const list = $('sw-dd-list');
  const hint = $('sw-dd-hint');
  if (!list) return;

  const q = ($('sw-search')?.value || '').trim().toLowerCase();
  const { first, firstIsIos } = pickerRules();

  const match = s => !q
    || (s.hostname || '').toLowerCase().includes(q)
    || s.ip_address.toLowerCase().includes(q)
    || (s.site || '').toLowerCase().includes(q);

  const visible = S.switches.filter(match);

  // Group by site
  const groups = new Map();
  visible.forEach(s => {
    const key = s.site || '';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(s);
  });
  const order = orderedSiteKeys(groups);

  if (!visible.length) {
    list.innerHTML = `<div class="sw-dd-empty">${
      S.switches.length ? 'No switch matches that search.' : 'No switches added yet.'}</div>`;
  } else {
    list.innerHTML = order.map(site => {
      const rows = orderedSwitches(groups.get(site))
        .map(s => {
          const on      = S.swIds.includes(s.id);
          const isNexus = (s.switch_type || 'ios').toLowerCase() === 'nexus';
          const isPeer  = !!first && !on && first.vpc_peer_id === s.id;
          // Never disable switches - clicking will handle deselecting automatically
          const off = false;
          const cls = ['sw-opt', on ? 'on' : '', isPeer ? 'peer' : '', off ? 'off' : '']
                        .filter(Boolean).join(' ');
          const tags = [
            on ? `<span class="badge b-accent">${S.swIds.indexOf(s.id) === 0 ? 'SELECTED' : 'PEER'}</span>` : '',
            isPeer ? '<span class="badge b-cyan">VPC PEER</span>' : '',
            (!on && !isPeer && s.vpc_peer_id) ? '<span class="badge b-gray">VPC</span>' : '',
            isReadOnlySwitch(s) ? '<span class="badge b-amber">READ</span>' : '',
          ].filter(Boolean).join('');
          return `<div class="${cls}" ${off ? '' : `data-sw="${s.id}"`}>
            <div class="sw-opt-info">
              <div class="sw-opt-name">${esc(s.hostname || s.ip_address)}</div>
              <div class="sw-opt-ip">${esc(s.ip_address)} · ${esc(switchTypeLabel(s.switch_type))}</div>
            </div>${tags ? `<span class="sw-opt-tags">${tags}</span>` : ''}</div>`;
        }).join('');
      return `<div class="sw-site-group">
        <div class="sw-site-head">${esc(siteLabel(site))}
          <span class="cnt">${groups.get(site).length}</span></div>
        ${rows}</div>`;
    }).join('');
  }

  // Hint line
  if (hint) {
    if (!S.swIds.length) {
      hint.textContent = 'Pick one switch. Two Nexus switches in a VPC pair can be selected together.';
    } else if (firstIsIos) {
      hint.textContent = 'IOS switches are managed one at a time. Deselect to choose another.';
    } else if (S.swIds.length === 1) {
      const peer = first.vpc_peer_id ? swById(first.vpc_peer_id) : null;
      hint.textContent = peer
        ? `VPC peer highlighted: ${peer.hostname || peer.ip_address}. Click it to manage both.`
        : 'Select a second Nexus switch, or set a VPC peer in Manage Switches.';
    } else {
      hint.textContent = 'Two Nexus switches selected — write operations apply to both.';
    }
  }

  renderPickerHeader();
  paintPickerCursor();
}

/* Keyboard-driven highlight for the switch picker, mirroring the generic
   .sel component's cursor/paintCursor pattern (see enhanceSelects). */
function paintPickerCursor() {
  const rows = els('.sw-opt[data-sw]', $('sw-dd-list'));
  if (!rows.length) return;
  rows.forEach((n, i) => n.classList.toggle('cursor', i === pickerCursor));
  const active = rows[pickerCursor];
  if (active) active.scrollIntoView({ block: 'nearest' });
}

function renderPickerHeader() {
  const sel  = selected();
  const main = $('sw-pick-main');
  const meta = $('sw-pick-meta');
  const btn  = $('sw-pick-btn');
  const chip = $('tb-chip');
  const chipTxt = $('tb-chip-txt');

  if (sel.length) {
    const names = sel.map(s => s.hostname || s.ip_address);
    main.textContent = names.join('  +  ');
    const sites = [...new Set(sel.map(s => siteLabel(s.site)))].join(', ');
    const readOnly = sel.filter(isReadOnlySwitch);
    meta.textContent = (sel.length > 1
      ? `VPC pair · ${sites}`
      : `${sel[0].ip_address} · ${sites}`)
      + (readOnly.length ? ' · read only' : '');
    btn.classList.add('has-sel');
    btn.classList.toggle('is-readonly', readOnly.length > 0);
    chip.hidden = false;
    chipTxt.textContent = sel.length > 1 ? names.join(' ↔ ') : names[0];
    chip.classList.toggle('is-readonly', readOnly.length > 0);
  } else {
    main.textContent = 'No switch selected';
    meta.textContent = '';
    btn.classList.remove('has-sel', 'is-readonly');
    chip.hidden = true;
    chip.classList.remove('is-readonly');
  }
  renderSaveButton();
}

/* Save button: visible whenever a switch is selected; highlighted when any
   selected switch has unsaved running-config changes. */
function renderSaveButton() {
  const btn = $('btn-save');
  if (!btn) return;
  const sel = selected();
  btn.hidden = !(isAdmin() && sel.length > 0);
  if (btn.hidden) return;

  const dirty = sel.filter(s => s.pending_changes);
  btn.classList.toggle('pending', dirty.length > 0);
  btn.classList.toggle('btn-warning', dirty.length > 0);
  btn.classList.toggle('btn-secondary', dirty.length === 0);
  const label = dirty.length
    ? `Save Config <span class="save-count">${dirty.length}</span>`
    : 'Save Config';
  el('.btn-label', btn).innerHTML = label;
  btn.title = dirty.length
    ? `Unsaved changes on: ${dirty.map(s => s.hostname || s.ip_address).join(', ')}`
    : 'Copy running-config to startup-config on the selected switch(es)';
  renderPendingNote();
}

/* The unsaved-changes banner under the top bar was removed as unwanted
   noise — the Save Config button's own highlight already communicates
   pending changes. This just clears out any leftover banner. */
function renderPendingNote() {
  const bar = $('save-bar');
  if (!bar || bar.dataset.busy === '1') return;
  if (bar.dataset.kind === 'pending') { bar.innerHTML = ''; delete bar.dataset.kind; }
}

/* ══════════ SITE LABELS ══════════ */
async function refreshMeta() {
  try {
    const m = await api('GET', '/api/meta');
    S.sites        = m.sites || [];
    S.builtinSites = m.builtin_sites || [];
    S.customSites  = m.custom_sites || [];
    S.siteOrder    = m.switch_layout?.labels || [];
    S.switchOrder  = m.switch_layout?.switch_ids || [];
    fillSiteSelects();
  } catch (e) { /* non-fatal */ }
}

function toggleSwitch(id) {
  const cand = swById(id);
  if (!cand) return;
  const idx = S.swIds.indexOf(id);
  
  // If already selected, deselect it
  if (idx >= 0) {
    S.swIds.splice(idx, 1);
  } else {
    const first = primary();
    
    // If nothing selected, select this one
    if (!S.swIds.length) {
      S.swIds = [id];
    }
    // If this is the VPC peer of the currently selected NX-OS switch, add it (multi-select)
    else if (first && first.vpc_peer_id === id && S.swIds.length === 1) {
      S.swIds.push(id);
    }
    // All other cases: replace the selection
    else {
      S.swIds = [id];
    }
  }
  
  // Save selected switch IDs to localStorage
  localStorage.setItem('giga_swIds', JSON.stringify(S.swIds));
  
  // Clear all switch-specific data displays when switching switches
  clearSwitchData();
  
  buildPicker();
  if (S.swIds.length) closePicker();
  document.dispatchEvent(new CustomEvent('giga:switch-selection-change', {
    detail: { switchIds: [...S.swIds] },
  }));
}

const PAGE_RESULT_CONTAINERS = {
  'acl-checker': ['r-check'],
  'ip-checker': ['r-ip'],
  'acl-viewer': ['r-viewer'],
  // The generated preview belongs to the switch it was generated for, so it
  // has to go when the selection changes -- it was outliving it.
  'object-groups': ['r-og', 'r-og-preview'],
  'redundant': ['r-red'],
  'summary': ['r-sum'],
  'vpc-sync': ['r-vpc-sync'],
  'rule-add': ['r-rule'],
  'add-acl': ['r-add-acl'],
  'time-range': ['r-tr-list', 'r-tr-preview'],
  'templates': ['r-templates'],
  'reverse-direction': ['r-rev'],
  'dashboard': ['r-dash-activity', 'r-dash-health', 'r-dash-requests'],
  'requests': ['r-requests'],
};

function clearCommandResultBar() {
  const bar = $('save-bar');
  if (!bar || !['save', 'save-output'].includes(bar.dataset.kind)) return;
  bar.innerHTML = '';
  delete bar.dataset.kind;
  renderPendingNote();
}

function clearPageResults(pageId) {
  (PAGE_RESULT_CONTAINERS[pageId] || []).forEach(id => {
    const container = $(id);
    if (container) container.innerHTML = '';
  });
  clearCommandResultBar();
}

/* Full reset of every section: every result/output container emptied,
   every plain field blanked, every select back to its first option, and
   growable entry lists (object groups, time ranges, templates) collapsed
   back to their clean starting state. Used on logout, on switching pages,
   and on switching the selected switch(es) — none of those should leave
   another section showing stale output or half-filled fields. */
function resetAllSectionState() {
  const containers = [...new Set(Object.values(PAGE_RESULT_CONTAINERS).flat())];
  containers.forEach(id => {
    const el = $(id);
    if (el) el.innerHTML = '';
  });
  clearCommandResultBar();

  // Toasts have their own multi-second dismiss timer, independent of page
  // state, so a recent error toast would otherwise still be sitting there.
  const toastBox = $('toasts');
  if (toastBox) {
    [...toastBox.children].forEach(t => {
      if (t._killTimer) clearTimeout(t._killTimer);
      t.remove();
    });
  }

  els('.page input[type="text"], .page input[type="search"], .page input[type="number"], '
    + '.page input:not([type]), .page textarea').forEach(i => { i.value = ''; });
  els('.page select').forEach(sel => { sel.selectedIndex = 0; });
  ['og-entries', 'tr-entries'].forEach(id => {
    const c = $(id);
    if (c) c.innerHTML = '';
  });
  resetTemplateForm();
  // Not a working field -- it mirrors a persisted server-wide setting that's
  // only (re)loaded at login, so restore its real value immediately.
  fillIdleTimeoutSelect();
  fillLogRetentionControls();
}

function clearSwitchData() {
  // Invalidate any in-flight result fetches so a late response for the
  // previous selection can't overwrite the newly selected switch's data.
  S.dataGen++;
  resetAllSectionState();
}

function closePicker() {
  $('sw-dd').hidden = true;
  $('sw-picker').classList.remove('open');
}
function togglePicker() {
  const dd = $('sw-dd');
  dd.hidden = !dd.hidden;
  $('sw-picker').classList.toggle('open', !dd.hidden);
  if (!dd.hidden) {
    buildPicker();
    setTimeout(() => $('sw-search')?.focus(), 40);
  }
}

async function openSwitchManagement() {
  closePicker();
  await refreshMeta();
  buildSwitchManager();
  // Set default SSH username to current user
  $('sw-username').placeholder = S.username;
  if (isSuper()) {
    $('sw-grant-block').hidden = false;
    renderAddResults(null);
    updateGrantTerminalVisibility();
    loadGrantUsers();
    loadGrantedSwitches();
  }
  openModal('m-switches');
}

async function loadSwitches({ silent = true } = {}) {
  try {
    S.switches = await api('GET', '/api/switches');
    S.swIds = S.swIds.filter(id => S.switches.some(s => s.id === id));
    buildPicker();
    buildSwitchManager();
    applyAccessGating();
    // Whether this account can write anywhere is only knowable once the
    // inventory has arrived, and that decides who sees My Requests.
    syncRequesterNav();
  } catch (e) {
    if (!silent) reportError(e, 'Could not load switches');
  }
}

/* ══════════ SWITCH MANAGER ══════════ */
let switchOrderSaving = false;

function buildSwitchManager() {
  const wrap = $('sw-mgr-list');
  if (!wrap) return;
  const q = ($('sw-mgr-search')?.value || '').trim().toLowerCase();
  const match = s => !q
    || (s.hostname || '').toLowerCase().includes(q)
    || s.ip_address.toLowerCase().includes(q)
    || (s.site || '').toLowerCase().includes(q);

  const visible = S.switches.filter(match);
  
  // Update bulk save button visibility
  const dirtyAll = S.switches.filter(s => s.pending_changes);
  const bulkActions = $('sw-mgr-bulk-actions');
  const bulkSaveLabel = $('bulk-save-label');
  if (bulkActions && bulkSaveLabel) {
    if (isAdmin() && dirtyAll.length > 0) {
      bulkActions.hidden = false;
      bulkSaveLabel.textContent = `Save All Unsaved Configs (${dirtyAll.length})`;
    } else {
      bulkActions.hidden = true;
    }
  } else if (bulkActions) {
    // If label doesn't exist, just hide the whole thing
    bulkActions.hidden = true;
  }
  
  if (!visible.length) {
    wrap.innerHTML = `<div class="empty"><span class="empty-icon">◇</span>${
      S.switches.length ? 'No switch matches that filter.' : 'No switches added yet.'}</div>`;
    return;
  }

  const groups = new Map();
  visible.forEach(s => {
    const k = s.site || '';
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(s);
  });
  const order = orderedSiteKeys(groups);
  const canReorder = !q;

  wrap.innerHTML = order.map(site => {
    const cards = orderedSwitches(groups.get(site))
      .map(s => {
        const isNexus = (s.switch_type || 'ios').toLowerCase() === 'nexus';
        return `<div class="sw-card">
          <div class="sw-card-info">
            <div class="sw-card-name">${esc(s.hostname || s.ip_address)}</div>
            <div class="sw-card-ip">${esc(s.ip_address)}${s.ssh_username ? ` · ${esc(s.ssh_username)}` : ''}</div>
            <div class="sw-card-tags">
              <span class="badge b-gray">${esc(switchTypeLabel(s.switch_type))}</span>
              <span class="badge b-gray">${esc(siteLabel(s.site))}</span>
              ${s.use_enable ? '<span class="badge b-amber">ENABLE</span>' : ''}
              ${s.pending_changes ? '<span class="badge b-amber">UNSAVED</span>' : ''}
              ${s.has_saved_password ? '<span class="badge b-green">PASS SAVED</span>'
                                     : '<span class="badge b-red">NO PASS</span>'}
              ${s.vpc_peer_name ? `<span class="badge b-cyan">VPC ↔ ${esc(s.vpc_peer_name)}</span>`
                                : (isNexus ? '<span class="badge b-gray">NO VPC PEER</span>' : '')}
              ${isReadOnlySwitch(s) ? '<span class="badge b-amber">READ ONLY</span>' : ''}
              ${s.created_by ? `<span class="badge b-gray">FROM ${esc(s.created_by.toUpperCase())}</span>` : ''}
            </div>
          </div>
          <div class="sw-card-btns">
            ${canReorder ? `<span class="order-buttons" aria-label="Move switch">
              <button class="order-btn" type="button" data-move-switch="${s.id}" data-direction="-1"
                title="Move switch up" aria-label="Move ${esc(s.hostname || s.ip_address)} up" ${switchOrderSaving ? 'disabled' : ''}>↑</button>
              <button class="order-btn" type="button" data-move-switch="${s.id}" data-direction="1"
                title="Move switch down" aria-label="Move ${esc(s.hostname || s.ip_address)} down" ${switchOrderSaving ? 'disabled' : ''}>↓</button>
            </span>` : ''}
            ${isNexus ? `<button class="btn btn-sm btn-secondary" data-vpc="${s.id}">VPC Peer</button>` : ''}
            <button class="btn btn-sm btn-secondary" data-edit="${s.id}">Edit</button>
            <button class="btn btn-sm btn-danger" data-del="${s.id}">Remove</button>
          </div>
        </div>`;
      }).join('');
    return `<div class="site-block">
      <div class="site-title"><span>${esc(siteLabel(site))}</span>
        ${canReorder ? `<span class="order-buttons" aria-label="Move location">
          <button class="order-btn" type="button" data-move-site="${esc(site)}" data-direction="-1"
            title="Move location up" aria-label="Move ${esc(siteLabel(site))} up" ${switchOrderSaving ? 'disabled' : ''}>↑</button>
          <button class="order-btn" type="button" data-move-site="${esc(site)}" data-direction="1"
            title="Move location down" aria-label="Move ${esc(siteLabel(site))} down" ${switchOrderSaving ? 'disabled' : ''}>↓</button>
        </span>` : ''}</div>${cards}</div>`;
  }).join('');
}

async function persistSwitchOrder(previousSites, previousSwitches) {
  switchOrderSaving = true;
  buildSwitchManager();
  try {
    const result = await api('PUT', '/api/switches/order', {
      labels: orderedSiteKeys(),
      switch_ids: mergeOrder(S.switchOrder, S.switches.map(sw => sw.id)),
    });
    S.siteOrder = result.labels || S.siteOrder;
    S.switchOrder = result.switch_ids || S.switchOrder;
  } catch (error) {
    S.siteOrder = previousSites;
    S.switchOrder = previousSwitches;
    reportError(error, 'Could not save the switch order');
  } finally {
    switchOrderSaving = false;
    buildSwitchManager();
    buildPicker();
  }
}

function moveSite(site, direction) {
  if (switchOrderSaving) return;
  const groups = new Map();
  S.switches.forEach(sw => groups.set(sw.site || '', true));
  const visible = orderedSiteKeys(groups);
  const from = visible.indexOf(site);
  const to = from + direction;
  if (from < 0 || to < 0 || to >= visible.length) return;
  const previousSites = [...S.siteOrder];
  const previousSwitches = [...S.switchOrder];
  const full = orderedSiteKeys();
  const a = full.indexOf(site);
  const b = full.indexOf(visible[to]);
  [full[a], full[b]] = [full[b], full[a]];
  S.siteOrder = full;
  buildSwitchManager();
  buildPicker();
  persistSwitchOrder(previousSites, previousSwitches);
}

function moveSwitch(switchId, direction) {
  if (switchOrderSaving) return;
  const current = swById(switchId);
  if (!current) return;
  const siblings = orderedSwitches(S.switches.filter(
    sw => (sw.site || '') === (current.site || '')));
  const from = siblings.findIndex(sw => sw.id === switchId);
  const to = from + direction;
  if (from < 0 || to < 0 || to >= siblings.length) return;
  const previousSites = [...S.siteOrder];
  const previousSwitches = [...S.switchOrder];
  const full = mergeOrder(S.switchOrder, S.switches.map(sw => sw.id));
  const a = full.indexOf(switchId);
  const b = full.indexOf(siblings[to].id);
  [full[a], full[b]] = [full[b], full[a]];
  S.switchOrder = full;
  buildSwitchManager();
  buildPicker();
  persistSwitchOrder(previousSites, previousSwitches);
}

/* ══════════ ROUTING ══════════ */
const TITLES = {
  'acl-checker': 'Access Checker', 'ip-checker': 'IP ACL Lookup',
  'acl-viewer': 'ACL Viewer', 'object-groups': 'Object Groups',
  'redundant': 'Redundancy Checker', 'summary': 'Summary Suggester',
  'vpc-sync': 'VPC Sync Check',
  'rule-add': 'Add ACL Rule', 'add-acl': 'Add ACL', 'time-range': 'Time Ranges',
  'templates': 'Templates', 'reverse-direction': 'Reverse Direction',
  'logs': 'Activity Logs', 'users': 'Users', 'change-pw': 'Change Password',
  'requests': 'My Requests',
  'dashboard': 'Dashboard',
};

const SIDE_SECTIONS = [
  { id: 'acl-checker', icon: '⌕', detail: 'Check traffic against the selected switch ACLs' },
  { id: 'ip-checker', icon: '⌖', detail: 'Find an IP interface and its applied ACL' },
  { id: 'acl-viewer', icon: '☷', detail: 'Browse access lists and interface bindings' },
  { id: 'object-groups', icon: '◫', detail: 'Inspect address and port object groups' },
  { id: 'redundant', icon: '◇', detail: 'Find redundant ACL entries' },
  { id: 'summary', icon: '✦', detail: 'Review ACL summary suggestions' },
  { id: 'vpc-sync', icon: '⇄', detail: 'Check ACL and VLAN sync between VPC peers' },
  { id: 'rule-add', icon: '＋', detail: 'Preview and add an ACL rule', admin: true },
  { id: 'add-acl', icon: '▣', detail: 'Create a brand-new ACL, optionally from a template', admin: true },
  { id: 'time-range', icon: '◷', detail: 'View and manage switch time ranges' },
  { id: 'templates', icon: '▤', detail: 'Reusable rule blocks you can apply to any ACL', admin: true },
  { id: 'reverse-direction', icon: '⇄', detail: 'Swap source and destination on an ACL', admin: true },
];

let sidePageId = null;

function currentMainPageId() {
  return el('.nav-item.active[data-page]')?.dataset.page || null;
}

function closeSideLauncher() { $('side-launcher').hidden = true; }

function buildSideLauncher() {
  const current = currentMainPageId();
  const choices = SIDE_SECTIONS.filter(item =>
    item.id !== current && (!item.admin || isAdmin()));
  $('side-launcher-list').innerHTML = choices.map(item => `
    <button class="side-launcher-option" type="button" data-side-page="${item.id}">
      <span class="side-option-icon">${item.icon}</span>
      <span class="side-option-copy"><strong>${esc(TITLES[item.id])}</strong>
        <small>${esc(item.detail)}</small></span>
      <span aria-hidden="true">›</span>
    </button>`).join('');
}

function openSideLauncher() {
  if (!S.swIds.length) {
    return warn('No switch selected', 'Choose a switch before opening a Side Tab.');
  }
  buildSideLauncher();
  $('side-launcher').hidden = false;
  setTimeout(() => el('.side-launcher-option')?.focus(), 30);
}

function closeSideWorkspace() {
  if (sidePageId) {
    clearPageResults(sidePageId);
    const page = $('pg-' + sidePageId);
    if (page) {
      page.classList.remove('side-active');
      el('main.main')?.appendChild(page);
    }
  }
  sidePageId = null;
  $('side-workspace').hidden = true;
  $('side-workspace-body').replaceChildren();
  $('btn-side-panel').setAttribute('aria-expanded', 'false');
}

function openSidePage(id) {
  if (!SIDE_SECTIONS.some(item => item.id === id && (!item.admin || isAdmin()))) return;
  if (id === currentMainPageId()) {
    closeSideLauncher();
    return info('Already open', `${TITLES[id]} is already open in the main workspace.`);
  }
  if (sidePageId) closeSideWorkspace();
  const page = $('pg-' + id);
  if (!page) return;
  page.classList.remove('active');
  page.classList.add('side-active');
  $('side-workspace-body').appendChild(page);
  sidePageId = id;
  $('side-workspace-title').textContent = TITLES[id] || '';
  $('side-workspace').hidden = false;
  $('btn-side-panel').setAttribute('aria-expanded', 'true');
  closeSideLauncher();
}

/* ══════════ INTERACTIVE SSH TERMINAL ══════════ */
if (false) { // Replaced by terminal.js multi-workspace implementation.
const terminalState = {
  sessionId: null,
  socket: null,
  entries: [],
  resizeObserver: null,
  closing: false,
  syncInput: false,
};

function terminalSocketSend(message) {
  if (terminalState.socket?.readyState === WebSocket.OPEN) {
    terminalState.socket.send(JSON.stringify(message));
  }
}

function fitTerminals() {
  if ($('terminal-window').hidden || $('terminal-window').classList.contains('is-minimized')) return;
  terminalState.entries.forEach(entry => {
    try { entry.fit.fit(); } catch { /* pane may still be laying out */ }
  });
}

function terminalStatus(index, status, message) {
  const entry = terminalState.entries[index];
  if (!entry) return;
  entry.status = status;
  entry.dot.className = `terminal-status-dot ${status}`;
  if (status === 'connected') {
    entry.overlay.hidden = true;
    setTimeout(() => entry.term.focus(), 20);
  } else if (status === 'connecting') {
    entry.overlay.hidden = false;
    entry.overlay.textContent = message || 'Connecting…';
  } else {
    entry.overlay.hidden = false;
    entry.overlay.textContent = message || 'SSH connection closed.';
  }
}

function terminalAllEnded() {
  return terminalState.entries.length > 0 && terminalState.entries.every(entry =>
    entry.status === 'error' || entry.status === 'disconnected');
}

function disposeTerminalClient() {
  terminalState.resizeObserver?.disconnect();
  terminalState.resizeObserver = null;
  terminalState.entries.forEach(entry => {
    try { entry.term.dispose(); } catch { /* already disposed */ }
  });
  terminalState.entries = [];
  $('terminal-body').replaceChildren();
}

function closeTerminalWindow() {
  if (!terminalState.sessionId && $('terminal-window')?.hidden) return;
  terminalState.closing = true;
  const sessionId = terminalState.sessionId;
  terminalSocketSend({ type: 'close' });
  try { terminalState.socket?.close(1000, 'Terminal closed by user'); } catch { /* closed */ }
  terminalState.socket = null;

  // Releases a reservation even if the WebSocket had not connected yet.
  if (sessionId && S.token) {
    fetch(`/api/terminal/sessions/${encodeURIComponent(sessionId)}`, {
      method: 'DELETE', headers: { Authorization: `Bearer ${S.token}` },
    }).catch(() => {});
  }
  terminalState.sessionId = null;
  disposeTerminalClient();
  const win = $('terminal-window');
  win.hidden = true;
  win.classList.remove('is-minimized', 'is-fullscreen', 'has-dual');
  terminalState.syncInput = false;
  $('btn-terminal-sync').hidden = true;
  $('btn-terminal-sync').classList.remove('is-active');
  $('btn-terminal-sync').setAttribute('aria-pressed', 'false');
  $('btn-terminal-min').textContent = '—';
  $('btn-terminal-min').title = 'Minimize terminal';
  $('btn-terminal-max').textContent = '□';
  $('btn-terminal-max').title = 'Enter full screen';
  terminalState.closing = false;
}

function buildTerminalPanes(switches) {
  const body = $('terminal-body');
  const dual = switches.length === 2;
  $('terminal-window').classList.toggle('has-dual', dual);
  $('btn-terminal-sync').hidden = !dual;
  body.style.setProperty('--terminal-count', switches.length);
  body.innerHTML = switches.map((sw, index) => `
    <div class="terminal-pane" data-terminal="${index}">
      <div class="terminal-pane-head">
        <span class="terminal-status-dot connecting"></span>
        <strong>${esc(sw.name)}</strong><span class="terminal-ip">${esc(sw.ip)}</span>
      </div>
      <div class="terminal-surface" id="terminal-surface-${index}"></div>
      <div class="terminal-overlay">Preparing secure terminal…</div>
    </div>`).join('');

  terminalState.entries = switches.map((sw, index) => {
    const term = new window.Terminal({
      cursorBlink: true,
      cursorStyle: 'block',
      fontFamily: '"JetBrains Mono", Consolas, monospace',
      fontSize: 13,
      lineHeight: 1.18,
      scrollback: 5000,
      convertEol: true,
      theme: {
        background: '#080b12', foreground: '#dce3ef', cursor: '#75e6b4',
        selectionBackground: '#35445f', black: '#111827', brightBlack: '#64748b',
        red: '#f05b6e', green: '#4ade80', yellow: '#facc15', blue: '#60a5fa',
        magenta: '#c084fc', cyan: '#67e8f9', white: '#e5e7eb',
      },
    });
    const fit = new window.FitAddon.FitAddon();
    term.loadAddon(fit);
    term.open($(`terminal-surface-${index}`));
    term.onData(data => {
      const destinations = terminalState.syncInput
        ? terminalState.entries
            .map((entry, terminal) => ({ entry, terminal }))
            .filter(item => item.entry.status === 'connected')
            .map(item => item.terminal)
        : [index];
      destinations.forEach(terminal =>
        terminalSocketSend({ type: 'input', terminal, data }));
    });
    term.onResize(size => terminalSocketSend({
      type: 'resize', terminal: index, cols: size.cols, rows: size.rows,
    }));
    const pane = el(`.terminal-pane[data-terminal="${index}"]`, body);
    return {
      sw, term, fit, status: 'connecting',
      dot: el('.terminal-status-dot', pane),
      overlay: el('.terminal-overlay', pane),
    };
  });

  terminalState.resizeObserver = new ResizeObserver(() =>
    requestAnimationFrame(fitTerminals));
  terminalState.resizeObserver.observe($('terminal-window'));
  requestAnimationFrame(() => { fitTerminals(); terminalState.entries[0]?.term.focus(); });
}

async function openTerminalWindow() {
  if (!isAdmin()) return bad('Access denied', 'Only administrators can open switch terminals.');
  if (terminalState.sessionId) {
    $('terminal-window').hidden = false;
    $('terminal-window').classList.remove('is-minimized');
    fitTerminals();
    return info('Terminal already active', 'Close the current terminal before opening another.');
  }
  if (!needSwitch()) return;
  const switches = selected();
  if (switches.length > 2) return bad('Too many switches', 'Select one switch or one VPC pair.');
  if (switches.length === 2 &&
      (switches[0].vpc_peer_id !== switches[1].id ||
       switches[1].vpc_peer_id !== switches[0].id)) {
    return bad('Not a VPC pair', 'Two terminals can only be opened for a configured VPC pair.');
  }
  const missingPassword = switches.find(sw => !sw.has_saved_password);
  if (missingPassword) {
    return bad('Saved password required',
      `Save the SSH password for ${missingPassword.hostname || missingPassword.ip_address} first.`);
  }
  if (!window.Terminal || !window.FitAddon?.FitAddon) {
    return bad('Terminal unavailable', 'The local terminal renderer could not be loaded.');
  }

  const button = $('btn-terminal');
  setBusy(button, true, 'Opening…');
  try {
    const response = await api('POST', '/api/terminal/sessions', { switch_ids: S.swIds });
    terminalState.sessionId = response.session_id;
    terminalState.closing = false;
    $('terminal-head-sub').textContent = response.switches.map(sw => sw.name).join(' · ');
    $('terminal-window').hidden = false;
    buildTerminalPanes(response.switches);

    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const socket = new WebSocket(
      `${protocol}//${location.host}/api/terminal/ws/${encodeURIComponent(response.session_id)}`);
    terminalState.socket = socket;
    socket.addEventListener('open', () => requestAnimationFrame(fitTerminals));
    socket.addEventListener('message', event => {
      if (terminalState.socket !== socket) return;
      let message;
      try { message = JSON.parse(event.data); } catch { return; }
      const index = Number(message.terminal);
      if (message.type === 'output' && terminalState.entries[index]) {
        terminalState.entries[index].term.write(message.data || '');
      } else if (message.type === 'status') {
        terminalStatus(index, message.status, message.message);
        if (message.status === 'error') bad('SSH connection failed', message.message);
        if (terminalAllEnded()) setTimeout(closeTerminalWindow, 900);
      } else if (message.type === 'ended') {
        if (message.message && !terminalState.closing) info('Terminal ended', message.message);
        setTimeout(closeTerminalWindow, 250);
      }
    });
    socket.addEventListener('close', () => {
      if (terminalState.socket !== socket) return;
      if (!terminalState.closing && terminalState.sessionId) {
        setTimeout(closeTerminalWindow, 250);
      }
    });
    socket.addEventListener('error', () => {
      if (terminalState.socket !== socket) return;
      if (!terminalState.closing) bad('Terminal connection lost', 'The terminal WebSocket could not connect.');
    });
  } catch (error) {
    closeTerminalWindow();
    reportError(error, 'Could not open the terminal');
  } finally {
    setBusy(button, false);
  }
}

function toggleTerminalMinimize() {
  const win = $('terminal-window');
  const minimized = win.classList.toggle('is-minimized');
  if (minimized) win.classList.remove('is-fullscreen');
  $('btn-terminal-min').textContent = minimized ? '▢' : '—';
  $('btn-terminal-min').title = minimized ? 'Restore terminal' : 'Minimize terminal';
  requestAnimationFrame(fitTerminals);
}

function toggleTerminalFullscreen() {
  const win = $('terminal-window');
  win.classList.remove('is-minimized');
  const fullscreen = win.classList.toggle('is-fullscreen');
  $('btn-terminal-max').textContent = fullscreen ? '❐' : '□';
  $('btn-terminal-max').title = fullscreen ? 'Exit full screen' : 'Enter full screen';
  requestAnimationFrame(fitTerminals);
}

function toggleTerminalSync() {
  if (terminalState.entries.length !== 2) return;
  terminalState.syncInput = !terminalState.syncInput;
  const button = $('btn-terminal-sync');
  button.classList.toggle('is-active', terminalState.syncInput);
  button.setAttribute('aria-pressed', terminalState.syncInput ? 'true' : 'false');
  button.title = terminalState.syncInput
    ? 'Synchronized input is on — click to disable'
    : 'Synchronize input between both VPC terminals';
  if (terminalState.syncInput) {
    info('VPC input synchronized', 'Keyboard input will be sent to both connected switches.');
  }
  terminalState.entries[0]?.term.focus();
}
}

function showPage(id) {
  // A read-only switch makes the write pages unavailable, however they are
  // reached — a nav click, a deep link, or a programmatic jump.
  if (WRITE_PAGES.includes(id) && S.swIds.length && !selectedCanWrite()) {
    warn('Read-only switch', readOnlySelectionNote()
      + ' That page changes a switch, so it is unavailable.');
    return;
  }
  const previousPage = currentMainPageId();
  if (previousPage && previousPage !== id) {
    clearMegaRuleSuggestion();
    resetAllSectionState();
  }
  if (id === sidePageId) closeSideWorkspace();
  els('.page').forEach(p => p.classList.remove('active'));
  els('.nav-item').forEach(n => n.classList.remove('active'));
  $('pg-' + id)?.classList.add('active');
  el(`.nav-item[data-page="${id}"]`)?.classList.add('active');
  $('tb-title').textContent = TITLES[id] || '';
  if (id === 'users') {
    renderMagaSelector();
    renderThemeSelector();
    if (isAdmin()) loadUsers();
  }
  if (id === 'logs')  loadLogs();
  if (id === 'requests') loadMyRequests();
  if (id === 'dashboard') loadDashboard();
  if (id === 'vpc-sync') updateVpcSyncEligibility();
  if (id === 'templates') {
    if (!$('tpl-lines').children.length) addTplLineRow();
    loadTemplateShareCandidates();
    loadTemplates();
  }
  if (id === 'add-acl') {
    updateAclCreateKindVisibility();
    loadTemplates().then(populateAclCreateTemplateSelect);
    updateAclCreateEligibility();
  }
  // Save current page to localStorage
  localStorage.setItem('giga_page', id);
  closeMobileNav();
}

function setMobileNav(open) {
  const app = $('app-screen');
  const backdrop = $('sidebar-backdrop');
  const button = $('btn-mobile-menu');
  if (!app || !backdrop || !button) return;
  const enabled = window.matchMedia('(max-width: 860px)').matches;
  const shouldOpen = enabled && open;
  app.classList.toggle('nav-open', shouldOpen);
  backdrop.hidden = !shouldOpen;
  button.setAttribute('aria-expanded', shouldOpen ? 'true' : 'false');
  document.body.classList.toggle('mobile-nav-open', shouldOpen);
}

function closeMobileNav() { setMobileNav(false); }

function showLogin() {
  closeSideLauncher();
  closeSideWorkspace();
  closeMobileNav();
  $('app-screen').hidden = true;
  $('maga-stage').hidden = true;
  $('login-screen').hidden = false;
  $('login-password').value = '';
  setTimeout(() => $('login-username')?.focus(), 60);
}

async function showApp() {
  closeMobileNav();
  $('login-screen').hidden = true;
  $('app-screen').hidden = false;
  $('u-name').textContent = S.username || '';
  $('u-role').textContent = S.role === 'super_admin' ? 'Super Admin'
                          : S.role === 'admin' ? 'Administrator' : 'User';
  $('avatar').textContent = (S.username || 'U')[0].toUpperCase();
  S.megaVisible = localStorage.getItem(megaVisibilityKey()) === 'true';
  syncMegaVisibilityControl();
  renderMagaStage();
  els('.admin-only').forEach(e => { e.hidden = !isAdmin(); });
  els('.super-only').forEach(e => { e.hidden = !isSuper(); });
  syncRequesterNav();
  if ($('idle-timeout-wrap')) $('idle-timeout-wrap').hidden = !isSuper();
  if ($('log-retention-wrap')) $('log-retention-wrap').hidden = !isSuper();
  const scope = $('logs-scope');
  if (scope) scope.textContent = isSuper()
    ? 'Activity for every user (super admin view)'
    : 'Your activity history';

  try {
    const meta = await api('GET', '/api/meta');
    S.sites        = meta.sites || [];
    S.builtinSites = meta.builtin_sites || [];
    S.customSites  = meta.custom_sites || [];
    S.siteOrder    = meta.switch_layout?.labels || [];
    S.switchOrder  = meta.switch_layout?.switch_ids || [];
    S.roles        = meta.roles || [];
    S.idleTimeoutMinutes = meta.idle_timeout_minutes || 0;
    S.logAutoDeleteDays = meta.log_auto_delete_days || 0;
    S.logAutoDeleteZip = !!meta.log_auto_delete_zip;
    S.logRetentionLastRun = meta.log_retention_last_run || null;
  } catch { /* non-fatal */ }
  registerSiteSelect('sw-site');
  registerSiteSelect('esw-site');
  fillSiteSelects();
  fillRoleSelect();
  fillIdleTimeoutSelect();
  fillLogRetentionControls();
  enhanceSelects(document);
  armIdleTimer();
  startSessionWatch();
  await loadSwitches();
  announceAnsweredRequests();
  // Restore the last viewed page. Admins (and super admins) land on the
  // Dashboard; anyone else carrying a stale 'dashboard' falls back, because
  // showPage itself does no permission check and would otherwise open a
  // hidden section.
  const stored = localStorage.getItem('giga_page');
  const home = isAdmin() ? 'dashboard' : 'acl-checker';
  const lastPage = (!stored || (stored === 'dashboard' && !isAdmin()))
    ? home : stored;
  showPage(lastPage);
}

function fillSiteSelects() {
  const opts = '<option value="">Unassigned</option>'
    + S.sites.map(s => `<option value="${esc(s)}">${esc(s.toUpperCase())}</option>`).join('');
  ['sw-site', 'esw-site'].forEach(id => {
    const e = $(id);
    if (!e) return;
    e.innerHTML = opts;
    if (e._selRefresh) e._selRefresh();
  });
}
function fillRoleSelect() {
  const sel = $('nu-role');
  if (!sel) return;
  const label = { user: 'user', admin: 'admin', super_admin: 'super admin' };
  sel.innerHTML = S.roles
    .filter(r => r !== 'super_admin' || isSuper())
    .map(r => `<option value="${esc(r)}">${esc(label[r] || r)}</option>`).join('');
  if (sel._selRefresh) sel._selRefresh();
}
function fillIdleTimeoutSelect() {
  const sel = $('idle-timeout-select');
  if (!sel) return;
  sel.value = String(S.idleTimeoutMinutes || 0);
  if (sel._selRefresh) sel._selRefresh();
}
function fillLogRetentionControls() {
  const sel = $('log-auto-delete-select');
  if (!sel) return;
  sel.value = String(S.logAutoDeleteDays || 0);
  if (sel._selRefresh) sel._selRefresh();
  $('log-auto-delete-zip').checked = !!S.logAutoDeleteZip;
  const hint = $('log-retention-last-run');
  hint.textContent = S.logRetentionLastRun
    ? `Last automatic sweep: ${fmtTime(S.logRetentionLastRun)}` : '';
}

/* ══════════ PICKER MODAL (ACLs / groups) ══════════ */
let pickResolve = null;
function openPicker(title, items) {
  return new Promise(resolve => {
    pickResolve = resolve;
    $('pick-title').textContent = title;
    $('pick-body').innerHTML = items.length
      ? items.map(i => `<button class="pick-item" data-pick="${esc(i.value)}">${
            esc(i.label)}${i.hint ? ` <span class="pick-hint ${esc(i.hintClass || '')}">${esc(i.hint)}</span>` : ''
          }</button>`).join('')
      : '<div class="empty"><span class="empty-icon">◇</span>Nothing to choose from.</div>';
    let done = false;
    const finish = v => { if (done) return; done = true; closeModal('m-pick'); resolve(v); };
    const mo = new MutationObserver(() => {
      if ($('m-pick').hidden) { mo.disconnect(); finish(null); }
    });
    mo.observe($('m-pick'), { attributes: true, attributeFilter: ['hidden'] });
    openModal('m-pick');
  });
}

async function pickAcl(target) {
  if (!needSwitch()) return;
  try {
    const d = await api('POST', '/api/analysis/list-acls', { switch_ids: S.swIds });
    const names = d.acl_names || [];
    if (!names.length) {
      warn('No ACLs found', 'The selected switch has no IP access lists.');
      return;
    }
    const v = await openPicker('Select ACL', names.map(n => ({ value: n, label: n })));
    if (v) $(target).value = v;
  } catch (e) { reportError(e, 'Could not list ACLs'); }
}

async function pickGroup(target, kind) {
  if (!needSwitch()) return;
  try {
    const d = await api('POST', '/api/analysis/object-groups', { switch_ids: [S.swIds[0]] });
    const sw = (d.switches || [])[0];
    if (sw && sw.error) { bad('Switch error', sw.error); return; }
    const groups = (sw?.groups || []).filter(g => g.kind === kind);
    if (!groups.length) {
      warn(`No ${kind} groups`, `The switch has no ${kind} object groups configured.`);
      return;
    }
    const v = await openPicker(kind === 'port' ? 'Select Port Group' : 'Select Address Group',
      groups.map(g => ({ value: g.name, label: g.name,
                         hint: `${g.members.length} member${g.members.length === 1 ? '' : 's'}` })));
    if (v) {
      $(target).value = `${kind === 'port' ? 'portgroup' : 'addrgroup'} ${v}`;
      // Programmatic fills don't fire 'input' on their own; anything keyed to
      // this field (e.g. the 'established' offer) must still re-evaluate.
      $(target).dispatchEvent(new Event('input', { bubbles: true }));
    }
  } catch (e) { reportError(e, 'Could not list object groups'); }
}

async function pickRuleTimeRange(target) {
  if (!needSwitch()) return;
  try {
    const d = await api('POST', '/api/analysis/time-ranges', {
      switch_ids: withConfiguredVpcPeer(S.swIds),
    });
    const failed = (d.switches || []).filter(row => row.error);
    if (failed.length) throw new Error(failed[0].error);
    const rows = (d.switches || []).filter(row => !row.error);
    if (!rows.length) {
      const message = (d.switches || []).find(row => row.error)?.error
        || 'The selected switch did not return any time ranges.';
      throw new Error(message);
    }
    const firstRanges = rows[0].time_ranges || [];
    const common = firstRanges.filter(range => rows.every(row =>
      (row.time_ranges || []).some(item =>
        item.name.toLowerCase() === range.name.toLowerCase())));
    if (!common.length) {
      warn('No common time ranges', S.swIds.length > 1
        ? 'No time range is configured on both selected VPC peers.'
        : 'No time ranges are configured on the selected switch.');
      return;
    }
    const value = await openPicker('Select Time Range', common.map(range => ({
      value: range.name,
      label: range.name,
      hint: `· ${timeRangeStatus(range).toUpperCase()}`,
      hintClass: `is-${timeRangeStatus(range)}`,
    })));
    if (value !== null) $(target).value = value;
  } catch (e) {
    reportError(e, 'Could not list time ranges');
  }
}

function timeRangeStatus(range) {
  if (!(range.entries || []).length) return 'empty';
  return ['active', 'inactive'].includes(range.status)
    ? range.status
    : 'unknown';
}

/* ══════════ RENDER HELPERS ══════════ */
function swGroup(sr, bodyHTML, collapseIndex = 0) {
  // For multi-switch results, use collapsible format
  // For VPC pairs (2 switches), expand both; for 3+, collapse after second
  if (collapseIndex !== null && collapseIndex !== undefined) {
    const meta = sr.pending_changes ? 'UNSAVED' : '';
    return switchResult(
      {
        hostname: sr.switch_name,
        ip: sr.switch_ip || '',
        type: sr.is_nexus ? 'nexus' : 'ios',
        meta
      },
      bodyHTML,
      collapseIndex > 1  // Collapse only after first two switches
    );
  }
  // Fallback for single switch (backwards compatibility)
  const tags = [
    sr.is_nexus ? '<span class="badge b-cyan">NX-OS</span>' : '<span class="badge b-gray">IOS</span>',
  ].join('');
  return `<div class="swg">
    <div class="swg-head"><span class="dot dot-green"></span>
      <span>${esc(sr.switch_name)}</span>
      <span class="ip">${esc(sr.switch_ip || '')}</span>${tags}</div>
    <div class="swg-body">${bodyHTML}</div></div>`;
}

function ruleRows(rules, opts = {}) {
  if (!rules || !rules.length) {
    return '<div style="color:var(--muted);font-size:12px;padding:6px 0">This ACL has no rules.</div>';
  }
  return rules.map(r => {
    const m = r.match(/^(\d+)\s+(.*)$/);
    const seq = m ? m[1] : '';
    const body = m ? m[2] : r;
    const permit = /^permit/i.test(body.trim());
    const edit = opts.editable && seq
      ? `<button type="button" class="btn btn-xs btn-secondary" data-view-edit-rule
          data-switch-id="${opts.switchId}" data-acl-name="${esc(opts.aclName)}"
          data-acl-kind="${esc(opts.aclKind || 'extended')}"
          data-rule="${esc(r)}">Edit</button>`
      : '';
    const del = opts.deletable && seq
      ? `<button class="btn btn-xs btn-danger" onclick="delRule(${opts.switchId},'${jsq(opts.aclName)}',${seq},'${jsq(opts.aclKind || 'extended')}')">✕</button>`
      : '';
    return `<div class="rule"><span class="rule-seq">${esc(seq)}</span>
      <span class="rule-txt ${permit ? 'rule-permit' : 'rule-deny'}">${esc(body)}</span>
      ${edit}${del}</div>`;
  }).join('');
}

function aclPanel(acl, opts = {}) {
  const ifaces = (acl.applied_on || []);
  const tags = ifaces.length
    ? ifaces.map(a => `<span class="iface-tag">${esc(a.interface || '?')} <strong>${esc(a.direction)}</strong>
        ${opts.editable && /^vlan\d+$/i.test(a.interface || '')
          ? `<button type="button" class="iface-remove" data-view-detach-acl
              data-switch-id="${opts.switchId}" data-acl-name="${esc(acl.acl_name)}"
              data-interface="${esc(a.interface)}" data-direction="${esc(a.direction)}"
              title="Remove this VLAN binding" aria-label="Remove ${esc(acl.acl_name)} from ${esc(a.interface)}">✕</button>`
          : ''}</span>`).join('')
    : '<span style="font-size:11.5px;color:var(--muted)">Not applied to any interface</span>';
  const badge = ifaces.length
    ? `<span class="badge b-accent">${ifaces.length} interface${ifaces.length === 1 ? '' : 's'}</span>`
    : '<span class="badge b-gray">unused</span>';
  const adminTools = opts.editable ? `<div class="viewer-admin-tools">
      <form class="viewer-action" data-view-add-rule data-switch-id="${opts.switchId}"
            data-acl-name="${esc(acl.acl_name)}" data-acl-kind="${esc(acl.acl_kind || 'extended')}" novalidate>
        <div class="field"><label>Add rule manually <span class="label-hint">sequence required · permit or deny</span></label>
          <input type="text" name="rule" maxlength="400" spellcheck="false"
            placeholder="110 permit tcp host 10.0.0.1 any eq 443"></div>
        <button type="submit" class="btn btn-sm btn-primary">Add Rule</button>
        <span class="viewer-scope-note" style="grid-column:1/-1">The rule affects every interface where this ACL is applied.</span>
        <div class="viewer-action-status" style="grid-column:1/-1"></div>
      </form>
      <form class="viewer-action viewer-vlan-action" data-view-attach-acl
            data-switch-id="${opts.switchId}" data-acl-name="${esc(acl.acl_name)}" novalidate>
        <div class="field"><label>Apply ACL to VLAN</label>
          <input type="text" name="vlan" maxlength="8" inputmode="numeric"
            placeholder="748" spellcheck="false"></div>
        <div class="field"><label>Direction</label><select name="direction">
          <option value="in">Inbound</option><option value="out">Outbound</option></select></div>
        <button type="submit" class="btn btn-sm btn-secondary">Apply to VLAN</button>
        <div class="viewer-action-status"></div>
      </form>
    </div>` : '';
  return `<div class="acl" data-viewer-acl="${esc(acl.acl_name)}" data-switch-id="${opts.switchId || ''}">
    <div class="acl-head">
      <span onclick="this.closest('.acl').classList.toggle('open')" style="display:flex;align-items:center;gap:10px;flex:1;cursor:pointer;min-width:0">
        <span class="acl-name">${esc(acl.acl_name)}</span>
        <span class="acl-stats">${acl.total_rules || 0} rules</span>${badge}
        <span class="acl-caret">▼</span></span>
      <button type="button" class="btn btn-xs btn-secondary" data-view-report-acl
          data-switch-id="${opts.switchId}" data-acl-name="${esc(acl.acl_name)}"
          title="Plain-language report of what this ACL allows and blocks">Report</button>
      ${opts.editable ? `<button type="button" class="btn btn-xs btn-danger" data-view-delete-acl
          data-switch-id="${opts.switchId}" data-acl-name="${esc(acl.acl_name)}"
          data-acl-kind="${esc(acl.acl_kind || 'extended')}" data-interface-count="${ifaces.length}"
          title="Delete this ACL">Delete</button>` : ''}
    </div>
    <div class="acl-body">
      <div class="acl-ifaces">${tags}</div>
      ${adminTools}
      <div class="rules">${ruleRows(acl.rules, { ...opts, aclName: acl.acl_name, aclKind: acl.acl_kind })}</div>
    </div></div>`;
}

/* ══════════ RENDERERS ══════════ */

function renderCheck(d) {
  const rows = d.switches || [];
  if (!rows.length) return '<div class="alert a-warn">No switch returned a result.</div>';
  const useCollapsible = rows.length > 1;
  const resultHtml = rows.map((sr, idx) => {
    if (sr.error) return swGroup(sr, `<div class="alert a-error">${esc(sr.error)}</div>`, useCollapsible ? idx : null);
    if (!sr.on_this_switch) {
      return swGroup(sr, `<div class="alert a-info">${esc(sr.note || 'Not relevant to this switch.')}</div>
        ${sr.src_route || sr.dst_route ? `<details><summary>Show route output</summary>
          <div class="cli">${esc((sr.src_route || '') + '\n\n' + (sr.dst_route || ''))}</div></details>` : ''}`, useCollapsible ? idx : null);
    }
    const side = (obj, label, ip) => {
      if (!obj) return '';
      const rawVerdict = (obj.verdict || 'N/A').toUpperCase();
      const v = rawVerdict === 'PERMITTED' ? 'PERMIT'
              : rawVerdict === 'DENIED' ? 'DENY'
              : rawVerdict;
      const c = v === 'PERMIT' ? 'ok'
              : v === 'DENY' ? 'no'
              : 'na';
      const ic = v === 'PERMIT' ? '✓'
               : v === 'DENY' ? '✕'
               : '—';
      
      // Show expired time-range matches if any
      let expiredNote = '';
      if (obj.expired_time_range_matches && obj.expired_time_range_matches.length > 0) {
        const expiredRules = obj.expired_time_range_matches.map(m => 
          `<div class="cli" style="margin-top:6px;opacity:0.8"><strong>Expired:</strong> ${esc(m.rule)}<br><em style="font-size:11px">Time-range "${esc(m.time_range)}" is not active (would have ${esc((m.action || '').replace('PERMITTED', 'PERMIT').replace('DENIED', 'DENY'))})</em></div>`
        ).join('');
        expiredNote = `<div class="alert a-warn" style="margin-top:10px;font-size:12px">
          <strong>⏱ Expired Time-Range Matches</strong><br>
          This traffic matched ${obj.expired_time_range_matches.length} rule(s) with inactive time-ranges:
          ${expiredRules}
        </div>`;
      }
      
      return `<div class="verdict ${c}">
        <div class="v-label">${esc(label)} — ${esc(ip)}</div>
        <span class="v-badge ${c}">${ic} ${esc(v)}</span>
        ${obj.vlan ? `<div class="mrow">Interface: <strong>${esc(obj.vlan)}</strong></div>` : ''}
        ${obj.acl_applied ? `<div class="mrow">ACL: <strong>${esc(obj.acl_name)}</strong> · applied <strong>${esc(obj.acl_direction)}</strong>bound</div>` : ''}
        <div class="mrow">${esc(obj.verdict_reason)}</div>
        ${obj.matched_rule ? `<div class="cli">${esc(obj.matched_rule)}</div>` : ''}
        ${expiredNote}
      </div>`;
    };
    return swGroup(sr, side(sr.source_side, 'Source side', d.src_ip)
                     + side(sr.destination_side, 'Destination side', d.dst_ip), useCollapsible ? idx : null);
  }).join('');
  const addRuleAction = d.verdict === 'DENY' && isAdmin() && d.show_add_rule_button
    ? `<div class="card access-add-rule"><span>This access is denied.</span>
        <button type="button" class="btn btn-primary" data-access-add-rule>Add Rule</button></div>`
    : '';
  /* Somebody who cannot change these switches gets the other offer: ask an
     admin. Only for switches that actually evaluated the traffic and denied
     it -- if the gateway was never here there is nothing on this switch to
     open, and nothing to ask for. */
  const blockers = selectedCanWrite() ? [] : (d.switches || []).flatMap(sr => {
    if (!sr.on_this_switch || sr.switch_id == null) return [];
    const sides = [['source', sr.source_side], ['destination', sr.destination_side]];
    const hit = sides.find(([, side]) =>
      String((side || {}).verdict || '').toUpperCase().startsWith('DENIED'));
    if (!hit) return [];
    const [sideName, side] = hit;
    return [{ switchId: sr.switch_id, switchName: sr.switch_name || '', side: sideName,
              vlan: side.vlan || null, aclName: side.acl_name || null,
              matchedRule: side.matched_rule || null }];
  });
  const requestAction = blockers.length ? `<div class="card access-add-rule" style="display:block">
      <div style="margin-bottom:10px"><strong>This access is denied, and you cannot change these switches.</strong>
        <div class="label-hint" style="margin-top:4px">You can ask an administrator to open it.
          They will see exactly what you checked, and on which interface it was blocked.</div></div>
      ${blockers.map(b => `<div class="actions" style="margin-top:8px">
        <button type="button" class="btn btn-primary btn-sm" data-request-access="${b.switchId}"
          >Request access on ${esc(b.switchName)}</button>
        <span class="dash-muted" style="font-size:12px">blocked ${esc(b.side)} side${
          b.vlan ? ` on ${esc(b.vlan)}` : ''}${b.aclName ? ` by ${esc(b.aclName)}` : ''}</span>
      </div>`).join('')}
    </div>` : '';
  pendingRequestBlockers = blockers;
  pendingRequestAccess = { src_ip: d.src_ip, dst_ip: d.dst_ip, protocol: d.protocol,
                           port: d.port || '', icmp_type: d.icmp_type || '' };
  const html = `<div class="stagger" id="check-results">${resultHtml}${addRuleAction}${requestAction}</div>`;
  // Setup collapsible handlers after render
  if (useCollapsible) {
    setTimeout(() => {
      const container = document.getElementById('check-results');
      if (container) setupCollapsibleResults(container);
    }, 10);
  }
  return html;
}

function renderIp(d) {
  const rows = d.switches || [];
  if (!rows.length) return '<div class="alert a-warn">No result.</div>';
  const globalLookup = Boolean(d.global_lookup);
  const useCollapsible = rows.length > 1;
  const html = `<div class="stagger" id="ip-results">` + rows.map((sr, idx) => {
    if (sr.error) return swGroup(sr, `<div class="alert a-error">${esc(sr.error)}</div>`, useCollapsible ? idx : null);
    if (!sr.on_switch) {
      return swGroup(sr, `<div class="alert a-info">The gateway for <strong>${esc(d.ip_address)}</strong>
        is not on this switch${sr.interface ? `, the route points to <code>${esc(sr.interface)}</code>` : ''}.</div>
        <details><summary>Show route output</summary><div class="cli">${esc(sr.route_output || '')}</div></details>`, useCollapsible ? idx : null);
    }
    let body = `<div class="mrow">Interface: <strong>${esc(sr.interface || '—')}</strong></div>`;
    if (!sr.acls.length) {
      body += `<div class="alert a-warn" style="margin-top:11px">No ACL is applied to
        <strong>${esc(sr.interface)}</strong>, so traffic through it is permitted by default.</div>`;
    } else {
      body += `<div class="alert a-success" style="margin-top:11px">${sr.acls.length}
        ACL${sr.acls.length === 1 ? '' : 's'} applied to <strong>${esc(sr.interface)}</strong>.</div>`;
      body += sr.acls.map(a => `<div class="acl">
        <div class="acl-head${globalLookup ? ' acl-open-target' : ''}"
          ${globalLookup
            ? `data-ip-switch="${sr.switch_id}" data-ip-acl="${esc(a.acl_name)}" role="button" tabindex="0" title="Open this ACL in ACL Viewer"`
            : `onclick="this.closest('.acl').classList.toggle('open')"`}>
          <span class="acl-name">${esc(a.acl_name)}</span>
          <span class="badge b-accent">${esc(a.direction)}</span>
          <span class="acl-stats">${a.rule_count} rules</span>
          <span class="acl-caret">${globalLookup ? '↗' : '▼'}</span></div>
        <div class="acl-body"><div class="rules">${ruleRows(a.rules)}</div></div></div>`).join('');
    }
    body += `<details style="margin-top:10px"><summary>Show route output</summary>
      <div class="cli">${esc(sr.route_output || '')}</div></details>`;
    return swGroup(sr, body, useCollapsible ? idx : null);
  }).join('') + `</div>`;
  if (useCollapsible) {
    setTimeout(() => {
      const container = document.getElementById('ip-results');
      if (container) setupCollapsibleResults(container);
    }, 10);
  }
  return html;
}

let latestDeniedAccess = null;
/* The denied sides the current result offers to raise a request for, and the
   check that produced them. Held here rather than re-derived from the DOM. */
let pendingRequestBlockers = [];
let pendingRequestAccess = null;

function openAddRuleFromAccess(access = latestDeniedAccess) {
  if (!access || !isAdmin()) return;
  clearMegaRuleSuggestion();
  showPage('rule-add');
  const form = $('f-rule');
  form?.reset();
  $('r-rule').innerHTML = '';
  $('add-src').value = access.src_ip || '';
  $('add-dst').value = access.dst_ip || '';
  $('add-proto').value = access.protocol || 'all';
  $('add-port').value = access.port || '';
  $('add-icmp-type').value = access.icmp_type || '';
  $('add-time-range').value = '';
  /* The note the requester wrote, when this came from a request -- it is the
     one piece of context the switch will keep. */
  $('add-remark').value = access.remark || '';
  $('add-remark-seq').value = '';
  $('add-seq').value = '';
  /* These are enhanced selects: the native .value is what the form submits,
     but the visible control is a sibling that only redraws when told. Without
     this the protocol reads "All (IP)" however it was set, which is the value
     form.reset() left behind rather than the one just written. */
  ['add-proto', 'add-icmp-type'].forEach(id => {
    const sel = $(id);
    if (sel && sel._selRefresh) sel._selRefresh();
  });
  $('add-proto').dispatchEvent(new Event('change', { bubbles: true }));
  $('add-icmp-type').dispatchEvent(new Event('change', { bubbles: true }));
  el('main.main')?.scrollTo({ top: 0, behavior: 'smooth' });
  setTimeout(() => $('add-src')?.focus(), 220);
}

function renderGlobalIp(d) {
  const rows = d.switches || [];
  if (!rows.length) {
    return '<div class="alert a-warn">No switches are configured for your account.</div>';
  }
  const gateways = rows.filter(sr => !sr.error && sr.on_switch);
  const unavailable = rows.filter(sr => sr.error);
  if (!gateways.length) {
    return `<div class="alert a-info">The gateway for <strong>${esc(d.ip_address)}</strong>
      was not found on any managed switch.</div>${unavailable.length
        ? `<div class="alert a-warn" style="margin-top:10px">${unavailable.length} switch${unavailable.length === 1 ? ' was' : 'es were'} unavailable during the lookup.</div>`
        : ''}`;
  }
  return renderIp({ ...d, switches: gateways, global_lookup: true }) + (unavailable.length
    ? `<div class="alert a-warn" style="margin-top:10px">${unavailable.length} other switch${unavailable.length === 1 ? ' was' : 'es were'} unavailable during the lookup.</div>`
    : '');
}

function renderViewer(d) {
  const rows = d.switches || [];
  if (!rows.length) return '<div class="alert a-warn">No result.</div>';
  const useCollapsible = rows.length > 1;
  const containerId = 'viewer-results';
  const html = `<div class="stagger" id="${containerId}">` + rows.map((sr, idx) => {
    if (sr.error) return swGroup(sr, `<div class="alert a-error">${esc(sr.error)}</div>`, useCollapsible ? idx : null);
    if (sr.note)  return swGroup(sr, `<div class="alert a-info">${esc(sr.note)}</div>`, useCollapsible ? idx : null);
    if (!sr.acls?.length) {
      return swGroup(sr, '<div class="empty"><span class="empty-icon">◇</span>No ACLs on this switch.</div>', useCollapsible ? idx : null);
    }
    return swGroup(sr, sr.acls.map(a =>
      aclPanel(a, { deletable: isAdmin(), editable: isAdmin(), switchId: sr.switch_id })).join(''), useCollapsible ? idx : null);
  }).join('') + `</div>`;
  if (useCollapsible) {
    setTimeout(() => {
      const container = $(containerId);
      if (container) setupCollapsibleResults(container);
    }, 0);
  }
  return html;
}

function renderObjectGroups(d) {
  const rows = d.switches || [];
  const useCollapsible = rows.length > 1;
  const containerId = 'og-results';
  const html = `<div class="stagger" id="${containerId}">` + rows.map((sr, idx) => {
    if (sr.error) return swGroup(sr, `<div class="alert a-error">${esc(sr.error)}</div>`, useCollapsible ? idx : null);
    if (!sr.groups?.length) {
      return swGroup(sr, `<div class="empty"><span class="empty-icon">◇</span>${
        esc(sr.note || 'No object groups configured.')}</div>`, useCollapsible ? idx : null);
    }
    const admin = isAdmin();
    const section = (kind, label) => {
      const gs = sr.groups.filter(g => g.kind === kind);
      if (!gs.length) return '';
      return `<div class="sec-label" style="margin-top:8px">${label} · ${gs.length}</div>`
        + gs.map(g => `<div class="og">
            <div class="og-head" style="display:flex;align-items:center;gap:10px">
              <span onclick="this.closest('.og').classList.toggle('open')" style="display:flex;align-items:center;gap:10px;flex:1;cursor:pointer">
                <span class="og-name">${esc(g.name)}</span>
                <span class="badge ${kind === 'port' ? 'b-amber' : 'b-cyan'}">${kind}</span>
                <span class="acl-stats">${g.members.length} member${g.members.length === 1 ? '' : 's'}</span>
                <span class="acl-caret">▼</span></span>
              ${admin ? `<button type="button" class="btn btn-xs btn-danger" data-og-del-group
                  data-switch-id="${sr.switch_id}" data-name="${esc(g.name)}" data-kind="${kind}"
                  title="Delete this object group">Delete</button>` : ''}
            </div>
            <div class="og-body">${g.members.length
              ? g.members.map(m => `<div class="og-member" style="display:flex;align-items:center;justify-content:space-between;gap:8px">
                  <span class="mono" style="font-size:12px">${esc(m)}</span>
                  ${admin ? `<span style="display:flex;gap:6px;flex-shrink:0">
                    <button type="button" class="btn btn-xs btn-secondary" data-og-edit-member
                      data-switch-id="${sr.switch_id}" data-name="${esc(g.name)}" data-kind="${kind}"
                      data-member="${esc(m)}">Edit</button>
                    <button type="button" class="btn btn-xs btn-danger" data-og-del-member
                      data-switch-id="${sr.switch_id}" data-name="${esc(g.name)}" data-kind="${kind}"
                      data-member="${esc(m)}">✕</button></span>` : ''}
                </div>`).join('')
              : '<div style="color:var(--muted);font-size:12px">No members listed.</div>'}
              ${admin ? ogAddMemberFormHTML(sr.switch_id, g.name, kind, sr.is_nexus) : ''}
            </div>
          </div>`).join('');
    };
    return swGroup(sr, section('address', 'Address Groups') + section('port', 'Port Groups'), useCollapsible ? idx : null);
  }).join('') + `</div>`;
  if (useCollapsible) {
    setTimeout(() => {
      const container = $(containerId);
      if (container) setupCollapsibleResults(container);
    }, 0);
  }
  return html;
}

/* ══════════ OBJECT GROUP MANAGEMENT ══════════ */

function ogHeaderForSwitch(switchId, name, kind) {
  const sw = swById(switchId);
  const type = (sw?.switch_type || 'ios').toLowerCase();
  const isNexus = type === 'nexus' || type === 'nxos';
  if (kind === 'address') return (isNexus ? 'object-group ip address ' : 'object-group network ') + name;
  return (isNexus ? 'object-group ip port ' : 'object-group service ') + name;
}

function prefixToNetmask(len) {
  const n = +len;
  const mask = n === 0 ? 0 : (0xFFFFFFFF << (32 - n)) >>> 0;
  return [(mask >>> 24) & 255, (mask >>> 16) & 255, (mask >>> 8) & 255, mask & 255].join('.');
}

/* Renders the input fields for one address/port member row. Shared by the
   Create Object Group entry list and each loaded group's Add Member form.
   Address and port rows share the same shape: one field that accepts a
   plain value OR a nested-group reference (addrgroup/portgroup NAME),
   picked via the ⊕ button — mirroring the Add Rule form's fields. */
function ogRowFields(uid, kind, isNexus) {
  if (kind === 'address') {
    if (isNexus) {
      return `<div class="field" style="flex:1;min-width:220px"><label>Prefix <span class="label-hint">or bare IP for a host</span></label>
        <input type="text" id="og-prefix-${uid}" placeholder="10.0.0.0/24  ·  10.0.0.1" class="mono" spellcheck="false"></div>`;
    }
    return `<div class="field" style="flex:1;min-width:220px"><label>Address <span class="label-hint">or nested group</span></label>
      <div class="input-with-btn">
        <input type="text" id="og-addr-${uid}" placeholder="10.0.0.1  ·  10.0.0.0/24  ·  addrgroup NAME" class="mono" spellcheck="false">
        <button type="button" class="btn btn-secondary btn-sm" data-og-pick-group="${uid}" data-og-pick-kind="address" title="Pick address group">⊕</button>
      </div></div>`;
  }
  if (isNexus) {
    return `<div class="field" style="flex:1;min-width:180px"><label>Port</label>
      <input type="text" id="og-port-${uid}" placeholder="443  ·  8080-9000" class="mono" spellcheck="false"></div>`;
  }
  return `<div class="field" style="min-width:150px"><label>Protocol</label>
      <select id="og-proto-${uid}">
        <option value="tcp">TCP</option><option value="udp">UDP</option><option value="tcp-udp">TCP-UDP</option>
      </select></div>
    <div class="field" style="flex:1;min-width:220px"><label>Port <span class="label-hint">or nested group</span></label>
      <div class="input-with-btn">
        <input type="text" id="og-port-${uid}" placeholder="443  ·  8080-9000  ·  www  ·  portgroup NAME" class="mono" spellcheck="false">
        <button type="button" class="btn btn-secondary btn-sm" data-og-pick-group="${uid}" data-og-pick-kind="port" title="Pick port group">⊕</button>
      </div></div>`;
}

function currentOgPlatform() {
  const sw = swById(S.swIds[0]);
  const type = (sw?.switch_type || 'ios').toLowerCase();
  return type === 'nexus' || type === 'nxos';
}

let ogSeq = 0;
function addOgEntry() {
  ogSeq++;
  const uid = `e${ogSeq}`;
  const kind = $('og-kind').value;
  const isNexus = currentOgPlatform();
  const div = document.createElement('div');
  div.className = 'tre og-entry';
  div.id = `oge-${uid}`;
  div.dataset.kind = kind;
  div.dataset.nexus = isNexus ? '1' : '0';
  div.innerHTML = `
    <div style="display:flex;align-items:flex-start;gap:12px;flex-wrap:wrap">
      ${ogRowFields(uid, kind, isNexus)}
      <div class="field" style="flex:0 0 auto"><label style="visibility:hidden">Remove</label>
        <button type="button" class="btn btn-sm btn-danger" data-oge-del="${uid}">Remove</button></div>
    </div>`;
  $('og-entries').appendChild(div);
  enhanceSelects(div);
}

/* Collect and validate one row's fields into an ObjectGroupMemberInput payload. */
function collectOgMemberRow(uid, kind, isNexus) {
  if (kind === 'address') {
    if (isNexus) {
      return { prefix: V.prefix($(`og-prefix-${uid}`)?.value || '', 'Prefix') };
    }
    const raw = ($(`og-addr-${uid}`)?.value || '').trim();
    if (!raw) throw new Error('Enter an address or an object group.');
    if (raw.toLowerCase().startsWith('addrgroup')) {
      const parts = raw.split(/\s+/);
      if (parts.length !== 2) throw new Error('Use "addrgroup NAME".');
      return { group_ref: V.groupIdent(parts[1], 'Nested group') };
    }
    const safe = V.cliSafe(raw, 'Address');
    const badAddr = 'Address is not valid. Use a network address or select an object group.';
    if (safe.includes('/')) {
      const [ip, pfx] = safe.split('/');
      if (!V.ipv4(ip) || !/^\d{1,2}$/.test(pfx) || +pfx > 32) throw new Error(badAddr);
      return { prefix: safe };
    }
    if (!V.ipv4(safe)) throw new Error(badAddr);
    return { prefix: safe };
  }
  if (isNexus) {
    return { port: V.portOnly($(`og-port-${uid}`)?.value || '') };
  }
  const proto = $(`og-proto-${uid}`)?.value || 'tcp';
  const raw = ($(`og-port-${uid}`)?.value || '').trim();
  if (!raw) throw new Error('Enter a port or an object group.');
  if (raw.toLowerCase().startsWith('portgroup')) {
    const parts = raw.split(/\s+/);
    if (parts.length !== 2) throw new Error('Use "portgroup NAME".');
    return { group_ref: V.groupIdent(parts[1], 'Nested group') };
  }
  return { protocol: proto, port: V.iosPort(raw, proto) };
}

function collectOgEntries() {
  const kind = $('og-kind').value;
  const out = [];
  els('.og-entry').forEach(block => {
    const uid = block.id.replace('oge-', '');
    out.push(collectOgMemberRow(uid, kind, block.dataset.nexus === '1'));
  });
  if (!out.length) throw new Error('Add at least one rule.');
  return out;
}

/* Best-effort client-side mirror of the backend's member-line generation,
   used only to show a realistic command preview before it is confirmed —
   the switch's actual line is always computed authoritatively server-side. */
function ogPreviewLine(member, kind, isNexus) {
  if (member.group_ref) return `group-object ${member.group_ref}`;
  if (kind === 'address') {
    const hasSlash = member.prefix.includes('/');
    const ip = hasSlash ? member.prefix.split('/')[0] : member.prefix;
    const pfx = hasSlash ? +member.prefix.split('/')[1] : 32;
    if (pfx === 32) return `host ${ip}`;
    if (isNexus) return `${ip}/${pfx}`;
    return `${ip} ${prefixToNetmask(pfx)}`;
  }
  const rangeM = member.port.match(/^(\d+)-(\d+)$/);
  const opSyntax = rangeM ? `range ${rangeM[1]} ${rangeM[2]}` : `eq ${member.port}`;
  return isNexus ? opSyntax : `${member.protocol} ${opSyntax}`;
}

function renderOgCreatePreview(d) {
  const rows = (d.switches || []).filter(s => !s.error);
  const errored = (d.switches || []).filter(s => s.error);
  let html = errored.map(s =>
    `<div class="alert a-error">${esc(s.switch_name)}: ${esc(s.error)}</div>`).join('');
  if (!rows.length) {
    return html || '<div class="alert a-warn">No switch returned a preview.</div>';
  }
  html += rows.map(s => `<div class="pv" id="ogpv-${s.switch_id}">
      <div class="pv-title">${esc(s.switch_name)} · ${esc(d.kind)} group ${esc(d.name)}</div>
      <div style="font-size:11.5px;color:var(--muted);margin:11px 0 5px">Commands (run inside <code>configure terminal</code>):</div>
      <div class="cli">${esc((s.commands || []).join('\n'))}</div>
      <div class="actions" style="margin-top:13px">
        <button class="btn btn-success" data-og-apply="${s.switch_id}">Approve &amp; Apply</button>
        <button class="btn btn-ghost" onclick="document.getElementById('ogpv-${s.switch_id}').remove()">Skip</button>
      </div>
      <div id="ogpv-${s.switch_id}-st"></div></div>`).join('');
  setTimeout(() => {
    els('[data-og-apply]', $('r-og-preview')).forEach(btn => {
      const sid = +btn.dataset.ogApply;
      const commands = rows.find(r => r.switch_id === sid)?.commands || [];
      btn.onclick = () => applyOgCreate(sid, d.name, d.kind, commands);
    });
  }, 0);
  return html;
}

async function applyOgCreate(switchId, name, kind, commands) {
  const targetSwitches = await confirmVpcAware(switchId, {
    title: 'Create object group',
    message: `Create ${kind} group "${name}"? Running-config only.`,
    commands, okLabel: 'Apply', okClass: 'btn-success',
  });
  if (!targetSwitches) return;
  const st = $(`ogpv-${switchId}-st`);
  if (st) st.innerHTML = spinner('Applying and verifying…');
  try {
    const results = await Promise.all(targetSwitches.map(sw =>
      api('POST', '/api/write/object-group-apply', { switch_id: sw.id, name, kind, commands })));
    const allOk = results.every(r => r.success);
    toastViewerResults(results, targetSwitches, allOk ? 'Object group created' : 'Object group create');
    if (st) st.innerHTML = viewerResultsHtml(results, targetSwitches);
    document.getElementById(`ogpv-${switchId}`)?.remove();
    await loadSwitches();
    await refreshObjectGroups();
    if (allOk && !document.querySelector('#r-og-preview .pv')) {
      $('og-name').value = '';
      $('og-entries').innerHTML = '';
    }
  } catch (e) {
    if (st) st.innerHTML = `<div class="alert a-error">${esc(e.message)}</div>`;
    reportError(e, 'Could not create the object group');
  }
}

/* Add Member mini-form embedded in each loaded group card. */
let ogAddSeq = 0;
function ogAddMemberFormHTML(switchId, groupName, kind, isNexus) {
  ogAddSeq++;
  const uid = `a${ogAddSeq}`;
  return `<form class="viewer-action" data-og-add-member data-switch-id="${switchId}"
        data-name="${esc(groupName)}" data-kind="${kind}" data-nexus="${isNexus ? '1' : '0'}"
        data-uid="${uid}" novalidate>
      <div style="display:flex;align-items:flex-end;gap:12px;flex-wrap:wrap;margin-top:10px">
        ${ogRowFields(uid, kind, isNexus)}
        <button type="submit" class="btn btn-sm btn-primary" style="margin-bottom:2px">Add Member</button>
      </div>
      <div class="viewer-action-status"></div>
    </form>`;
}

async function addOgMember(form) {
  const switchId = +form.dataset.switchId;
  const name = form.dataset.name;
  const kind = form.dataset.kind;
  const isNexus = form.dataset.nexus === '1';
  const uid = form.dataset.uid;
  const status = el('.viewer-action-status', form);
  let member;
  try {
    member = collectOgMemberRow(uid, kind, isNexus);
  } catch (err) { return fieldError(status, err.message); }

  const header = ogHeaderForSwitch(switchId, name, kind);
  const targetSwitches = await confirmVpcAware(switchId, {
    title: 'Add object group member',
    message: `Add a member to ${name}? The switch will validate and verify it.`,
    commands: [header, ` ${ogPreviewLine(member, kind, isNexus)}`],
    okLabel: 'Add Member', okClass: 'btn-warning',
  });
  if (!targetSwitches) return;
  status.hidden = false;
  status.innerHTML = spinner('Applying and verifying the member…');
  try {
    const results = await Promise.all(targetSwitches.map(sw =>
      api('POST', '/api/write/object-group-member-add', { switch_id: sw.id, name, kind, member })));
    const allOk = results.every(r => r.success);
    toastViewerResults(results, targetSwitches, allOk ? 'Member added' : 'Add member');
    if (allOk) { status.hidden = true; status.innerHTML = ''; }
    else status.innerHTML = viewerResultsHtml(results, targetSwitches);
    await refreshObjectGroups();
  } catch (error) {
    status.innerHTML = `<div class="alert a-error">${esc(error.message)}</div>`;
    reportError(error, 'Could not add the member');
  }
}

async function delOgMember(button) {
  const switchId = +button.dataset.switchId;
  const name = button.dataset.name;
  const kind = button.dataset.kind;
  const memberLine = button.dataset.member;
  const header = ogHeaderForSwitch(switchId, name, kind);
  const targetSwitches = await confirmVpcAware(switchId, {
    title: 'Delete object group member',
    message: `Remove this member from ${name}?`,
    commands: [header, ` no ${memberLine}`],
    okLabel: 'Delete Member', okClass: 'btn-danger',
  });
  if (!targetSwitches) return;
  try {
    const results = await Promise.all(targetSwitches.map(sw =>
      api('POST', '/api/write/object-group-member-delete',
        { switch_id: sw.id, name, kind, member_line: memberLine })));
    toastViewerResults(results, targetSwitches, 'Member deleted');
    await refreshObjectGroups();
  } catch (error) {
    reportError(error, 'Could not delete the member');
  }
}

async function deleteObjectGroup(button) {
  const switchId = +button.dataset.switchId;
  const name = button.dataset.name;
  const kind = button.dataset.kind;
  const header = ogHeaderForSwitch(switchId, name, kind);
  const targetSwitches = await confirmVpcAware(switchId, {
    title: 'Delete object group',
    message: `Delete ${kind} group "${name}"? This removes it and all of its members.`,
    commands: [`no ${header}`],
    okLabel: 'Delete Group', okClass: 'btn-danger',
  });
  if (!targetSwitches) return;
  try {
    const results = await Promise.all(targetSwitches.map(sw =>
      api('POST', '/api/write/object-group-delete', { switch_id: sw.id, name, kind })));
    toastViewerResults(results, targetSwitches, 'Object group deleted');
    await refreshObjectGroups();
  } catch (error) {
    reportError(error, 'Could not delete the object group');
  }
}

let ogEditState = null;
function openOgMemberEdit(button) {
  if (!isAdmin()) return;
  ogEditState = {
    switchId: +button.dataset.switchId,
    name: button.dataset.name,
    kind: button.dataset.kind,
    originalMember: button.dataset.member,
  };
  const sw = swById(ogEditState.switchId);
  $('og-edit-context').textContent = `${ogEditState.name} · ${sw?.hostname || sw?.ip_address || 'switch'}`;
  $('og-edit-member').value = ogEditState.originalMember;
  fieldError($('og-edit-error'), '');
  $('og-edit-output').innerHTML = '';
  openModal('m-og-edit');
  setTimeout(() => $('og-edit-member')?.focus(), 80);
}

async function saveOgMemberEdit() {
  if (!ogEditState || !isAdmin()) return;
  const replacement = $('og-edit-member').value.trim();
  if (!replacement) return fieldError($('og-edit-error'), 'Enter the replacement member.');
  const { switchId, name, kind, originalMember } = ogEditState;
  const header = ogHeaderForSwitch(switchId, name, kind);
  const targetSwitches = await confirmVpcAware(switchId, {
    title: 'Replace object group member',
    message: 'The old member will be removed first. If the replacement fails, the original member will be restored automatically.',
    commands: [header, ` no ${originalMember}`, ` ${replacement}`],
    okLabel: 'Replace Member', okClass: 'btn-warning',
  });
  if (!targetSwitches) return;
  const button = $('btn-og-edit-save');
  setBusy(button, true, 'Replacing…');
  fieldError($('og-edit-error'), '');
  $('og-edit-output').innerHTML = spinner('Replacing and verifying the member…');
  try {
    const results = await Promise.all(targetSwitches.map(sw =>
      api('POST', '/api/write/object-group-member-edit', {
        switch_id: sw.id, name, kind,
        original_member: originalMember, new_member: replacement,
      })));
    const failed = results.find(r => !r.success);
    if (failed) {
      fieldError($('og-edit-error'), failed.message);
      $('og-edit-output').innerHTML = failed.output ? switchOutputBlock(failed.output) : '';
      bad('Member replace failed', failed.message);
      return;
    }
    closeModal('m-og-edit');
    ogEditState = null;
    toastViewerResults(results, targetSwitches, 'Member replaced');
    await refreshObjectGroups();
  } catch (error) {
    fieldError($('og-edit-error'), error.message);
    $('og-edit-output').innerHTML = '';
    reportError(error, 'Could not edit the member');
  } finally {
    setBusy(button, false);
  }
}

async function refreshObjectGroups() {
  if (!S.swIds.length) return;
  const box = $('r-og');
  const gen = S.dataGen;
  box.innerHTML = skeleton(4);
  try {
    const d = await api('POST', '/api/analysis/object-groups', { switch_ids: S.swIds });
    if (gen !== S.dataGen) return;
    box.innerHTML = renderObjectGroups(d);
    revealResult(box);
  } catch (e) {
    if (gen !== S.dataGen) return;
    box.innerHTML = `<div class="alert a-error">${esc(e.message)}</div>`;
    reportError(e, 'Could not load object groups');
  }
}

function renderTimeRanges(d) {
  const rows = d.switches || [];
  const useCollapsible = rows.length > 1;
  const containerId = 'tr-results';
  const html = `<div class="stagger" id="${containerId}">` + rows.map((sr, idx) => {
    if (sr.error) return swGroup(sr, `<div class="alert a-error">${esc(sr.error)}</div>`, useCollapsible ? idx : null);
    if (!sr.time_ranges?.length) {
      return swGroup(sr, `<div class="empty"><span class="empty-icon">◇</span>${
        esc(sr.note || 'No time ranges configured.')}</div>`, useCollapsible ? idx : null);
    }
    return swGroup(sr, sr.time_ranges.map(t => {
      const status = timeRangeStatus(t);
      const cls = status === 'active' ? 'on' : status === 'inactive' ? 'off' : '';
      const badge = status === 'active' ? '<span class="badge b-green">ACTIVE</span>'
                  : status === 'inactive' ? '<span class="badge b-red">INACTIVE</span>'
                  : status === 'empty' ? '<span class="badge b-gray">EMPTY</span>'
                  : '<span class="badge b-gray">UNKNOWN</span>';
      const trDataJson = JSON.stringify({ name: t.name, entries: t.entries, switchId: sr.switch_id }).replace(/"/g, '&quot;');
      return `<div class="tr-item ${cls}">
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:space-between">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
            <span class="tr-name">${esc(t.name)}</span>${badge}
          </div>
          <div class="admin-only" ${isAdmin() ? '' : 'hidden'} style="display:flex;gap:6px">
            <button class="btn btn-sm btn-secondary" onclick='editTimeRange(${trDataJson})' title="Edit time range">Edit</button>
            <button class="btn btn-sm btn-danger" onclick='deleteTimeRange("${jsq(t.name)}", ${sr.switch_id})' title="Delete time range">Delete</button>
          </div>
        </div>
        ${t.entries.length ? t.entries.map(e => `<div class="tr-entry-line">${esc(e)}</div>`).join('')
                           : '<div class="tr-entry-line" style="color:var(--muted)">No entries listed.</div>'}
      </div>`;
    }).join(''), useCollapsible ? idx : null);
  }).join('') + `</div>`;
  if (useCollapsible) {
    setTimeout(() => {
      const container = $(containerId);
      if (container) setupCollapsibleResults(container);
    }, 0);
  }
  return html;
}

function renderRedundant(d) {
  const rows = d.switches || [];
  const useCollapsible = rows.length > 1;
  const containerId = 'redundant-results';
  const countIn = list => (list || []).reduce(
    (m, g) => m + (g.redundant_rules?.length || 0), 0);
  const html = `<div class="stagger" id="${containerId}">` + rows.map((sr, idx) => {
    if (sr.error) return swGroup(sr, `<div class="alert a-error">${esc(sr.error)}</div>`, useCollapsible ? idx : null);
    const items = sr.results || [];
    if (!items.length) return swGroup(sr, '<div class="empty"><span class="empty-icon">◇</span>No ACLs found.</div>', useCollapsible ? idx : null);
    /* Dead schedules count towards "is there anything to show for this ACL"
       but never towards the redundancy badge: a rule whose schedule expired
       is not covered by another rule, it simply never fires. */
    const countOf = i => countIn(i.redundancies) + countIn(i.superseded_by_later)
      + (i.wrong_direction_rules?.length || 0) + (i.dead_schedule_rules?.length || 0);
    const total = items.reduce((n, i) => n + countOf(i), 0);
    /* One button for everything on screen: whichever ACL was analysed, or
       all of them. Counts what it would actually remove, so the label is the
       promise rather than a guess. */
    const sweepable = isAdmin()
      ? redundantSweepPlan(sr).reduce((n, p) => n + p.seqs.length, 0) : 0;
    const sweepBar = sweepable ? `<div class="actions" style="margin-bottom:12px">
        <button class="btn btn-sm btn-danger" id="btn-red-sweep"
          onclick="sweepRedundant(${sr.switch_id})">Remove all ${sweepable} on this switch</button>
        <span class="dash-muted" style="font-size:12px">redundant and wrong-direction rules
          across every ACL below · dead schedules are left alone</span>
      </div>` : '';
    const body = sweepBar + (total === 0
        ? '<div class="alert a-success">No redundant rules found.</div>' : '')
      + items.filter(i => countOf(i) > 0 || i.error).map(i => {
        const groupsForAcl = i.redundancies || [];
        const trailingForAcl = i.superseded_by_later || [];
        const wrongForAcl = i.wrong_direction_rules || [];
        const deadForAcl = i.dead_schedule_rules || [];
        const n = countIn(i.redundancies) + countIn(i.superseded_by_later);
        const aclKind = i.acl_kind || 'extended';
        const allSeqs = groupsForAcl.flatMap(g =>
          (g.redundant_rules || []).map(r => r.sequence).filter(s => s != null));
        const removeAllBtn = isAdmin() && allSeqs.length
          ? `<button type="button" class="btn btn-xs btn-danger" style="margin-left:auto"
              onclick="deleteAllRedundantInAcl(${sr.switch_id},'${jsq(i.acl_name)}','${jsq(aclKind)}',${
                esc(JSON.stringify(allSeqs))})">Remove all ${allSeqs.length} redundant</button>`
          : '';
        const trailingSeqs = trailingForAcl.flatMap(g =>
          (g.redundant_rules || []).map(r => r.sequence).filter(s => s != null));
        const trailingReason = 'Each was checked for a conflicting rule between it and the '
          + 'later rule that covers it — verify against your real traffic before removing.';
        const trailingRemoveAllBtn = isAdmin() && trailingSeqs.length
          ? `<button type="button" class="btn btn-xs btn-warning" style="margin-left:auto"
              onclick="deleteAllRedundantInAcl(${sr.switch_id},'${jsq(i.acl_name)}','${jsq(aclKind)}',${
                esc(JSON.stringify(trailingSeqs))},'${jsq(trailingReason)}')"
              >Remove all ${trailingSeqs.length}</button>`
          : '';
        const wrongSeqs = wrongForAcl.map(r => r.sequence).filter(s => s != null);
        const deadSeqs = deadForAcl.map(r => r.sequence).filter(s => s != null);
        const deadReason = 'Its time-range has already ended, so the rule can never '
          + 'match again. Renewing the schedule is often the better fix.';
        const deadRemoveAllBtn = isAdmin() && deadSeqs.length
          ? `<button type="button" class="btn btn-xs" style="margin-left:auto;background:var(--orange);color:#fff;border-color:var(--orange)"
              onclick="deleteAllRedundantInAcl(${sr.switch_id},'${jsq(i.acl_name)}','${jsq(aclKind)}',${
                esc(JSON.stringify(deadSeqs))},'${jsq(deadReason)}')"
              >Remove all ${deadSeqs.length} dead</button>`
          : '';
        const wrongReason = 'Its source/destination never overlaps any VLAN interface '
          + 'this ACL is applied to in the matching direction.';
        const wrongRemoveAllBtn = isAdmin() && wrongSeqs.length
          ? `<button type="button" class="btn btn-xs btn-danger" style="margin-left:auto"
              onclick="deleteAllRedundantInAcl(${sr.switch_id},'${jsq(i.acl_name)}','${jsq(aclKind)}',${
                esc(JSON.stringify(wrongSeqs))},'${jsq(wrongReason)}')"
              >Remove all ${wrongSeqs.length} wrong</button>`
          : '';
        return `<div class="card card-flat" style="margin-bottom:10px">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:${(n || wrongForAcl.length) ? '12px' : '0'}">
            <span class="mono" style="font-size:12.5px;font-weight:700">${esc(i.acl_name)}</span>
            <span class="badge ${n ? 'b-amber' : 'b-green'}">${n} redundant</span>
            ${wrongForAcl.length ? `<span class="badge b-red">${wrongForAcl.length} wrong-direction</span>` : ''}
            ${deadForAcl.length ? `<span class="badge" style="background:var(--orange-bg);color:var(--orange);border-color:var(--orange)"
              >${deadForAcl.length} dead schedule${deadForAcl.length === 1 ? '' : 's'}</span>` : ''}
            <span style="color:var(--muted);font-size:11.5px">${i.total_rules} rules</span>
            ${i.error ? `<span class="badge b-red">error</span>` : ''}
            ${removeAllBtn}</div>
          ${i.error ? `<div class="alert a-error">${esc(i.error)}</div>` : ''}
          ${groupsForAcl.map(g => `<div class="finding">
            <div class="f-label">Covered by</div>
            <div class="f-rule">${esc(g.covered_by_rule)}</div>
            <div class="f-note">Makes ${(g.redundant_rules || []).length} rule${
              (g.redundant_rules || []).length === 1 ? '' : 's'} redundant:</div>
            ${(g.redundant_rules || []).map(r => `<div class="f-rule"
                style="display:flex;align-items:center;justify-content:space-between;gap:8px">
              <span>${esc(r.raw)}</span>
              ${isAdmin() && r.sequence != null ? `<button type="button" class="btn btn-xs btn-danger"
                  onclick="deleteRedundantRule(${sr.switch_id},'${jsq(i.acl_name)}',${r.sequence},'${jsq(aclKind)}')"
                  >✕</button>` : ''}
            </div>`).join('')}
          </div>`).join('')}
          ${trailingForAcl.length ? `<div class="alert a-warn" style="margin-top:${groupsForAcl.length ? '14px' : '0'};margin-bottom:10px">
              <strong>Covered by a later broader rule</strong> — these were
              checked for a conflicting rule in between, but double-check your
              access list before removing.${trailingRemoveAllBtn ? `<div style="margin-top:9px">${trailingRemoveAllBtn}</div>` : ''}
            </div>
            ${trailingForAcl.map(g => `<div class="finding">
              <div class="f-label">Covered by a later rule</div>
              <div class="f-rule">${esc(g.covered_by_rule)}</div>
              <div class="f-note">Makes ${(g.redundant_rules || []).length} rule${
                (g.redundant_rules || []).length === 1 ? '' : 's'} redundant, no conflicts found in between:</div>
              ${(g.redundant_rules || []).map(r => {
                const reason = `Also covered by rule ${g.covered_by_sequence ?? '?'} below it, `
                  + `with nothing conflicting in between.`;
                return `<div class="f-rule" style="display:flex;align-items:center;justify-content:space-between;gap:8px">
                  <span>${esc(r.raw)}</span>
                  ${isAdmin() && r.sequence != null ? `<button type="button" class="btn btn-xs btn-warning"
                      onclick="deleteRedundantRule(${sr.switch_id},'${jsq(i.acl_name)}',${r.sequence},'${jsq(aclKind)}','${jsq(reason)}')"
                      title="Only redundant because of the later rule above — double-check before removing"
                      >✕</button>` : ''}
                </div>`;
              }).join('')}
            </div>`).join('')}` : ''}
          ${wrongForAcl.length ? `<div class="alert a-error" style="margin-top:${
              (groupsForAcl.length || trailingForAcl.length) ? '14px' : '0'};margin-bottom:10px">
              <strong>Wrong-direction rules</strong> — these can never match real traffic
              through any VLAN interface this ACL is applied to.${
                wrongRemoveAllBtn ? `<div style="margin-top:9px">${wrongRemoveAllBtn}</div>` : ''}
            </div>
            ${wrongForAcl.map(r => {
              const against = (r.checked_against || []).map(c =>
                `${c.interface} ${c.direction}bound (${c.subnet})`).join(', ');
              const reason = against ? `Does not overlap ${against}.` : wrongReason;
              return `<div class="finding wrong">
                <div class="f-rule" style="display:flex;align-items:center;justify-content:space-between;gap:8px">
                  <span>${esc(r.raw)}</span>
                  ${isAdmin() && r.sequence != null ? `<button type="button" class="btn btn-xs btn-danger"
                      onclick="deleteRedundantRule(${sr.switch_id},'${jsq(i.acl_name)}',${r.sequence},'${jsq(aclKind)}','${jsq(reason)}')"
                      >✕</button>` : ''}
                </div>
                <div class="f-note">Checked against: ${esc(against)}</div>
              </div>`;
            }).join('')}` : ''}
          ${deadForAcl.length ? `<div class="alert" style="margin-top:${
              (groupsForAcl.length || trailingForAcl.length || wrongForAcl.length) ? '14px' : '0'};margin-bottom:10px;
              background:var(--orange-bg);border-color:var(--orange)">
              <strong>Dead schedule rules</strong> — their time-range has already ended,
              so these can never match again. Renewing the schedule is often the better
              fix; removing the rule is the other one.${
                deadRemoveAllBtn ? `<div style="margin-top:9px">${deadRemoveAllBtn}</div>` : ''}
            </div>
            ${deadForAcl.map(r => `<div class="finding dead">
              <div class="f-label">Schedule ${esc(r.time_range || 'expired')}</div>
              ${(r.entries || []).length ? `<div class="f-note">${esc((r.entries || []).join(' · '))}</div>` : ''}
              <div class="f-rule" style="display:flex;align-items:center;justify-content:space-between;gap:8px">
                <span>${esc(r.raw)}</span>
                ${isAdmin() && r.sequence != null ? `<button type="button" class="btn btn-xs btn-warning"
                    onclick="deleteRedundantRule(${sr.switch_id},'${jsq(i.acl_name)}',${r.sequence},'${jsq(aclKind)}','${jsq(deadReason)}')"
                    title="${esc(deadReason)}">✕</button>` : ''}
              </div>
            </div>`).join('')}` : ''}</div>`;
      }).join('');
    return swGroup(sr, body, useCollapsible ? idx : null);
  }).join('') + `</div>`;
  if (useCollapsible) {
    setTimeout(() => {
      const container = $(containerId);
      if (container) setupCollapsibleResults(container);
    }, 0);
  }
  return html;
}

async function refreshRedundant() {
  if (!needSwitch()) return;
  const box = $('r-red');
  const name = $('red-acl').value.trim();
  const gen = S.dataGen;
  box.innerHTML = skeleton(4);
  try {
    const d = name
      ? await api('POST', '/api/analysis/redundant', { switch_ids: S.swIds, acl_name: V.ident(name, 'ACL name') })
      : await api('POST', '/api/analysis/redundant-all', { switch_ids: S.swIds });
    if (gen !== S.dataGen) return;
    lastRedundantResult = d;
    box.innerHTML = renderRedundant(d);
    revealResult(box);
  } catch (e) {
    if (gen !== S.dataGen) return;
    box.innerHTML = `<div class="alert a-error">${esc(e.message)}</div>`;
    reportError(e, 'Redundancy analysis failed');
  }
}

async function refreshSummary() {
  if (!needSwitch()) return;
  const box = $('r-sum');
  const name = $('sum-acl').value.trim();
  const gen = S.dataGen;
  box.innerHTML = skeleton(4);
  try {
    const d = name
      ? await api('POST', '/api/analysis/suggest-summary', { switch_ids: S.swIds, acl_name: V.ident(name, 'ACL name') })
      : await api('POST', '/api/analysis/suggest-summary-all', { switch_ids: S.swIds });
    if (gen !== S.dataGen) return;
    lastSummaryResult = d;
    box.innerHTML = renderSummary(d);
    revealResult(box);
  } catch (e) {
    if (gen !== S.dataGen) return;
    box.innerHTML = `<div class="alert a-error">${esc(e.message)}</div>`;
    reportError(e, 'Summary analysis failed');
  }
}

async function deleteRedundantRule(switchId, aclName, seq, aclKind = 'extended', reasonNote = '') {
  const gen = S.dataGen;
  const sw = swById(switchId);
  const name = sw ? (sw.hostname || sw.ip_address) : 'the switch';
  const targetSwitches = await confirmVpcAware(switchId, {
    title: 'Remove redundant rule',
    message: `Remove rule ${seq} from ${aclName} on ${name}?`
           + ` This changes running-config only — use Save Config afterwards.`
           + (reasonNote ? ` ${reasonNote}` : ''),
    commands: [aclContextForSwitch(switchId, aclName, aclKind), ` no ${seq}`, 'exit'],
    okLabel: 'Remove Rule', okClass: 'btn-danger',
  });
  if (!targetSwitches) return;
  try {
    const results = await Promise.all(targetSwitches.map(sw2 =>
      api('POST', '/api/write/rule-delete',
        { switch_id: sw2.id, acl_name: aclName, sequence_number: seq })));
    const successful = results.filter(r => r.success);
    const failed = results.filter(r => !r.success);
    if (successful.length) {
      const msg = targetSwitches.length > 1
        ? `Rule removed from ${successful.length} switch${successful.length === 1 ? '' : 'es'}`
        : 'Rule removed';
      ok(msg, successful[0].message, targetSwitches.length === 1 ? {
        switchId: targetSwitches[0].id,
        commands: successful[0].undo_commands,
        label: successful[0].undo_label || 'restore the rule',
        outputTarget: 'r-red',
      } : null);
    }
    if (failed.length) bad('Some deletes failed', failed.map(r => r.message).join('; '));
    await loadSwitches();
    if (gen === S.dataGen) await refreshRedundant();
  } catch (e) { reportError(e, 'Could not remove the rule'); }
}

async function deleteAllRedundantInAcl(switchId, aclName, aclKind, seqs, reasonNote = '') {
  const gen = S.dataGen;
  const sw = swById(switchId);
  const name = sw ? (sw.hostname || sw.ip_address) : 'the switch';
  const commands = [aclContextForSwitch(switchId, aclName, aclKind)]
    .concat(seqs.map(s => ` no ${s}`))
    .concat(['exit']);
  const targetSwitches = await confirmVpcAware(switchId, {
    title: 'Remove all redundant rules',
    message: `Remove ${seqs.length} redundant rule${seqs.length === 1 ? '' : 's'} from ${aclName} on ${name}?`
           + ` This changes running-config only — use Save Config afterwards.`
           + (reasonNote ? ` ${reasonNote}` : ''),
    commands,
    okLabel: 'Remove All', okClass: 'btn-danger',
  });
  if (!targetSwitches) return;
  try {
    // Sequence numbers are static identifiers, so deleting several in
    // parallel (and across VPC-paired switches) is safe — one
    // /api/write/rule-delete call per switch per sequence number.
    const results = await Promise.all(
      targetSwitches.flatMap(sw2 =>
        seqs.map(seq => api('POST', '/api/write/rule-delete',
          { switch_id: sw2.id, acl_name: aclName, sequence_number: seq })))
    );
    const successful = results.filter(r => r.success);
    const failed = results.filter(r => !r.success);
    if (successful.length) {
      ok(`${successful.length} rule${successful.length === 1 ? '' : 's'} removed`,
         `From ${aclName} on ${name}.`);
    }
    if (failed.length) bad('Some deletes failed', failed.map(r => r.message).join('; '));
    await loadSwitches();
    if (gen === S.dataGen) await refreshRedundant();
  } catch (e) { reportError(e, 'Could not remove the redundant rules'); }
}

function renderSummary(d) {
  const rows = d.switches || [];
  const useCollapsible = rows.length > 1;
  const containerId = 'summary-results';
  const html = `<div class="stagger" id="${containerId}">` + rows.map((sr, idx) => {
    if (sr.error) return swGroup(sr, `<div class="alert a-error">${esc(sr.error)}</div>`, useCollapsible ? idx : null);
    const items = sr.results || [];
    const total = items.reduce((n, i) => n + (i.suggestions?.length || 0), 0);
    const applyAll = isAdmin() ? summarySweepPlan(sr).length : 0;
    const sweepBar = applyAll ? `<div class="actions" style="margin-bottom:12px">
        <button class="btn btn-sm btn-warning" id="btn-sum-sweep"
          onclick="sweepSummary(${sr.switch_id})">Apply all ${applyAll} on this switch</button>
        <span class="dash-muted" style="font-size:12px">across every ACL below ·
          read the widened-match warnings first</span>
      </div>` : '';
    const body = sweepBar + (total === 0
        ? '<div class="alert a-success">No summary opportunities found — the ACLs are already compact.</div>' : '')
      + items.filter(i => (i.suggestions?.length || 0) > 0 || i.error).map((i, ii) => {
        const n = i.suggestions?.length || 0;
        return `<div class="card card-flat" style="margin-bottom:10px">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:${n ? '12px' : '0'}">
            <span class="mono" style="font-size:12.5px;font-weight:700">${esc(i.acl_name)}</span>
            <span class="badge ${n ? 'b-accent' : 'b-green'}">${n} suggestion${n === 1 ? '' : 's'}</span>
            <span style="color:var(--muted);font-size:11.5px">${i.total_rules} rules</span></div>
          ${i.error ? `<div class="alert a-error">${esc(i.error)}</div>` : ''}
          ${(i.suggestions || []).map((s, si) => {
            const seqs = (s.replaces || []).map(r => {
              const m = r.match(/^(\d+)/); return m ? +m[1] : null;
            }).filter(x => x !== null);
            const uid = `sa-${sr.switch_id}-${ii}-${si}`;
            const extra = s.extra_addresses || [];
            const extraBlock = extra.length
              ? ''
              : `<div class="alert a-success" style="margin-top:8px">Exact match — no extra addresses added.</div>`;
            return `<div class="finding sug">
              <div class="f-label">Suggested summary rule</div>
              <div class="f-rule" style="color:var(--accent-2)">${esc(s.suggestion)}</div>
              <div class="f-note">Would replace ${(s.replaces || []).length} rule${(s.replaces||[]).length===1?'':'s'}:</div>
              ${(s.replaces || []).map(r => `<div class="f-rule">${esc(r)}</div>`).join('')}
              ${extraBlock}
              ${isAdmin() && seqs.length ? `<div class="actions" style="margin-top:11px">
                <button class="btn btn-sm btn-secondary"
                  onclick="applySummary(${sr.switch_id},'${jsq(i.acl_name)}','${jsq(s.suggestion)}',${
                    esc(JSON.stringify(seqs))},'${uid}')">Replace with Summary</button></div>
                <div id="${uid}"></div>` : ''}
            </div>`;
          }).join('')}</div>`;
      }).join('');
    return swGroup(sr, body, useCollapsible ? idx : null);
  }).join('') + `</div>`;
  if (useCollapsible) {
    setTimeout(() => {
      const container = $(containerId);
      if (container) setupCollapsibleResults(container);
    }, 0);
  }
  return html;
}

/* ══════════ VPC SYNC CHECK ══════════ */
function vpcSyncEligiblePair() {
  if (S.swIds.length !== 2) return null;
  const [a, b] = S.swIds.map(swById);
  if (!a || !b) return null;
  if (a.vpc_peer_id !== b.id || b.vpc_peer_id !== a.id) return null;
  return [a, b];
}

function updateVpcSyncEligibility() {
  if (!$('vpc-sync-empty')) return;
  const pair = vpcSyncEligiblePair();
  $('vpc-sync-empty').hidden = !!pair;
  $('vpc-sync-form').hidden = !pair;
  if (pair) {
    const [a, b] = pair;
    $('vpc-sync-pair-label').textContent =
      `${a.hostname || a.ip_address} ↔ ${b.hostname || b.ip_address}`;
  } else {
    $('r-vpc-sync').innerHTML = '';
  }
}

async function refreshVpcSync() {
  const pair = vpcSyncEligiblePair();
  if (!pair) return;
  const box = $('r-vpc-sync');
  const gen = S.dataGen;
  box.innerHTML = skeleton(4);
  try {
    const d = await api('POST', '/api/analysis/vpc-sync-check', { switch_ids: S.swIds });
    if (gen !== S.dataGen) return;
    box.innerHTML = renderVpcSync(d);
    revealResult(box);
  } catch (e) {
    if (gen !== S.dataGen) return;
    box.innerHTML = `<div class="alert a-error">${esc(e.message)}</div>`;
    reportError(e, 'VPC sync check failed');
  }
}

function renderVpcSync(d) {
  const a = d.switch_a, b = d.switch_b;
  if (!a || !b) return '<div class="alert a-error">Could not resolve the VPC pair.</div>';
  const aLabel = `${a.label}${a.site ? ` (${siteLabel(a.site)})` : ''}`;
  const bLabel = `${b.label}${b.site ? ` (${siteLabel(b.site)})` : ''}`;
  const aclDiffs = d.acl_diffs || [];
  const vlanDiffs = d.vlan_diffs || [];

  const aclStatusText = {
    mismatch: 'Rules differ between the two switches',
    missing_on_a: `Missing on ${aLabel}`,
    missing_on_b: `Missing on ${bLabel}`,
  };

  const aclSection = `<div class="card card-flat" style="margin-bottom:14px">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:${aclDiffs.length ? '12px' : '0'}">
      <span class="sec-label" style="margin:0">ACL Content</span>
      <span class="badge ${aclDiffs.length ? 'b-amber' : 'b-green'}">${aclDiffs.length} mismatch${aclDiffs.length === 1 ? '' : 'es'}</span>
    </div>
    ${!aclDiffs.length
      ? '<div class="alert a-success">All ACLs match between both switches.</div>'
      : aclDiffs.map(diff => {
          const canAtoB = diff.status !== 'missing_on_a';
          const canBtoA = diff.status !== 'missing_on_b';
          return `<div class="finding">
            <div class="f-label mono">${esc(diff.acl_name)}</div>
            <div class="f-note">${esc(aclStatusText[diff.status] || diff.status)}</div>
            ${(diff.only_in_a || []).length ? `<div class="f-note" style="margin-top:8px">Only on ${esc(aLabel)}:</div>
              ${diff.only_in_a.map(l => `<div class="f-rule">${esc(l)}</div>`).join('')}` : ''}
            ${(diff.only_in_b || []).length ? `<div class="f-note" style="margin-top:8px">Only on ${esc(bLabel)}:</div>
              ${diff.only_in_b.map(l => `<div class="f-rule">${esc(l)}</div>`).join('')}` : ''}
            ${isAdmin() ? `<div class="actions" style="margin-top:11px">
              ${canAtoB ? `<button type="button" class="btn btn-xs btn-warning"
                  onclick="syncAclToPeer(${a.id},${b.id},'${jsq(diff.acl_name)}')"
                  >Sync ${esc(a.label)} → ${esc(b.label)}</button>` : ''}
              ${canBtoA ? `<button type="button" class="btn btn-xs btn-warning"
                  onclick="syncAclToPeer(${b.id},${a.id},'${jsq(diff.acl_name)}')"
                  >Sync ${esc(b.label)} → ${esc(a.label)}</button>` : ''}
            </div>` : ''}
          </div>`;
        }).join('')}
  </div>`;

  const vlanStatusText = {
    missing_on_a: `Not applied on ${aLabel}`,
    missing_on_b: `Not applied on ${bLabel}`,
    direction_mismatch: 'Applied in different directions',
  };

  const vlanSection = `<div class="card card-flat">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:${vlanDiffs.length ? '12px' : '0'}">
      <span class="sec-label" style="margin:0">VLAN ACL Bindings</span>
      <span class="badge ${vlanDiffs.length ? 'b-amber' : 'b-green'}">${vlanDiffs.length} mismatch${vlanDiffs.length === 1 ? '' : 'es'}</span>
    </div>
    ${!vlanDiffs.length
      ? '<div class="alert a-success">VLAN ACL bindings match between both switches.</div>'
      : vlanDiffs.map(v => {
          const rowA = v.direction_a ? `${esc(aLabel)}: ${v.direction_a}bound` : `${esc(aLabel)}: not applied`;
          const rowB = v.direction_b ? `${esc(bLabel)}: ${v.direction_b}bound` : `${esc(bLabel)}: not applied`;
          return `<div class="finding">
            <div class="f-label">${esc(v.acl_name)} on ${esc(v.interface)}</div>
            <div class="f-note">${esc(vlanStatusText[v.status] || v.status)}</div>
            <div class="f-rule">${rowA} · ${rowB}</div>
            ${isAdmin() ? `<div class="actions" style="margin-top:11px">
              ${v.direction_a ? `<button type="button" class="btn btn-xs btn-warning"
                  onclick="applyVlanBindingToPeer(${b.id},'${jsq(v.interface)}','${jsq(v.acl_name)}','${v.direction_a}'${
                    v.direction_b ? `,'${v.direction_b}'` : ''})"
                  >Apply ${esc(a.label)}'s binding to ${esc(b.label)}</button>` : ''}
              ${v.direction_b ? `<button type="button" class="btn btn-xs btn-warning"
                  onclick="applyVlanBindingToPeer(${a.id},'${jsq(v.interface)}','${jsq(v.acl_name)}','${v.direction_b}'${
                    v.direction_a ? `,'${v.direction_a}'` : ''})"
                  >Apply ${esc(b.label)}'s binding to ${esc(a.label)}</button>` : ''}
            </div>` : ''}
          </div>`;
        }).join('')}
  </div>`;

  return aclSection + vlanSection;
}

async function syncAclToPeer(sourceSwitchId, targetSwitchId, aclName) {
  const source = swById(sourceSwitchId);
  const target = swById(targetSwitchId);
  const sourceName = source ? (source.hostname || source.ip_address) : 'the source switch';
  const targetName = target ? (target.hostname || target.ip_address) : 'the target switch';
  let preview;
  try {
    preview = await api('POST', '/api/write/acl-sync-preview',
      { source_switch_id: sourceSwitchId, target_switch_id: targetSwitchId, acl_name: aclName });
  } catch (e) { reportError(e, 'Could not preview the sync'); return; }
  if (!preview.changed) {
    ok('Already in sync', `'${aclName}' already matches on ${targetName}.`);
    await refreshVpcSync();
    return;
  }
  const proceed = await confirmDialog({
    title: 'Sync ACL to peer',
    message: `Sync '${aclName}' from ${sourceName} to ${targetName}? Only the sequence `
           + `number(s) below are touched — everything else on ${targetName} is left alone. `
           + `This changes running-config only — use Save Config afterwards.`,
    commands: preview.commands,
    okLabel: 'Sync ACL', okClass: 'btn-warning',
  });
  if (!proceed) return;
  try {
    const r = await api('POST', '/api/write/acl-sync',
      { source_switch_id: sourceSwitchId, target_switch_id: targetSwitchId, acl_name: aclName });
    if (r.success) {
      ok('ACL synced', r.message, {
        switchId: targetSwitchId,
        commands: r.undo_commands,
        label: r.undo_label || 'restore the previous ACL',
        outputTarget: 'r-vpc-sync',
      });
    } else {
      bad('Sync failed', r.message);
    }
    await loadSwitches();
    await refreshVpcSync();
  } catch (e) { reportError(e, 'Could not sync the ACL'); }
}

async function applyVlanBindingToPeer(targetSwitchId, iface, aclName, direction, detachDirection = null) {
  const target = swById(targetSwitchId);
  const targetName = target ? (target.hostname || target.ip_address) : 'the switch';
  const commands = [`interface ${iface}`];
  if (detachDirection) commands.push(`no ip access-group ${aclName} ${detachDirection}`);
  commands.push(`ip access-group ${aclName} ${direction}`);
  const proceed = await confirmDialog({
    title: 'Apply ACL to VLAN',
    message: `Apply '${aclName}' ${direction}bound on ${iface} on ${targetName}?`
           + (detachDirection ? ` This first removes the existing ${detachDirection}bound binding.` : '')
           + ` This changes running-config only — use Save Config afterwards.`,
    commands,
    okLabel: 'Apply', okClass: 'btn-warning',
  });
  if (!proceed) return;
  try {
    if (detachDirection) {
      const dr = await api('POST', '/api/write/acl-interface',
        { switch_id: targetSwitchId, interface: iface, acl_name: aclName,
          direction: detachDirection, action: 'detach' });
      if (!dr.success) { bad('Apply failed', dr.message); return; }
    }
    const r = await api('POST', '/api/write/acl-interface',
      { switch_id: targetSwitchId, interface: iface, acl_name: aclName,
        direction, action: 'attach' });
    if (r.success) {
      ok('ACL applied', r.message, {
        switchId: targetSwitchId,
        commands: r.undo_commands,
        label: 'undo the VLAN ACL change',
        outputTarget: 'r-vpc-sync',
      });
    } else {
      bad('Apply failed', r.message);
    }
    await loadSwitches();
    await refreshVpcSync();
  } catch (e) { reportError(e, 'Could not apply the ACL to the VLAN'); }
}

const rulePreviewGroups = new Map();

function rulePreviewKey(preview) {
  return [preview.acl_name, preview.side,
          ...(preview.acl_directions || [preview.acl_direction]).sort()]
    .join('|').toLowerCase();
}

function renderRulePreview(d) {
  rulePreviewGroups.clear();
  const rows = d.switches || [];
  if (!rows.length) return '<div class="alert a-warn">No switch returned a preview.</div>';
  const useCollapsible = rows.length > 1;
  const containerId = 'rule-preview-results';
  const html = `<div class="stagger" id="${containerId}">` + rows.map((sr, si) => {
    if (sr.error) return swGroup(sr, `<div class="alert a-error">${esc(sr.error)}</div>`, useCollapsible ? si : null);
    if (sr.note)  return swGroup(sr, `<div class="alert a-info">${esc(sr.note)}</div>`, useCollapsible ? si : null);
    if (!sr.previews?.length) {
      return swGroup(sr, '<div class="alert a-warn">Nothing to apply on this switch.</div>', useCollapsible ? si : null);
    }
    const actionable = (sr.previews || []).filter(p => !p.warning);
    const allExisting = actionable.length > 0
      && actionable.every(p => p.already_permitted);
    let body = allExisting
      ? `<div class="alert a-warn"><strong>Access is already permitted by existing rules.</strong>
         Adding another permit may be redundant — review the matching rules below.</div>` : '';
    body += sr.previews.map((p, pi) => {
      if (p.warning) return `<div class="alert a-warn"><strong>${esc(p.side)} side:</strong> ${esc(p.warning)}</div>`;
      const uid = `pv-${si}-${pi}`;
      const groupKey = rulePreviewKey(p);
      if (!rulePreviewGroups.has(groupKey)) rulePreviewGroups.set(groupKey, []);
      rulePreviewGroups.get(groupKey).push({
        uid, switchId: sr.switch_id, switchName: sr.switch_name,
        aclName: p.acl_name, aclContext: p.acl_context || '',
        remark: p.remark_syntax ? (p.remark || '') : '',
        remarkSequence: p.remark_sequence ?? null,
        replacedRemark: p.replaced_remark || '',
      });
      const eas = p.existing_accesses || (p.existing_access ? [p.existing_access] : []);
      const warnBlock = eas.length ? `<div class="alert a-warn">
          <strong>Access is permitted on the ${esc(p.side)} side.</strong>
          ${eas.map(ea => `<div style="margin-top:5px">ACL <code>${esc(ea.acl_name)}</code>
            (${esc(ea.acl_direction)}bound) on ${esc(ea.vlan)}</div>
            ${ea.matched_rule ? `<div class="cli" style="margin:7px 0 0">${esc(ea.matched_rule)}</div>` : ''}`).join('')}
        </div>` : '';
      const denyBlock = p.blocking_rule ? `<div class="alert a-info">
          <strong>A denying rule currently blocks this access.</strong>
          The automatic sequence was selected above it.
          <div class="cli" style="margin:7px 0 0">${esc(p.blocking_rule)}</div>
        </div>` : '';
      const directions = (p.acl_directions || [p.acl_direction])
        .map(d => `${esc(d)}bound`).join(' and ');
      return `<div class="pv" id="${uid}">
        <div class="pv-title">${esc(p.side)} side · ${esc(p.acl_name)} (${directions})</div>
        ${warnBlock}${denyBlock}
        <div class="mrow">Interface <strong>${esc(p.vlan)}</strong> · sequence <strong>${esc(p.sequence_number)}</strong></div>
        <div style="font-size:11.5px;color:var(--muted);margin-top:5px">${esc(p.sequence_reason || '')}</div>
        <div style="margin:11px 0 5px;font-size:11.5px;color:var(--muted)">Commands to apply:</div>
        <div class="cli" id="${uid}-rule" style="margin-bottom:${p.remark_syntax ? '7px' : '0'}">${esc(p.rule_syntax)}</div>
        ${p.remark_warning ? `<div class="alert a-warn">${esc(p.remark_warning)}</div>` : ''}
        ${p.replaced_remark && p.replaced_remark.toLowerCase() !== (p.remark_syntax || '').toLowerCase()
          ? `<div class="alert a-info" style="margin-bottom:7px">The existing remark at sequence ${esc(p.remark_sequence)} will be replaced.<div class="cli" style="margin-top:7px">${esc(`no ${p.remark_sequence} remark`)}</div></div>` : ''}
        ${p.remark_syntax ? `<div class="cli" id="${uid}-remark" style="margin-bottom:7px">${esc(p.remark_syntax)}</div>` : ''}
        <div style="font-size:10.5px;color:var(--muted);margin-top:5px">Click Edit to change the permit rule.</div>
        <div style="font-size:11.5px;color:var(--muted);margin-bottom:11px">${esc(p.explanation)}</div>
        <div class="actions">
          <button class="btn btn-sm btn-success" onclick="applyRule('${uid}',${sr.switch_id},'${jsq(p.acl_name)}','${jsq(sr.switch_name)}','${jsq(p.acl_context || '')}','${jsq(groupKey)}')">Approve &amp; Apply</button>
          <button class="btn btn-sm btn-secondary" onclick="editRule('${uid}')">Edit</button>
        </div>
        <div class="apply-status" id="${uid}-st"></div></div>`;
    }).join('');
    return swGroup(sr, body, useCollapsible ? si : null);
  }).join('') + `</div>`;
  if (useCollapsible) {
    setTimeout(() => {
      const container = $(containerId);
      if (container) setupCollapsibleResults(container);
    }, 0);
  }
  return html;
}

/* ══════════ WRITE ACTIONS (confirm → apply → undo) ══════════ */

window.runUndoFromToast = async function (uid, btnElement) {
  const rec = (window.__undo || {})[uid];
  if (!rec) { 
    warn('Nothing to undo', 'This action can no longer be reverted.'); 
    return; 
  }
  
  // Close the toast
  const toast = btnElement.closest('.toast');
  if (toast) {
    if (toast._killTimer) clearTimeout(toast._killTimer);
    toast.classList.add('out');
    setTimeout(() => toast.remove(), 200);
  }
  
  const proceed = await confirmDialog({
    title: 'Undo change',
    message: `This will ${rec.label} on the switch. The following commands will be sent:`,
    commands: rec.commands,
    okLabel: 'Run Undo', okClass: 'btn-warning',
  });
  if (!proceed) return;
  
  try {
    const r = await api('POST', '/api/write/undo',
      { switch_id: rec.switchId, commands: rec.commands, label: rec.label });
    if (r.success) {
      ok('Change reverted', r.message);
      if (rec.outputTarget) {
        setSwitchCommandResult(rec.outputTarget, r.message, r.output,
                               'Undo switch output');
      }
      delete window.__undo[uid];
      // Refresh switch data to update pending_changes flags
      await loadSwitches();
      // Force UI refresh
      renderSaveButton();
      buildSwitchManager();
    } else {
      bad('Undo failed', r.message);
      if (rec.outputTarget) {
        const target = $(rec.outputTarget);
        if (target) target.innerHTML = `<div class="alert a-error">${esc(r.message)}</div>`
          + switchOutputBlock(r.output, 'Undo switch output');
      }
    }
  } catch (e) {
    reportError(e, 'Undo failed');
  }
};

window.editRule = function (uid) {
  const box = $(`${uid}-rule`);
  if (!box || box.dataset.editing === '1') return;
  const val = box.textContent.trim();
  box.dataset.editing = '1';
  box.innerHTML = `<textarea class="edit-area" id="${uid}-edit" spellcheck="false">${esc(val)}</textarea>`;
  $(`${uid}-edit`).focus();
};

window.applyRule = async function (uid, switchId, aclName, switchName,
                                   aclContext, groupKey = '') {
  const fallback = { uid, switchId, switchName, aclName, aclContext,
                     remark: '', remarkSequence: null, replacedRemark: '' };
  const group = rulePreviewGroups.get(groupKey) || [fallback];
  const selectedSw = S.swIds.length === 1 ? swById(S.swIds[0]) : swById(switchId);
  const sourceSw = selectedSw || swById(switchId);
  const peerSw = sourceSw?.vpc_peer_id ? swById(sourceSw.vpc_peer_id) : null;
  const sourceTarget = group.find(target => target.switchId === sourceSw?.id) || fallback;
  const peerTarget = peerSw
    ? group.find(target => target.switchId === peerSw.id)
    : null;

  const ruleFor = target => {
    const edit = $(`${target.uid}-edit`);
    const disp = $(`${target.uid}-rule`);
    return (edit ? edit.value : disp?.textContent || '').trim();
  };
  const commandsFor = target => [
    target.aclContext || aclContextForSwitch(target.switchId, target.aclName),
    ` ${ruleFor(target)}`,
    ...(target.remark && target.replacedRemark &&
        target.replacedRemark.trim().replace(/\s+/g, ' ').toLowerCase() !==
          `${target.remarkSequence ?? ''} remark ${target.remark}`.trim().replace(/\s+/g, ' ').toLowerCase()
      ? [` no ${target.remarkSequence ?? ''} remark`]
      : []),
    ...(target.remark && target.remarkSequence !== null
      ? [` ${target.remarkSequence} remark ${target.remark}`]
      : []),
    'exit',
  ];

  let targets = [sourceTarget];
  if (peerSw) {
    if (!peerTarget) {
      bad('VPC peer preview unavailable',
          `No matching ACL preview was generated for ${peerSw.hostname || peerSw.ip_address}. Generate a fresh preview and try again.`);
      return;
    }
    const sourceName = sourceSw.hostname || sourceSw.ip_address;
    const peerName = peerSw.hostname || peerSw.ip_address;
    const bothSelected = S.swIds.includes(sourceSw.id) && S.swIds.includes(peerSw.id);
    if (bothSelected) {
      targets = [sourceTarget, peerTarget];
      const proceed = await confirmDialog({
        title: 'Apply ACL rule to VPC pair?',
        message: `The matching generated rule will be applied to both ${sourceName} and ${peerName}. Each switch keeps its own previewed sequence number. Running-config only.`,
        commands: targets.flatMap(target => [
          `${target.switchName}:`, ...commandsFor(target),
        ]),
        okLabel: 'Apply to Both', okClass: 'btn-success',
      });
      if (!proceed) return;
    } else {
      const radioName = `vpc-rule-choice-${Date.now()}`;
      const proceed = await confirmDialog({
        title: 'Apply ACL rule to VPC pair?',
        message: `You are adding a rule on ${sourceName}. This switch has a VPC peer: ${peerName}.`,
        extraHTML: `<div class="vpc-choice"><strong>Apply to:</strong>
          <label><input type="radio" name="${radioName}" value="both" checked>
            <span>Both switches (${esc(sourceName)} and ${esc(peerName)})</span></label>
          <label><input type="radio" name="${radioName}" value="single">
            <span>Only ${esc(sourceName)}</span></label></div>`,
        okLabel: 'Apply Rule', okClass: 'btn-success',
      });
      if (!proceed) return;
      const choice = document.querySelector(`input[name="${radioName}"]:checked`)?.value;
      targets = choice === 'both' ? [sourceTarget, peerTarget] : [sourceTarget];
    }
  } else {
    const rule = ruleFor(sourceTarget);
    const proceed = await confirmDialog({
      title: 'Apply ACL rule',
      message: `This will add the rule to ${aclName} on ${switchName}. It changes running-config only — use Save Config afterwards.`,
      commands: commandsFor(sourceTarget),
      okLabel: 'Apply Rule', okClass: 'btn-success',
    });
    if (!proceed) return;
  }

  for (const target of targets) {
    const rule = ruleFor(target);
    if (!rule) { bad('Nothing to apply', `The rule for ${target.switchName} is empty.`); return; }
    if (/^\s*(\d+\s+)?deny\b/i.test(rule)) {
      bad('Not allowed', 'Deny rules cannot be created from this application.');
      return;
    }
    try { V.cliSafe(rule, 'Rule'); }
    catch (e) { bad('Invalid rule', e.message); return; }
  }

  targets.forEach(target => {
    const status = $(`${target.uid}-st`);
    if (status) status.innerHTML = spinner('Applying…');
  });
  await Promise.all(targets.map(async target => {
    const status = $(`${target.uid}-st`);
    try {
      const result = await api('POST', '/api/write/rule-apply', {
        switch_id: target.switchId,
        acl_name: target.aclName,
        rule_syntax: ruleFor(target),
        remark: target.remark || null,
        remark_sequence: target.remarkSequence,
      });
      if (result.success) {
        ok(`Rule applied on ${target.switchName}`, result.message, {
          switchId: target.switchId,
          commands: result.undo_commands,
          label: result.undo_label || 'remove the rule',
          outputTarget: status?.id || '',
        });
        if (status) status.innerHTML = switchCommandResult(
          result.message, result.output);
      } else {
        bad(`Rule rejected on ${target.switchName}`, result.message);
        if (status) status.innerHTML = `<div class="alert a-error">${esc(result.message)}</div>`
          + (result.output ? switchOutputBlock(result.output) : '');
      }
    } catch (error) {
      reportError(error, `Could not apply the rule on ${target.switchName}`);
      if (status) status.innerHTML = `<div class="alert a-error">${esc(error.message)}</div>`;
    }
  }));
  await loadSwitches();
};

window.delRule = async function (switchId, aclName, seq, aclKind = 'extended') {
  const gen = S.dataGen;
  const sw = swById(switchId);
  const name = sw ? (sw.hostname || sw.ip_address) : 'the switch';
  const targetSwitches = await confirmVpcAware(switchId, {
    title: 'Remove ACL rule',
    message: `Remove rule ${seq} from ${aclName} on ${name}?`
           + ` This changes running-config only — use Save Config afterwards.`,
    commands: [aclContextForSwitch(switchId, aclName, aclKind), ` no ${seq}`, 'exit'],
    okLabel: 'Remove Rule', okClass: 'btn-danger',
  });
  if (!targetSwitches) return;
  try {
    const results = await Promise.all(targetSwitches.map(sw2 =>
      api('POST', '/api/write/rule-delete',
        { switch_id: sw2.id, acl_name: aclName, sequence_number: seq })));
    const successful = results.filter(r => r.success);
    const failed = results.filter(r => !r.success);
    if (successful.length) {
      const msg = targetSwitches.length > 1
        ? `Rule removed from ${successful.length} switch${successful.length === 1 ? '' : 'es'}`
        : 'Rule removed';
      ok(msg, successful[0].message, targetSwitches.length === 1 ? {
        switchId: targetSwitches[0].id,
        commands: successful[0].undo_commands,
        label: successful[0].undo_label || 'restore the rule',
        outputTarget: 'r-viewer',
      } : null);
    }
    if (failed.length) bad('Some deletes failed', failed.map(r => r.message).join('; '));
    await loadSwitches();
    await refreshViewer();
    if (gen === S.dataGen) {
      $('r-viewer')?.insertAdjacentHTML('afterbegin', viewerResultsHtml(results, targetSwitches));
    }
  } catch (e) { reportError(e, 'Could not remove the rule'); }
};

window.applySummary = async function (switchId, aclName, summaryRule, seqs, uid) {
  const cmds = [aclContextForSwitch(switchId, aclName)]
    .concat(seqs.map(s => ` no ${s}`))
    .concat([` ${summaryRule}`, 'exit']);
  const targetSwitches = await confirmVpcAware(switchId, {
    title: 'Replace rules with a summary',
    message: `Remove ${seqs.length} rule(s) from ${aclName} and add the summary rule? `
           + `Running-config only — use Save Config afterwards.`,
    commands: cmds,
    okLabel: 'Apply Summary', okClass: 'btn-warning',
  });
  if (!targetSwitches) return;
  const st = $(uid);
  if (st) st.innerHTML = spinner('Applying…');
  try {
    const results = await Promise.all(targetSwitches.map(sw2 =>
      api('POST', '/api/write/summary-apply',
        { switch_id: sw2.id, acl_name: aclName,
          summary_rule: summaryRule, rules_to_remove: seqs })));
    const successful = results.filter(r => r.success);
    const failed = results.filter(r => !r.success);
    if (successful.length) {
      const msg = targetSwitches.length > 1
        ? `Summary applied on ${successful.length} switch${successful.length === 1 ? '' : 'es'}`
        : 'Summary applied';
      ok(msg, successful[0].message, targetSwitches.length === 1 ? {
        switchId: targetSwitches[0].id,
        commands: successful[0].undo_commands,
        label: successful[0].undo_label || 'restore the original rules',
        outputTarget: uid,
      } : null);
      if (st) st.innerHTML = switchCommandResult(successful[0].message, successful[0].output);
    }
    if (failed.length) {
      bad('Some applies failed', failed.map(r => r.message).join('; '));
      if (!successful.length && st) st.innerHTML = `<div class="alert a-error">${
        esc(failed.map(r => r.message).join('; '))}</div>`;
    }
    await loadSwitches();
  } catch (e) {
    reportError(e, 'Could not apply the summary');
    if (st) st.innerHTML = '';
  }
};

/* ══════════ REVERSE DIRECTION ══════════ */
async function refreshReverseDirection() {
  if (!needSwitch()) return;
  const sw = primary();
  if (!sw) return;
  const name = V.ident($('rev-acl').value.trim(), 'ACL name');
  const box = $('r-rev');
  const gen = S.dataGen;
  box.innerHTML = skeleton(4);
  try {
    const d = await api('POST', '/api/analysis/reverse-direction-preview',
      { switch_id: sw.id, acl_name: name });
    if (gen !== S.dataGen) return;
    box.innerHTML = renderReverseDirection(sw.id, d);
    revealResult(box);
  } catch (e) {
    if (gen !== S.dataGen) return;
    box.innerHTML = `<div class="alert a-error">${esc(e.message)}</div>`;
    reportError(e, 'Could not preview the reversal');
  }
}

/* Where the ACL is applied, and a way to move each binding to the opposite
   direction. Reversing the rules without moving the binding usually leaves
   the ACL filtering the wrong way round, so it belongs on this page. */
function renderReverseBindings(switchId, d) {
  const bindings = d.applied_on || [];
  if (!bindings.length) {
    return `<div class="card card-flat" style="margin-bottom:10px">
      <span class="sec-label" style="margin:0">Where this ACL is applied</span>
      <div class="f-note" style="margin-top:8px">Not applied to any interface, so
        reversing the rules changes nothing on its own.</div>
    </div>`;
  }
  return `<div class="card card-flat" style="margin-bottom:10px">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px">
      <span class="sec-label" style="margin:0">Where this ACL is applied</span>
      <span class="badge b-accent">${bindings.length} binding${bindings.length === 1 ? '' : 's'}</span>
    </div>
    <div class="f-note" style="margin-bottom:10px">Swapping source and destination usually
      means the ACL should move to the opposite direction too.</div>
    ${bindings.map(b => {
      const other = b.direction === 'in' ? 'out' : 'in';
      const isVlan = /^vlan\d+$/i.test(b.interface || '');
      return `<div class="finding" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <span class="mono" style="font-size:12.5px;font-weight:700">${esc(b.interface)}</span>
        <span class="badge ${b.direction === 'in' ? 'b-cyan' : 'b-gray'}">${
          b.direction === 'in' ? 'inbound' : 'outbound'}</span>
        ${isAdmin() && isVlan ? `<button type="button" class="btn btn-xs btn-warning"
            style="margin-left:auto"
            onclick="flipAclBinding(${switchId},'${jsq(d.acl_name)}','${jsq(b.interface)}','${jsq(b.direction)}')"
            title="Move this binding to ${other}bound">Make ${other}bound</button>`
          : `<span class="f-note" style="margin-left:auto">${
              isVlan ? '' : 'Not a VLAN interface — change it on the switch.'}</span>`}
      </div>`;
    }).join('')}
  </div>`;
}

function renderReverseDirection(switchId, d) {
  const reversible = d.reversible || [];
  const manual = d.manual || [];
  const bindings = renderReverseBindings(switchId, d);
  if (!reversible.length && !manual.length) {
    return bindings
      + '<div class="alert a-success">No permit/deny rules to reverse — either the ACL is '
      + 'empty or it\'s a standard ACL (nothing to swap a destination with).</div>';
  }
  const allSeqs = reversible.map(r => r.sequence).filter(s => s != null);
  const reverseAllBtn = isAdmin() && allSeqs.length
    ? `<button type="button" class="btn btn-sm btn-warning" style="margin-left:auto"
        onclick="applyReverseDirection(${switchId},'${jsq(d.acl_name)}','${jsq(d.acl_kind || 'extended')}',${
          esc(JSON.stringify(allSeqs))})">Reverse all ${allSeqs.length}</button>`
    : '';
  const reversibleSection = reversible.length ? `<div class="card card-flat" style="margin-bottom:${manual.length ? '10px' : '0'}">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px">
      <span class="sec-label" style="margin:0">Will be reversed</span>
      <span class="badge b-amber">${reversible.length} rule${reversible.length === 1 ? '' : 's'}</span>
      ${reverseAllBtn}
    </div>
    ${reversible.map(r => `<div class="finding sug">
      <div class="f-rule">${esc(r.original)}</div>
      <div class="f-note">becomes:</div>
      <div class="f-rule" style="display:flex;align-items:center;justify-content:space-between;gap:8px;color:var(--accent-2)">
        <span>${esc(r.reversed)}</span>
        ${isAdmin() && r.sequence != null ? `<button type="button" class="btn btn-xs btn-warning"
            onclick="applyReverseDirection(${switchId},'${jsq(d.acl_name)}','${jsq(d.acl_kind || 'extended')}',${
              esc(JSON.stringify([r.sequence]))})">Reverse</button>` : ''}
      </div>
    </div>`).join('')}
  </div>` : '';
  const manualSection = manual.length ? `<div class="alert a-warn" style="margin-bottom:10px">
      <strong>${manual.length} rule${manual.length === 1 ? '' : 's'} can't be reversed automatically</strong> —
      ${manual.length === 1 ? 'it references' : 'they reference'} an IOS object-group. Reverse
      ${manual.length === 1 ? 'it' : 'them'} manually.
      ${manual.map(r => `<div class="f-rule" style="margin-top:8px">${esc(r.original)}</div>`).join('')}
    </div>` : '';
  return bindings + reversibleSection + manualSection;
}

window.flipAclBinding = async function (switchId, aclName, iface, direction) {
  const target = direction === 'in' ? 'out' : 'in';
  const targetSwitches = await confirmVpcAware(switchId, {
    title: 'Move ACL binding',
    message: `Move ${aclName} on ${iface} from ${direction}bound to ${target}bound? `
           + `Running-config only — use Save Config afterwards.`,
    commands: [`interface ${iface}`,
               `no ip access-group ${aclName} ${direction}`,
               `ip access-group ${aclName} ${target}`],
    okLabel: `Make ${target}bound`, okClass: 'btn-warning',
  });
  if (!targetSwitches) return;
  try {
    const results = await Promise.all(targetSwitches.map(sw2 =>
      api('POST', '/api/write/acl-interface-flip',
        { switch_id: sw2.id, acl_name: aclName, interface: iface, direction })));
    const successful = results.filter(r => r.success);
    const failed = results.filter(r => !r.success);
    if (successful.length) {
      ok(targetSwitches.length > 1 ? `Binding moved on ${successful.length} switches`
                                   : 'Binding moved',
        successful[0].message, targetSwitches.length === 1 ? {
          switchId: targetSwitches[0].id,
          commands: successful[0].undo_commands,
          label: successful[0].undo_label || 'restore the original direction',
          outputTarget: 'r-rev',
        } : null);
    }
    if (failed.length) bad('Some moves failed', failed.map(r => r.message).join('; '));
    await loadSwitches();
    await refreshReverseDirection();
  } catch (e) { reportError(e, 'Could not move the ACL binding'); }
};

window.applyReverseDirection = async function (switchId, aclName, aclKind, seqs) {
  const targetSwitches = await confirmVpcAware(switchId, {
    title: 'Reverse rule direction',
    message: `Reverse ${seqs.length} rule${seqs.length === 1 ? '' : 's'} in ${aclName}? `
           + `Each is removed and re-added with source and destination swapped. `
           + `Running-config only — use Save Config afterwards.`,
    okLabel: 'Reverse', okClass: 'btn-warning',
  });
  if (!targetSwitches) return;
  try {
    const results = await Promise.all(targetSwitches.map(sw2 =>
      api('POST', '/api/write/reverse-direction-apply',
        { switch_id: sw2.id, acl_name: aclName, sequences: seqs })));
    const successful = results.filter(r => r.success);
    const failed = results.filter(r => !r.success);
    if (successful.length) {
      const msg = targetSwitches.length > 1
        ? `Reversed on ${successful.length} switch${successful.length === 1 ? '' : 'es'}`
        : 'Rule(s) reversed';
      ok(msg, successful[0].message, targetSwitches.length === 1 ? {
        switchId: targetSwitches[0].id,
        commands: successful[0].undo_commands,
        label: successful[0].undo_label || 'restore the original direction',
        outputTarget: 'r-rev',
      } : null);
    }
    if (failed.length) bad('Some reversals failed', failed.map(r => r.message).join('; '));
    await loadSwitches();
    await refreshReverseDirection();
  } catch (e) { reportError(e, 'Could not reverse the rule(s)'); }
};

/* ══════════ TEMPLATES ══════════ */
let templatesCache = [];
let templatesViewDirection = {};
let tplEditingId = null;
let tplLineSeq = 0;

async function loadTemplates() {
  const box = $('r-templates');
  const gen = S.dataGen;
  box.innerHTML = skeleton(3);
  try {
    const d = await api('GET', '/api/templates');
    if (gen !== S.dataGen) return;
    templatesCache = d.templates || [];
    box.innerHTML = renderTemplatesList(templatesCache);
  } catch (e) {
    if (gen !== S.dataGen) return;
    box.innerHTML = `<div class="alert a-error">${esc(e.message)}</div>`;
    reportError(e, 'Could not load templates');
  }
}

function renderTemplatesList(templates) {
  if (!templates.length) {
    return '<div class="empty"><span class="empty-icon">▤</span>No templates yet — create one below.</div>';
  }
  const sw0 = swById(S.swIds[0]);
  return templates.map(t => {
    const viewDir = templatesViewDirection[t.id] || t.direction;
    const lines = viewDir === t.direction ? t.lines : t.reversed_lines;
    const platformLabel = t.switch_type === 'nexus' ? 'NX-OS' : 'IOS';
    const kindBadge = t.acl_kind === 'standard' ? '<span class="badge b-amber">Standard</span>' : '';
    const ownerBadge = t.is_owner
      ? '<span class="badge b-green">Owned</span>'
      : `<span class="badge b-cyan">Shared by ${esc(t.owner_username)}</span>`;
    const skippedNote = (viewDir !== t.direction && t.skipped_reversal_count)
      ? `<div class="alert a-warn" style="margin-top:8px">${t.skipped_reversal_count} line(s) in the
          original (${t.direction}bound) direction referenced an IOS object-group and couldn't be
          auto-reversed — create a separate template manually (a different name) if you need them.</div>`
      : '';
    const matches = sw0 && (sw0.switch_type || 'ios') === t.switch_type;
    const applyTitle = matches
      ? 'Apply this template to an ACL on the selected switch'
      : `Select ${platformLabel === 'IOS' ? 'an' : 'a'} ${platformLabel} switch first`;
    return `<div class="card card-flat" style="margin-bottom:10px">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px">
        <span class="mono" style="font-size:12.5px;font-weight:700">${esc(t.name)}</span>
        <span class="badge b-gray">${platformLabel}</span>
        ${kindBadge}
        ${ownerBadge}
        <span style="color:var(--muted);font-size:11.5px">${lines.length} line${lines.length === 1 ? '' : 's'}</span>
      </div>
      <div class="actions" style="margin-bottom:10px">
        <button type="button" class="btn btn-xs ${viewDir === 'in' ? 'btn-primary' : 'btn-secondary'}"
          onclick="setTemplateViewDirection(${t.id},'in')">Inbound</button>
        <button type="button" class="btn btn-xs ${viewDir === 'out' ? 'btn-primary' : 'btn-secondary'}"
          onclick="setTemplateViewDirection(${t.id},'out')">Outbound</button>
        ${isAdmin() ? `<button type="button" class="btn btn-xs btn-warning" style="margin-left:auto"
          title="${esc(applyTitle)}" ${matches ? '' : 'disabled'}
          onclick="applyTemplateFlow(${t.id},'${viewDir}','${jsq(t.switch_type)}')">Apply to ACL</button>` : ''}
        ${t.is_owner ? `<button type="button" class="btn btn-xs btn-secondary" onclick="editTemplateRow(${t.id})">Edit</button>
          <button type="button" class="btn btn-xs btn-danger" onclick="deleteTemplateRow(${t.id},'${jsq(t.name)}')">Delete</button>` : ''}
      </div>
      ${lines.length ? lines.map(l => `<div class="f-rule">${esc(l)}</div>`).join('')
        : '<div class="empty" style="padding:10px 0"><span class="empty-icon">◇</span>No lines for this direction.</div>'}
      ${skippedNote}
    </div>`;
  }).join('');
}

function setTemplateViewDirection(id, dir) {
  templatesViewDirection[id] = dir;
  $('r-templates').innerHTML = renderTemplatesList(templatesCache);
}

function tplIsStandard() {
  return $('tpl-switch-type').value === 'ios' && $('tpl-acl-kind').value === 'standard';
}

function tplLinePlaceholder() {
  return tplIsStandard() ? 'permit 10.0.0.0 0.0.0.255' : 'permit tcp host 10.0.0.1 host 10.0.0.2 eq 22';
}

function updateTplAclKindVisibility() {
  const wrap = $('tpl-acl-kind-wrap');
  if (wrap) wrap.hidden = $('tpl-switch-type').value !== 'ios';
  const ph = tplLinePlaceholder();
  els('.tpl-line-input').forEach(inp => { inp.placeholder = ph; });
}

function addTplLineRow(value = '') {
  const uid = `tplline-${tplLineSeq++}`;
  const row = document.createElement('div');
  row.className = 'input-with-btn';
  row.id = uid;
  row.style.marginBottom = '8px';
  row.innerHTML = `<input type="text" class="mono tpl-line-input"
      placeholder="${esc(tplLinePlaceholder())}" spellcheck="false" value="${esc(value)}">
    <button type="button" class="btn btn-secondary btn-sm" data-tpl-line-del="${uid}">✕</button>`;
  $('tpl-lines').appendChild(row);
}

function resetTemplateForm() {
  tplEditingId = null;
  $('tpl-name').value = '';
  $('tpl-switch-type').value = 'nexus';
  $('tpl-acl-kind').value = 'extended';
  $('tpl-direction').value = 'in';
  updateTplAclKindVisibility();
  $('tpl-lines').innerHTML = '';
  addTplLineRow();
  tplShareSelected = new Set();
  tplShareSyncLabel();
  $('tpl-form-label').textContent = 'Create Template';
  $('btn-tpl-cancel-edit').hidden = true;
  fieldError($('tpl-form-error'), '');
}

/* Bespoke multi-select dropdown for "Share With" — reuses the exact
   .sel/.sel-btn/.sel-menu/.sel-opt styling every other dropdown in this
   app uses, but toggles membership instead of closing on pick (the
   built-in enhanceSelect() component is single-select only). */
let tplShareCandidates = [];
let tplShareSelected = new Set();

function tplShareSyncLabel() {
  const txt = el('.sel-btn-txt', $('tpl-share-btn'));
  if (!txt) return;
  if (tplShareSelected.size === 0) {
    txt.textContent = 'Select admins…';
    txt.classList.add('placeholder');
  } else {
    txt.textContent = [...tplShareSelected].join(', ');
    txt.classList.remove('placeholder');
  }
}

function closeTplShareMenu() {
  const menu = document.querySelector('.tpl-share-menu');
  if (menu) menu.remove();
  $('tpl-share-sel')?.classList.remove('open');
}

function openTplShareMenu() {
  if (document.querySelector('.tpl-share-menu')) { closeTplShareMenu(); return; }
  closeAllSelects();
  const wrap = $('tpl-share-sel');
  const btn = $('tpl-share-btn');
  const menu = document.createElement('div');
  menu.className = 'sel-menu tpl-share-menu';
  menu.innerHTML = tplShareCandidates.length
    ? tplShareCandidates.map(u => `<div class="sel-opt${tplShareSelected.has(u.username) ? ' on' : ''}"
        data-username="${esc(u.username)}">
        <span class="sel-opt-txt">${esc(u.username)}</span>
      </div>`).join('')
    : '<div class="sel-opt" style="cursor:default;opacity:.6">No other admins</div>';
  document.body.appendChild(menu);
  wrap.classList.add('open');
  const r = btn.getBoundingClientRect();
  menu.style.minWidth = `${r.width}px`;
  let left = r.left;
  if (left + menu.offsetWidth + 8 > window.innerWidth) left = window.innerWidth - menu.offsetWidth - 8;
  menu.style.left = `${Math.round(Math.max(8, left))}px`;
  menu.style.top = `${Math.round(r.bottom + 5)}px`;
  wrap._selClose = closeTplShareMenu;
  menu.addEventListener('mousedown', e => {
    const opt = e.target.closest('.sel-opt[data-username]');
    if (!opt) return;
    e.preventDefault();
    const u = opt.dataset.username;
    if (tplShareSelected.has(u)) tplShareSelected.delete(u); else tplShareSelected.add(u);
    opt.classList.toggle('on');
    tplShareSyncLabel();
  });
}

async function loadTemplateShareCandidates() {
  $('tpl-share-wrap').hidden = !isAdmin();
  if (!isAdmin()) return;
  try {
    const d = await api('GET', '/api/templates/share-candidates');
    tplShareCandidates = d.users || [];
    tplShareSelected = new Set();
    tplShareSyncLabel();
  } catch (e) { reportError(e, 'Could not load the share list'); }
}

function editTemplateRow(id) {
  const t = templatesCache.find(x => x.id === id);
  if (!t) return;
  tplEditingId = id;
  $('tpl-name').value = t.name;
  $('tpl-switch-type').value = t.switch_type;
  $('tpl-acl-kind').value = t.acl_kind || 'extended';
  $('tpl-direction').value = t.direction;
  updateTplAclKindVisibility();
  $('tpl-lines').innerHTML = '';
  (t.lines.length ? t.lines : ['']).forEach(l => addTplLineRow(l));
  tplShareSelected = new Set(t.shared_with || []);
  tplShareSyncLabel();
  $('tpl-form-label').textContent = `Edit Template: ${t.name}`;
  $('btn-tpl-cancel-edit').hidden = false;
  fieldError($('tpl-form-error'), '');
  $('tpl-form-label').scrollIntoView({ behavior: 'smooth', block: 'center' });
}

async function deleteTemplateRow(id, name) {
  const proceed = await confirmDialog({
    title: 'Delete template',
    message: `Delete template '${name}'? This only removes the saved template — it doesn't `
           + `touch any rules already applied to a switch from it.`,
    okLabel: 'Delete', okClass: 'btn-danger',
  });
  if (!proceed) return;
  try {
    await api('DELETE', `/api/templates/${id}`);
    ok('Template deleted', `'${name}' was removed.`);
    if (tplEditingId === id) resetTemplateForm();
    await loadTemplates();
  } catch (e) { reportError(e, 'Could not delete the template'); }
}

window.applyTemplateFlow = async function (templateId, direction, switchType) {
  if (!needSwitch()) return;
  const sw0 = swById(S.swIds[0]);
  const platformLabel = switchType === 'nexus' ? 'NX-OS' : 'IOS';
  if (!sw0 || (sw0.switch_type || 'ios') !== switchType) {
    return warn('Wrong switch type',
      `Select ${platformLabel === 'IOS' ? 'an' : 'a'} ${platformLabel} switch to apply this template.`);
  }
  let aclNames;
  try {
    const d = await api('POST', '/api/analysis/list-acls', { switch_ids: S.swIds });
    aclNames = d.acl_names || [];
  } catch (e) { return reportError(e, 'Could not list ACLs'); }
  if (!aclNames.length) return warn('No ACLs found', 'The selected switch has no IP access lists.');
  const aclName = await openPicker('Select ACL', aclNames.map(n => ({ value: n, label: n })));
  if (!aclName) return;
  let preview;
  try {
    preview = await api('POST', '/api/analysis/template-apply-preview',
      { template_id: templateId, switch_id: sw0.id, acl_name: aclName, direction });
  } catch (e) { return reportError(e, 'Could not preview the template apply'); }
  const targetSwitches = await confirmVpcAware(sw0.id, {
    title: 'Apply template',
    message: `Apply this template's ${direction}bound rules to ${aclName}? Running-config `
           + `only — use Save Config afterwards.`,
    commands: preview.commands,
    okLabel: 'Apply', okClass: 'btn-warning',
  });
  if (!targetSwitches) return;
  try {
    const results = await Promise.all(targetSwitches.map(sw2 =>
      api('POST', '/api/write/template-apply',
        { template_id: templateId, switch_id: sw2.id, acl_name: aclName, direction })));
    const successful = results.filter(r => r.success);
    const failed = results.filter(r => !r.success);
    if (successful.length) {
      const msg = targetSwitches.length > 1
        ? `Template applied on ${successful.length} switch${successful.length === 1 ? '' : 'es'}`
        : 'Template applied';
      ok(msg, successful[0].message, targetSwitches.length === 1 ? {
        switchId: targetSwitches[0].id,
        commands: successful[0].undo_commands,
        label: successful[0].undo_label || 'remove the added rules',
        outputTarget: 'r-templates',
      } : null);
    }
    if (failed.length) bad('Some applies failed', failed.map(r => r.message).join('; '));
    await loadSwitches();
  } catch (e) { reportError(e, 'Could not apply the template'); }
};

/* ══════════ ACL REPORT ══════════ */
function downloadBlob(filename, content, mime) {
  const blob = content instanceof Blob ? content
    : new Blob([content], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoked on a later tick so the download has already started.
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function rptAnchor(prefix, name) {
  return prefix + String(name).replace(/[^A-Za-z0-9_.-]/g, '-').toLowerCase();
}

/* Turn the quoted group and schedule names inside an already-escaped
   sentence into links down to their definitions, so a reader can follow a
   reference instead of hunting for it. */
function rptLinkRefs(escapedText, item) {
  const link = (name, prefix, hint) => {
    const quoted = `&quot;${esc(name)}&quot;`;
    escapedText = escapedText.split(quoted).join(
      `<a class="rpt-ref-link" data-rpt-ref="${esc(rptAnchor(prefix, name))}"
        title="${hint} ${esc(name)}">${quoted}</a>`);
  };
  (item.groups || []).forEach(n => link(n, 'rptgrp-', 'Show the members of'));
  (item.schedules || []).forEach(n => link(n, 'rptsch-', 'Show the schedule'));
  return escapedText;
}

function renderAclReport(r) {
  const s = r.summary;
  const item = (it, n) => `<div class="rpt-item">
      <div class="rpt-num">${n}</div>
      <div class="rpt-text">
        ${it.sequence !== null && it.sequence !== undefined
          ? `<span class="rpt-seq">rule ${it.sequence}</span>` : ''}${
          rptLinkRefs(esc(it.text), it)}
        ${(it.details || []).map(d =>
          `<div class="rpt-detail">${rptLinkRefs(esc(d), it)}</div>`).join('')}
      </div></div>`;
  const section = (title, items, empty) => `<div class="rpt-sec">${esc(title)}</div>`
    + (items.length ? items.map((it, i) => item(it, i + 1)).join('')
       : `<div class="rpt-detail" style="border:none;padding-left:0">${esc(empty)}</div>`);

  const rules = n => `${n} rule${n === 1 ? '' : 's'}`;
  let html = `<div class="rpt-short">
      <div>This list contains ${rules(s.total)}.
        ${rules(s.allowed)} ${s.allowed === 1 ? 'allows' : 'allow'} access;
        ${rules(s.blocked)} ${s.blocked === 1 ? 'blocks' : 'block'} access.</div>
      <div class="rpt-default">${esc(r.default_action)}</div>
      ${r.scope_note ? `<div class="rpt-scope">${esc(r.scope_note)}</div>` : ''}
    </div>`;
  html += section('What is allowed', r.allowed, 'Nothing is explicitly allowed.');
  html += section('What is blocked', r.blocked, 'Nothing is explicitly blocked.');
  if (r.unparsed.length) {
    html += `<div class="rpt-sec">Lines that could not be translated</div>
      <div class="rpt-detail" style="border:none;padding-left:0;margin-bottom:6px">
        Shown exactly as configured so nothing is left out:</div>
      <div class="rpt-members">${esc(r.unparsed.join('\n'))}</div>`;
  }
  if (r.time_ranges.length) {
    html += `<div class="rpt-sec">Schedules used</div>` + r.time_ranges.map(t =>
      `<div class="rpt-grp" id="${esc(rptAnchor('rptsch-', t.name))}">
        <span class="rpt-grp-name">${esc(t.name)}</span>
        <span class="rpt-seq">currently ${esc(t.status)}</span>
        ${t.description.map(d => `<div class="rpt-detail">${esc(d)}</div>`).join('')}
      </div>`).join('');
  }
  if (r.groups.length) {
    html += `<div class="rpt-sec">Group definitions</div>` + r.groups.map(g =>
      `<div class="rpt-grp" id="${esc(rptAnchor('rptgrp-', g.name))}">
        <span class="rpt-grp-name">${esc(g.name)}</span>
        <span class="rpt-seq">${g.count} ${esc(g.kind)}</span>
        ${g.nested && g.nested.length ? `<div class="rpt-detail">Includes ${
          g.nested.map(n => `<a class="rpt-ref-link" data-rpt-ref="${esc(rptAnchor('rptgrp-', n))}"
            >${esc(n)}</a>`).join(', ')}</div>` : ''}
        ${g.members.length ? `<div class="rpt-members">${esc(g.members.join('\n'))}</div>` : ''}
      </div>`).join('');
  }
  return html;
}

window.openAclReport = async function (switchId, aclName) {
  $('report-acl-name').textContent = aclName;
  $('report-body').innerHTML = skeleton(4);
  ['btn-report-md', 'btn-report-html']
    .forEach(id => { $(id).disabled = true; });
  openModal('m-report');
  try {
    const d = await api('POST', '/api/analysis/acl-report',
      { switch_id: switchId, acl_name: aclName });
    $('report-body').innerHTML = renderAclReport(d.report);
    const stamp = (d.report.generated_at || '').replace(/[^0-9]/g, '').slice(0, 8);
    const base = `acl-report-${aclName}${stamp ? `-${stamp}` : ''}`.replace(/[^\w.-]/g, '_');
    ['btn-report-md', 'btn-report-html']
      .forEach(id => { $(id).disabled = false; });
    $('btn-report-md').onclick = () => downloadBlob(`${base}.md`, d.markdown, 'text/markdown');
    $('btn-report-html').onclick = () => downloadBlob(`${base}.html`, d.html, 'text/html');
  } catch (e) {
    $('report-body').innerHTML = `<div class="alert a-error">${esc(e.message)}</div>`;
    reportError(e, 'Could not build the report');
  }
};

/* ══════════ ADD ACL ══════════ */
function currentAclCreatePlatform() {
  const sw0 = swById(S.swIds[0]);
  return sw0 ? (sw0.switch_type || 'ios') : null;
}

function currentAclCreateAclKind() {
  return currentAclCreatePlatform() === 'ios' ? $('aacl-acl-kind').value : 'extended';
}

function updateAclCreateKindVisibility() {
  const wrap = $('aacl-kind-wrap');
  if (!wrap) return;
  const isIos = currentAclCreatePlatform() === 'ios';
  wrap.hidden = !isIos;
  if (!isIos) $('aacl-acl-kind').value = 'extended';
}

function populateAclCreateTemplateSelect() {
  const sel = $('aacl-template');
  if (!sel) return;
  const platform = currentAclCreatePlatform();
  const aclKind = currentAclCreateAclKind();
  const prev = sel.value;
  const options = platform
    ? templatesCache.filter(t => t.switch_type === platform && (t.acl_kind || 'extended') === aclKind)
    : [];
  sel.innerHTML = '<option value="">None</option>'
    + options.map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join('');
  sel.value = options.some(t => String(t.id) === prev) ? prev : '';
  updateAclCreateDirectionVisibility();
}

function updateAclCreateDirectionVisibility() {
  const wrap = $('aacl-direction-wrap');
  if (wrap) wrap.hidden = !$('aacl-template').value;
}

function updateAclCreateEligibility() {
  const btn = $('btn-aacl-create');
  if (!btn) return;
  const matches = !!currentAclCreatePlatform();
  btn.disabled = !matches;
  btn.title = matches
    ? 'Create this ACL on the selected switch'
    : 'Select a switch first';
}

function refreshAclCreateForSwitchSelection() {
  updateAclCreateKindVisibility();
  populateAclCreateTemplateSelect();
  updateAclCreateEligibility();
}

window.createAclFlow = async function () {
  if (!needSwitch()) return;
  const sw0 = swById(S.swIds[0]);
  const platform = sw0.switch_type || 'ios';
  const aclKind = currentAclCreateAclKind();
  let name;
  try {
    name = V.ident($('aacl-name').value, 'ACL name');
  } catch (e) { return bad('Check your input', e.message); }
  const implicitAction = $('aacl-implicit').value;
  const templateId = $('aacl-template').value ? +$('aacl-template').value : null;
  const direction = templateId ? $('aacl-direction').value : null;
  const payload = { acl_name: name, switch_id: sw0.id, switch_type: platform, acl_kind: aclKind,
                    implicit_action: implicitAction, template_id: templateId, direction };

  let preview;
  try {
    preview = await api('POST', '/api/analysis/acl-create-preview', payload);
  } catch (e) { return reportError(e, 'Could not preview the ACL create'); }

  const targetSwitches = await confirmVpcAware(sw0.id, {
    title: 'Create ACL',
    message: `Create ACL '${name}' on the selected switch? Running-config only — `
           + `use Save Config afterwards.`,
    commands: preview.commands,
    okLabel: 'Create', okClass: 'btn-primary',
  });
  if (!targetSwitches) return;

  try {
    const results = await Promise.all(targetSwitches.map(sw2 =>
      api('POST', '/api/write/acl-create', { ...payload, switch_id: sw2.id })));
    const successful = results.filter(r => r.success);
    const failed = results.filter(r => !r.success);
    if (successful.length) {
      const msg = targetSwitches.length > 1
        ? `ACL created on ${successful.length} switch${successful.length === 1 ? '' : 'es'}`
        : 'ACL created';
      ok(msg, successful[0].message, targetSwitches.length === 1 ? {
        switchId: targetSwitches[0].id,
        commands: successful[0].undo_commands,
        label: successful[0].undo_label || 'delete the ACL',
        outputTarget: 'r-add-acl',
      } : null);
    }
    if (failed.length) bad('Some creates failed', failed.map(r => r.message).join('; '));
    await loadSwitches();
  } catch (e) { reportError(e, 'Could not create the ACL'); }
};

/* ══════════ SAVE CONFIG ══════════ */
window.saveConfig = async function saveConfig() {
  if (!needSwitch()) return;
  const sel = selected();
  const names = sel.map(s => s.hostname || s.ip_address);
  const dirty = sel.filter(s => s.pending_changes);
  const extra = dirty.length
    ? `Unsaved changes are pending on ${dirty.map(s => s.hostname || s.ip_address).join(' and ')}.`
    : 'No changes have been made through this application since the last save. '
      + 'Saving is still safe and will persist anything changed elsewhere.';

  const proceed = await confirmDialog({
    title: 'Save configuration',
    message: `Copy running-config to startup-config on ${names.join(' and ')}? `
           + `This makes the running configuration permanent. ${extra}`,
    commands: ['copy running-config startup-config'],
    okLabel: 'Save Config', okClass: 'btn-warning',
  });
  if (!proceed) return;

  const bar = $('save-bar');
  const btn = $('btn-save');
  bar.dataset.busy = '1';
  bar.dataset.kind = 'save';
  bar.innerHTML = spinner('Saving configuration…');
  setBusy(btn, true, 'Saving…');
  try {
    const r = await api('POST', '/api/write/save-config', { switch_ids: S.swIds });
    bar.innerHTML = (r.results || []).map(x =>
      `${x.success ? '' : `<div class="alert a-error">${esc(x.switch_name)}: ${esc(x.message)}</div>`}`
      + (x.success
        ? switchCommandResult(`${x.switch_name}: ${x.message}`, x.output,
                              `${x.switch_name} · switch output`)
        : switchOutputBlock(x.output, `${x.switch_name} · switch output`))
    ).join('') || switchCommandResult(r.message, '', 'Switch output');
    if (r.success) {
      ok('Configuration saved', r.message);
    } else {
      bad('Save failed', r.message);
    }
  } catch (e) {
    bar.innerHTML = '';
    delete bar.dataset.kind;
    reportError(e, 'Could not save configuration');
  } finally {
    delete bar.dataset.busy;
    setBusy(btn, false);
    await loadSwitches();   // refresh pending_changes flags
  }
};

window.bulkSaveAllConfigs = async function bulkSaveAllConfigs() {
  const dirtyAll = S.switches.filter(s => s.pending_changes);
  if (!dirtyAll.length) {
    info('No unsaved changes', 'All switches are up to date.');
    return;
  }

  const names = dirtyAll.map(s => s.hostname || s.ip_address);
  const proceed = await confirmDialog({
    title: 'Save all configurations',
    message: `Copy running-config to startup-config on ${dirtyAll.length} switch${dirtyAll.length === 1 ? '' : 'es'}? `
           + `This will save: ${names.join(', ')}.`,
    commands: ['copy running-config startup-config'],
    okLabel: 'Save All', okClass: 'btn-warning',
  });
  if (!proceed) return;

  const btn = $('btn-bulk-save');
  setBusy(btn, true, 'Saving…');
  
  let success = false;
  try {
    const r = await api('POST', '/api/write/bulk-save-config', { switch_ids: dirtyAll.map(s => s.id) });
    success = r.success;
    const bar = $('save-bar');
    if (bar) {
      bar.dataset.kind = 'save-output';
      bar.innerHTML = (r.results || []).map(x =>
        `${x.success ? '' : `<div class="alert a-error">${esc(x.switch_name)}: ${esc(x.message)}</div>`}`
        + (x.success
          ? switchCommandResult(`${x.switch_name}: ${x.message}`, x.output,
                                `${x.switch_name} · switch output`)
          : switchOutputBlock(x.output, `${x.switch_name} · switch output`))
      ).join('') || switchCommandResult(r.message, '', 'Switch output');
    }
    
    if (r.success) {
      ok('Configurations saved', r.message);
    } else {
      bad('Some saves failed', r.message);
    }
  } catch (e) {
    reportError(e, 'Could not save configurations');
  } finally {
    setBusy(btn, false);
    // Always reload switches to refresh pending_changes status, even on error
    await loadSwitches();
    // Force re-render of the button area after data is loaded
    buildSwitchManager();
  }
};

/* ══════════ TIME RANGE BUILDER ══════════ */
let trSeq = 0;
function addTrEntry() {
  trSeq++;
  const id = trSeq;
  const div = document.createElement('div');
  div.className = 'tre';
  div.id = `tre-${id}`;
  div.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px">
      <div style="display:flex;gap:11px;align-items:center">
        <label style="font-size:10.5px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.1em">Type</label>
        <select id="tre-type-${id}" style="width:150px">
          <option value="periodic">Periodic</option><option value="absolute">Absolute</option></select>
      </div>
      <button type="button" class="btn btn-sm btn-danger" data-tre-del="${id}">Remove</button>
    </div>
    <div id="tre-body-${id}">${trPeriodic(id)}</div>`;
  $('tr-entries').appendChild(div);
  $(`tre-type-${id}`).addEventListener('change', e => {
    closeTimePicker();
    closeDatePicker();
    $(`tre-body-${id}`).innerHTML = e.target.value === 'absolute' ? trAbsolute(id) : trPeriodic(id);
    enhanceSelects($(`tre-body-${id}`));
    setupTimePickers(id, e.target.value);
  });
  enhanceSelects(div);
  setupTimePickers(id, 'periodic');
}
function trPeriodic(id) {
  return `<div class="tre-row">
    <div class="field" style="min-width:178px"><label>Days</label>
      <select id="tre-days-${id}">
        <option value="daily">Every day</option><option value="weekdays">Weekdays (Mon–Fri)</option>
        <option value="weekend">Weekend (Sat–Sun)</option><option value="monday">Monday</option>
        <option value="tuesday">Tuesday</option><option value="wednesday">Wednesday</option>
        <option value="thursday">Thursday</option><option value="friday">Friday</option>
        <option value="saturday">Saturday</option><option value="sunday">Sunday</option></select></div>
    <div class="field"><label>Start time</label>
      <div class="time-input-group">
        <input type="text" id="tre-st-${id}" value="08:00" class="mono time-display" readonly>
        <button type="button" class="icon-btn time-icon-btn" data-time-input="tre-st-${id}">
          <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd"/></svg>
        </button>
      </div>
    </div>
    <div class="field"><label>End time</label>
      <div class="time-input-group">
        <input type="text" id="tre-et-${id}" value="18:00" class="mono time-display" readonly>
        <button type="button" class="icon-btn time-icon-btn" data-time-input="tre-et-${id}">
          <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd"/></svg>
        </button>
      </div>
    </div>
  </div>`;
}
function trAbsolute(id) {
  const now = new Date();
  const today = now.toISOString().split('T')[0];
  const currentTime = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
  
  return `<div class="tre-row">
      <div class="field"><label>Start time</label>
        <div class="time-input-group">
          <input type="text" id="tre-ast-${id}" value="${currentTime}" class="mono time-display" readonly>
          <button type="button" class="icon-btn time-icon-btn" data-time-input="tre-ast-${id}">
            <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd"/></svg>
          </button>
        </div>
      </div>
      <div class="field" style="flex:2"><label>Start date</label>
        <div class="date-input-group">
          <input type="text" id="tre-asd-${id}-display" value="${formatDateDisplay(today)}" class="mono date-display" readonly>
          <input type="date" id="tre-asd-${id}" value="${today}" class="hidden-date-input">
          <button type="button" class="icon-btn date-icon-btn" data-date-input="tre-asd-${id}">
            <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1zm0 5a1 1 0 000 2h8a1 1 0 100-2H6z" clip-rule="evenodd"/></svg>
          </button>
        </div>
      </div>
    </div>
    <div class="tre-row" style="margin-top:12px">
      <div class="field"><label>End time</label>
        <div class="time-input-group">
          <input type="text" id="tre-aet-${id}" value="23:59" class="mono time-display" readonly>
          <button type="button" class="icon-btn time-icon-btn" data-time-input="tre-aet-${id}">
            <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd"/></svg>
          </button>
        </div>
      </div>
      <div class="field" style="flex:2"><label>End date</label>
        <div class="date-input-group">
          <input type="text" id="tre-aed-${id}-display" class="mono date-display" readonly>
          <input type="date" id="tre-aed-${id}" class="hidden-date-input">
          <button type="button" class="icon-btn date-icon-btn" data-date-input="tre-aed-${id}">
            <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1zm0 5a1 1 0 000 2h8a1 1 0 100-2H6z" clip-rule="evenodd"/></svg>
          </button>
        </div>
      </div>
    </div>`;
}

function formatDateDisplay(dateStr) {
  if (!dateStr) return '';
  const d = new Date(dateStr + 'T00:00:00');
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  return `${d.getDate()} ${months[d.getMonth()]} ${d.getFullYear()}`;
}
const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
function toCiscoDate(v) {
  if (!v) return '';
  const [y, m, d] = v.split('-');
  return `${+d} ${MONTHS[+m - 1]} ${y}`;
}

/* ══════════ TIME PICKER & DATE PICKER SETUP ══════════ */
function setupTimePickers(id, type) {
  // Setup time picker buttons
  setTimeout(() => {
    document.querySelectorAll('.time-icon-btn').forEach(btn => {
      if (btn._timeSetup) return;
      btn._timeSetup = true;
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        const inputId = btn.dataset.timeInput;
        openTimePicker(inputId, btn);
      });
    });
    
    // Setup date picker buttons - use custom calendar
    document.querySelectorAll('.date-icon-btn').forEach(btn => {
      if (btn._dateSetup) return;
      btn._dateSetup = true;
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        const inputId = btn.dataset.dateInput;
        const displayInputId = inputId + '-display';
        openDatePicker(inputId, displayInputId, btn);
      });
    });
  }, 50);
}

function openTimePicker(inputId, button) {
  // Close any existing time picker
  closeTimePicker();
  closeDatePicker();
  
  const input = $(inputId);
  if (!input) return;
  
  const currentValue = input.value || '00:00';
  const [hours24, minutes] = currentValue.split(':').map(v => parseInt(v) || 0);
  
  // Convert to 12-hour format
  let hours12 = hours24 % 12;
  if (hours12 === 0) hours12 = 12;
  const ampm = hours24 >= 12 ? 'PM' : 'AM';
  
  const picker = document.createElement('div');
  picker.className = 'ios-time-picker';
  
  // Build hours (1-12) - need triple copies for infinite scroll effect
  const hoursHTML = Array.from({length: 12 * 3}, (_, i) => {
    const hour = (i % 12) + 1;
    const isSelected = (i >= 12 && i < 24) && hour === hours12;
    return `<div class="time-option ${isSelected ? 'selected' : ''}" data-hour="${hour}">${hour}</div>`;
  }).join('');
  
  // Build minutes (00-59) - need triple copies for infinite scroll effect
  const minutesHTML = Array.from({length: 60 * 3}, (_, i) => {
    const minute = i % 60;
    const isSelected = (i >= 60 && i < 120) && minute === minutes;
    return `<div class="time-option ${isSelected ? 'selected' : ''}" data-minute="${minute}">${String(minute).padStart(2, '0')}</div>`;
  }).join('');
  
  // Build AM/PM
  const ampmHTML = `
    <div class="time-option ${ampm === 'AM' ? 'selected' : ''}" data-ampm="AM">AM</div>
    <div class="time-option ${ampm === 'PM' ? 'selected' : ''}" data-ampm="PM">PM</div>
  `;
  picker.innerHTML = `
    <div class="time-picker-display">
      <input type="text" class="time-display-input" id="time-display-input" 
             value="${String(hours12).padStart(2, '0')}:${String(minutes).padStart(2, '0')} ${ampm}" 
             placeholder="HH:MM AM/PM" maxlength="8" />
      <div class="time-display-label">Scroll or type to set time</div>
    </div>
    <div class="time-picker-wheels">
      <div class="time-wheel-container">
        <div class="time-wheel-label">Hour</div>
        <div class="time-wheel" id="hour-wheel">${hoursHTML}</div>
      </div>
      <div class="time-wheel-separator">:</div>
      <div class="time-wheel-container">
        <div class="time-wheel-label">Minute</div>
        <div class="time-wheel" id="minute-wheel">${minutesHTML}</div>
      </div>
      <div class="time-wheel-container time-wheel-ampm">
        <div class="time-wheel-label">Period</div>
        <div class="time-wheel" id="ampm-wheel">${ampmHTML}</div>
      </div>
    </div>
    <div class="time-picker-highlight"></div>
    <div class="time-picker-actions">
      <button type="button" class="btn btn-sm btn-ghost time-cancel">Cancel</button>
      <button type="button" class="btn btn-sm btn-primary time-ok">OK</button>
    </div>
  `;
  
  document.body.appendChild(picker);
  
  // Position the picker
  const rect = button.getBoundingClientRect();
  picker.style.position = 'fixed';
  
  const pickerWidth = 360;
  const pickerHeight = picker.offsetHeight;
  
  let left = rect.right + 10;
  if (left + pickerWidth > window.innerWidth - 20) {
    left = rect.left - pickerWidth - 10;
  }
  if (left < 20) left = 20;
  
  let top = rect.top;
  if (top + pickerHeight > window.innerHeight - 20) {
    top = window.innerHeight - pickerHeight - 20;
  }
  if (top < 20) top = 20;
  
  picker.style.left = left + 'px';
  picker.style.top = top + 'px';
  
  const hourWheel = picker.querySelector('#hour-wheel');
  const minuteWheel = picker.querySelector('#minute-wheel');
  const ampmWheel = picker.querySelector('#ampm-wheel');
  const displayInput = picker.querySelector('#time-display-input');
  
  let selectedHour = hours12;
  let selectedMinute = minutes;
  let selectedAMPM = ampm;
  
  function updateDisplayFromPicker() {
    // Show 12-hour format in the display with AM/PM
    const h = String(selectedHour).padStart(2, '0');
    const m = String(selectedMinute).padStart(2, '0');
    displayInput.value = `${h}:${m} ${selectedAMPM}`;
  }
  
  // Allow manual editing of the time input
  displayInput.addEventListener('input', (e) => {
    const val = e.target.value.toUpperCase();
    // Allow typing HH:MM AM/PM format
    if (/^[\d:APM\s]*$/.test(val)) {
      // Auto-add colon after 2 digits
      const noSpace = val.replace(/\s/g, '');
      if (noSpace.length === 2 && !val.includes(':')) {
        e.target.value = val + ':';
      }
    } else {
      // Revert to previous valid value
      e.target.value = e.target.value.slice(0, -1);
    }
  });
  
  displayInput.addEventListener('blur', () => {
    // Validate and sync with wheels
    const val = displayInput.value.trim().toUpperCase();
    const match = val.match(/^(\d{1,2}):(\d{2})\s*(AM|PM)$/);
    if (match) {
      let h = parseInt(match[1]);
      const m = parseInt(match[2]);
      const period = match[3];
      
      if (h >= 1 && h <= 12 && m >= 0 && m <= 59) {
        selectedHour = h;
        selectedMinute = m;
        selectedAMPM = period;
        scrollToSelected(hourWheel, selectedHour, 'hour');
        scrollToSelected(minuteWheel, selectedMinute, 'minute');
        scrollToSelected(ampmWheel, selectedAMPM, 'ampm');
        updateDisplayFromPicker();
      } else {
        updateDisplayFromPicker();
      }
    } else {
      updateDisplayFromPicker();
    }
  });
  
  function scrollToSelected(wheel, value, type) {
    let selector;
    if (type === 'hour') {
      // Scroll to middle set (12-23 index range)
      const options = Array.from(wheel.querySelectorAll('[data-hour]'));
      const targetOption = options.find((opt, idx) => 
        idx >= 12 && idx < 24 && parseInt(opt.dataset.hour) === value
      );
      if (targetOption) {
        const wheelHeight = wheel.offsetHeight;
        const optionHeight = targetOption.offsetHeight;
        const scrollTop = targetOption.offsetTop - (wheelHeight / 2) + (optionHeight / 2);
        wheel.scrollTop = scrollTop;
      }
    } else if (type === 'minute') {
      // Scroll to middle set (60-119 index range)
      const options = Array.from(wheel.querySelectorAll('[data-minute]'));
      const targetOption = options.find((opt, idx) => 
        idx >= 60 && idx < 120 && parseInt(opt.dataset.minute) === value
      );
      if (targetOption) {
        const wheelHeight = wheel.offsetHeight;
        const optionHeight = targetOption.offsetHeight;
        const scrollTop = targetOption.offsetTop - (wheelHeight / 2) + (optionHeight / 2);
        wheel.scrollTop = scrollTop;
      }
    } else if (type === 'ampm') {
      const option = wheel.querySelector(`[data-ampm="${value}"]`);
      if (option) {
        const wheelHeight = wheel.offsetHeight;
        const optionHeight = option.offsetHeight;
        const scrollTop = option.offsetTop - (wheelHeight / 2) + (optionHeight / 2);
        wheel.scrollTop = scrollTop;
      }
    }
  }
  
  function handleWheelScroll(wheel, type) {
    const wheelHeight = wheel.offsetHeight;
    const options = Array.from(wheel.children);
    
    let closestOption = null;
    let closestDistance = Infinity;
    
    options.forEach(option => {
      const rect = option.getBoundingClientRect();
      const wheelRect = wheel.getBoundingClientRect();
      const optionCenter = rect.top + rect.height / 2;
      const wheelCenter = wheelRect.top + wheelRect.height / 2;
      const distance = Math.abs(optionCenter - wheelCenter);
      
      if (distance < closestDistance) {
        closestDistance = distance;
        closestOption = option;
      }
    });
    
    if (closestOption) {
      options.forEach(opt => opt.classList.remove('selected'));
      closestOption.classList.add('selected');
      
      if (type === 'hour') {
        selectedHour = parseInt(closestOption.dataset.hour);
      } else if (type === 'minute') {
        selectedMinute = parseInt(closestOption.dataset.minute);
      } else if (type === 'ampm') {
        selectedAMPM = closestOption.dataset.ampm;
      }
      
      updateDisplayFromPicker();
    }
  }
  
  // Infinite scroll effect for hours
  let isHourScrolling = false;
  let hourScrollTimeout;
  hourWheel.addEventListener('scroll', () => {
    if (isHourScrolling) return;
    clearTimeout(hourScrollTimeout);
    hourScrollTimeout = setTimeout(() => {
      handleWheelScroll(hourWheel, 'hour');
      
      // Check if we need to loop
      const scrollTop = hourWheel.scrollTop;
      const scrollHeight = hourWheel.scrollHeight;
      const clientHeight = hourWheel.clientHeight;
      const optionHeight = 40; // Match CSS
      const setHeight = 12 * optionHeight;
      
      if (scrollTop < setHeight / 2) {
        // Near top, jump to middle set
        isHourScrolling = true;
        hourWheel.scrollTop = scrollTop + setHeight;
        setTimeout(() => { isHourScrolling = false; }, 50);
      } else if (scrollTop > setHeight * 2 - clientHeight / 2) {
        // Near bottom, jump to middle set
        isHourScrolling = true;
        hourWheel.scrollTop = scrollTop - setHeight;
        setTimeout(() => { isHourScrolling = false; }, 50);
      }
      
      scrollToSelected(hourWheel, selectedHour, 'hour');
    }, 100);
  });
  
  // Infinite scroll effect for minutes
  let isMinuteScrolling = false;
  let minuteScrollTimeout;
  minuteWheel.addEventListener('scroll', () => {
    if (isMinuteScrolling) return;
    clearTimeout(minuteScrollTimeout);
    minuteScrollTimeout = setTimeout(() => {
      handleWheelScroll(minuteWheel, 'minute');
      
      // Check if we need to loop
      const scrollTop = minuteWheel.scrollTop;
      const scrollHeight = minuteWheel.scrollHeight;
      const clientHeight = minuteWheel.clientHeight;
      const optionHeight = 40;
      const setHeight = 60 * optionHeight;
      
      if (scrollTop < setHeight / 2) {
        isMinuteScrolling = true;
        minuteWheel.scrollTop = scrollTop + setHeight;
        setTimeout(() => { isMinuteScrolling = false; }, 50);
      } else if (scrollTop > setHeight * 2 - clientHeight / 2) {
        isMinuteScrolling = true;
        minuteWheel.scrollTop = scrollTop - setHeight;
        setTimeout(() => { isMinuteScrolling = false; }, 50);
      }
      
      scrollToSelected(minuteWheel, selectedMinute, 'minute');
    }, 100);
  });
  
  // AM/PM scroll handler
  let ampmScrollTimeout;
  ampmWheel.addEventListener('scroll', () => {
    clearTimeout(ampmScrollTimeout);
    ampmScrollTimeout = setTimeout(() => {
      handleWheelScroll(ampmWheel, 'ampm');
      scrollToSelected(ampmWheel, selectedAMPM, 'ampm');
    }, 100);
  });
  
  // Click to select
  hourWheel.addEventListener('click', (e) => {
    const option = e.target.closest('[data-hour]');
    if (option) {
      selectedHour = parseInt(option.dataset.hour);
      scrollToSelected(hourWheel, selectedHour, 'hour');
      updateDisplayFromPicker();
    }
  });
  
  minuteWheel.addEventListener('click', (e) => {
    const option = e.target.closest('[data-minute]');
    if (option) {
      selectedMinute = parseInt(option.dataset.minute);
      scrollToSelected(minuteWheel, selectedMinute, 'minute');
      updateDisplayFromPicker();
    }
  });
  
  ampmWheel.addEventListener('click', (e) => {
    const option = e.target.closest('[data-ampm]');
    if (option) {
      selectedAMPM = option.dataset.ampm;
      scrollToSelected(ampmWheel, selectedAMPM, 'ampm');
      updateDisplayFromPicker();
    }
  });
  
  // Initialize scroll positions
  setTimeout(() => {
    scrollToSelected(hourWheel, selectedHour, 'hour');
    scrollToSelected(minuteWheel, selectedMinute, 'minute');
    scrollToSelected(ampmWheel, selectedAMPM, 'ampm');
  }, 50);
  
  // OK button
  picker.querySelector('.time-ok').addEventListener('click', () => {
    // Convert 12-hour to 24-hour for storage
    let hour24 = selectedHour % 12;
    if (selectedAMPM === 'PM') hour24 += 12;
    
    const h = String(hour24).padStart(2, '0');
    const m = String(selectedMinute).padStart(2, '0');
    input.value = `${h}:${m}`;
    closeTimePicker();
  });
  
  // Cancel button
  picker.querySelector('.time-cancel').addEventListener('click', () => {
    closeTimePicker();
  });
  
  // Close on outside click
  setTimeout(() => {
    document.addEventListener('click', handleOutsideClick);
  }, 100);
  
  function handleOutsideClick(e) {
    if (!picker.contains(e.target) && e.target !== button && e.target !== input) {
      closeTimePicker();
    }
  }
  
  picker._outsideClickHandler = handleOutsideClick;
}

function closeTimePicker() {
  const picker = document.querySelector('.ios-time-picker');
  if (picker) {
    if (picker._outsideClickHandler) {
      document.removeEventListener('click', picker._outsideClickHandler);
    }
    picker.remove();
  }
}

function openDatePicker(inputId, displayInputId, button) {
  // Close any existing date picker
  closeDatePicker();
  closeTimePicker();
  
  const hiddenInput = $(inputId);
  const displayInput = $(displayInputId);
  if (!hiddenInput || !displayInput) return;
  
  const today = new Date();
  const currentValue = hiddenInput.value || '';
  const [year, month, day] = currentValue ? currentValue.split('-').map(v => parseInt(v)) : [today.getFullYear(), today.getMonth() + 1, today.getDate()];
  
  const picker = document.createElement('div');
  picker.className = 'modern-date-picker';
  
  let currentYear = year;
  let currentMonth = month;
  let selectedDay = currentValue ? day : null;
  
  function renderCalendar() {
    const monthNames = ['January', 'February', 'March', 'April', 'May', 'June',
                        'July', 'August', 'September', 'October', 'November', 'December'];
    
    const firstDay = new Date(currentYear, currentMonth - 1, 1).getDay();
    const daysInMonth = new Date(currentYear, currentMonth, 0).getDate();
    const daysInPrevMonth = new Date(currentYear, currentMonth - 1, 0).getDate();
    
    let daysHTML = '';
    
    // Previous month days
    for (let i = firstDay - 1; i >= 0; i--) {
      const d = daysInPrevMonth - i;
      daysHTML += `<div class="cal-day prev-month">${d}</div>`;
    }
    
    // Current month days
    for (let d = 1; d <= daysInMonth; d++) {
      const isSelected = (d === selectedDay && currentMonth === month && currentYear === year && selectedDay !== null);
      const isToday = (() => {
        const now = new Date();
        return d === now.getDate() && 
               currentMonth === (now.getMonth() + 1) && 
               currentYear === now.getFullYear();
      })();
      const classes = ['cal-day', isSelected ? 'selected' : '', isToday ? 'today' : ''].filter(Boolean).join(' ');
      daysHTML += `<div class="${classes}" data-day="${d}">${d}</div>`;
    }
    
    // Next month days
    const totalCells = firstDay + daysInMonth;
    const remainingCells = totalCells % 7 === 0 ? 0 : 7 - (totalCells % 7);
    for (let d = 1; d <= remainingCells; d++) {
      daysHTML += `<div class="cal-day next-month">${d}</div>`;
    }
    
    // Build month options
    const monthOptions = monthNames.map((name, i) => {
      return `<option value="${i + 1}" ${(i + 1) === currentMonth ? 'selected' : ''}>${name}</option>`;
    }).join('');
    
    picker.innerHTML = `
      <div class="cal-header">
        <select class="cal-select" id="month-select">${monthOptions}</select>
        <div class="cal-year-control">
          <button type="button" class="cal-year-btn" id="year-prev">‹</button>
          <input type="number" class="cal-year-input" id="year-input" value="${currentYear}" min="1900" max="2100">
          <button type="button" class="cal-year-btn" id="year-next">›</button>
        </div>
      </div>
      <div class="cal-weekdays">
        <div>Su</div><div>Mo</div><div>Tu</div><div>We</div><div>Th</div><div>Fr</div><div>Sa</div>
      </div>
      <div class="cal-days">${daysHTML}</div>
      <div class="cal-footer">
        <button type="button" class="btn btn-sm btn-ghost date-clear">Clear</button>
        <button type="button" class="btn btn-sm btn-secondary date-today">Today</button>
        <button type="button" class="btn btn-sm btn-primary date-ok">OK</button>
      </div>
    `;
    
    attachCalendarEvents();
  }
  
  function attachCalendarEvents() {
    // Month selection
    const monthSelect = picker.querySelector('#month-select');
    if (monthSelect) {
      monthSelect.addEventListener('change', (e) => {
        currentMonth = parseInt(e.target.value);
        renderCalendar();
      });
    }
    
    // Year input
    const yearInput = picker.querySelector('#year-input');
    if (yearInput) {
      yearInput.addEventListener('change', (e) => {
        const newYear = parseInt(e.target.value);
        if (newYear >= 1900 && newYear <= 2100) {
          currentYear = newYear;
          renderCalendar();
        } else {
          e.target.value = currentYear;
        }
      });
      
      yearInput.addEventListener('blur', (e) => {
        const newYear = parseInt(e.target.value);
        if (isNaN(newYear) || newYear < 1900 || newYear > 2100) {
          e.target.value = currentYear;
        }
      });
    }
    
    // Year navigation buttons
    const yearPrev = picker.querySelector('#year-prev');
    const yearNext = picker.querySelector('#year-next');
    
    if (yearPrev) {
      yearPrev.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        currentYear--;
        if (currentYear < 1900) currentYear = 1900;
        renderCalendar();
      });
    }
    
    if (yearNext) {
      yearNext.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        currentYear++;
        if (currentYear > 2100) currentYear = 2100;
        renderCalendar();
      });
    }
    
    /* Writing .value in code never fires an input/change event, so anything
       that reacts live to a picked date (the Activity Logs date filter)
       would never hear about it. Dispatch one explicitly. */
    const applyDate = dateStr => {
      hiddenInput.value = dateStr;
      displayInput.value = dateStr ? formatDateDisplay(dateStr) : '';
      hiddenInput.dispatchEvent(new Event('change', { bubbles: true }));
    };

    // Day selection
    picker.querySelectorAll('.cal-day[data-day]').forEach(el => {
      el.addEventListener('click', () => {
        selectedDay = parseInt(el.dataset.day);
        applyDate(`${currentYear}-${String(currentMonth).padStart(2, '0')}-${String(selectedDay).padStart(2, '0')}`);
        closeDatePicker();
      });
    });

    // Footer buttons
    picker.querySelector('.date-clear')?.addEventListener('click', () => {
      applyDate('');
      closeDatePicker();
    });

    picker.querySelector('.date-today')?.addEventListener('click', () => {
      const now = new Date();
      currentYear = now.getFullYear();
      currentMonth = now.getMonth() + 1;
      selectedDay = now.getDate();
      applyDate(`${currentYear}-${String(currentMonth).padStart(2, '0')}-${String(selectedDay).padStart(2, '0')}`);
      closeDatePicker();
    });

    picker.querySelector('.date-ok')?.addEventListener('click', () => {
      if (selectedDay) {
        applyDate(`${currentYear}-${String(currentMonth).padStart(2, '0')}-${String(selectedDay).padStart(2, '0')}`);
      }
      closeDatePicker();
    });
  }
  
  document.body.appendChild(picker);
  renderCalendar();
  
  // Position the picker
  const rect = button.getBoundingClientRect();
  picker.style.position = 'fixed';
  
  const pickerWidth = 340;
  const pickerHeight = picker.offsetHeight;
  
  let left = rect.right + 10;
  if (left + pickerWidth > window.innerWidth - 20) {
    left = rect.left - pickerWidth - 10;
  }
  if (left < 20) left = 20;
  
  let top = rect.top;
  if (top + pickerHeight > window.innerHeight - 20) {
    top = window.innerHeight - pickerHeight - 20;
  }
  if (top < 20) top = 20;
  
  picker.style.left = left + 'px';
  picker.style.top = top + 'px';
  
  // Close on outside click
  setTimeout(() => {
    document.addEventListener('click', handleOutsideClick);
  }, 100);
  
  function handleOutsideClick(e) {
    if (!picker.contains(e.target) && e.target !== button && e.target !== displayInput) {
      closeDatePicker();
    }
  }
  
  picker._outsideClickHandler = handleOutsideClick;
}

function closeDatePicker() {
  const picker = document.querySelector('.modern-date-picker');
  if (picker) {
    if (picker._outsideClickHandler) {
      document.removeEventListener('click', picker._outsideClickHandler);
    }
    picker.remove();
  }
}
function collectTrEntries() {
  const out = [];
  els('.tre').forEach(block => {
    const id = +block.id.replace('tre-', '');
    const type = $(`tre-type-${id}`)?.value;
    if (type === 'periodic') {
      const st = $(`tre-st-${id}`)?.value || '';
      const et = $(`tre-et-${id}`)?.value || '';
      V.time(st, 'Start time'); V.time(et, 'End time');
      if (st >= et) throw new Error('The start time must be earlier than the end time.');
      out.push({ type: 'periodic', days: $(`tre-days-${id}`)?.value || 'daily',
                 start_time: st, end_time: et });
    } else {
      const st = $(`tre-ast-${id}`)?.value || '';
      const sd = $(`tre-asd-${id}`)?.value || '';
      const et = $(`tre-aet-${id}`)?.value || '';
      const ed = $(`tre-aed-${id}`)?.value || '';
      if (!sd && !ed) throw new Error('An absolute entry needs a start and/or an end date.');
      const item = { type: 'absolute' };
      if (sd) { 
        if (st) V.time(st, 'Start time');
        if (st) item.start_time = st;
        item.start_date = toCiscoDate(sd);
      }
      if (ed) { 
        if (et) V.time(et, 'End time');
        if (et) item.end_time = et;
        item.end_date = toCiscoDate(ed);
      }
      if (sd && ed && `${sd}${st}` >= `${ed}${et}`) {
        throw new Error('The absolute start must be earlier than the end.');
      }
      out.push(item);
    }
  });
  if (!out.length) throw new Error('Add at least one entry.');
  return out;
}

function renderTrPreview(d) {
  const area = $('r-tr-preview');
  const swList = d.switches || [];
  area.innerHTML = `<div class="pv">
    <div class="pv-title">Time range · ${esc(d.name)}</div>
    <div class="mrow">Preview available for <strong>${esc(swList.map(s => s.switch_name).join(', '))}</strong></div>
    <div style="font-size:11.5px;color:var(--muted);margin:11px 0 5px">Commands (run inside <code>configure terminal</code>):</div>
    <div class="cli">${esc((d.commands || []).join('\n'))}</div>
    <div class="actions" style="margin-top:13px">
      <button class="btn btn-success" id="btn-tr-apply">Approve &amp; Apply</button>
      <button class="btn btn-ghost" onclick="document.getElementById('r-tr-preview').innerHTML=''">Cancel</button>
    </div>
    <div id="tr-apply-st"></div></div>`;

  $('btn-tr-apply').onclick = async () => {
    let targetSwitches = [...swList];
    const selectedIds = d.selected_switch_ids || [...S.swIds];
    const selectedSw = selectedIds.length === 1 ? swById(selectedIds[0]) : null;
    const peerSw = selectedSw?.vpc_peer_id ? swById(selectedSw.vpc_peer_id) : null;
    if (selectedSw && peerSw && swList.some(item => item.switch_id === peerSw.id)) {
      const selectedName = selectedSw.hostname || selectedSw.ip_address;
      const peerName = peerSw.hostname || peerSw.ip_address;
      const radioName = `vpc-time-range-choice-${Date.now()}`;
      const proceed = await confirmDialog({
        title: 'Apply time range to VPC pair?',
        message: `You are adding time range "${d.name}" on ${selectedName}. This switch has a VPC peer: ${peerName}.`,
        extraHTML: `<div class="vpc-choice"><strong>Apply to:</strong>
          <label><input type="radio" name="${radioName}" value="both" checked>
            <span>Both switches (${esc(selectedName)} and ${esc(peerName)})</span></label>
          <label><input type="radio" name="${radioName}" value="single">
            <span>Only ${esc(selectedName)}</span></label></div>`,
        okLabel: 'Apply', okClass: 'btn-success',
      });
      if (!proceed) return;
      const choice = document.querySelector(`input[name="${radioName}"]:checked`)?.value;
      if (choice !== 'both') {
        targetSwitches = swList.filter(item => item.switch_id === selectedSw.id);
      }
    } else {
      const proceed = await confirmDialog({
        title: selectedIds.length > 1 ? 'Apply time range to VPC pair?' : 'Apply time range',
        message: `Create or update time range "${d.name}" on `
               + `${targetSwitches.map(s => s.switch_name).join(' and ')}. Running-config only.`,
        commands: d.commands,
        okLabel: targetSwitches.length > 1 ? 'Apply to Both' : 'Apply',
        okClass: 'btn-success',
      });
      if (!proceed) return;
    }
    const st = $('tr-apply-st');
    st.innerHTML = spinner('Applying…');
    let html = '';
    let allSucceeded = true;
    for (const s of targetSwitches) {
      try {
        const r = await api('POST', '/api/write/time-range-apply',
          { switch_id: s.switch_id, name: d.name, commands: d.commands });
        if (r.success) {
          // Show toast with undo button
          ok(`Applied on ${s.switch_name}`, r.message, {
            switchId: s.switch_id,
            commands: r.undo_commands,
            label: r.undo_label || 'revert the time range',
            outputTarget: 'tr-apply-st',
          });
          html += switchCommandResult(`${s.switch_name}: ${r.message}`, r.output,
                                      `${s.switch_name} · switch output`);
        } else {
          allSucceeded = false;
          bad(`Failed on ${s.switch_name}`, r.message);
          html += `<div class="alert a-error">${esc(s.switch_name)}: ${esc(r.message)}</div>`
                + (r.output ? switchOutputBlock(
                    r.output, `${s.switch_name} · switch output`) : '');
        }
      } catch (e) {
        allSucceeded = false;
        reportError(e, `Failed on ${s.switch_name}`);
        html += `<div class="alert a-error">${esc(s.switch_name)}: ${esc(e.message)}</div>`;
      }
      st.innerHTML = html;
    }
    await loadSwitches();
    
    // Reset fields after successful application
    if (allSucceeded) {
      $('tr-name').value = '';
      $('tr-entries').innerHTML = '';
    }
  };
}

/* Delete a time range */
async function deleteTimeRange(name, switchId) {
  const sourceSw = swById(switchId);
  if (!sourceSw) {
    bad('No switch', 'Switch not found.');
    return;
  }
  
  // Check if this switch has a VPC peer
  const peerSw = sourceSw.vpc_peer_id ? swById(sourceSw.vpc_peer_id) : null;
  let targetSwitches = [sourceSw];
  
  // Check if both VPC switches are currently selected
  const bothSelected = peerSw && S.swIds.includes(sourceSw.id) && S.swIds.includes(peerSw.id);
  
  // If both VPC switches are selected, delete from both without asking
  if (bothSelected) {
    targetSwitches = [sourceSw, peerSw];
    const switchNames = targetSwitches.map(s => s.hostname || s.ip_address).join(' and ');
    const proceed = await confirmDialog({
      title: 'Delete time range',
      message: `Delete time range "${name}" from both VPC switches (${switchNames})? ` +
               `This will remove it from their running-config.`,
      okLabel: 'Delete',
      okClass: 'btn-danger'
    });
    if (!proceed) return;
  }
  // If there's a VPC peer but not both selected, ask if they want to delete from both
  else if (peerSw) {
    const peerName = peerSw.hostname || peerSw.ip_address;
    const sourceName = sourceSw.hostname || sourceSw.ip_address;
    
    const choice = await confirmDialog({
      title: 'Delete time range from VPC pair?',
      message: `You are deleting time range "${name}" from ${sourceName}. ` +
               `This switch has a VPC peer: ${peerName}.`,
      extraHTML: `
        <div style="margin-top:16px;padding:12px;background:var(--bg-secondary);border-radius:6px">
          <div style="font-weight:600;margin-bottom:8px">Delete from:</div>
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-bottom:6px">
            <input type="radio" name="vpc-delete-choice" value="both" checked>
            <span>Both switches (${sourceName} and ${peerName})</span>
          </label>
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
            <input type="radio" name="vpc-delete-choice" value="single">
            <span>Only ${sourceName}</span>
          </label>
        </div>
      `,
      okLabel: 'Delete',
      okClass: 'btn-danger'
    });
    
    if (!choice) return;
    
    // Check which option was selected
    const selectedOption = document.querySelector('input[name="vpc-delete-choice"]:checked')?.value;
    if (selectedOption === 'both') {
      targetSwitches = [sourceSw, peerSw];
    }
  } else {
    // No VPC peer, just confirm single switch deletion
    const proceed = await confirmDialog({
      title: 'Delete time range',
      message: `Delete time range "${name}" from ${sourceSw.hostname || sourceSw.ip_address}? ` +
               `This will remove it from the switch's running-config.`,
      okLabel: 'Delete',
      okClass: 'btn-danger'
    });
    if (!proceed) return;
  }

  try {
    // Delete from all target switches
    const results = await Promise.all(
      targetSwitches.map(sw => 
        api('POST', '/api/write/time-range-delete', { switch_id: sw.id, name })
      )
    );
    
    const successful = results.filter(r => r.success);
    const failed = results.filter(r => !r.success);
    
    if (successful.length > 0) {
      const msg = targetSwitches.length > 1
        ? `Time range deleted from ${successful.length} switch${successful.length === 1 ? '' : 'es'}`
        : 'Time range deleted';
      ok(msg, successful[0].message, successful.length === 1 ? {
        switchId: targetSwitches[0].id,
        commands: successful[0].undo_commands,
        label: successful[0].undo_label || 'restore the time range',
        outputTarget: 'r-tr-preview',
      } : null);
    }
    
    if (failed.length > 0) {
      bad('Some deletes failed', failed.map(r => r.message).join('; '));
    }
    $('r-tr-preview').innerHTML = results.map((r, index) =>
      `${r.success ? '' : `<div class="alert a-error">${esc(r.message)}</div>`}`
      + (r.success
        ? switchCommandResult(r.message, r.output,
            `${targetSwitches[index].hostname || targetSwitches[index].ip_address} · switch output`)
        : switchOutputBlock(r.output,
            `${targetSwitches[index].hostname || targetSwitches[index].ip_address} · switch output`))
    ).join('');
    
    await loadSwitches();
    // Reload the time ranges list
    if ($('r-tr-list').innerHTML !== '') {
      $('btn-load-tr').click();
    }
  } catch (e) {
    reportError(e, 'Could not delete time range');
  }
}

/* Edit a time range - populate the form with existing data */
function editTimeRange(data) {
  // Scroll to the create section
  const createCard = document.querySelector('#pg-time-range .card.admin-only');
  if (createCard) {
    createCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // Populate the name field
  $('tr-name').value = data.name;

  // Clear existing entries and reset sequence
  $('tr-entries').innerHTML = '';
  trSeq = 0;

  // Parse and create all entries
  if (data.entries && data.entries.length > 0) {
    data.entries.forEach(entryStr => {
      const parsed = parseTimeRangeEntry(entryStr);
      if (parsed) {
        // Create the entry with values already populated
        createAndPopulateTrEntry(parsed);
      }
    });
  }

  // Clear the preview area
  $('r-tr-preview').innerHTML = '';
}

/* Create a time range entry and populate it immediately */
function createAndPopulateTrEntry(parsed) {
  trSeq++;
  const id = trSeq;
  const div = document.createElement('div');
  div.className = 'tre';
  div.id = `tre-${id}`;
  
  // Build the HTML based on type
  const typeSelect = `
    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px">
      <div style="display:flex;gap:11px;align-items:center">
        <label style="font-size:10.5px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.1em">Type</label>
        <select id="tre-type-${id}" style="width:150px">
          <option value="periodic" ${parsed.type === 'periodic' ? 'selected' : ''}>Periodic</option>
          <option value="absolute" ${parsed.type === 'absolute' ? 'selected' : ''}>Absolute</option>
        </select>
      </div>
      <button type="button" class="btn btn-sm btn-danger" data-tre-del="${id}">Remove</button>
    </div>`;
  
  // Build the body based on type
  let bodyHtml = '';
  if (parsed.type === 'periodic') {
    bodyHtml = `<div class="tre-row">
      <div class="field" style="min-width:178px"><label>Days</label>
        <select id="tre-days-${id}">
          <option value="daily" ${parsed.days === 'daily' ? 'selected' : ''}>Every day</option>
          <option value="weekdays" ${parsed.days === 'weekdays' ? 'selected' : ''}>Weekdays (Mon–Fri)</option>
          <option value="weekend" ${parsed.days === 'weekend' ? 'selected' : ''}>Weekend (Sat–Sun)</option>
          <option value="monday" ${parsed.days === 'monday' ? 'selected' : ''}>Monday</option>
          <option value="tuesday" ${parsed.days === 'tuesday' ? 'selected' : ''}>Tuesday</option>
          <option value="wednesday" ${parsed.days === 'wednesday' ? 'selected' : ''}>Wednesday</option>
          <option value="thursday" ${parsed.days === 'thursday' ? 'selected' : ''}>Thursday</option>
          <option value="friday" ${parsed.days === 'friday' ? 'selected' : ''}>Friday</option>
          <option value="saturday" ${parsed.days === 'saturday' ? 'selected' : ''}>Saturday</option>
          <option value="sunday" ${parsed.days === 'sunday' ? 'selected' : ''}>Sunday</option>
        </select>
      </div>
      <div class="field"><label>Start time</label>
        <div class="time-input-group">
          <input type="text" id="tre-st-${id}" value="${esc(parsed.start_time || '08:00')}" class="mono time-display" readonly>
          <button type="button" class="icon-btn time-icon-btn" data-time-input="tre-st-${id}">
            <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd"/></svg>
          </button>
        </div>
      </div>
      <div class="field"><label>End time</label>
        <div class="time-input-group">
          <input type="text" id="tre-et-${id}" value="${esc(parsed.end_time || '18:00')}" class="mono time-display" readonly>
          <button type="button" class="icon-btn time-icon-btn" data-time-input="tre-et-${id}">
            <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd"/></svg>
          </button>
        </div>
      </div>
    </div>`;
  } else {
    // Absolute type
    const now = new Date();
    const defaultDate = now.toISOString().split('T')[0];
    const defaultTime = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
    
    bodyHtml = `<div class="tre-row">
      <div class="field"><label>Start time</label>
        <div class="time-input-group">
          <input type="text" id="tre-ast-${id}" value="${esc(parsed.start_time || defaultTime)}" class="mono time-display" readonly>
          <button type="button" class="icon-btn time-icon-btn" data-time-input="tre-ast-${id}">
            <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd"/></svg>
          </button>
        </div>
      </div>
      <div class="field" style="flex:2"><label>Start date</label>
        <div class="date-input-group">
          <input type="text" id="tre-asd-${id}-display" value="${esc(parsed.start_date ? formatDateDisplay(parsed.start_date) : '')}" class="mono date-display" readonly>
          <input type="date" id="tre-asd-${id}" value="${esc(parsed.start_date || '')}" class="hidden-date-input">
          <button type="button" class="icon-btn date-icon-btn" data-date-input="tre-asd-${id}">
            <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1zm0 5a1 1 0 000 2h8a1 1 0 100-2H6z" clip-rule="evenodd"/></svg>
          </button>
        </div>
      </div>
    </div>
    <div class="tre-row" style="margin-top:12px">
      <div class="field"><label>End time</label>
        <div class="time-input-group">
          <input type="text" id="tre-aet-${id}" value="${esc(parsed.end_time || '23:59')}" class="mono time-display" readonly>
          <button type="button" class="icon-btn time-icon-btn" data-time-input="tre-aet-${id}">
            <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd"/></svg>
          </button>
        </div>
      </div>
      <div class="field" style="flex:2"><label>End date</label>
        <div class="date-input-group">
          <input type="text" id="tre-aed-${id}-display" value="${esc(parsed.end_date ? formatDateDisplay(parsed.end_date) : '')}" class="mono date-display" readonly>
          <input type="date" id="tre-aed-${id}" value="${esc(parsed.end_date || '')}" class="hidden-date-input">
          <button type="button" class="icon-btn date-icon-btn" data-date-input="tre-aed-${id}">
            <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1zm0 5a1 1 0 000 2h8a1 1 0 100-2H6z" clip-rule="evenodd"/></svg>
          </button>
        </div>
      </div>
    </div>`;
  }
  
  div.innerHTML = typeSelect + `<div id="tre-body-${id}">${bodyHtml}</div>`;
  $('tr-entries').appendChild(div);
  
  // Setup event listener for type change
  $(`tre-type-${id}`).addEventListener('change', e => {
    closeTimePicker();
    closeDatePicker();
    $(`tre-body-${id}`).innerHTML = e.target.value === 'absolute' ? trAbsolute(id) : trPeriodic(id);
    enhanceSelects($(`tre-body-${id}`));
    setupTimePickers(id, e.target.value);
  });
  
  // Enhance selects and setup time pickers
  enhanceSelects(div);
  setupTimePickers(id, parsed.type);
}

/* Parse a time range entry string from the switch output */
function parseTimeRangeEntry(entryStr) {
  /* Strip the sequence number the switch prints in front of every entry --
     "10 absolute start ..." -- and tolerate seconds on the times. Both are
     how a real NX-OS box reports a range; without this the anchored patterns
     below never matched, Edit populated the name and nothing else, and the
     rules it was supposed to open for editing silently vanished. */
  entryStr = String(entryStr || '').trim().replace(/^\d+\s+/, '');
  const HHMM = '(\\d{1,2}:\\d{2})(?::\\d{2})?';

  // Periodic format: "periodic weekdays 08:00 to 18:00" or "periodic daily 08:00 to 18:00"
  const periodicMatch = entryStr.match(
    new RegExp(`^periodic\\s+([\\w-]+(?:\\s+[\\w-]+)*?)\\s+${HHMM}\\s+to\\s+${HHMM}`, 'i'));
  if (periodicMatch) {
    return {
      type: 'periodic',
      days: periodicMatch[1].toLowerCase(),
      start_time: periodicMatch[2].padStart(5, '0'),
      end_time: periodicMatch[3].padStart(5, '0')
    };
  }

  // Absolute format: "absolute start 08:00 01 January 2024 end 18:00 31 December 2024"
  // Also handle partial formats like just start or just end
  const absoluteMatch = entryStr.match(new RegExp(
    `^absolute(?:\\s+start\\s+${HHMM}\\s+(\\d{1,2}\\s+\\w+\\s+\\d{4}))?`
    + `(?:\\s+end\\s+${HHMM}\\s+(\\d{1,2}\\s+\\w+\\s+\\d{4}))?`, 'i'));
  if (absoluteMatch) {
    return {
      type: 'absolute',
      start_time: absoluteMatch[1] ? absoluteMatch[1].padStart(5, '0') : '',
      start_date: absoluteMatch[2] ? parseAbsoluteDate(absoluteMatch[2]) : '',
      end_time: absoluteMatch[3] ? absoluteMatch[3].padStart(5, '0') : '',
      end_date: absoluteMatch[4] ? parseAbsoluteDate(absoluteMatch[4]) : ''
    };
  }

  return null;
}

/* Convert Cisco date format to YYYY-MM-DD */
function parseAbsoluteDate(ciscoDate) {
  const months = {
    january: '01', february: '02', march: '03', april: '04',
    may: '05', june: '06', july: '07', august: '08',
    september: '09', october: '10', november: '11', december: '12'
  };
  
  const match = ciscoDate.match(/(\d{1,2})\s+(\w+)\s+(\d{4})/i);
  if (match) {
    const day = match[1].padStart(2, '0');
    const month = months[match[2].toLowerCase()] || '01';
    const year = match[3];
    return `${year}-${month}-${day}`;
  }
  return '';
}

/* Populate entry fields based on parsed data */
function populateEntryFields(id, data) {
  const typeSelect = $(`tre-type-${id}`);
  if (!typeSelect) return;

  typeSelect.value = data.type;
  typeSelect.dispatchEvent(new Event('change'));

  // Wait for the form to update
  setTimeout(() => {
    if (data.type === 'periodic') {
      if ($(`tre-days-${id}`)) $(`tre-days-${id}`).value = data.days;
      if ($(`tre-st-${id}`)) $(`tre-st-${id}`).value = data.start_time;
      if ($(`tre-et-${id}`)) $(`tre-et-${id}`).value = data.end_time;
    } else if (data.type === 'absolute') {
      if ($(`tre-ast-${id}`) && data.start_time) $(`tre-ast-${id}`).value = data.start_time;
      if ($(`tre-asd-${id}`) && data.start_date) {
        $(`tre-asd-${id}`).value = data.start_date;
        $(`tre-asd-${id}-display`).value = formatDateDisplay(data.start_date);
      }
      if ($(`tre-aet-${id}`) && data.end_time) $(`tre-aet-${id}`).value = data.end_time;
      if ($(`tre-aed-${id}`) && data.end_date) {
        $(`tre-aed-${id}`).value = data.end_date;
        $(`tre-aed-${id}-display`).value = formatDateDisplay(data.end_date);
      }
    }
    enhanceSelects($(`tre-${id}`));
  }, 50);
}

/* ══════════ USERS ══════════ */
const ROLE_TXT  = { user: 'user', admin: 'admin', super_admin: 'super admin' };
const ROLE_CLS  = { user: 'b-gray', admin: 'b-accent', super_admin: 'b-cyan' };
const ROLE_RANK = { user: 1, admin: 2, super_admin: 3 };

function fmtWait(secs) {
  if (!secs || secs <= 0) return '';
  if (secs < 60) return `${secs}s`;
  return `${Math.ceil(secs / 60)}m`;
}

window.unlockUser = async function (id, username) {
  const proceed = await confirmDialog({
    title: 'Unlock account',
    message: `Clear the lock and failed-attempt counter for "${username}"? `
           + `They will be able to sign in immediately.`,
    okLabel: 'Unlock', okClass: 'btn-warning',
  });
  if (!proceed) return;
  try {
    const r = await api('POST', `/api/auth/users/${id}/unlock`);
    if (r.changed === false) info('Nothing to unlock', r.message);
    else ok('Account unlocked', r.message);
    await loadUsers();
  } catch (e) { reportError(e, 'Could not unlock the account'); }
};

async function loadUsers() {
  const tb = $('users-tbody');
  tb.innerHTML = `<tr><td colspan="5">${spinner('Loading users…')}</td></tr>`;
  try {
    const users = await api('GET', '/api/auth/users');
    managedUsers = users;
    const myRank = ROLE_RANK[S.role] || 0;
    tb.innerHTML = users.map(u => {
      const isMe = u.username === S.username;
      // Equal or higher privilege may manage the target
      const canTouch = !isMe && myRank >= (ROLE_RANK[u.role] || 0);
      const roleOpts = ['user', 'admin']
        .concat(isSuper() ? ['super_admin'] : [])
        .map(r => `<option value="${r}" ${u.role === r ? 'selected' : ''}>${ROLE_TXT[r]}</option>`).join('');
      // Pre-lockout failed-attempt counts stay private to the account itself —
      // other admins only need to know once a lock actually needs clearing.
      const lockBadge = u.locked
        ? `<span class="badge b-red" title="Locked after failed sign-in attempts">
             🔒 LOCKED ${esc(fmtWait(u.seconds_remaining))}</span>`
        : '';
      const unlockBtn = u.locked && canTouch
        ? `<button class="btn btn-xs btn-warning" onclick="unlockUser(${u.id},'${jsq(u.username)}')">Unlock</button>`
        : '';
      
      // Trusted hosts display
      const trustedHosts = u.trusted_hosts ? esc(u.trusted_hosts) : '<span style="color:var(--muted)">Any IP</span>';
      
      return `<tr>
        <td><strong>${esc(u.username)}</strong>${isMe ? ' <span class="badge b-gray">you</span>' : ''}
            ${lockBadge}</td>
        <td><span class="badge ${ROLE_CLS[u.role] || 'b-gray'}">${esc(ROLE_TXT[u.role] || u.role)}</span></td>
        <td><span class="maga-table-badge"${isMe ? ' id="my-mega-cell"' : ''}>${megaBadgeMarkup(u.mega)}</span></td>
        <td style="font-size:11px;">${trustedHosts}</td>
        <td><div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
          ${canTouch ? `
            <span style="display:inline-block;width:150px"><select id="ur-${u.id}" class="sel-sm">${roleOpts}</select></span>
            <button class="btn btn-xs btn-secondary" onclick="setRole(${u.id},'${jsq(u.username)}')">Set Role</button>
            <button class="btn btn-xs btn-danger" onclick="delUser(${u.id},'${jsq(u.username)}')">Delete</button>`
          : isMe ? '<span style="color:var(--muted);font-size:11px">Your own account</span>'
                 : '<span style="color:var(--muted);font-size:11px">Higher privilege — protected</span>'}
          ${unlockBtn}
          ${(canTouch || isMe)
            ? `<button class="btn btn-xs btn-secondary" onclick="openResetPw(${u.id},'${jsq(u.username)}')">Reset Pass</button>`
            : ''}
          ${(isSuper() && !isMe) || (isAdmin() && isMe)
            ? `<button class="btn btn-xs btn-primary" onclick="openTrustedHosts(${u.id},'${jsq(u.username)}','${jsq(u.trusted_hosts || '')}')">Trusted Hosts</button>`
            : ''}
          ${isSuper() && (isMe || u.role !== 'super_admin')
            ? `<button class="btn btn-xs btn-secondary" onclick="openRenameUser(${u.id},'${jsq(u.username)}')">Rename</button>`
            : ''}
        </div></td></tr>`;
    }).join('');
    enhanceSelects(tb);
  } catch (e) {
    tb.innerHTML = `<tr><td colspan="5"><div class="alert a-error">${esc(e.message)}</div></td></tr>`;
  }
}

/* ══════════ MEGAS ══════════ */
const MAGA_CATALOG = {
  byte:  { name: 'Vibe Coder', note: 'A little robot coding away on its chest screen.' },
  spark: { name: 'RJ45',       note: 'An Ethernet plug that chases packets.' },
  orbit: { name: 'Ping',       note: 'A floating Wi-Fi scanner and signal finder.' },
  moss:  { name: 'Rack',       note: 'A miniature server rack with busy LEDs.' },
};

/* One user's Mega as it appears in the users table. Split out so that choosing
   a new Mega can refresh your own row in place, rather than leaving it stale
   until the next visit to the page reloads the table. */
function megaBadgeMarkup(mega) {
  const type = MAGA_CATALOG[mega] ? mega : 'byte';
  return `<span class="maga-table-dot maga-${type}"></span>${esc(MAGA_CATALOG[type].name)}`;
}

function magaMarkup(type, compact = false) {
  const safeType = MAGA_CATALOG[type] ? type : 'byte';
  return `<span class="maga-pet ${compact ? 'maga-pet-compact' : ''}" data-maga="${safeType}" aria-hidden="true">
    <span class="maga-shadow"></span>
    <span class="maga-tail"><i></i></span>
    <span class="maga-antenna"><i></i></span>
    <span class="maga-ear maga-ear-left"></span><span class="maga-ear maga-ear-right"></span>
    <span class="maga-body"><span class="maga-panel"></span></span>
    <span class="maga-head"><span class="maga-face"><i class="maga-eye maga-eye-left"></i><i class="maga-eye maga-eye-right"></i><i class="maga-mouth"></i></span></span>
    <span class="maga-foot maga-foot-left"></span><span class="maga-foot maga-foot-right"></span>
    <span class="maga-spark maga-spark-one"></span><span class="maga-spark maga-spark-two"></span>
    <span class="maga-tech"><i></i><i></i><i></i><i></i></span>
  </span>`;
}

function renderMagaStage() {
  const stage = $('maga-stage');
  if (!stage) return;
  megaRuleSuggestion = null;
  stage.classList.remove(
    'is-search-open', 'has-activity', 'is-excited', 'is-curious',
    'is-processing', 'is-scanning', 'is-dragging', 'has-rule-suggestion'
  );
  const type = MAGA_CATALOG[S.maga] ? S.maga : 'byte';
  stage.innerHTML = `<div class="mega-status-bubble" aria-live="polite">
    <span class="mega-live-status" data-mega-status hidden></span>
    <button type="button" class="mega-rule-suggestion" hidden>
      <strong>Access is denied</strong><span>Add an ACL rule</span>
    </button>
    <form class="mega-ip-form" novalidate hidden>
      <span class="mega-search-row"><input type="text" class="mega-ip-input" maxlength="15"
        inputmode="decimal" autocomplete="off" spellcheck="false" placeholder="Search an IP"
        aria-label="IPv4 address"><button type="submit" class="mega-ip-submit" aria-label="Search">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8.5" cy="8.5" r="5.5"/><path d="M12.5 12.5L17 17"/></svg>
        </button></span>
      <span class="mega-ip-feedback" aria-live="polite"></span>
    </form>
  </div>${magaMarkup(type)}`;
  stage.title = `${MAGA_CATALOG[type].name} · click to search · double-click to play`;
  stage.setAttribute('aria-label', `Move or play with ${MAGA_CATALOG[type].name}, your Mega`);
  stage.hidden = !S.token || !S.megaVisible;
  updateMegaActivityBubble();
  requestAnimationFrame(() => {
    restoreMegaPosition(stage);
    updateMegaActivityBubble();
  });
  startMegaLife();
}

function renderMagaSelector() {
  const box = $('maga-options');
  if (!box) return;
  const busy = appActivities.size > 0;
  box.setAttribute('aria-busy', busy ? 'true' : 'false');
  box.innerHTML = Object.entries(MAGA_CATALOG).map(([id, maga]) => {
    const selected = S.maga === id;
    /* The name/description are deliberately not drawn -- the artwork is the
       label here. They stay on title/aria-label so hovering and screen
       readers can still tell the four apart. */
    return `<button class="maga-option ${selected ? 'is-selected' : ''}" type="button" ${busy ? 'disabled' : ''}
              role="radio" aria-checked="${selected}" data-maga-choice="${id}"
              title="${esc(maga.name)} — ${esc(maga.note)}" aria-label="${esc(maga.name)}">
      <span class="maga-preview">${magaMarkup(id, true)}</span>
      <span class="maga-check" aria-hidden="true">✓</span>
    </button>`;
  }).join('');
}

async function chooseMaga(type, button) {
  if (!MAGA_CATALOG[type] || type === S.maga || appActivities.size) return;
  const state = $('maga-save-state');
  els('.maga-option', $('maga-options')).forEach(b => { b.disabled = true; });
  if (state) state.textContent = 'Saving your Mega…';
  try {
    const result = await api('PUT', '/api/auth/me/mega', { mega: type });
    S.maga = result.mega;
    localStorage.setItem('giga_mega', S.maga);
    const mine = managedUsers.find(user => user.username === S.username);
    if (mine) mine.mega = S.maga;
    const myCell = $('my-mega-cell');
    if (myCell) myCell.innerHTML = megaBadgeMarkup(S.maga);
    renderMagaSelector();
    renderMagaStage();
    const stage = $('maga-stage');
    stage.classList.add('is-excited');
    setTimeout(() => stage.classList.remove('is-excited'), 900);
    if (state) state.textContent = `${MAGA_CATALOG[type].name} is now your Mega.`;
  } catch (error) {
    reportError(error, 'Could not save your Mega');
    if (state) state.textContent = 'Your selection could not be saved.';
    renderMagaSelector();
  } finally {
    button?.blur();
  }
}

let megaDragState = null;
let megaIgnoreClick = false;
let megaLifeTimer = null;
let megaClickTimer = null;
let megaRuleSuggestion = null;

function megaVisibilityKey() {
  return `giga_mega_visible_${S.username || 'user'}`;
}

function syncMegaVisibilityControl() {
  const button = $('btn-mega-visibility');
  if (!button) return;
  button.classList.toggle('mega-is-hidden', !S.megaVisible);
  button.setAttribute('aria-pressed', S.megaVisible ? 'true' : 'false');
  button.title = S.megaVisible ? 'Hide your Mega' : 'Show your Mega';
}

function toggleMegaVisibility() {
  clearMegaRuleSuggestion();
  S.megaVisible = !S.megaVisible;
  localStorage.setItem(megaVisibilityKey(), String(S.megaVisible));
  // Persist against the account, so the choice follows the person rather
  // than the browser. Failing is harmless — the local copy still applies.
  api('PUT', '/api/auth/me/mega-visible', { visible: S.megaVisible })
    .catch(() => {});
  syncMegaVisibilityControl();
  renderMagaStage();
  info(S.megaVisible ? 'Mega shown' : 'Mega hidden',
       S.megaVisible ? 'Your Mega is back.' : 'Click your name again whenever you want it back.');
}

function isValidMegaIp(value) {
  if (!value || value.length > 15 || !/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return false;
  return value.split('.').every(part => {
    if (part.length > 1 && part.startsWith('0')) return false;
    const number = Number(part);
    return Number.isInteger(number) && number >= 0 && number <= 255;
  });
}

function openMegaIpSearch() {
  if (appActivities.size) return;
  const stage = $('maga-stage');
  const form = el('.mega-ip-form', stage);
  if (!stage || !form) return;
  stage.classList.add('is-search-open');
  form.hidden = false;
  const feedback = el('.mega-ip-feedback', form);
  if (feedback) feedback.innerHTML = '';
  updateMegaActivityBubble();
  setTimeout(() => el('.mega-ip-input', form)?.focus(), 30);
}

function offerMegaRuleSuggestion(access) {
  const stage = $('maga-stage');
  const button = stage ? el('.mega-rule-suggestion', stage) : null;
  if (!stage || !button || stage.hidden || !S.megaVisible || !isAdmin()) return false;
  closeMegaIpSearch();
  megaRuleSuggestion = access;
  stage.classList.add('has-rule-suggestion');
  button.hidden = false;
  updateMegaActivityBubble();
  return true;
}

function clearMegaRuleSuggestion() {
  megaRuleSuggestion = null;
  const stage = $('maga-stage');
  if (!stage) return;
  stage.classList.remove('has-rule-suggestion');
  const button = el('.mega-rule-suggestion', stage);
  if (button) button.hidden = true;
  updateMegaActivityBubble();
}

function closeMegaIpSearch() {
  const stage = $('maga-stage');
  if (!stage) return;
  stage.classList.remove('is-search-open');
  const form = el('.mega-ip-form', stage);
  if (form) {
    form.hidden = true;
    const input = el('.mega-ip-input', form);
    const feedback = el('.mega-ip-feedback', form);
    if (input) input.value = '';
    if (feedback) feedback.innerHTML = '';
  }
  updateMegaActivityBubble();
}

function renderMegaIpResults(data) {
  const rows = data.switches || [];
  const gateways = rows.filter(row => !row.error && row.on_switch);
  const withAcls = gateways.filter(row => row.acls?.length);
  if (!rows.length) {
    return '<span class="mega-ip-message is-info">No switches are configured for your account.</span>';
  }
  if (!gateways.length) {
    const unavailable = rows.filter(row => row.error).length;
    return `<span class="mega-ip-message is-warn">The gateway for <strong>${esc(data.ip_address)}</strong>
      was not found on any managed switch.${unavailable ? ` ${unavailable} switch${unavailable === 1 ? ' was' : 'es were'} unavailable.` : ''}</span>`;
  }
  if (!withAcls.length) {
    const locations = gateways.map(row => `${row.switch_name} · ${row.interface || 'interface unknown'}`).join(', ');
    return `<span class="mega-ip-message is-info">Gateway found on <strong>${esc(locations)}</strong>,
      but no ACL is applied to its interface.</span>`;
  }
  return `<span class="mega-ip-matches">${withAcls.map(row => `<span class="mega-ip-match">
      <span class="mega-ip-match-head"><strong>${esc(row.switch_name)}</strong><small>${esc(row.switch_ip || '')} · ${esc(row.interface || '—')}</small></span>
      ${row.acls.map(acl => `<button type="button" class="mega-acl-choice" data-mega-switch="${row.switch_id}"
        data-mega-acl="${esc(acl.acl_name)}"><span>${esc(acl.acl_name)}</span><small>${esc(acl.direction)} · ${acl.rule_count} rules</small></button>`).join('')}
    </span>`).join('')}</span>`;
}

async function runMegaIpLookup(event) {
  event.preventDefault();
  if (appActivities.size) return;
  const form = event.currentTarget;
  const input = el('.mega-ip-input', form);
  const feedback = el('.mega-ip-feedback', form);
  const value = (input?.value || '').trim();
  if (!isValidMegaIp(value)) {
    feedback.innerHTML = '<span class="mega-ip-message is-error">Enter a valid IPv4 address.</span>';
    input.value = '';
    input.focus();
    return;
  }
  const controls = els('input,button', form);
  controls.forEach(control => { control.disabled = true; });
  feedback.innerHTML = '<span class="mega-ip-message is-info">Searching every managed switch…</span>';
  try {
    const result = await api('POST', '/api/acl/check-ip-global', { ip_address: value });
    feedback.innerHTML = renderMegaIpResults(result);
  } catch (error) {
    feedback.innerHTML = `<span class="mega-ip-message is-error">${esc(error.message)}</span>`;
  } finally {
    controls.forEach(control => { control.disabled = false; });
  }
}

async function openLookupAcl(switchId, aclName) {
  const sw = swById(Number(switchId));
  if (!sw) {
    bad('Switch unavailable', 'Refresh switch management and try again.');
    return;
  }
  const ids = [sw.id];
  if (sw.vpc_peer_id && swById(sw.vpc_peer_id)) ids.push(sw.vpc_peer_id);
  S.swIds = ids;
  localStorage.setItem('giga_swIds', JSON.stringify(S.swIds));
  clearSwitchData();
  buildPicker();
  document.dispatchEvent(new CustomEvent('giga:switch-selection-change', {
    detail: { switchIds: [...S.swIds] },
  }));
  closeMegaIpSearch();
  showPage('acl-viewer');
  $('view-acl').value = aclName;
  await refreshViewer();
  els('#r-viewer .acl').forEach(panel => panel.classList.add('open'));
}

function megaPositionKey() {
  return `giga_mega_position_${S.username || 'user'}`;
}

function restoreMegaPosition(stage = $('maga-stage')) {
  if (!stage || stage.hidden) return;
  let saved;
  try { saved = JSON.parse(localStorage.getItem(megaPositionKey()) || 'null'); }
  catch { saved = null; }
  if (!saved || !Number.isFinite(saved.x) || !Number.isFinite(saved.y)) {
    stage.style.removeProperty('left');
    stage.style.removeProperty('top');
    stage.style.removeProperty('right');
    stage.style.removeProperty('bottom');
    return;
  }
  const maxX = Math.max(4, window.innerWidth - stage.offsetWidth - 4);
  const maxY = Math.max(4, window.innerHeight - stage.offsetHeight - 4);
  stage.style.left = `${Math.max(4, Math.min(maxX, saved.x * maxX))}px`;
  stage.style.top = `${Math.max(4, Math.min(maxY, saved.y * maxY))}px`;
  stage.style.right = 'auto';
  stage.style.bottom = 'auto';
}

function saveMegaPosition(stage) {
  const rect = stage.getBoundingClientRect();
  const maxX = Math.max(1, window.innerWidth - rect.width);
  const maxY = Math.max(1, window.innerHeight - rect.height);
  localStorage.setItem(megaPositionKey(), JSON.stringify({
    x: Math.max(0, Math.min(1, rect.left / maxX)),
    y: Math.max(0, Math.min(1, rect.top / maxY)),
  }));
}

function clampMegaPosition() {
  const stage = $('maga-stage');
  if (!stage || stage.hidden || stage.style.left === '') return;
  const rect = stage.getBoundingClientRect();
  const left = Math.max(4, Math.min(window.innerWidth - rect.width - 4, rect.left));
  const top = Math.max(4, Math.min(window.innerHeight - rect.height - 4, rect.top));
  stage.style.left = `${left}px`;
  stage.style.top = `${top}px`;
  saveMegaPosition(stage);
  updateMegaActivityBubble();
}

function beginMegaDrag(event) {
  if (event.button !== 0 || event.target.closest('.mega-status-bubble')) return;
  const stage = event.currentTarget;
  const rect = stage.getBoundingClientRect();
  megaDragState = {
    pointerId: event.pointerId, startX: event.clientX, startY: event.clientY,
    left: rect.left, top: rect.top, lastX: event.clientX, moved: false,
  };
  stage.setPointerCapture?.(event.pointerId);
}

function moveMega(event) {
  if (!megaDragState || megaDragState.pointerId !== event.pointerId) return;
  const dx = event.clientX - megaDragState.startX;
  const dy = event.clientY - megaDragState.startY;
  if (!megaDragState.moved && Math.hypot(dx, dy) < 5) return;
  megaDragState.moved = true;
  megaIgnoreClick = true;
  const stage = event.currentTarget;
  const maxX = window.innerWidth - stage.offsetWidth - 4;
  const maxY = window.innerHeight - stage.offsetHeight - 4;
  stage.style.left = `${Math.max(4, Math.min(maxX, megaDragState.left + dx))}px`;
  stage.style.top = `${Math.max(4, Math.min(maxY, megaDragState.top + dy))}px`;
  stage.style.right = 'auto';
  stage.style.bottom = 'auto';
  stage.classList.add('is-dragging');
  stage.classList.toggle('is-facing-left', event.clientX < megaDragState.lastX);
  updateMegaActivityBubble();
  megaDragState.lastX = event.clientX;
  event.preventDefault();
}

function endMegaDrag(event) {
  if (!megaDragState || megaDragState.pointerId !== event.pointerId) return;
  const stage = event.currentTarget;
  const moved = megaDragState.moved;
  stage.classList.remove('is-dragging');
  if (moved) saveMegaPosition(stage);
  stage.releasePointerCapture?.(event.pointerId);
  megaDragState = null;
}

function startMegaLife() {
  if (megaLifeTimer || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const moods = ['is-curious', 'is-processing', 'is-scanning'];
  megaLifeTimer = setInterval(() => {
    const stage = $('maga-stage');
    if (!stage || stage.hidden || stage.classList.contains('is-dragging')) return;
    const mood = moods[Math.floor(Math.random() * moods.length)];
    stage.classList.add(mood);
    setTimeout(() => stage.classList.remove(mood), 1400);
  }, 6500);
}

window.setRole = async function (id, username) {
  const sel = $(`ur-${id}`);
  if (!sel) return;
  const role = sel.value;
  const proceed = await confirmDialog({
    title: 'Change role',
    message: `Change ${username}'s role to "${ROLE_TXT[role] || role}"?`,
    okLabel: 'Change Role',
  });
  if (!proceed) { await loadUsers(); return; }
  try {
    const r = await api('PUT', `/api/auth/users/${id}/role`, { role });
    if (r.changed === false) info('No change made', r.message);
    else ok('Role updated', r.message);
    await loadUsers();
  } catch (e) { reportError(e, 'Could not change the role'); await loadUsers(); }
};

window.delUser = async function (id, username) {
  const proceed = await confirmDialog({
    title: 'Delete user',
    message: `Permanently delete the account "${username}"? This cannot be undone.`,
    okLabel: 'Delete User', okClass: 'btn-danger',
  });
  if (!proceed) return;
  try {
    const r = await api('DELETE', `/api/auth/users/${id}`);
    ok('User deleted', r.message);
    await loadUsers();
  } catch (e) { reportError(e, 'Could not delete the user'); }
};

let managedUsers = [];
let renameUserId = null;
window.openRenameUser = function (id, username) {
  renameUserId = id;
  $('ru-current').textContent = username;
  $('ru-name').value = username;
  fieldError($('ru-err'), '');
  openModal('m-renameuser');
  setTimeout(() => {
    $('ru-name')?.focus();
    $('ru-name')?.select();
  }, 50);
};

let resetPwId = null;
window.openResetPw = function (id, username) {
  resetPwId = id;
  $('rp-user').textContent = username;
  $('rp-new').value = ''; $('rp-cf').value = '';
  fieldError($('rp-err'), '');
  openModal('m-resetpw');
};

/* ══════════ SWITCH GRANTS & BULK ADD ══════════ */
/* A super admin can add a switch to other people's accounts. The row is
   theirs to use but not to change: only the granter can edit or remove it.
   Everyone gets the bulk path for their own switches. */

const GRANT = { users: [], granted: [] };

/* A switch a super admin granted read-only can be analysed but not changed.
   The server enforces this at the point commands are sent; the UI hides the
   controls so nobody is offered a button that always fails. */
const isReadOnlySwitch = sw => sw && (sw.access_level || 'write') === 'read';

/* A write grant can have had the terminal withheld on its own. Older rows
   report it as true, so an absent field means yes rather than no. */
const hasTerminalAccess = sw => sw && sw.terminal_access !== false;

function selectedCanUseTerminal() {
  const rows = S.swIds.map(swById).filter(Boolean);
  return rows.length > 0 && rows.every(
    sw => !isReadOnlySwitch(sw) && hasTerminalAccess(sw));
}

function terminalBlockedNote() {
  const blocked = S.swIds.map(swById)
    .filter(sw => sw && !isReadOnlySwitch(sw) && !hasTerminalAccess(sw));
  if (!blocked.length) return readOnlySelectionNote();
  const names = blocked.map(sw => sw.hostname || sw.ip_address).join(', ');
  return `Your access to ${names} does not include a terminal.`;
}

function selectedCanWrite() {
  const rows = S.swIds.map(swById).filter(Boolean);
  return rows.length > 0 && rows.every(sw => !isReadOnlySwitch(sw));
}

function readOnlySelectionNote() {
  const blocked = S.swIds.map(swById).filter(isReadOnlySwitch);
  if (!blocked.length) return '';
  const names = blocked.map(sw => sw.hostname || sw.ip_address).join(', ');
  return `You have read-only access to ${names}.`;
}

/* Called after any switch selection change: write controls follow the
   selection, not just the role. */
function applyAccessGating() {
  const writable = selectedCanWrite();
  const terminalUsable = selectedCanUseTerminal();
  [['btn-save', writable, readOnlySelectionNote],
   ['btn-terminal', terminalUsable, terminalBlockedNote]].forEach(
    ([id, allowed, note]) => {
      const btn = $(id);
      if (!btn || !isAdmin()) return;
      btn.disabled = !allowed;
      if (allowed) {
        btn.removeAttribute('data-tip');
        btn.title = '';
      } else {
        btn.title = note();
      }
    });
  const blocked = !writable && S.swIds.length > 0;
  els('.nav-item[data-page]').forEach(item => {
    if (!WRITE_PAGES.includes(item.dataset.page)) return;
    // Hidden, not dimmed: a dimmed item is still clickable, and the page
    // behind it could still run a preview.
    item.hidden = blocked || !isAdmin();
  });
  if (blocked && WRITE_PAGES.includes(currentMainPageId())) {
    showPage('acl-checker');
    warn('Read-only switch', readOnlySelectionNote()
      + ' Those pages change a switch, so they are unavailable.');
  }
}

/* Pages whose whole purpose is changing a switch. */
const WRITE_PAGES = ['rule-add', 'add-acl', 'templates', 'reverse-direction'];

function grantSelectedUsers() {
  return els('#sw-grant-users input[type=checkbox]:checked').map(c => c.value);
}

function renderGrantUsers() {
  const box = $('sw-grant-users');
  if (!box) return;
  const others = GRANT.users.filter(u => u.username !== S.username);
  if (!others.length) {
    box.innerHTML = '<div class="dash-empty">There are no other accounts yet.</div>';
    return;
  }
  box.innerHTML = others.map(u => `
    <label class="grant-user">
      <input type="checkbox" value="${esc(u.username)}" data-role="${esc(u.role)}">
      <span class="grant-user-name">${esc(u.username)}</span>
      <span class="badge ${ROLE_CLS[u.role] || 'b-gray'}">${esc(ROLE_TXT[u.role] || u.role)}</span>
    </label>`).join('');
  els('#sw-grant-users input[type=checkbox]').forEach(c =>
    c.addEventListener('change', updateGrantAccessHint));
  updateGrantAccessHint();
}

/* Read-only never carries a terminal, so the choice only exists on a write
   grant. Hidden rather than disabled: a ticked box that does nothing reads as
   a promise the grant is not making. */
function updateGrantTerminalVisibility() {
  const wrap = $('sw-grant-terminal-wrap');
  const sel = $('sw-grant-access');
  if (!wrap || !sel) return;
  wrap.hidden = sel.value === 'read';
}

/* A plain user has no write features anywhere, so write access would mean
   nothing for them — say so rather than letting the server silently downgrade. */
function updateGrantAccessHint() {
  const hint = $('sw-grant-access-hint');
  if (!hint) return;
  const plain = els('#sw-grant-users input[type=checkbox]:checked')
    .filter(c => c.dataset.role === 'user').map(c => c.value);
  hint.textContent = plain.length
    ? `${plain.join(', ')} ${plain.length === 1 ? 'is a' : 'are'} `
      + `standard user${plain.length === 1 ? '' : 's'}, `
      + 'so they can only be given read access.'
    : '';
}

async function loadGrantUsers() {
  if (!isSuper()) return;
  try {
    GRANT.users = await api('GET', '/api/auth/users');
  } catch (e) { GRANT.users = []; }
  renderGrantUsers();
}

function switchBulkIps() {
  if (!$('sw-bulk').checked) {
    const ip = $('sw-ip').value.trim();
    return ip ? [ip] : [];
  }
  return $('sw-ips').value.split(/[\n,;]+/).map(v => v.trim()).filter(Boolean);
}

function resetSwitchForm() {
  $('sw-ip').value = '';
  $('sw-ips').value = '';
  $('sw-pass').value = '';
  $('sw-username').value = '';
  $('sw-enable').checked = false;
  $('sw-enable-pass').value = '';
  $('sw-enable-wrap').style.display = 'none';
  els('#sw-grant-users input[type=checkbox]').forEach(c => { c.checked = false; });
  if ($('sw-grant-self')) $('sw-grant-self').checked = false;
  if ($('sw-grant-terminal')) $('sw-grant-terminal').checked = true;
  updateGrantTerminalVisibility();
  updateGrantAccessHint();
}

const GRANT_STATUS_CLS = { added: 'b-green', updated: 'b-green',
                           skipped: 'b-amber', error: 'b-red' };

/* Every IP and every person gets a line, so a partial result is legible
   rather than a single "some of it worked". */
function renderAddResults(d) {
  const box = $('sw-add-results');
  if (!box) return;
  if (!d) { box.innerHTML = ''; return; }
  box.innerHTML = `<div class="card card-pad0 grant-results">
    <div class="dash-feed-head">
      <span class="dash-section-title">Result</span>
      <span class="dash-feed-count">${d.added} added · ${d.updated} updated`
      + `${d.skipped ? ` · ${d.skipped} skipped` : ''}`
      + `${d.failed ? ` · ${d.failed} unreachable` : ''}</span>
    </div>
    ${d.results.map(r => `
      <div class="grant-result">
        <div class="grant-result-head">
          <span class="grant-ip">${esc(r.ip_address)}</span>
          ${r.hostname ? `<span class="grant-host">${esc(r.hostname)}</span>` : ''}
          ${r.status === 'error'
            ? `<span class="badge b-red">unreachable</span>` : ''}
        </div>
        ${r.error ? `<div class="grant-error">${esc(r.error)}</div>` : ''}
        ${(r.targets || []).map(t => `
          <div class="grant-target">
            <span class="badge ${GRANT_STATUS_CLS[t.status] || 'b-gray'}">${esc(t.status)}</span>
            <span class="grant-user-name">${esc(t.username)}</span>
            ${t.access_level ? `<span class="dash-muted">${esc(t.access_level)}${
              t.access_level !== 'read' && t.terminal_access === false
                ? ', no terminal' : ''}</span>` : ''}
            ${t.error ? `<span class="grant-error">${esc(t.error)}</span>` : ''}
          </div>`).join('')}
      </div>`).join('')}
  </div>`;
}

/* Conflicts the server reported that a confirmation can clear. Switches
   someone added themselves are never in here — those are never taken over. */
function overridableConflicts(d) {
  return d.results.flatMap(r => (r.targets || [])
    .filter(t => t.status === 'skipped' && /Confirm to take it over/.test(t.error || ''))
    .map(t => ({ ip: r.ip_address, username: t.username, error: t.error })));
}

async function submitSwitchAdd(overwrite = false) {
  const errEl = $('sw-err'), btn = $('btn-addsw');
  fieldError(errEl, '');
  const ips = switchBulkIps();
  const pass = $('sw-pass').value;
  const username = $('sw-username').value.trim();
  const useEnable = $('sw-enable').checked;
  const enablePass = $('sw-enable-pass').value;
  const targets = isSuper() ? grantSelectedUsers() : [];

  try {
    if (!ips.length) throw new Error('Enter at least one switch IP address.');
    const bad = ips.filter(ip => !V.ipv4(ip));
    if (bad.length) {
      throw new Error(`Not ${bad.length === 1 ? 'a valid IPv4 address' : 'valid IPv4 addresses'}: ${bad.join(', ')}.`);
    }
    if (!pass) throw new Error('Enter the SSH password so the switch can be reached.');
    if (useEnable && !enablePass) {
      throw new Error('Enable password is required when "Requires enable password" is checked.');
    }
  } catch (err) { return fieldError(errEl, err.message); }

  setBusy(btn, true, ips.length > 1 ? `Connecting to ${ips.length}…` : 'Connecting…');
  try {
    const d = await api('POST', '/api/switches/bulk', {
      ip_addresses: ips,
      ssh_username: username || S.username,
      ssh_password: pass,
      switch_type: $('sw-type').value,
      site: $('sw-site').value || null,
      use_enable: useEnable,
      enable_password: useEnable ? enablePass : null,
      save_password: true,
      usernames: targets.length ? targets : null,
      access_level: targets.length ? $('sw-grant-access').value : null,
      terminal_access: targets.length ? $('sw-grant-terminal').checked : null,
      include_self: targets.length ? $('sw-grant-self').checked : false,
      overwrite_granted: overwrite,
    });
    renderAddResults(d);

    const takeovers = overwrite ? [] : overridableConflicts(d);
    if (takeovers.length) {
      const lines = takeovers.map(t => `· ${t.username} — ${t.ip}`).join('\n');
      const proceed = await confirmDialog({
        title: 'Already granted by someone else',
        message: 'Another super admin already gave these people this switch:\n\n'
          + lines + '\n\nTaking over replaces their credentials and access level.',
        okLabel: 'Take over',
      });
      if (proceed) return submitSwitchAdd(true);
    }

    if (d.added || d.updated) {
      resetSwitchForm();
      ok('Switches saved',
         `${d.added} added, ${d.updated} updated`
         + (d.skipped ? `, ${d.skipped} skipped` : '')
         + (d.failed ? `, ${d.failed} could not be reached.` : '.'));
      await loadSwitches({ silent: false });
      await loadGrantedSwitches();
    } else if (d.failed) {
      fieldError(errEl, 'None of the switches could be reached. See the result below.');
    } else if (d.skipped) {
      fieldError(errEl, 'Nothing was changed. See the result below.');
    }
  } catch (err) {
    fieldError(errEl, err.message);
    reportError(err, 'Could not add the switch');
  } finally { setBusy(btn, false); }
}

/* ── switches you granted ── */

async function loadGrantedSwitches() {
  if (!isSuper()) return;
  const box = $('sw-granted-list');
  if (!box) return;
  try {
    const d = await api('GET', '/api/switches/granted');
    GRANT.granted = d.switches;
    renderGrantedSwitches();
  } catch (e) {
    box.innerHTML = `<div class="alert a-error">${esc(e.message)}</div>`;
  }
}

function renderGrantedSwitches() {
  const box = $('sw-granted-list');
  const block = $('sw-granted-block');
  if (!box) return;
  if (block) block.hidden = !isSuper();
  if (!GRANT.granted.length) {
    box.innerHTML = '<div class="dash-empty">You have not added any switches for other people.</div>';
    return;
  }
  const byOwner = new Map();
  GRANT.granted.forEach((s, i) => {
    if (!byOwner.has(s.owner_username)) byOwner.set(s.owner_username, []);
    byOwner.get(s.owner_username).push({ ...s, _i: i });
  });
  box.innerHTML = [...byOwner.entries()].map(([owner, rows]) => `
    <div class="granted-group">
      <div class="granted-group-head">${esc(owner)}
        <span class="cnt">${rows.length}</span></div>
      ${rows.map(s => grantedRowHtml(s, s._i)).join('')}
    </div>`).join('');
}

function grantedRowHtml(s, i) {
  return `
    <div class="granted-row">
      <div class="granted-main">
        <div class="granted-name">${esc(s.hostname || s.ip_address)}
          <span class="dash-muted">${esc(s.ip_address)}</span></div>
        <div class="granted-meta">ssh ${esc(s.ssh_username || '—')}
          ${s.site ? `· ${esc(s.site)}` : ''}</div>
      </div>
      <span class="badge ${s.access_level === 'read' ? 'b-amber' : 'b-green'}"
        >${s.access_level === 'read' ? 'read only' : 'write'}</span>
      ${s.access_level !== 'read' && !s.terminal_access
        ? '<span class="badge b-amber" title="Write access without an SSH terminal">no terminal</span>'
        : ''}
      <button class="btn btn-xs btn-secondary" onclick="openGrantEdit(${i})">Edit</button>
      <button class="btn btn-xs btn-danger" onclick="removeGrantedSwitch(${i})">Remove</button>
    </div>`;
}

window.updateGrantEditTerminal = function () {
  const wrap = $('ge-terminal-wrap');
  const sel = $('ge-access');
  if (wrap && sel) wrap.hidden = sel.value === 'read';
};

function promptGrantEdit(sw) {
  const extra = `
    <div class="field"><label>Their access</label>
      <select id="ge-access" onchange="updateGrantEditTerminal()">
        <option value="write"${sw.access_level !== 'read' ? ' selected' : ''}>Write</option>
        <option value="read"${sw.access_level === 'read' ? ' selected' : ''}>Read only</option>
      </select>
      <label class="toggle-row toggle-inline grant-terminal" id="ge-terminal-wrap"
             ${sw.access_level === 'read' ? 'hidden' : ''}>
        <input type="checkbox" id="ge-terminal"${sw.terminal_access ? ' checked' : ''}>
        <span>Terminal access</span>
      </label></div>
    <div class="field"><label>SSH Username <span class="label-hint">leave blank to keep</span></label>
      <input type="text" id="ge-user" autocomplete="off" spellcheck="false"
             placeholder="${esc(sw.ssh_username || '')}"></div>
    <div class="field"><label>SSH Password <span class="label-hint">leave blank to keep</span></label>
      <input type="password" id="ge-pass" autocomplete="new-password"
             placeholder="unchanged"></div>`;
  return confirmDialog({
    title: `Edit ${sw.hostname || sw.ip_address}`,
    message: `This switch belongs to ${sw.owner_username}. `
      + 'Changing the password or access level takes effect immediately and '
      + 'closes any session they have open on it.',
    okLabel: 'Save changes', extraHTML: extra,
  }).then(confirmed => {
    if (!confirmed) return null;
    // Read before the next dialog overwrites the shared container.
    const body = { access_level: $('ge-access') ? $('ge-access').value : null };
    if ($('ge-terminal')) body.terminal_access = $('ge-terminal').checked;
    const user = $('ge-user') ? $('ge-user').value.trim() : '';
    const pass = $('ge-pass') ? $('ge-pass').value : '';
    if (user) body.ssh_username = user;
    if (pass) body.ssh_password = pass;
    return body;
  });
}

window.openGrantEdit = async function (index) {
  const s = GRANT.granted[index];
  if (!s) return;
  const level = await promptGrantEdit(s);
  if (!level) return;
  try {
    const d = await api('PUT', `/api/switches/granted/${s.id}`, level);
    if (d.changed) ok('Updated', d.message);
    else info('No change', 'Nothing was different.');
    await loadGrantedSwitches();
  } catch (e) { reportError(e, 'Could not update the switch'); }
};

window.removeGrantedSwitch = async function (index) {
  const s = GRANT.granted[index];
  if (!s) return;
  const proceed = await confirmDialog({
    title: 'Take back this switch',
    message: `Remove '${s.hostname || s.ip_address}' from ${s.owner_username}'s switches? `
      + 'They will lose access to it entirely.',
    okLabel: 'Remove', okClass: 'btn-danger',
  });
  if (!proceed) return;
  try {
    const d = await api('DELETE', `/api/switches/granted/${s.id}`);
    ok('Removed', d.message);
    await loadGrantedSwitches();
  } catch (e) { reportError(e, 'Could not remove the switch'); }
};

/* ══════════ DASHBOARD (admin) ══════════ */
/* Two halves with different costs: activity is pure database and repaints
   freely; the switch analysis is SSH-backed, so it only ever renders the last
   stored scan and never triggers one on its own. */

const DASH = { window: '24h', slice: null, health: null, detail: null,
  /* The open tile's payload is kept so its rows can be opened up and, for
     the inventory list, re-filtered without another round trip. */
  detailData: null, detailLabel: '', switchOwner: '' };

function dashAgo(seconds) {
  if (seconds == null) return 'never';
  if (seconds < 90) return 'just now';
  const mins = Math.round(seconds / 60);
  if (mins < 90) return `${mins} min ago`;
  const hours = Math.round(mins / 60);
  if (hours < 36) return `${hours} h ago`;
  return `${Math.round(hours / 24)} d ago`;
}

function dashSliceParams() {
  const p = [`window=${encodeURIComponent(DASH.window)}`];
  if (DASH.slice) {
    p.push(`start=${encodeURIComponent(DASH.slice.start)}`);
    p.push(`end=${encodeURIComponent(DASH.slice.end)}`);
  }
  return p.join('&');
}

/* ── activity tiles ── */

const DASH_TILE_TIP = {
  changes: 'Writes that reached a switch in this period.',
  rules_added: 'Rules added to an ACL in this period.',
  rules_removed: 'Rules removed from an ACL in this period.',
  failed_operations: 'Operations that the switch rejected or that could not complete.',
  failed_logins: 'Rejected sign-in attempts, including those blocked by a lockout.',
  signed_in: 'Accounts that used the app within the idle-logout window. '
           + 'Sessions are not tracked, so this reflects recent activity.',
  switches: () => isSuper()
    ? 'Every switch registered, across every account. A switch two people '
      + 'have each registered counts once for each of them — the entries are '
      + 'separate records with their own credentials and access level.'
    : 'Switches you have registered.',
  unsaved: 'Switches whose running config has not been written to startup config.',
};

const DASH_TILES = [
  { kind: 'changes',           label: 'Changes' },
  { kind: 'rules_added',       label: 'Rules added' },
  { kind: 'rules_removed',     label: 'Rules removed' },
  { kind: 'failed_operations', label: 'Failed operations' },
  { kind: 'failed_logins',     label: 'Failed sign-ins' },
  { kind: 'signed_in',         label: 'Active users' },
  { kind: 'switches',          label: 'Switches' },
  { kind: 'unsaved',           label: 'Unsaved configs' },
];

function dashTileTip(t) {
  const tip = DASH_TILE_TIP[t.kind];
  return (typeof tip === 'function' ? tip() : tip) || t.label;
}

function renderDashTiles(k) {
  return `<div class="grid-4 dash-tiles">${DASH_TILES.map(t => `
    <div class="dash-tile ${DASH.detail === t.kind ? 'open' : ''}"
         role="button" tabindex="0" onclick="dashShowDetail('${t.kind}')"
         data-tip="${esc(dashTileTip(t))}"
         data-tip-hint="click to see the entries behind it">
      <div class="dash-tile-value">${k[t.kind] ?? 0}</div>
      <div class="dash-tile-label">${esc(t.label)}</div>
      ${t.hint ? `<div class="dash-tile-hint">${esc(t.hint)}</div>` : ''}
    </div>`).join('')}</div>
  <div id="dash-detail"></div>`;
}

/* ── the bar strip ── */

function dashBucketLabel(iso, seconds) {
  const d = new Date(/[zZ]|[+-]\d\d:\d\d$/.test(iso) ? iso : iso + 'Z');
  if (isNaN(d)) return '';
  const p = n => String(n).padStart(2, '0');
  if (seconds >= 86400) return `${p(d.getDate())}/${p(d.getMonth() + 1)}`;
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
}

function dashBucketFull(iso) {
  const d = new Date(/[zZ]|[+-]\d\d:\d\d$/.test(iso) ? iso : iso + 'Z');
  if (isNaN(d)) return iso;
  return d.toLocaleString(undefined, { weekday: 'short', day: 'numeric',
    month: 'short', hour: '2-digit', minute: '2-digit' });
}

function renderDashBars(d) {
  const peak = Math.max(1, ...d.buckets.map(b => b.count));
  const unit = d.bucket_seconds >= 86400 ? 'day'
    : d.bucket_seconds >= 3600 ? 'hour' : `${d.bucket_seconds / 60} minutes`;
  const dense = d.buckets.length > 12;
  return `<div class="card">
    <div class="dash-head">
      <div class="dash-section-title">Timeline</div>
      ${DASH.slice ? `<button class="btn btn-ghost btn-xs" onclick="dashClearSlice()"
        data-tip="Every tile and list below is limited to the highlighted ${esc(unit)}."
        data-tip-hint="click to go back to the whole window">
        Showing one ${esc(unit)} · show the whole window</button>` : ''}
    </div>
    <div class="dash-bars ${dense ? 'dense' : ''}">${d.buckets.map((b, i) => {
      const selected = DASH.slice && DASH.slice.start === b.start;
      return `<div class="dash-bar-slot ${selected ? 'selected' : ''}"
           onclick="dashSelectBucket(${i})"
           data-tip-title="${esc(dashBucketFull(b.start))}"
           data-tip="${b.count} ${b.count === 1 ? 'change' : 'changes'}"
           data-tip-hint="${selected ? 'click again to show the whole window'
                                     : 'click to focus this period'}">
        <div class="dash-bar-label">${esc(dashBucketLabel(b.start, d.bucket_seconds))}</div>
        <div class="dash-bar-track">
          <div class="dash-bar" style="height:${Math.round((b.count / peak) * 100)}%"></div>
        </div>
      </div>`;
    }).join('')}</div>
  </div>`;
}

/* One styled tooltip for the whole page. Native title= is slow to appear,
   unstyled, and truncates — everything on this page routes through here. */
function dashTipEl() {
  let tip = $('dash-tip');
  if (!tip) {
    tip = document.createElement('div');
    tip.id = 'dash-tip';
    tip.className = 'dash-tip';
    tip.hidden = true;
    document.body.appendChild(tip);
  }
  return tip;
}

function dashTipShow(event, html) {
  const tip = dashTipEl();
  tip.innerHTML = html;
  tip.hidden = false;
  const pad = 14;
  const rect = tip.getBoundingClientRect();
  let x = event.clientX + pad;
  if (x + rect.width > window.innerWidth - 8) x = event.clientX - rect.width - pad;
  let y = event.clientY - rect.height - pad;
  if (y < 8) y = event.clientY + pad;      // flip below when there is no room above
  tip.style.left = `${Math.max(8, x)}px`;
  tip.style.top = `${y}px`;
}

window.dashTipHide = function () {
  const tip = $('dash-tip');
  if (tip) tip.hidden = true;
};

/* Delegated so it covers content rendered after this runs. An element opts in
   with data-tip, and optionally data-tip-title / data-tip-hint. */
function wireDashTooltips() {
  const page = $('pg-dashboard');
  if (!page || page.dataset.tipsWired) return;
  page.dataset.tipsWired = '1';
  page.addEventListener('mousemove', e => {
    const host = e.target.closest('[data-tip]');
    if (!host) { dashTipHide(); return; }
    const title = host.dataset.tipTitle;
    const hint = host.dataset.tipHint;
    dashTipShow(e,
      (title ? `<div class="dash-tip-when">${esc(title)}</div>` : '')
      + `<div class="dash-tip-body">${esc(host.dataset.tip)}</div>`
      + (hint ? `<div class="dash-tip-hint">${esc(hint)}</div>` : ''));
  });
  page.addEventListener('mouseleave', dashTipHide);
  page.addEventListener('click', dashTipHide, true);
}

window.dashSelectBucket = function (index) {
  const b = (DASH.activity && DASH.activity.buckets || [])[index];
  if (!b) return;
  /* Clicking the selected bar again clears the focus. */
  DASH.slice = (DASH.slice && DASH.slice.start === b.start)
    ? null : { start: b.start, end: b.end };
  dashTipHide();
  loadDashActivity();
};

window.dashClearSlice = function () {
  DASH.slice = null;
  loadDashActivity();
};

/* ── activity feeds ── */

const DASH_EVENT_LABEL = {
  rule_add: 'rule added', rule_delete: 'rule removed', rule_edit: 'rule edited',
  acl_create: 'ACL created', acl_delete: 'ACL deleted', acl_binding: 'ACL binding',
  summary_apply: 'summary applied', template_apply: 'template applied',
  reverse_apply: 'direction reversed', object_group: 'object group',
  time_range: 'schedule', undo: 'undo', config_save: 'config saved',
  write_failed: 'failed', login: 'sign-in', login_failed: 'sign-in failed',
  switch_admin: 'switch admin', user_admin: 'user admin',
  analysis: 'read', terminal: 'terminal',
};

const DASH_LEVEL_CLS = { ERROR: 'b-red', WARN: 'b-amber', SUCCESS: 'b-green' };

function dashFeed(title, entries, emptyText, kind, opts = {}) {
  const body = entries.length ? entries.map((e, i) => `
    <div class="dash-feed-row" onclick="dashShowLog('${kind}', ${i})">
      <div class="dash-feed-when">${esc(fmtTime(e.timestamp))}</div>
      <div class="dash-feed-main">
        <div class="dash-feed-msg">${esc(e.message)}</div>
        <div class="dash-feed-meta">
          <span class="dash-feed-user">${esc(e.username)}</span>
          ${e.switch_label ? `<span class="dash-feed-sw">${esc(e.switch_label)}</span>` : ''}
          ${opts.showKind && e.event_type
            ? `<span class="badge ${DASH_LEVEL_CLS[e.level] || 'b-gray'}">${
                esc(DASH_EVENT_LABEL[e.event_type] || e.event_type)}</span>` : ''}
        </div>
      </div>
    </div>`).join('') : `<div class="dash-empty">${esc(emptyText)}</div>`;
  return `<div class="card card-pad0 dash-feed-card" data-feed="${kind}">
    <div class="dash-feed-head"><span class="dash-section-title">${esc(title)}</span>
      <div class="dash-feed-search-wrap">
        <button class="btn-icon dash-feed-search-btn" type="button" title="Search"
                aria-label="Search ${esc(title)}" onclick="dashToggleFeedSearch(this)">
          <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M9 3a6 6 0 104.472 10.03l3.249 3.249a1 1 0 001.414-1.414l-3.249-3.249A6 6 0 009 3zm-4 6a4 4 0 118 0 4 4 0 01-8 0z" clip-rule="evenodd"/></svg>
        </button>
        <input type="search" class="dash-feed-search" placeholder="Search…" hidden
               oninput="dashFilterFeed(this)">
      </div>
    </div>
    <div class="dash-feed">${body}</div>
  </div>`;
}

function renderDashActivity(d) {
  let html = renderDashTiles(d.kpis);
  html += renderDashBars(d);
  html += `<div class="grid-2">
    ${dashFeed('Last actions', d.recent_actions,
               'No changes were made in this period.', 'actions', { showKind: true })}
    ${dashFeed('User activity', d.recent_activity,
               'Nothing was logged in this period.', 'activity', { showKind: true })}
  </div>`;
  return html;
}

window.dashShowLog = function (kind, i) {
  const list = kind === 'actions' ? DASH.activity?.recent_actions
             : kind === 'detail' ? DASH.detailData?.entries
             : DASH.activity?.recent_activity;
  const l = list && list[i];
  if (!l) return;
  $('ld-time').textContent = fmtTime(l.timestamp);
  $('ld-level').textContent = l.level;
  $('ld-user').textContent = l.username;
  $('ld-ip').textContent = l.ip_address || 'not recorded';
  $('ld-msg').textContent = l.message;
  $('ld-desc').textContent = l.description || '(no additional detail)';
  openModal('m-log');
};

window.dashToggleFeedSearch = function (btn) {
  const wrap = btn.closest('.dash-feed-search-wrap');
  const input = wrap.querySelector('.dash-feed-search');
  const card = btn.closest('.card');
  input.hidden = !input.hidden;
  if (input.hidden) {
    input.value = '';
    card.querySelectorAll('.dash-feed-row').forEach(r => { r.hidden = false; });
  } else {
    input.focus();
  }
};

window.dashFilterFeed = function (input) {
  const card = input.closest('.card');
  const q = input.value.trim().toLowerCase();
  card.querySelectorAll('.dash-feed-row').forEach(row => {
    row.hidden = q ? !row.textContent.toLowerCase().includes(q) : false;
  });
};

/* ── tile drill-down ── */

window.dashShowDetail = async function (kind) {
  const box = $('dash-detail');
  if (!box) return;
  if (DASH.detail === kind) {        // second click closes it
    DASH.detail = null;
    DASH.detailData = null;
    box.innerHTML = '';
    dashHighlightTile(null);
    return;
  }
  DASH.detail = kind;
  DASH.switchOwner = '';
  dashHighlightTile(kind);
  box.innerHTML = skeleton(2);
  const label = (DASH_TILES.find(t => t.kind === kind) || {}).label || kind;
  DASH.detailLabel = label;
  try {
    const d = await api('GET',
      `/api/dashboard/activity/detail?kind=${encodeURIComponent(kind)}&${dashSliceParams()}`);
    DASH.detailData = d;
    box.innerHTML = renderDashDetail(kind, label, d);
    enhanceSelects(box);
  } catch (e) {
    box.innerHTML = `<div class="alert a-error">${esc(e.message)}</div>`;
  }
};

/* Scoped to the activity tiles, and forced to a real boolean: passing
   undefined to classList.toggle makes it flip rather than turn off, which
   would light up the analysis tiles further down the page. */
function dashHighlightTile(kind) {
  els('.dash-tiles .dash-tile').forEach((t, i) =>
    t.classList.toggle('open', !!(DASH_TILES[i] && DASH_TILES[i].kind === kind)));
}


window.dashFilterSwitchOwner = function (owner) {
  DASH.switchOwner = owner;
  const box = $('dash-detail');
  if (!box || !DASH.detail || !DASH.detailData) return;
  box.innerHTML = renderDashDetail(DASH.detail, DASH.detailLabel, DASH.detailData);
  enhanceSelects(box);
};

/* All of the addresses, not just the newest one: an account being used from
   two places at once is the thing worth seeing here, and collapsing it to a
   single address would hide exactly that. */
function dashUserIps(u) {
  const ips = u.ips || [];
  if (!ips.length) return '<span class="dash-muted">unknown</span>';
  return `<span class="dash-ips">${ips.map(ip =>
    `<span class="dash-ip">${esc(ip)}</span>`).join('')}</span>`;
}

function renderDashDetail(kind, label, d) {
  const close = `<button class="btn btn-ghost btn-xs" onclick="dashShowDetail('${kind}')">Close</button>`;
  const head = t => `<div class="dash-head"><div class="dash-section-title">${esc(t)}</div>${close}</div>`;

  if (d.users) {
    return `<div class="card">${head(label)}
      ${d.users.length ? `<div class="t-wrap"><table class="table"><thead><tr>
        <th>User</th><th>Role</th>
        <th data-tip="Every address this account has been active from in this window.">Signed in from</th>
        <th>Last seen</th></tr></thead><tbody>
        ${d.users.map(u => `<tr><td>${esc(u.username)}</td><td>${esc(u.role)}</td>
          <td>${dashUserIps(u)}</td>
          <td class="t-time">${esc(fmtTime(u.last_seen))}</td></tr>`).join('')}
        </tbody></table></div>`
        : `<div class="dash-empty">Nobody has used the app recently.
             Sessions are not tracked, so this only counts recent requests.</div>`}
    </div>`;
  }

  if (d.switches) {
    const isInventory = kind === 'switches';
    /* A super admin's inventory spans every account, so it needs a way to
       narrow to one. Filtered here rather than server-side, so the list of
       owners to choose from stays complete while a filter is applied. */
    const owners = [...new Set(d.switches.map(s => s.owner))].sort();
    const picked = isInventory && owners.length > 1 ? DASH.switchOwner : '';
    const rows = picked ? d.switches.filter(s => s.owner === picked) : d.switches;
    const ownerFilter = isInventory && owners.length > 1 ? `
      <select class="sel-sm" aria-label="Filter by owner"
              onchange="dashFilterSwitchOwner(this.value)">
        <option value="">All users</option>
        ${owners.map(o => `<option value="${esc(o)}" ${o === picked ? 'selected' : ''}
          >${esc(o)}</option>`).join('')}
      </select>` : '';
    const cols = isInventory
      ? ['Switch', 'Location', 'Owner', 'Type', 'IP', 'Access', 'VPC Peer']
      : ['Switch', 'Location', 'Owner', 'Last changed'];
    const row = s => isInventory
      ? `<tr><td>${esc(s.switch_label)}</td><td>${esc(s.site || '—')}</td>
          <td>${esc(s.owner)}</td><td>${esc(switchTypeLabel(s.switch_type))}</td>
          <td class="mono">${esc(s.ip_address || '—')}</td>
          <td><span class="badge ${s.access_level === 'read' ? 'b-amber' : 'b-green'}">${
            esc(s.access_level === 'read' ? 'Read only' : 'Write')}</span></td>
          <td>${esc(s.vpc_peer_label || '—')}</td></tr>`
      : `<tr><td>${esc(s.switch_label)}</td><td>${esc(s.site || '—')}</td>
          <td>${esc(s.owner)}</td>
          <td class="t-time">${s.last_change_at ? esc(fmtTime(s.last_change_at)) : '—'}</td></tr>`;
    return `<div class="card">
      <div class="dash-head">
        <div class="dash-section-title">${esc(picked ? `${label} — ${picked}` : label)}</div>
        <div class="dash-head-tools">${ownerFilter}${close}</div>
      </div>
      ${rows.length ? `<div class="t-wrap"><table class="table"><thead><tr>
        ${cols.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>
        ${rows.map(row).join('')}
        </tbody></table></div>` : `<div class="dash-empty">Nothing to show.</div>`}
    </div>`;
  }

  const shown = d.entries.length;
  const more = d.total > shown ? ` (showing the most recent ${shown})` : '';
  return `<div class="card">${head(`${label} — ${d.total}${more}`)}
    ${shown ? `<div class="dash-feed dash-feed-tall">${d.entries.map((e, i) => `
      <div class="dash-feed-row" onclick="dashShowLog('detail', ${i})">
        <div class="dash-feed-when">${esc(fmtTime(e.timestamp))}</div>
        <div class="dash-feed-main">
          <div class="dash-feed-msg">${esc(e.message)}</div>
          <div class="dash-feed-meta">
            <span class="dash-feed-user">${esc(e.username)}</span>
            ${e.switch_label ? `<span class="dash-feed-sw">${esc(e.switch_label)}</span>` : ''}
            <span class="badge ${DASH_LEVEL_CLS[e.level] || 'b-gray'}">${esc(e.level)}</span>
          </div>
        </div>
      </div>`).join('')}</div>`
      : `<div class="dash-empty">Nothing matched in this period.</div>`}
  </div>`;
}

/* ── switch analysis ── */

function dashMeter(side, label = '') {
  if (!side || side.percent == null) return '<span class="dash-muted">—</span>';
  const pct = side.percent;
  const tone = pct >= 90 ? 'crit' : pct >= 80 ? 'warn' : 'ok';
  const parts = [`${pct}% of the ACL TCAM used`];
  if (side.used != null) parts.push(`${side.used} entries used`);
  if (side.free != null) parts.push(`${side.free} free`);
  const tip = parts.join(' · ');
  return `<span class="dash-meter" data-tip="${esc(tip)}"${
    label ? ` data-tip-title="${esc(label)}"` : ''}>
    <span class="dash-meter-track"><span class="dash-meter-fill ${tone}"
      style="width:${Math.min(100, pct)}%"></span></span>
    <span class="dash-meter-text">${pct.toFixed(1)}%</span></span>`;
}

/* A count is only meaningful when the fetch behind it worked, so an
   unreachable switch shows its problem instead of a tidy row of zeros. */
const DASH_STATUS = {
  ok: ['b-green', 'OK'],
  partial: ['b-amber', 'Partial'],
  error: ['b-red', 'Unreachable'],
  no_credentials: ['b-amber', 'No password saved'],
  never_scanned: ['b-gray', 'Not scanned'],
};

const DASH_UNREADABLE = ['never_scanned', 'error', 'no_credentials'];

function dashCountCell(row, field, page, opts = {}) {
  if (DASH_UNREADABLE.includes(row.status)) return '<span class="dash-muted">—</span>';
  const n = Array.isArray(field)
    ? field.reduce((sum, f) => sum + (row[f] || 0), 0)
    : (row[field] || 0);
  if (!n) return '<span class="dash-zero">0</span>';
  const tip = opts.title ? ` data-tip="${esc(opts.title(row))}"` : '';
  return `<a class="dash-jump"${tip} data-tip-hint="click to open the detail"
    onclick="dashOpen('${page}', ${row.switch_id})">${n}</a>`;
}

/* The Redundancy Checker counts both passes together, so the dashboard must
   too — otherwise the same switch reports two different numbers. */
const DASH_REDUNDANT_FIELDS = ['redundant_count', 'trailing_redundant_count'];

function dashRedundantTitle(row) {
  return `${row.redundant_count || 0} covered by an earlier rule, `
       + `${row.trailing_redundant_count || 0} superseded by a later one`;
}

function dashVpcCounts(row) {
  return (row.vpc_mismatch_count || 0) + (row.vpc_binding_mismatch_count || 0);
}

function dashVpcLabel(row) {
  if (row.vpc_sync_status === 'match') return 'in sync';
  const n = dashVpcCounts(row);
  return n ? `${n} mismatch${n === 1 ? '' : 'es'}` : 'mismatch';
}

function dashSwitchTip(row) {
  const bits = [row.switch_ip, switchTypeLabel(row.switch_type)];
  if (row.site) bits.push(row.site);
  return bits.filter(Boolean).join(' · ');
}

/* A pair can only be compared when both halves were read in the same sweep.
   When either is unreachable the stored verdict is whatever the last good
   sweep found, and showing it would report a switch nobody can currently
   reach as "in sync". Every other count on this row is already withheld for
   the same reason; this one used to be the exception. */
function dashVpcCell(row, byId) {
  if (!row.vpc_peer_id) {
    return '<span class="dash-muted" data-tip="This switch has no VPC peer.">—</span>';
  }
  const peer = byId.get(row.vpc_peer_id);
  const unread = DASH_UNREADABLE.includes(row.status);
  const peerUnread = !peer || DASH_UNREADABLE.includes(peer.status);
  if (unread || peerUnread) {
    return `<span class="dash-muted" data-tip="${esc(unread
      ? 'Not compared — this switch could not be read. See the status column.'
      : 'Not compared — its VPC peer was not read in this sweep.')}">—</span>`;
  }
  if (!row.vpc_sync_status) {
    return `<span class="dash-muted" data-tip="Not compared yet.">—</span>`;
  }
  return `<span class="badge ${row.vpc_sync_status === 'match' ? 'b-green' : 'b-red'}"
    data-tip="${esc(dashVpcTitle(row))}">${dashVpcLabel(row)}</span>`;
}

function dashVpcTitle(row) {
  if (row.vpc_sync_status === 'match') return 'Rules and VLAN bindings match its peer.';
  const acls = row.vpc_mismatch_count || 0;
  const bindings = row.vpc_binding_mismatch_count || 0;
  const parts = [];
  if (acls) parts.push(`${acls} ACL${acls === 1 ? '' : 's'} whose rules differ`);
  if (bindings) parts.push(bindings === 1
    ? '1 VLAN binding that differs'
    : `${bindings} VLAN bindings that differ`);
  return parts.length ? `Compared with its peer: ${parts.join(', ')}.`
                      : 'Differs from its peer.';
}

/* Same order as Switch Management: locations in the user's chosen order, and
   switches in theirs within each location. The API returns them by id, which
   matches nothing the user has arranged. */
function dashSortSwitches(rows) {
  const sitePos = new Map(orderedSiteKeys().map((site, i) => [site, i]));
  const swPos = new Map(mergeOrder(
    S.switchOrder, S.switches.map(sw => sw.id)).map((id, i) => [id, i]));
  const last = Number.MAX_SAFE_INTEGER;
  return [...rows].sort((a, b) => {
    const sa = sitePos.get(a.site || '') ?? last;
    const sb = sitePos.get(b.site || '') ?? last;
    if (sa !== sb) return sa - sb;
    const pa = swPos.get(a.switch_id) ?? last;
    const pb = swPos.get(b.switch_id) ?? last;
    if (pa !== pb) return pa - pb;
    return (a.switch_label || '').localeCompare(b.switch_label || '');
  });
}


function renderDashHealth(d) {
  const t = d.totals;
  let html = `<div class="grid-4">
    ${[['Redundant rules', (t.redundant_count || 0) + (t.trailing_redundant_count || 0),
        'covered by an earlier rule, or superseded by a later one'],
       ['Wrong rules', t.wrong_direction_count, 'applied on the wrong side'],
       ['Dead schedule rules', t.rules_with_dead_schedule,
        'their time-range ended, so they never match'],
       ['Busiest TCAM', t.worst_tcam_percent == null ? '—'
          : `${t.worst_tcam_percent.toFixed(1)}%`, '']].map(([l, v, h]) => `
      <div class="dash-tile dash-tile-flat">
        <div class="dash-tile-value">${esc(String(v))}</div>
        <div class="dash-tile-label">${esc(l)}</div>
        ${h ? `<div class="dash-tile-hint">${esc(h)}</div>` : ''}
      </div>`).join('')}</div>`;

  if (!d.switches.length) {
    return html + `<div class="card"><div class="empty"><span class="empty-icon">◇</span>
      You have no switches registered, so there is nothing to analyse.</div></div>`;
  }

  html += `<div class="card card-pad0"><div class="t-wrap"><table class="table"><thead><tr>
    <th>Switch</th><th>Status</th><th>ACLs</th><th>Rules</th>
    <th>Redundant</th><th>Wrong rules</th>
    <th data-tip="Rules a summary could replace. Suggestions to review, not faults.">Summarizable</th>
    <th data-tip="Rules whose time-range already ended, so they can never match again.">Dead schedules</th>
    <th data-tip="Whether this switch agrees with its VPC peer on ACL rules and VLAN bindings.">VPC</th>
    <th>TCAM in</th><th>TCAM out</th><th>Scanned</th><th></th>
  </tr></thead><tbody>`;

  const byId = new Map(d.switches.map(s => [s.switch_id, s]));
  for (const row of dashSortSwitches(d.switches)) {
    const [cls, label] = DASH_STATUS[row.status] || ['b-gray', row.status];
    const problem = row.error ? ` data-tip="${esc(row.error)}"` : '';
    const tcam = row.tcam || {};
    const unsupported = tcam.status && tcam.status !== 'ok';
    const unread = DASH_UNREADABLE.includes(row.status);
    html += `<tr>
      <td data-tip="${esc(dashSwitchTip(row))}">${esc(row.switch_label)}${row.type_mismatch
        ? ' <span class="badge b-amber" data-tip="This switch answered the other platform\'s command, so its configured type looks wrong.">type?</span>'
        : ''}</td>
      <td><span class="badge ${cls}"${problem}>${esc(label)}</span></td>
      <td>${unread ? '—' : (row.acl_count ?? '—')}</td>
      <td>${unread ? '—' : (row.rule_count ?? '—')}</td>
      <td>${dashCountCell(row, DASH_REDUNDANT_FIELDS, 'redundant',
                          { title: dashRedundantTitle })}</td>
      <td>${dashCountCell(row, 'wrong_direction_count', 'redundant')}</td>
      <td>${dashCountCell(row, 'summarizable_count', 'summary')}</td>
      <td>${dashCountCell(row, 'rules_with_dead_schedule', 'time-range')}</td>
      <td>${dashVpcCell(row, byId)}</td>
      <td>${unsupported || unread
        ? `<span class="dash-muted" data-tip="${unread
            ? 'Not read — see the status column.'
            : 'This model does not report ACL TCAM use.'}">${unread ? '—' : 'n/a'}</span>`
        : dashMeter(tcam.ingress, 'Ingress')}</td>
      <td>${unsupported || unread ? '<span class="dash-muted">—</span>'
                                   : dashMeter(tcam.egress, 'Egress')}</td>
      <td class="t-time"${row.collected_at
        ? ` data-tip="${esc(fmtTime(row.collected_at))}"` : ''}>${esc(dashAgo(row.age_seconds))}</td>
      <td><button class="btn btn-xs btn-secondary" data-scan="${row.switch_id}"
            data-tip="Read this switch again over SSH and refresh its row."
            onclick="runDashScan([${row.switch_id}], this)">Scan</button></td>
    </tr>`;
  }
  html += `</tbody></table></div></div>`;
  return html;
}

/* Jump into the page that shows the detail behind a count, with the right
   switch selected — the dashboard summarises, it never duplicates detail. */
window.dashOpen = function (page, switchId) {
  // toggleSwitch would deselect a switch that is already active, so only
  // call it when this one is not part of the current selection.
  if (!S.swIds.includes(switchId)) toggleSwitch(switchId);
  showPage(page);
};

function updateDashHealthAge(d) {
  const elm = $('dash-health-age');
  if (!elm) return;
  const scanned = d.totals.scanned_count;
  if (!scanned) {
    elm.textContent = d.totals.switch_count
      ? 'Not scanned yet — press Scan now to read your switches.'
      : 'No switches registered.';
    return;
  }
  const ages = d.switches.map(s => s.age_seconds).filter(a => a != null);
  const parts = [`Last scan ${dashAgo(Math.min(...ages))}`,
                 `${scanned} of ${d.totals.switch_count} switch(es) scanned`];
  if (d.totals.error_count) parts.push(`${d.totals.error_count} could not be read`);
  elm.textContent = parts.join(' · ');
}

async function loadDashActivity() {
  const box = $('r-dash-activity');
  // Only paint a skeleton when there is nothing to keep. Replacing a full
  // page of content with four short bars collapses the layout and jumps the
  // scroll position every time a window or a bar is clicked.
  if (!box.children.length) box.innerHTML = skeleton(4);
  else box.classList.add('dash-loading');
  try {
    const d = await api('GET', `/api/dashboard/activity?${dashSliceParams()}`);
    DASH.activity = d;
    box.innerHTML = renderDashActivity(d);
    // Re-open the panel that was showing, against the new period. Clearing
    // the state first matters: dashShowDetail reads it as a second click on
    // the same tile and would close the panel instead of refreshing it.
    const reopen = DASH.detail;
    DASH.detail = null;
    if (reopen) dashShowDetail(reopen);
  } catch (e) {
    box.innerHTML = `<div class="alert a-error">${esc(e.message)}</div>`;
    reportError(e, 'Could not load activity');
  } finally {
    box.classList.remove('dash-loading');
  }
}

async function loadDashHealth() {
  const box = $('r-dash-health');
  box.innerHTML = skeleton(3);
  try {
    const d = await api('GET', '/api/dashboard/health');
    DASH.health = d;
    box.innerHTML = renderDashHealth(d);
    updateDashHealthAge(d);
  } catch (e) {
    box.innerHTML = `<div class="alert a-error">${esc(e.message)}</div>`;
    reportError(e, 'Could not load the switch analysis');
  }
}

function loadDashboard() {
  wireDashTooltips();
  DASH.slice = null;
  DASH.detail = null;
  loadDashActivity();
  loadAccessRequests();
  loadDashHealth();   // Reads stored snapshots only; opening the page costs no SSH.
}

async function runDashScan(switchIds, btn) {
  if (!Array.isArray(switchIds)) switchIds = null;   // null means every switch
  btn = btn || $('btn-dash-scan');
  setBusy(btn, true, 'Scanning…');
  try {
    const d = await api('POST', '/api/dashboard/health/scan',
                        switchIds ? { switch_ids: switchIds } : {});
    DASH.health = d;
    $('r-dash-health').innerHTML = renderDashHealth(d);
    updateDashHealthAge(d);
    const s = d.sweep;
    ok('Scan finished',
       `${s.scanned} switch(es) in ${s.duration_seconds}s — ${s.ok} healthy`
       + (s.failed ? `, ${s.failed} with problems.` : '.'));
  } catch (e) {
    reportError(e, 'Scan failed');
  } finally {
    // Always restore. A per-switch button is replaced by the re-render above
    // and this is a no-op for it, but the toolbar button survives and would
    // otherwise stay spinning and disabled after a successful scan.
    setBusy(btn, false);
  }
}

/* ══════════ SWEEPS ══════════
   Removing every redundancy, or applying every summary, across whatever is
   currently on screen -- one ACL when one was analysed, the whole switch when
   all of them were.

   Confirmed as one list of commands rather than one dialog per ACL: an
   operator who has just read the findings wants to act on them, not to click
   through forty identical prompts. The commands are shown in full, and the
   work still goes out one call per rule, so a failure on one ACL neither
   stops nor hides the rest. */

let lastRedundantResult = null;
let lastSummaryResult = null;

/* Every removable sequence on one switch, as {aclName, kind, seqs}. Dead
   schedules are deliberately excluded: renewing the schedule is usually the
   better fix, and sweeping them away silently is the opposite of that. */
function redundantSweepPlan(sr) {
  const plan = [];
  for (const item of (sr.results || [])) {
    const seqs = [];
    const take = groups => (groups || []).forEach(g =>
      (g.redundant_rules || []).forEach(r => {
        if (r.sequence != null) seqs.push(r.sequence);
      }));
    take(item.redundancies);
    take(item.superseded_by_later);
    (item.wrong_direction_rules || []).forEach(r => {
      if (r.sequence != null) seqs.push(r.sequence);
    });
    if (seqs.length) {
      plan.push({ aclName: item.acl_name, kind: item.acl_kind || 'extended',
                  seqs: [...new Set(seqs)] });
    }
  }
  return plan;
}

function summarySweepPlan(sr) {
  const plan = [];
  for (const item of (sr.results || [])) {
    for (const s of (item.suggestions || [])) {
      const seqs = (s.replaces || []).map(r => {
        const m = r.match(/^(\d+)/); return m ? +m[1] : null;
      }).filter(x => x !== null);
      if (seqs.length) {
        plan.push({ aclName: item.acl_name, kind: item.acl_kind || 'extended',
                    rule: s.suggestion, seqs });
      }
    }
  }
  return plan;
}

window.sweepRedundant = async function (switchId) {
  const sr = (lastRedundantResult?.switches || []).find(x => x.switch_id === switchId);
  if (!sr) return;
  const plan = redundantSweepPlan(sr);
  const total = plan.reduce((n, p) => n + p.seqs.length, 0);
  if (!total) return info('Nothing to remove', 'No redundant or wrong-direction rules were found.');

  const commands = plan.flatMap(p => [aclContextForSwitch(switchId, p.aclName, p.kind)]
    .concat(p.seqs.map(x => ` no ${x}`)).concat(['exit']));
  const targets = await confirmVpcAware(switchId, {
    title: 'Remove every redundant rule',
    message: `Remove ${total} rule${total === 1 ? '' : 's'} across `
           + `${plan.length} ACL${plan.length === 1 ? '' : 's'}? `
           + 'Dead-schedule rules are left alone — renewing the schedule is usually '
           + 'the better fix for those. This changes running-config only — use '
           + 'Save Config afterwards.',
    commands,
    okLabel: `Remove All ${total}`, okClass: 'btn-danger',
  });
  if (!targets) return;

  const btn = $('btn-red-sweep');
  setBusy(btn, true, 'Removing…');
  try {
    const results = await Promise.all(targets.flatMap(sw =>
      plan.flatMap(p => p.seqs.map(seq =>
        api('POST', '/api/write/rule-delete',
            { switch_id: sw.id, acl_name: p.aclName, sequence_number: seq })
          .catch(e => ({ success: false, message: e.message }))))));
    const good = results.filter(r => r.success).length;
    const bad = results.filter(r => !r.success);
    if (good) ok(`${good} rule${good === 1 ? '' : 's'} removed`,
                 `Across ${plan.length} ACL${plan.length === 1 ? '' : 's'}.`);
    if (bad.length) bad('Some removals failed',
                             [...new Set(bad.map(r => r.message))].join('; '));
    await loadSwitches();
    await refreshRedundant();
  } catch (e) { reportError(e, 'Could not remove the rules'); }
  finally { setBusy(btn, false); }
};

window.sweepSummary = async function (switchId) {
  const sr = (lastSummaryResult?.switches || []).find(x => x.switch_id === switchId);
  if (!sr) return;
  const plan = summarySweepPlan(sr);
  if (!plan.length) return info('Nothing to apply', 'No summary suggestions were found.');
  const replaced = plan.reduce((n, p) => n + p.seqs.length, 0);

  const commands = plan.flatMap(p => [aclContextForSwitch(switchId, p.aclName, p.kind)]
    .concat(p.seqs.map(x => ` no ${x}`)).concat([` ${p.rule}`, 'exit']));
  const targets = await confirmVpcAware(switchId, {
    title: 'Apply every summary',
    message: `Replace ${replaced} rule${replaced === 1 ? '' : 's'} with `
           + `${plan.length} summary rule${plan.length === 1 ? '' : 's'} across the ACLs below? `
           + 'Any summary that widens the match was flagged in the findings — read those '
           + 'first. This changes running-config only — use Save Config afterwards.',
    commands,
    okLabel: `Apply All ${plan.length}`, okClass: 'btn-warning',
  });
  if (!targets) return;

  const btn = $('btn-sum-sweep');
  setBusy(btn, true, 'Applying…');
  try {
    /* One call per suggestion, in order: each removes its own rules and adds
       its summary, so a failure leaves the others untouched rather than
       half-applying a batch. */
    const results = [];
    for (const sw of targets) {
      for (const p of plan) {
        results.push(await api('POST', '/api/write/summary-apply',
          { switch_id: sw.id, acl_name: p.aclName,
            summary_rule: p.rule, rules_to_remove: p.seqs })
          .catch(e => ({ success: false, message: e.message })));
      }
    }
    const good = results.filter(r => r.success).length;
    const bad = results.filter(r => !r.success);
    if (good) ok(`${good} summar${good === 1 ? 'y' : 'ies'} applied`,
                 `Replacing ${replaced} rule${replaced === 1 ? '' : 's'}.`);
    if (bad.length) bad('Some summaries failed',
                             [...new Set(bad.map(r => r.message))].join('; '));
    await loadSwitches();
    await refreshSummary();
  } catch (e) { reportError(e, 'Could not apply the summaries'); }
  finally { setBusy(btn, false); }
};

/* ══════════ ACCESS REQUESTS ══════════
   Somebody who can read a switch but not change it hands an admin the whole
   picture from a denied check: the switch, the interface, the ACL and the rule
   that blocked it. The admin can then act without re-running anything. */

const REQ_BADGE = { pending: 'b-amber', granted: 'b-green',
                    rejected: 'b-red', cancelled: 'b-gray' };

function describeRequest(r) {
  let out = `${r.src_ip} → ${r.dst_ip} ${r.protocol}`;
  if (r.port) out += `/${r.port}`;
  if (r.icmp_type) out += ` type ${r.icmp_type}`;
  return out;
}

/* My Requests is shown to everyone. Even a super admin can hold a switch
   somebody else granted them read-only, and then raising a request is the
   only way they have of asking. Hiding the page from admins meant the one
   account most likely to be read-only somewhere could not see what it had
   asked for. */
function syncRequesterNav() {
  els('.requester-only').forEach(e => { e.hidden = false; });
}

window.openAccessRequest = async function (switchId) {
  const b = pendingRequestBlockers.find(x => x.switchId === Number(switchId));
  if (!b || !pendingRequestAccess) return;
  const sw = swById(b.switchId);
  const peer = sw && sw.vpc_peer_id ? swById(sw.vpc_peer_id) : null;
  const peerName = peer ? (peer.hostname || peer.ip_address) : '';
  const a = pendingRequestAccess;

  const proceed = await confirmDialog({
    title: 'Request access',
    message: `An administrator will be asked to allow ${a.src_ip} → ${a.dst_ip} `
           + `${a.protocol}${a.port ? `/${a.port}` : ''} on ${b.switchName}.`,
    okLabel: 'Send Request',
    /* Deliberately not passed as `commands`: confirmDialog labels those
       "Commands that will be sent", and this rule is the opposite -- it is
       what is blocking the traffic, and nothing here sends anything. */
    extraHTML: `
      ${b.matchedRule ? `<div class="label-hint" style="margin-top:12px">Currently blocked by:</div>
        <div class="cli">${esc(b.matchedRule)}</div>` : ''}
      ${peer ? `<label class="toggle-row" style="margin-top:14px">
        <input type="checkbox" id="req-peer" checked>
        <span>Also request it on ${esc(peerName)}
          <span class="label-hint">its VPC peer — a separate request, approved on its own</span></span>
      </label>` : ''}
      <div class="field" style="margin-top:12px">
        <label>Why you need it <span class="label-hint">optional</span></label>
        <input type="text" id="req-remark" maxlength="400"
               placeholder="Write your note for the administrator here">
      </div>`,
  });
  if (!proceed) return;
  const remark = ($('req-remark')?.value || '').trim();
  const includePeer = Boolean(peer && $('req-peer')?.checked);
  try {
    const r = await api('POST', '/api/requests', {
      switch_id: b.switchId,
      src_ip: a.src_ip, dst_ip: a.dst_ip, protocol: a.protocol,
      port: a.port || null, icmp_type: a.icmp_type || null,
      remark: remark || null,
      denied_side: b.side, vlan: b.vlan, acl_name: b.aclName,
      matched_rule: b.matchedRule,
      include_peer: includePeer,
    });
    warn('Request sent', r.message);
    pendingRequestBlockers = [];
    els('[data-request-access]').forEach(x => x.closest('.access-add-rule')?.remove());
  } catch (e) { reportError(e, 'Could not send the request'); }
};

/* ── the requester's own list ── */
async function loadMyRequests() {
  const box = $('r-requests');
  if (!box) return;
  box.innerHTML = skeleton(3);
  try {
    const d = await api('GET', '/api/requests/mine');
    box.innerHTML = renderMyRequests(d.requests || []);
    // Seen means seen: cleared once the list is actually on screen, not when
    // the admin answered it.
    api('POST', '/api/requests/mine/seen').catch(() => {});
  } catch (e) {
    box.innerHTML = `<div class="alert a-error">${esc(e.message)}</div>`;
  }
}

function renderMyRequests(rows) {
  if (!rows.length) {
    return `<div class="card"><div class="empty"><span class="empty-icon">◇</span>
      You have not requested any access yet. Run an access check — if it comes back
      denied on a switch you can only read, you can ask an administrator from there.
    </div></div>`;
  }
  const pending = rows.filter(r => r.status === 'pending');
  const answered = rows.filter(r => r.status !== 'pending');
  const head = r => `<div class="f-label">${esc(r.switch_label || r.switch_ip || '')}
      <span class="badge ${REQ_BADGE[r.status] || 'b-gray'}" style="margin-left:8px">${esc(r.status)}</span></div>
    <div class="f-rule">${esc(describeRequest(r))}</div>`;
  let html = '';
  if (pending.length) {
    html += `<div class="card"><div class="sec-label">Waiting for an administrator</div>`
      + pending.map(r => `<div class="finding">${head(r)}
        ${r.vlan ? `<div class="f-note">Blocked on ${esc(r.vlan)}${
          r.acl_name ? ` by ${esc(r.acl_name)}` : ''}${r.denied_side ? ` · ${esc(r.denied_side)} side` : ''}</div>` : ''}
        ${r.remark ? `<div class="f-note">Your note: ${esc(r.remark)}</div>` : ''}
        <div class="actions" style="margin-top:10px">
          <button class="btn btn-xs btn-secondary" onclick="editRequestRemark(${r.id},'${jsq(r.remark || '')}')"
            >${r.remark ? 'Edit note' : 'Add a note'}</button>
          <button class="btn btn-xs btn-danger" onclick="cancelMyRequest(${r.id})">Withdraw</button>
        </div></div>`).join('') + `</div>`;
  }
  if (answered.length) {
    html += `<div class="card"><div class="sec-label">Answered</div>`
      + answered.map(r => `<div class="finding${r.status === 'granted' ? '' : ' wrong'}">${head(r)}
        <div class="f-note">${r.status === 'cancelled' ? 'You withdrew this request.'
          : `${r.status === 'granted' ? 'Granted' : 'Declined'} by ${esc(r.resolved_by || '')}`
            + (r.resolved_at ? ` · ${esc(fmtTime(r.resolved_at))}` : '')}</div>
        ${r.resolution_note ? `<div class="f-note">Reason: ${esc(r.resolution_note)}</div>` : ''}
      </div>`).join('') + `</div>`;
  }
  return html;
}

window.editRequestRemark = async function (id, current) {
  const proceed = await confirmDialog({
    title: 'Note for the administrator', okLabel: 'Save',
    message: 'Explaining why the access is needed makes it far more likely to be granted.',
    extraHTML: `<div class="field" style="margin-top:12px">
      <input type="text" id="req-edit" maxlength="400" value="${esc(current)}"
             placeholder="Why this access is needed"></div>`,
  });
  if (!proceed) return;
  try {
    await api('PUT', `/api/requests/${id}`, { remark: ($('req-edit')?.value || '').trim() });
    ok('Request updated', 'Your note was saved.');
    await loadMyRequests();
  } catch (e) { reportError(e, 'Could not update'); }
};

window.cancelMyRequest = async function (id) {
  const proceed = await confirmDialog({
    title: 'Withdraw this request',
    message: 'The administrators will no longer see it.',
    okLabel: 'Withdraw', okClass: 'btn-danger',
  });
  if (!proceed) return;
  try {
    await api('DELETE', `/api/requests/${id}`);
    ok('Request withdrawn', 'It has been removed from the queue.');
    await loadMyRequests();
  } catch (e) { reportError(e, 'Could not cancel'); }
};

/* ── the admin queue ── */
async function loadAccessRequests() {
  const box = $('r-dash-requests');
  if (!box || !isAdmin()) return;
  try {
    const d = await api('GET', '/api/requests');
    accessRequestCache = d.requests || [];
    box.innerHTML = renderAccessRequests(accessRequestCache);
  } catch { box.innerHTML = ''; }
}

function renderAccessRequests(rows) {
  /* The card shows even when empty: an admin who has never had a request
     would otherwise never learn this exists. */
  const body = rows.length ? rows.map(r => `<div class="finding">
      <div class="f-label">${esc(r.requester)} · ${esc(r.switch_label || r.switch_ip || '')}
        ${r.created_at ? `<span class="dash-muted" style="margin-left:8px;font-weight:400">${
          esc(fmtTime(r.created_at))}</span>` : ''}</div>
      <div class="f-rule">${esc(describeRequest(r))}</div>
      ${r.vlan ? `<div class="f-note">Blocked on ${esc(r.vlan)}${
        r.acl_name ? ` by ${esc(r.acl_name)}` : ''}${r.denied_side ? ` · ${esc(r.denied_side)} side` : ''}</div>` : ''}
      ${r.matched_rule ? `<div class="cli" style="margin-top:6px">${esc(r.matched_rule)}</div>` : ''}
      ${r.remark ? `<div class="f-note">Note: ${esc(r.remark)}</div>` : ''}
      ${!r.can_apply && r.reason_blocked ? `<div class="alert a-warn" style="margin-top:10px">${
        esc(r.reason_blocked)} You can still dismiss it, or leave it for an administrator who can.</div>` : ''}
      <div class="actions" style="margin-top:11px">
        ${r.can_apply ? `<button class="btn btn-xs btn-primary"
          onclick="applyAccessRequest(${r.id})">Apply</button>` : ''}
        <button class="btn btn-xs btn-success" onclick="completeAccessRequest(${r.id})">Mark Done</button>
        <button class="btn btn-xs btn-danger" onclick="dismissAccessRequest(${r.id})">Dismiss</button>
      </div></div>`).join('')
    : `<div class="empty"><span class="empty-icon">◇</span>No one is waiting on you.
        Requests appear here when somebody who can read a switch but not change it
        asks for a path to be opened.</div>`;
  return `<div class="card">
    <div class="sec-label">Access Requests${rows.length
      ? ` <span class="badge b-amber" style="margin-left:8px">${rows.length}</span>` : ''}</div>
    <p class="label-hint" style="margin:-6px 0 14px">Raised by people who can read a switch
      but not change it. Applying one fills in Add ACL Rule with exactly what they asked for.</p>
    ${body}</div>`;
}

let accessRequestCache = [];

window.applyAccessRequest = async function (id) {
  const r = accessRequestCache.find(x => x.id === id);
  if (!r) return;
  /* Select the acting admin's OWN entry for that device -- not the
     requester's, which they may not even hold. */
  const target = r.my_switch_id ?? r.switch_id;
  const sw = swById(target);
  if (!sw) {
    return bad('Switch not in your inventory',
               `${r.switch_label || r.switch_ip} was not granted to you, so you cannot apply `
               + 'this request. Another administrator will need to.');
  }
  if (!S.swIds.includes(sw.id)) {
    S.swIds = [sw.id];
    localStorage.setItem('giga_swIds', JSON.stringify(S.swIds));
    clearSwitchData();
    buildPicker();
    document.dispatchEvent(new CustomEvent('giga:switch-selection-change',
      { detail: { switchIds: [...S.swIds] } }));
  }
  /* The requester's note becomes the rule's remark. It is the only piece of
     the request that survives onto the switch, and it is what tells the next
     person reading the ACL why the line is there. */
  openAddRuleFromAccess({ src_ip: r.src_ip, dst_ip: r.dst_ip, protocol: r.protocol,
                          port: r.port || '', icmp_type: r.icmp_type || '',
                          remark: r.remark || '' });
};

window.completeAccessRequest = async function (id) {
  const r = accessRequestCache.find(x => x.id === id);
  const proceed = await confirmDialog({
    title: 'Mark this request done',
    message: r ? `Tell ${r.requester} the access for ${describeRequest(r)} on `
                 + `${r.switch_label || r.switch_ip} has been granted? `
                 + 'This removes it from every administrator’s queue.'
               : 'Mark this request as done?',
    okLabel: 'Mark Done', okClass: 'btn-success',
  });
  if (!proceed) return;
  try {
    const d = await api('POST', `/api/requests/${id}/done`, {});
    ok('Request completed', d.message);
    await loadAccessRequests();
  } catch (e) { reportError(e, 'Could not complete'); }
};

window.dismissAccessRequest = async function (id) {
  const r = accessRequestCache.find(x => x.id === id);
  const proceed = await confirmDialog({
    title: 'Dismiss this request',
    message: r ? `${r.requester} asked for ${describeRequest(r)} on `
                 + `${r.switch_label || r.switch_ip}. Dismissing removes it from every `
                 + 'administrator’s queue and tells them it was declined.'
               : 'Dismiss this request?',
    okLabel: 'Dismiss Request', okClass: 'btn-danger',
    extraHTML: `<div class="field" style="margin-top:12px">
      <label>Reason <span class="label-hint">optional, shown to them</span></label>
      <input type="text" id="req-reason" maxlength="400" placeholder="Use the VPN for this instead">
    </div>`,
  });
  if (!proceed) return;
  try {
    const d = await api('POST', `/api/requests/${id}/dismiss`,
      { note: ($('req-reason')?.value || '').trim() || null });
    ok('Request dismissed', d.message);
    await loadAccessRequests();
  } catch (e) { reportError(e, 'Could not dismiss'); }
};

/* Raised once per sign-in, from the count the server keeps rather than
   anything this browser remembers, so it survives a different machine. */
async function announceAnsweredRequests() {
  try {
    const d = await api('GET', '/api/requests/mine');
    if (!d.unseen) return;
    const bits = [d.unseen_granted ? `${d.unseen_granted} granted` : '',
                  d.unseen_rejected ? `${d.unseen_rejected} declined` : ''].filter(Boolean).join(', ');
    (d.unseen_granted ? ok : warn)(
      `${d.unseen} access request${d.unseen === 1 ? '' : 's'} answered`,
      `${bits}. Open My Requests to see the detail.`);
  } catch { /* not everyone has requests, and none of this is load-bearing */ }
}

/* ══════════ LOGS ══════════ */
const LVL_CLS = { SUCCESS: 'b-green', INFO: 'b-accent', WARN: 'b-amber', ERROR: 'b-red' };

async function loadLogs() {
  const tb = $('logs-tbody');
  tb.innerHTML = `<tr><td colspan="7">${spinner('Loading activity…')}</td></tr>`;
  try {
    S.logs = await api('GET', '/api/logs?limit=500');
    populateLogFilters();
    renderLogs();
  } catch (e) {
    tb.innerHTML = `<tr><td colspan="7"><div class="alert a-error">${esc(e.message)}</div></td></tr>`;
  }
}

function logLocation(l) {
  return l.switch_id ? siteLabel(l.switch_site) : '—';
}

function populateLogFilters() {
  const siteSel = $('log-site');
  const prevSite = siteSel.value;
  const sites = [...new Set(S.logs
    .map(l => l.switch_id ? l.switch_site : null)
    .filter(Boolean))].sort();
  siteSel.innerHTML = '<option value="">All locations</option>'
    + sites.map(s => `<option value="${esc(s)}">${esc(siteLabel(s))}</option>`).join('');
  siteSel.value = sites.includes(prevSite) ? prevSite : '';
  if (siteSel._selRefresh) siteSel._selRefresh();

  populateLogSwitchFilter();

  const adminField = $('log-admin-field');
  adminField.hidden = !isSuper();
  if (isSuper()) {
    const adminSel = $('log-admin');
    const prevAdmin = adminSel.value;
    const admins = [...new Set(S.logs.map(l => l.username))].sort();
    adminSel.innerHTML = '<option value="">All admins</option>'
      + admins.map(u => `<option value="${esc(u)}">${esc(u)}</option>`).join('');
    adminSel.value = admins.includes(prevAdmin) ? prevAdmin : '';
    if (adminSel._selRefresh) adminSel._selRefresh();
  }
}

/* Switch options are scoped to the selected location — picking a location
   first narrows which switches you can then filter by. */
function populateLogSwitchFilter() {
  const site = $('log-site').value;
  const switchSel = $('log-switch');
  const prevSwitch = switchSel.value;
  const switches = [...new Map(S.logs
    .filter(l => l.switch_id && (!site || l.switch_site === site))
    .map(l => [l.switch_id, l.switch_label || `#${l.switch_id}`])).entries()]
    .sort((a, b) => a[1].localeCompare(b[1]));
  switchSel.innerHTML = '<option value="">All switches</option>'
    + switches.map(([id, label]) => `<option value="${id}">${esc(label)}</option>`).join('');
  switchSel.value = switches.some(([id]) => String(id) === prevSwitch) ? prevSwitch : '';
  if (switchSel._selRefresh) switchSel._selRefresh();
}

/* Compared as local calendar-date strings (YYYY-MM-DD sorts correctly as
   text) so a log made late at night still lands on the day the user saw on
   their clock, matching how fmtTime() displays it. */
function logInDateRange(l, from, to) {
  if (!from && !to) return true;
  const iso = l.timestamp;
  const d = new Date(/[zZ]|[+-]\d\d:\d\d$/.test(iso) ? iso : iso + 'Z');
  if (isNaN(d)) return true;
  const p = n => String(n).padStart(2, '0');
  const day = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
  return (!from || day >= from) && (!to || day <= to);
}

function renderLogs() {
  const lvl = $('log-lvl').value;
  const q = $('log-q').value.trim().toLowerCase();
  const site = $('log-site').value;
  const switchId = $('log-switch').value;
  const admin = isSuper() ? $('log-admin').value : '';
  const dateFrom = $('log-date-from').value;
  const dateTo = $('log-date-to').value;
  S.logsView = S.logs.filter(l =>
    (!lvl || l.level === lvl) &&
    (!q || l.username.toLowerCase().includes(q) || l.message.toLowerCase().includes(q)
        || (l.ip_address || '').toLowerCase().includes(q)) &&
    (!site || l.switch_site === site) &&
    (!switchId || String(l.switch_id) === switchId) &&
    (!admin || l.username === admin) &&
    logInDateRange(l, dateFrom, dateTo));
  const tb = $('logs-tbody');
  const empty = $('logs-empty');
  if (!S.logsView.length) { tb.innerHTML = ''; empty.hidden = false; return; }
  empty.hidden = true;
  tb.innerHTML = S.logsView.map((l, i) => {
    const hasUndo = l.undo_commands && l.undo_label && l.switch_id;
    const actions = [];
    if (l.description) {
      actions.push(`<button class="btn btn-xs btn-secondary" onclick="showLog(${i})">View</button>`);
    }
    /* Undo runs against the switch the entry's own author owns, so it only
       ever succeeds for your own changes; a super admin sees everyone's
       entries and would otherwise get a confusing "switch not found". */
    if (hasUndo && isAdmin() && l.username === S.username) {
      actions.push(`<button class="btn btn-xs btn-warning" onclick="undoFromLog(${l.id}, ${i})">Undo</button>`);
    }
    const actionHtml = actions.length
      ? actions.join(' ')
      : '<span style="color:var(--muted);font-size:11px">—</span>';

    return `<tr>
      <td class="t-time">${esc(fmtTime(l.timestamp))}</td>
      <td><span class="badge ${LVL_CLS[l.level] || 'b-gray'}">${esc(l.level)}</span></td>
      <td>${esc(l.username)}</td>
      <td class="mono">${l.ip_address ? esc(l.ip_address)
        : '<span class="dash-muted">—</span>'}</td>
      <td>${esc(logLocation(l))}</td>
      <td>${esc(l.message)}</td>
      <td>${actionHtml}</td></tr>`;
  }).join('');
}

window.showLog = function (i) {
  const l = S.logsView[i];
  if (!l) return;
  $('ld-time').textContent = fmtTime(l.timestamp);
  $('ld-level').textContent = l.level;
  $('ld-user').textContent = l.username;
  $('ld-ip').textContent = l.ip_address || 'not recorded';
  $('ld-msg').textContent = l.message;
  $('ld-desc').textContent = l.description || '(no additional detail)';
  openModal('m-log');
};

window.undoFromLog = async function (logId, index) {
  const l = S.logsView[index];
  if (!l || !l.undo_commands) {
    warn('Nothing to undo', 'This action can no longer be reverted.');
    return;
  }
  
  // Parse undo commands to show in confirmation
  let undoCommands = [];
  try {
    undoCommands = JSON.parse(l.undo_commands);
  } catch {
    bad('Invalid undo data', 'The undo information is corrupted.');
    return;
  }
  const legacyRange = /^restore\s+time-range\s+([A-Za-z0-9_.-]+)$/i.exec(l.undo_label || '');
  const hasCliError = undoCommands.some(command => {
    const text = String(command).trim().toLowerCase();
    return text === '^' || text.includes('% invalid command')
      || text.startsWith('show running-config');
  });
  if (legacyRange && hasCliError) undoCommands = [`time-range ${legacyRange[1]}`];
  
  const proceed = await confirmDialog({
    title: 'Undo change',
    message: `This will ${l.undo_label} on the switch. The following commands will be sent:`,
    commands: undoCommands,
    okLabel: 'Run Undo', okClass: 'btn-warning',
  });
  if (!proceed) return;
  
  try {
    const r = await api('POST', '/api/logs/undo', { log_id: logId });
    if (r.success) {
      ok('Change reverted', r.message);
      await loadSwitches();
      await loadLogs();  // Refresh logs to update the list
    } else {
      bad('Undo failed', r.message);
    }
  } catch (e) {
    reportError(e, 'Undo failed');
  }
};

/* Confirm an action on a switch, offering to also apply it to its VPC peer
   when relevant — mirrors deleteTimeRange's VPC-peer confirmation flow.
   Returns the array of target switches to act on, or null if cancelled. */
async function confirmVpcAware(switchId, { title, message, commands = null,
                                           okLabel = 'Confirm', okClass = 'btn-primary',
                                           extraHTML = '' }) {
  const sourceSw = swById(switchId);
  if (!sourceSw) { bad('No switch', 'Switch not found.'); return null; }
  const peerSw = sourceSw.vpc_peer_id ? swById(sourceSw.vpc_peer_id) : null;
  if (!peerSw) {
    const proceed = await confirmDialog({ title, message, commands, okLabel, okClass, extraHTML });
    return proceed ? [sourceSw] : null;
  }
  const sourceName = sourceSw.hostname || sourceSw.ip_address;
  const peerName = peerSw.hostname || peerSw.ip_address;
  const bothSelected = S.swIds.includes(sourceSw.id) && S.swIds.includes(peerSw.id);
  if (bothSelected) {
    const proceed = await confirmDialog({
      title, commands, okLabel, okClass, extraHTML,
      message: `${message} This will be applied on both VPC switches (${sourceName} and ${peerName}).`,
    });
    return proceed ? [sourceSw, peerSw] : null;
  }
  const proceed = await confirmDialog({
    title, commands, okLabel, okClass,
    message: `${message} This switch has a VPC peer: ${peerName}.`,
    extraHTML: extraHTML + `
      <div style="margin-top:16px;padding:12px;background:var(--bg-secondary);border-radius:6px">
        <div style="font-weight:600;margin-bottom:8px">Apply to:</div>
        <label style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-bottom:6px">
          <input type="radio" name="vpc-choice" value="both" checked>
          <span>Both switches (${sourceName} and ${peerName})</span>
        </label>
        <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
          <input type="radio" name="vpc-choice" value="single">
          <span>Only ${sourceName}</span>
        </label>
      </div>`,
  });
  if (!proceed) return null;
  const selected = document.querySelector('input[name="vpc-choice"]:checked')?.value;
  return selected === 'both' ? [sourceSw, peerSw] : [sourceSw];
}

/* Render one switchCommandResult/error block per result, prefixed with the
   switch name whenever more than one switch was targeted. */
function viewerResultsHtml(results, targetSwitches) {
  return results.map((r, i) => {
    const label = targetSwitches.length > 1
      ? `${esc(targetSwitches[i].hostname || targetSwitches[i].ip_address)}: ` : '';
    return r.success
      ? switchCommandResult(label + r.message, r.output)
      : `<div class="alert a-error">${label}${esc(r.message)}</div>`
        + (r.output ? switchOutputBlock(r.output) : '');
  }).join('');
}

/* Every write action always shows a toast (success or failure) so the
   outcome is never missed — the in-page result banner alone was too easy to
   overlook, especially for failures buried in a form's status area. If the
   viewer is still showing the switch this job ran against, the full result
   (with switch output) is additionally shown in place; if the user has
   since swapped to a different switch, the toast is the only feedback,
   since injecting it into the wrong switch's view would be misleading. */
function toastViewerResults(results, targetSwitches, actionLabel) {
  results.forEach((r, i) => {
    const name = targetSwitches[i].hostname || targetSwitches[i].ip_address;
    if (r.success) ok(`${actionLabel} on ${name}`, r.message);
    else bad(`${actionLabel} failed on ${name}`, r.message);
  });
}

function notifyViewerResults(results, targetSwitches, gen, actionLabel) {
  toastViewerResults(results, targetSwitches, actionLabel);
  if (gen === S.dataGen) {
    $('r-viewer')?.insertAdjacentHTML('afterbegin', viewerResultsHtml(results, targetSwitches));
  }
}

/* ══════════ VIEWER REFRESH ══════════ */
async function refreshViewer({ openAcl = '', switchId = null } = {}) {
  const box = $('r-viewer');
  const name = $('view-acl').value.trim();
  const gen = S.dataGen;
  box.innerHTML = skeleton(4);
  try {
    const d = name
      ? await api('POST', '/api/analysis/view-acl', { switch_ids: S.swIds, acl_name: V.ident(name, 'ACL name') })
      : await api('POST', '/api/analysis/view-all-acls', { switch_ids: S.swIds });
    if (gen !== S.dataGen) return;
    box.innerHTML = renderViewer(d);
    enhanceSelects(box);
    if (openAcl) {
      const panel = els('[data-viewer-acl]', box).find(node =>
        node.dataset.viewerAcl === openAcl
        && (!switchId || +node.dataset.switchId === +switchId));
      panel?.classList.add('open');
    }
    revealResult(box);
  } catch (e) {
    if (gen !== S.dataGen) return;
    box.innerHTML = `<div class="alert a-error">${esc(e.message)}</div>`;
    reportError(e, 'Could not load ACLs');
  }
}

function viewerCommandSummary(result) {
  return result.success
    ? switchCommandResult(result.message, result.output)
    : `<div class="alert a-error">${esc(result.message)}</div>`
      + (result.output ? switchOutputBlock(result.output) : '');
}

function viewerContext(switchId, aclName, aclKind = 'extended') {
  return aclContextForSwitch(switchId, aclName, aclKind);
}

async function addViewerRule(form) {
  const gen = S.dataGen;
  const switchId = +form.dataset.switchId;
  const aclName = form.dataset.aclName;
  const aclKind = form.dataset.aclKind || 'extended';
  const input = form.elements.rule;
  const status = el('.viewer-action-status', form);
  const rule = input.value.trim();
  if (!rule) return fieldError(status, 'Enter a complete sequenced rule.');
  const seqMatch = rule.match(/^(\d+)\s+(permit|deny)\s+/i);
  if (!seqMatch) {
    return fieldError(status, 'Use a sequence followed by permit or deny, for example: 110 permit ip any any.');
  }
  const [, seq, action] = seqMatch;

  const panel = form.closest('.acl');
  const existingSeqs = [...(panel?.querySelectorAll('.rule-seq') || [])]
    .map(node => node.textContent.trim());
  if (existingSeqs.includes(seq)) {
    return fieldError(status,
      `Sequence ${seq} already exists in ${aclName}. Edit that rule instead of adding a new one.`);
  }

  status.hidden = true; status.innerHTML = '';
  let already = null;
  if (aclKind !== 'standard' && action.toLowerCase() === 'permit') {
    try {
      const check = await api('POST', '/api/write/rule-check-existing',
        { switch_id: switchId, acl_name: aclName, rule_syntax: rule });
      if (check.already_permitted) already = check;
    } catch (error) {
      // Duplicate check failed to complete — fall through without a warning.
    }
  }

  const targetSwitches = await confirmVpcAware(switchId, {
    title: 'Add ACL rule manually',
    message: already
      ? `Add this rule to ${aclName} anyway? The switch will validate and verify it.`
      : `Add this rule to ${aclName}? The switch will validate and verify it.`,
    commands: [viewerContext(switchId, aclName, aclKind), rule],
    okLabel: 'Add Rule', okClass: 'btn-warning',
    extraHTML: already ? `<div class="alert a-warn" style="margin-top:14px">
        <strong>Access is already permitted by an existing rule in ${esc(aclName)}.</strong>
        ${already.matched_rule ? `<div class="cli" style="margin-top:7px">${esc(already.matched_rule)}</div>` : ''}
      </div>` : '',
  });
  if (!targetSwitches) return;
  status.hidden = false;
  status.innerHTML = spinner('Applying and verifying the rule…');
  try {
    const results = await Promise.all(targetSwitches.map(sw =>
      api('POST', '/api/write/rule-apply', {
        switch_id: sw.id, acl_name: aclName, rule_syntax: rule,
        remark: null, remark_sequence: null,
      })));
    const allOk = results.every(r => r.success);
    if (allOk) input.value = '';
    await loadSwitches();
    await refreshViewer({ openAcl: aclName, switchId });
    toastViewerResults(results, targetSwitches, allOk ? 'Rule added' : 'Rule add');
    if (allOk) {
      status.hidden = true; status.innerHTML = '';
      if (gen === S.dataGen) $('r-viewer')?.insertAdjacentHTML('afterbegin', viewerResultsHtml(results, targetSwitches));
    } else if (gen === S.dataGen) {
      status.innerHTML = viewerResultsHtml(results, targetSwitches);
    }
  } catch (error) {
    status.innerHTML = `<div class="alert a-error">${esc(error.message)}</div>`;
    reportError(error, 'Could not add the ACL rule');
  }
}

async function attachViewerAcl(form) {
  const gen = S.dataGen;
  const switchId = +form.dataset.switchId;
  const aclName = form.dataset.aclName;
  const vlan = form.elements.vlan.value.trim();
  const direction = form.elements.direction.value;
  const status = el('.viewer-action-status', form);
  if (!/^(?:vlan\s*)?\d{1,4}$/i.test(vlan)) {
    return fieldError(status, 'Enter a VLAN number such as 748 or Vlan748.');
  }
  const iface = /^vlan/i.test(vlan) ? vlan.replace(/\s+/g, '') : `Vlan${vlan}`;

  const existingOnIface = els('[data-view-detach-acl]', $('r-viewer')).filter(btn =>
    +btn.dataset.switchId === switchId &&
    (btn.dataset.interface || '').toLowerCase() === iface.toLowerCase());
  const sameDirConflict = existingOnIface.find(btn =>
    btn.dataset.direction === direction && btn.dataset.aclName !== aclName);
  if (sameDirConflict) {
    return fieldError(status,
      `${iface} already has ACL ${sameDirConflict.dataset.aclName} applied ${direction}bound. `
      + `Remove that ACL from ${iface} first before applying a different one in the same direction.`);
  }
  const otherDirBinding = existingOnIface.find(btn => btn.dataset.direction !== direction);
  const message = otherDirBinding
    ? `${iface} already has ACL ${otherDirBinding.dataset.aclName} applied ${otherDirBinding.dataset.direction}bound. `
      + `Apply ${aclName} ${direction}bound as well?`
    : `Apply ${aclName} ${direction}bound on ${iface}?`;

  const targetSwitches = await confirmVpcAware(switchId, {
    title: 'Apply ACL to VLAN',
    message,
    commands: [`interface ${iface}`, `ip access-group ${aclName} ${direction}`],
    okLabel: 'Apply ACL', okClass: 'btn-warning',
  });
  if (!targetSwitches) return;
  status.hidden = false;
  status.innerHTML = spinner('Applying and verifying the VLAN binding…');
  try {
    const results = await Promise.all(targetSwitches.map(sw =>
      api('POST', '/api/write/acl-interface', {
        switch_id: sw.id, acl_name: aclName, interface: iface,
        direction, action: 'attach',
      })));
    const allOk = results.every(r => r.success);
    if (allOk) form.elements.vlan.value = '';
    await loadSwitches();
    await refreshViewer({ openAcl: aclName, switchId });
    toastViewerResults(results, targetSwitches, allOk ? 'ACL applied' : 'ACL apply');
    if (allOk) {
      status.hidden = true; status.innerHTML = '';
      if (gen === S.dataGen) $('r-viewer')?.insertAdjacentHTML('afterbegin', viewerResultsHtml(results, targetSwitches));
    } else if (gen === S.dataGen) {
      status.innerHTML = viewerResultsHtml(results, targetSwitches);
    }
  } catch (error) {
    status.innerHTML = `<div class="alert a-error">${esc(error.message)}</div>`;
    reportError(error, 'Could not apply the ACL to the VLAN');
  }
}

async function detachViewerAcl(button) {
  const gen = S.dataGen;
  const switchId = +button.dataset.switchId;
  const aclName = button.dataset.aclName;
  const iface = button.dataset.interface;
  const direction = button.dataset.direction;
  const targetSwitches = await confirmVpcAware(switchId, {
    title: 'Remove ACL from VLAN',
    message: `Remove ${aclName} ${direction}bound from ${iface}?`,
    commands: [`interface ${iface}`, `no ip access-group ${aclName} ${direction}`],
    okLabel: 'Remove ACL', okClass: 'btn-danger',
  });
  if (!targetSwitches) return;
  try {
    const results = await Promise.all(targetSwitches.map(sw =>
      api('POST', '/api/write/acl-interface', {
        switch_id: sw.id, acl_name: aclName, interface: iface,
        direction, action: 'detach',
      })));
    await loadSwitches();
    await refreshViewer({ openAcl: aclName, switchId });
    notifyViewerResults(results, targetSwitches, gen, 'ACL removed');
  } catch (error) {
    reportError(error, 'Could not remove the ACL from the VLAN');
  }
}

async function deleteViewerAcl(button) {
  const gen = S.dataGen;
  const switchId = +button.dataset.switchId;
  const aclName = button.dataset.aclName;
  const aclKind = button.dataset.aclKind || 'extended';
  const ifaceCount = +button.dataset.interfaceCount || 0;
  const usageWarning = ifaceCount
    ? ` This ACL is currently applied to ${ifaceCount} interface${ifaceCount === 1 ? '' : 's'} — deleting it removes that filtering.`
    : '';
  const targetSwitches = await confirmVpcAware(switchId, {
    title: 'Delete ACL',
    message: `Delete ${aclName} and all of its rules?${usageWarning}`,
    commands: [`no ${viewerContext(switchId, aclName, aclKind)}`],
    okLabel: 'Delete ACL', okClass: 'btn-danger',
  });
  if (!targetSwitches) return;
  try {
    const results = await Promise.all(targetSwitches.map(sw =>
      api('POST', '/api/write/acl-delete', { switch_id: sw.id, acl_name: aclName })));
    await loadSwitches();
    await refreshViewer();
    notifyViewerResults(results, targetSwitches, gen, 'ACL deleted');
  } catch (error) {
    reportError(error, 'Could not delete the ACL');
  }
}

let viewerEditState = null;

/* Strip trailing display-only annotations Cisco appends to `show` output —
   match counts and state markers like "(56 matches)" or "(inactive)" —
   that aren't part of the actual rule syntax and must never be typed back
   into a config command. */
function stripRuleAnnotations(rule) {
  return rule.replace(/(?:\s+\([^)]*\))+\s*$/, '');
}

function openViewerRuleEdit(button) {
  if (!isAdmin()) return;
  viewerEditState = {
    switchId: +button.dataset.switchId,
    aclName: button.dataset.aclName,
    aclKind: button.dataset.aclKind || 'extended',
    originalRule: button.dataset.rule,
  };
  $('view-edit-context').textContent = `${viewerEditState.aclName} · ${
    swById(viewerEditState.switchId)?.hostname || swById(viewerEditState.switchId)?.ip_address || 'switch'}`;
  $('view-edit-rule').value = stripRuleAnnotations(viewerEditState.originalRule);
  fieldError($('view-edit-error'), '');
  $('view-edit-output').innerHTML = '';
  openModal('m-view-rule-edit');
  setTimeout(() => $('view-edit-rule')?.focus(), 80);
}

async function saveViewerRuleEdit() {
  if (!viewerEditState || !isAdmin()) return;
  const gen = S.dataGen;
  const replacement = $('view-edit-rule').value.trim();
  const oldSeq = viewerEditState.originalRule.match(/^\s*(\d+)/)?.[1];
  if (!/^\d+\s+(?:permit|deny)\s+/i.test(replacement)) {
    return fieldError($('view-edit-error'),
      'Use a sequence followed by permit or deny, for example: 110 permit ip any any.');
  }
  const targetSwitches = await confirmVpcAware(viewerEditState.switchId, {
    title: 'Replace ACL rule',
    message: 'The old rule will be removed first. If the replacement fails, the original rule will be restored automatically.',
    commands: [viewerContext(viewerEditState.switchId, viewerEditState.aclName, viewerEditState.aclKind),
      `no ${oldSeq}`, replacement],
    okLabel: 'Replace Rule', okClass: 'btn-warning',
  });
  if (!targetSwitches) return;
  const button = $('btn-view-edit-save');
  setBusy(button, true, 'Replacing…');
  fieldError($('view-edit-error'), '');
  $('view-edit-output').innerHTML = spinner('Replacing and verifying the rule…');
  try {
    const results = await Promise.all(targetSwitches.map(sw =>
      api('POST', '/api/write/rule-edit', {
        switch_id: sw.id,
        acl_name: viewerEditState.aclName,
        original_rule: viewerEditState.originalRule,
        new_rule: replacement,
      })));
    const failed = results.find(r => !r.success);
    if (failed) {
      fieldError($('view-edit-error'), failed.message);
      $('view-edit-output').innerHTML = failed.output ? switchOutputBlock(failed.output) : '';
      bad('Rule replace failed', failed.message);
      return;
    }
    const target = { ...viewerEditState };
    closeModal('m-view-rule-edit');
    viewerEditState = null;
    await loadSwitches();
    await refreshViewer({ openAcl: target.aclName, switchId: target.switchId });
    notifyViewerResults(results, targetSwitches, gen, 'Rule replaced');
  } catch (error) {
    fieldError($('view-edit-error'), error.message);
    $('view-edit-output').innerHTML = '';
    reportError(error, 'Could not edit the ACL rule');
  } finally {
    setBusy(button, false);
  }
}

/* ══════════ VPC / EDIT SWITCH ══════════ */
let vpcId = null, editSwId = null;

function openVpc(id) {
  const s = swById(id);
  if (!s) return;
  vpcId = id;
  $('vpc-name').textContent = s.hostname || s.ip_address;
  const peers = S.switches.filter(x => x.id !== id
    && (x.switch_type || '').toLowerCase() === 'nexus');
  $('vpc-peer').innerHTML = '<option value="">— None (remove pairing) —</option>'
    + peers.map(x => `<option value="${x.id}" ${s.vpc_peer_id === x.id ? 'selected' : ''}>${
        esc(x.hostname || x.ip_address)} · ${esc(x.ip_address)} · ${esc(siteLabel(x.site))}</option>`).join('');
  if (!peers.length) {
    $('vpc-peer').innerHTML = '<option value="">No other Nexus switch available</option>';
  }
  if ($('vpc-peer')._selRefresh) $('vpc-peer')._selRefresh();
  openModal('m-vpc');
}

function openEditSw(id) {
  const s = swById(id);
  if (!s) return;
  editSwId = id;
  $('esw-name').textContent = s.hostname || s.ip_address;
  $('esw-type').value = s.switch_type || 'ios';
  $('esw-site').value = s.site || '';
  $('esw-enable').checked = !!s.use_enable;
  $('esw-username').value = '';
  $('esw-username').placeholder = s.ssh_username || S.username;
  $('esw-pass').value = '';
  $('esw-enable-pass').value = '';
  // Show/hide enable password field based on current state
  $('esw-enable-wrap').style.display = s.use_enable ? '' : 'none';
  fieldError($('esw-err'), '');
  openModal('m-editsw');
}

/* ══════════ INIT ══════════ */
document.addEventListener('DOMContentLoaded', () => {
  applyTheme(localStorage.getItem('giga_theme') || 'dark');

  /* ── password toggles ── */
  document.addEventListener('click', e => {
    const toggle = e.target.closest('.password-toggle');
    if (!toggle) return;
    const targetId = toggle.dataset.toggle;
    const input = $(targetId);
    if (!input) return;
    
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    toggle.classList.toggle('visible', isPassword);
  });

  /* generic modal close buttons */
  document.addEventListener('click', e => {
    const c = e.target.closest('[data-close]');
    if (c) closeModal(c.dataset.close);
  });
  /* close a modal by clicking its dim backdrop */
  els('.mbg').forEach(bg => bg.addEventListener('mousedown', e => {
    if (e.target === bg) bg.hidden = true;
  }));
  /* close custom dropdowns on any outside click
     (the menu now lives on <body>, so check for it explicitly) */
  document.addEventListener('mousedown', e => {
    if (!e.target.closest('.sel') && !e.target.closest('.sel-menu')) closeAllSelects();
  });
  /* Esc closes dropdown → modal → switch picker, in that order */
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape') return;
    if (els('.sel.open').length) { closeAllSelects(); return; }
    const open = els('.mbg').filter(m => !m.hidden);
    if (open.length) { closeModal(open[open.length - 1].id); return; }
    if ($('app-screen')?.classList.contains('nav-open')) {
      closeMobileNav(); return;
    }
    closePicker();
  });

  /* Keyboard shortcut to toggle Switch Picker: Ctrl+K (or Cmd+K on Mac) */
  document.addEventListener('keydown', e => {
    // Check for Ctrl+K or Cmd+K (metaKey is Cmd on Mac)
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      // Don't trigger if typing in an input field
      if (e.target.matches('input, textarea, select') || e.target.isContentEditable) return;
      // Don't trigger if not logged in
      if (!S.token) return;
      // Don't trigger if a modal is open
      const openModals = els('.mbg').filter(m => !m.hidden);
      if (openModals.length) return;

      e.preventDefault();
      togglePicker();
      // Focus the search input when opening
      if (!$('sw-dd').hidden) {
        setTimeout(() => $('sw-search')?.focus(), 50);
      }
    }
  });

  /* Keyboard shortcut to open the Keyboard Shortcuts help modal: ? */
  document.addEventListener('keydown', e => {
    if (e.key !== '?') return;
    if (e.target.matches('input, textarea, select') || e.target.isContentEditable) return;
    if (!S.token) return;
    const openModals = els('.mbg').filter(m => !m.hidden);
    if (openModals.length) return;
    e.preventDefault();
    openModal('m-shortcuts');
  });

  /* Action shortcuts: Ctrl+Alt+<letter>, matching the existing Ctrl+Alt+S
     pattern (no Cmd/metaKey branch — see the Keyboard Shortcuts help modal
     for why). Each skips typing fields and logged-out sessions. Unlike
     Ctrl+K/?, these close whatever modal is already open rather than doing
     nothing — the most common place to press one of these is the Keyboard
     Shortcuts modal itself, right after reading about it, and silently
     no-oping there just makes the shortcut look broken. */
  document.addEventListener('keydown', e => {
    if (!e.ctrlKey || !e.altKey) return;
    if (e.target.matches('input, textarea, select') || e.target.isContentEditable) return;
    if (!S.token) return;
    // Matched on the physical key (e.code), not the character it produces
    // (e.key): on layouts where Ctrl+Alt doubles as AltGr, a given letter
    // can type an accented/composed character instead of plain 'm'/'v'/etc,
    // which e.key would reflect but e.code never does.
    const key = { KeyG: 'g', KeyV: 'v', KeyO: 'o', KeyW: 'w', KeyI: 'i' }[e.code];
    if (!key) return;
    els('.mbg').filter(m => !m.hidden).forEach(m => closeModal(m.id));
    if (key === 'g') {
      e.preventDefault();
      openSwitchManagement().catch(err => reportError(err, 'Could not open Switch Management'));
    } else if (key === 'v') {
      e.preventDefault();
      toggleMegaVisibility();
    } else if (key === 'o') {
      e.preventDefault();
      // Trigger the real button rather than any terminal.js internals: this
      // inherits its disabled state exactly, so a read-only switch (or a
      // non-admin, or an already-open terminal) blocks the shortcut the
      // same way it blocks a click.
      $('btn-terminal')?.click();
    } else if (key === 'w') {
      e.preventDefault();
      // Same reasoning as Terminal above: click the real button so it
      // inherits the existing disabled/read-only gating from
      // applyAccessGating() instead of reimplementing it here.
      $('btn-save')?.click();
    } else if (key === 'i') {
      e.preventDefault();
      // The IP search lives on the Mega, so it only exists while the Mega
      // is on screen -- say so rather than silently doing nothing.
      if (!S.megaVisible || $('maga-stage')?.hidden) {
        return warn('Mega is hidden',
          'Turn your Mega back on (Ctrl+Alt+V) to use the global IP search.');
      }
      openMegaIpSearch();
    }
  });

  /* ── login ── */
  $('login-form').addEventListener('submit', async e => {
    e.preventDefault();
    const errEl = $('login-error');
    const btn = el('button[type=submit]', e.target);
    fieldError(errEl, '');
    const u = $('login-username').value.trim();
    const p = $('login-password').value;
    if (!u) return fieldError(errEl, 'Enter your username.');
    if (!p) return fieldError(errEl, 'Enter your password.');
    setBusy(btn, true, 'Signing in…');
    try {
      const d = await api('POST', '/api/auth/token',
        new URLSearchParams({ username: u, password: p }));
      setAuth(d.access_token, d.username, d.role, d.mega, d.mega_visible);
      applyTheme(d.theme || DEFAULT_THEME);
      $('login-password').value = '';
      await showApp();
      ok('Welcome back', `Signed in as ${d.username}.`);
    } catch (err) {
      fieldError(errEl, err.message);
      if (err.kind === 'locked') {
        errEl.className = 'alert a-error';
        bad('Account locked', err.message);
      } else {
        errEl.className = 'form-error';
      }
    } finally { setBusy(btn, false); }
  });

  /* ── logout ── */
  $('btn-logout').addEventListener('click', async () => {
    const proceed = await confirmDialog({
      title: 'Sign out', message: 'Sign out of GIGACL?', okLabel: 'Sign Out',
    });
    if (!proceed) return;
    releasePresence();
    clearAuth();
    resetAllSectionState();
    els('input[type=password]').forEach(i => { i.value = ''; });
    showLogin();
    info('Signed out', 'Your session has ended.');
  });

  $('btn-about').addEventListener('click', () => openModal('m-about'));
  $('btn-mega-visibility').addEventListener('click', toggleMegaVisibility);
  $('theme-options').addEventListener('click', e => {
    const button = e.target.closest('[data-theme-choice]');
    if (button) chooseTheme(button.dataset.themeChoice);
  });

  $('maga-options').addEventListener('click', e => {
    const button = e.target.closest('[data-maga-choice]');
    if (button) chooseMaga(button.dataset.magaChoice, button);
  });
  $('maga-stage').addEventListener('pointerdown', beginMegaDrag);
  $('maga-stage').addEventListener('pointermove', moveMega);
  $('maga-stage').addEventListener('pointerup', endMegaDrag);
  $('maga-stage').addEventListener('pointercancel', endMegaDrag);
  $('maga-stage').addEventListener('submit', e => {
    if (e.target.matches('.mega-ip-form')) runMegaIpLookup(e);
  });
  $('maga-stage').addEventListener('click', e => {
    const suggestion = e.target.closest('.mega-rule-suggestion');
    if (suggestion) {
      const access = megaRuleSuggestion;
      clearMegaRuleSuggestion();
      openAddRuleFromAccess(access);
      return;
    }
    const acl = e.target.closest('[data-mega-acl]');
    if (acl) {
      openLookupAcl(acl.dataset.megaSwitch, acl.dataset.megaAcl);
      return;
    }
    if (e.target.closest('.mega-ip-form')) return;
    if (megaIgnoreClick) {
      megaIgnoreClick = false;
      e.preventDefault();
      return;
    }
    if (appActivities.size) return;
    const stage = e.currentTarget;
    if (stage.classList.contains('has-rule-suggestion')) {
      clearMegaRuleSuggestion();
      return;
    }
    if (e.detail > 1) {
      clearTimeout(megaClickTimer);
      megaClickTimer = null;
      stage.classList.remove('is-excited');
      void stage.offsetWidth;
      stage.classList.add('is-excited');
      setTimeout(() => stage.classList.remove('is-excited'), 900);
      return;
    }
    clearTimeout(megaClickTimer);
    megaClickTimer = setTimeout(() => {
      megaClickTimer = null;
      if (stage.classList.contains('is-search-open')) {
        closeMegaIpSearch();
        return;
      }
      stage.classList.remove('is-excited');
      void stage.offsetWidth;
      stage.classList.add('is-excited');
      setTimeout(() => stage.classList.remove('is-excited'), 900);
      openMegaIpSearch();
    }, 260);
  });
  $('maga-stage').addEventListener('keydown', e => {
    if ((e.key === 'Enter' || e.key === ' ') && e.target === e.currentTarget && !appActivities.size) {
      e.preventDefault();
      openMegaIpSearch();
    }
    if (e.key === 'Escape' && e.currentTarget.classList.contains('is-search-open')) {
      closeMegaIpSearch();
      e.currentTarget.focus();
    }
  });
  document.addEventListener('pointerdown', e => {
    const stage = $('maga-stage');
    if (!stage || stage.contains(e.target)) return;
    if (megaClickTimer) {
      clearTimeout(megaClickTimer);
      megaClickTimer = null;
    }
    if (stage.classList.contains('is-search-open')) closeMegaIpSearch();
  });
  $('btn-side-panel').addEventListener('click', openSideLauncher);
  $('btn-side-change').addEventListener('click', openSideLauncher);
  $('btn-side-close').addEventListener('click', closeSideWorkspace);
  $('side-launcher').addEventListener('click', e => {
    if (e.target === $('side-launcher')) closeSideLauncher();
    const option = e.target.closest('[data-side-page]');
    if (option) openSidePage(option.dataset.sidePage);
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && !$('side-launcher').hidden) closeSideLauncher();
    if (e.ctrlKey && e.altKey && e.key.toLowerCase() === 's') {
      e.preventDefault();
      if ($('side-launcher').hidden) openSideLauncher();
      else closeSideLauncher();
    }
  });
  $('btn-mobile-menu').addEventListener('click', () => {
    setMobileNav(!$('app-screen').classList.contains('nav-open'));
  });
  $('sidebar-backdrop').addEventListener('click', closeMobileNav);
  window.addEventListener('resize', () => {
    if (!window.matchMedia('(max-width: 860px)').matches) closeMobileNav();
    clampMegaPosition();
  });
  els('.nav-item[data-page]').forEach(n =>
    n.addEventListener('click', () => showPage(n.dataset.page)));
  $('btn-save').addEventListener('click', saveConfig);
  $('btn-bulk-save').addEventListener('click', bulkSaveAllConfigs);

  /* ── switch picker ── */
  $('sw-pick-btn').addEventListener('click', e => { e.stopPropagation(); togglePicker(); });
  $('sw-search').addEventListener('input', buildPicker);
  $('sw-search').addEventListener('click', e => e.stopPropagation());
  $('sw-search').addEventListener('keydown', e => {
    const rows = els('.sw-opt[data-sw]', $('sw-dd-list'));
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (!rows.length) return;
      pickerCursor = Math.min(rows.length - 1, pickerCursor + 1);
      paintPickerCursor();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (!rows.length) return;
      pickerCursor = Math.max(0, pickerCursor - 1);
      paintPickerCursor();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (pickerCursor >= 0 && rows[pickerCursor]) {
        toggleSwitch(+rows[pickerCursor].dataset.sw);
      }
    }
  });
  $('sw-dd-list').addEventListener('click', e => {
    const opt = e.target.closest('[data-sw]');
    if (opt) toggleSwitch(+opt.dataset.sw);
  });
  document.addEventListener('click', e => {
    if (!e.target.closest('#sw-picker')) closePicker();
  });
  $('btn-open-sw').addEventListener('click', openSwitchManagement);
  $('sw-mgr-search').addEventListener('input', buildSwitchManager);
  
  /* ── the terminal choice only exists on a write grant ── */
  $('sw-grant-access').addEventListener('change', updateGrantTerminalVisibility);

  /* ── toggle enable password field ── */
  $('sw-enable').addEventListener('change', e => {
    $('sw-enable-wrap').style.display = e.target.checked ? '' : 'none';
    if (!e.target.checked) $('sw-enable-pass').value = '';
  });

  /* ── toggle enable password field in edit modal ── */
  $('esw-enable').addEventListener('change', e => {
    $('esw-enable-wrap').style.display = e.target.checked ? '' : 'none';
    if (!e.target.checked) $('esw-enable-pass').value = '';
  });



  /* ── add switch ── */
  $('f-addsw').addEventListener('submit', e => {
    e.preventDefault();
    submitSwitchAdd();
  });

  // The single-IP field and the list are the same operation underneath; the
  // toggle only changes which one is collected.
  $('sw-bulk').addEventListener('change', () => {
    const bulk = $('sw-bulk').checked;
    $('sw-ip-single-wrap').hidden = bulk;
    $('sw-ip-bulk-wrap').hidden = !bulk;
    $('btn-addsw').textContent = bulk ? 'Connect & Save All' : 'Connect & Save';
  });

  /* ── switch manager actions ── */
  $('sw-mgr-list').addEventListener('click', async e => {
    const moveSiteButton = e.target.closest('[data-move-site]');
    const moveSwitchButton = e.target.closest('[data-move-switch]');
    if (moveSiteButton) {
      moveSite(moveSiteButton.dataset.moveSite, +moveSiteButton.dataset.direction);
      return;
    }
    if (moveSwitchButton) {
      moveSwitch(+moveSwitchButton.dataset.moveSwitch, +moveSwitchButton.dataset.direction);
      return;
    }
    const del = e.target.closest('[data-del]');
    const ed  = e.target.closest('[data-edit]');
    const vp  = e.target.closest('[data-vpc]');
    if (vp) return openVpc(+vp.dataset.vpc);
    if (ed) return openEditSw(+ed.dataset.edit);
    if (del) {
      const id = +del.dataset.del;
      const s = swById(id);
      const proceed = await confirmDialog({
        title: 'Remove switch',
        message: `Remove "${s ? (s.hostname || s.ip_address) : 'this switch'}" from GIGACL? `
               + `Nothing on the switch itself is changed.`,
        okLabel: 'Remove', okClass: 'btn-danger',
      });
      if (!proceed) return;
      try {
        const r = await api('DELETE', `/api/switches/${id}`);
        S.swIds = S.swIds.filter(x => x !== id);
        S.dataGen++;
        ok('Switch removed', r.message);
        await loadSwitches();
      } catch (err) { reportError(err, 'Could not remove the switch'); }
    }
  });

  /* ── VPC save ── */
  $('btn-vpc-save').addEventListener('click', async () => {
    const val = $('vpc-peer').value;
    try {
      const r = await api('POST', '/api/switches/vpc-pair',
        { switch_id: vpcId, peer_switch_id: val ? +val : null });
      closeModal('m-vpc');
      if (r.changed === false) info('No change made', r.message);
      else ok('VPC pairing updated', r.message);
      await loadSwitches();
    } catch (e) { reportError(e, 'Could not update VPC pairing'); }
  });

  /* ── edit switch save ── */
  $('btn-esw-save').addEventListener('click', async () => {
    const errEl = $('esw-err');
    fieldError(errEl, '');
    const pass = $('esw-pass').value;
    const switchType = $('esw-type').value;
    const useEnable = $('esw-enable').checked;
    const enablePass = $('esw-enable-pass').value;
    const s = swById(editSwId);
    
    // Only validate enable password if:
    // 1. We're turning enable ON (wasn't enabled before)
    // 2. OR we're changing SSH password while enable is/will be ON
    const turningEnableOn = useEnable && !s.use_enable;
    const changingPassWithEnable = useEnable && pass;
    
    if ((turningEnableOn || changingPassWithEnable) && !enablePass) {
      const msg = turningEnableOn 
        ? 'Enable password is required when enabling "Requires an enable password".'
        : 'Enable password is required when changing SSH password with enable mode active.';
      fieldError(errEl, msg);
      return;
    }
    
    try {
      const sshUser = $('esw-username').value.trim();
      const r = await api('PUT', '/api/switches', {
        switch_id: editSwId,
        switch_type: switchType,
        ssh_username: sshUser || null,
        ssh_password: pass || null,
        site: $('esw-site').value || null,
        use_enable: useEnable,
        enable_password: enablePass || null });
      closeModal('m-editsw');
      if (r.changed === false) info('No change made', r.message);
      else ok('Switch updated', r.message);
      await loadSwitches();
    } catch (e) {
      fieldError(errEl, e.message);
      reportError(e, 'Could not update the switch');
    }
  });

  /* ── protocol → port / ICMP type visibility & auto-clear ── */
  [
    ['chk-proto', 'chk-port-wrap', 'chk-port', 'chk-icmp-type-wrap', 'chk-icmp-type'],
    ['add-proto', 'add-port-wrap', 'add-port', 'add-icmp-type-wrap', 'add-icmp-type'],
  ].forEach(([sel, wrap, portField, icmpWrap, icmpField]) => {
    const s = $(sel), w = $(wrap), pf = $(portField);
    const iw = $(icmpWrap), icf = $(icmpField);
    const upd = () => {
      const needsPort = ['tcp', 'udp'].includes(s.value);
      const needsIcmpType = s.value === 'icmp';
      w.hidden = !needsPort;
      if (!needsPort && pf.value) pf.value = '';
      if (iw) {
        iw.hidden = !needsIcmpType;
        if (!needsIcmpType && icf.value) {
          icf.value = '';
          icf.dispatchEvent(new Event('change', { bubbles: true }));
        }
      }
    };
    s.addEventListener('change', upd); upd();
  });

  /* ── 'established' offer: TCP only, and only alongside a service port.
     Registered after the block above so the protocol handler has already
     cleared the port field by the time this re-evaluates. ── */
  const updEstablished = () => {
    const wrap = $('add-established-wrap');
    if (!wrap) return;
    const box = $('add-established');
    const eligible = $('add-proto').value === 'tcp' && !!$('add-port').value.trim();
    wrap.hidden = !eligible;
    if (!eligible && box.checked) box.checked = false;
  };
  $('add-proto').addEventListener('change', updEstablished);
  $('add-port').addEventListener('input', updEstablished);
  updEstablished();

  /* ── ACCESS CHECK ── */
  $('f-check').addEventListener('submit', async e => {
    e.preventDefault();
    if (!needSwitch()) return;
    const box = $('r-check');
    let src, dst, proto, port, icmpType;
    try {
      proto = $('chk-proto').value;
      src = V.addr($('chk-src').value, 'Source', { group: false });
      dst = V.addr($('chk-dst').value, 'Destination', { group: false });
      if (src === 'any' && dst === 'any') throw new Error('Source and destination cannot both be "any".');
      port = V.port($('chk-port').value, proto);
      icmpType = V.icmpType($('chk-icmp-type').value, proto);
    } catch (err) { return bad('Check your input', err.message); }

    latestDeniedAccess = null;
    clearMegaRuleSuggestion();
    const gen = S.dataGen;
    box.innerHTML = skeleton(3);
    try {
      const d = await api('POST', '/api/acl/check',
        { switch_ids: S.swIds, src_ip: src, dst_ip: dst, protocol: proto, port, icmp_type: icmpType });
      if (gen !== S.dataGen) return;
      if (d.verdict === 'DENY' && isAdmin()) {
        latestDeniedAccess = {
          src_ip: d.src_ip, dst_ip: d.dst_ip,
          protocol: d.protocol, port: d.port || '',
          icmp_type: d.icmp_type || '',
        };
      }
      const megaOffered = latestDeniedAccess
        ? offerMegaRuleSuggestion(latestDeniedAccess)
        : false;
      d.show_add_rule_button = Boolean(latestDeniedAccess && !megaOffered);
      box.innerHTML = renderCheck(d);
      revealResult(box);
    } catch (err) {
      if (gen !== S.dataGen) return;
      box.innerHTML = `<div class="alert a-error">${esc(err.message)}</div>`;
      reportError(err, 'Access check failed');
    }
  });

  /* ── IP LOOKUP ── */
  $('f-ip').addEventListener('submit', async e => {
    e.preventDefault();
    const box = $('r-ip');
    const globalLookup = S.swIds.length === 0;
    let ip;
    try {
      ip = globalLookup
        ? V.cliSafe($('ip-addr').value || '', 'IP address')
        : V.addr($('ip-addr').value, 'IP address', { any: false, group: false });
      if (globalLookup && !isValidMegaIp(ip)) {
        throw new Error(`IP address "${ip}" is not a valid IPv4 address.`);
      }
    }
    catch (err) { return bad('Check your input', err.message); }
    const gen = S.dataGen;
    box.innerHTML = skeleton(3);
    try {
      const d = globalLookup
        ? await api('POST', '/api/acl/check-ip-global', { ip_address: ip })
        : await api('POST', '/api/acl/check-ip', { switch_ids: S.swIds, ip_address: ip });
      if (gen !== S.dataGen) return;
      box.innerHTML = globalLookup ? renderGlobalIp(d) : renderIp(d);
      revealResult(box);
    } catch (err) {
      if (gen !== S.dataGen) return;
      box.innerHTML = `<div class="alert a-error">${esc(err.message)}</div>`;
      reportError(err, 'Lookup failed');
    }
  });
  $('r-check').addEventListener('click', e => {
    const reqBtn = e.target.closest('[data-request-access]');
    if (reqBtn) {
      openAccessRequest(reqBtn.dataset.requestAccess);
      return;
    }
    if (e.target.closest('[data-access-add-rule]')) {
      openAddRuleFromAccess();
    }
  });
  $('r-ip').addEventListener('click', e => {
    const acl = e.target.closest('[data-ip-acl]');
    if (acl) openLookupAcl(acl.dataset.ipSwitch, acl.dataset.ipAcl);
  });
  $('r-ip').addEventListener('keydown', e => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const acl = e.target.closest('[data-ip-acl]');
    if (!acl) return;
    e.preventDefault();
    openLookupAcl(acl.dataset.ipSwitch, acl.dataset.ipAcl);
  });

  /* ── ACL VIEWER ── */
  $('btn-view').addEventListener('click', () => { if (needSwitch()) refreshViewer(); });
  $('btn-pick-view').addEventListener('click', () => pickAcl('view-acl'));
  $('r-viewer').addEventListener('submit', e => {
    const addRuleForm = e.target.closest('[data-view-add-rule]');
    const attachForm = e.target.closest('[data-view-attach-acl]');
    if (!addRuleForm && !attachForm) return;
    e.preventDefault();
    if (!isAdmin()) return;
    if (addRuleForm) addViewerRule(addRuleForm);
    else attachViewerAcl(attachForm);
  });
  $('r-viewer').addEventListener('click', e => {
    const edit = e.target.closest('[data-view-edit-rule]');
    const detach = e.target.closest('[data-view-detach-acl]');
    const delAcl = e.target.closest('[data-view-delete-acl]');
    const report = e.target.closest('[data-view-report-acl]');
    if (edit) openViewerRuleEdit(edit);
    else if (detach) detachViewerAcl(detach);
    else if (delAcl) deleteViewerAcl(delAcl);
    else if (report) openAclReport(+report.dataset.switchId, report.dataset.aclName);
  });
  $('btn-view-edit-save').addEventListener('click', saveViewerRuleEdit);

  /* Group and schedule references jump to their definition below. */
  $('report-body').addEventListener('click', e => {
    const link = e.target.closest('[data-rpt-ref]');
    if (!link) return;
    const target = $(link.dataset.rptRef);
    if (!target) return;
    target.scrollIntoView({ behavior: 'smooth', block: 'center' });
    target.classList.remove('rpt-flash');
    void target.offsetWidth;          // restart the animation on a repeat click
    target.classList.add('rpt-flash');
  });

  /* ── OBJECT GROUPS ── */
  $('btn-load-og').addEventListener('click', () => { if (needSwitch()) refreshObjectGroups(); });

  $('pg-object-groups').addEventListener('click', e => {
    const pick = e.target.closest('[data-og-pick-group]');
    if (!pick) return;
    const uid = pick.dataset.ogPickGroup, kind = pick.dataset.ogPickKind;
    pickGroup(kind === 'address' ? `og-addr-${uid}` : `og-port-${uid}`, kind);
  });

  $('r-og').addEventListener('submit', e => {
    const form = e.target.closest('[data-og-add-member]');
    if (form) { e.preventDefault(); addOgMember(form); }
  });
  $('r-og').addEventListener('click', e => {
    const editBtn = e.target.closest('[data-og-edit-member]');
    const delBtn = e.target.closest('[data-og-del-member]');
    const delGroupBtn = e.target.closest('[data-og-del-group]');
    if (editBtn) openOgMemberEdit(editBtn);
    else if (delBtn) delOgMember(delBtn);
    else if (delGroupBtn) deleteObjectGroup(delGroupBtn);
  });
  $('btn-og-edit-save').addEventListener('click', saveOgMemberEdit);

  $('btn-og-add-entry').addEventListener('click', addOgEntry);
  $('og-entries').addEventListener('click', e => {
    const del = e.target.closest('[data-oge-del]');
    if (del) $(`oge-${del.dataset.ogeDel}`)?.remove();
  });
  $('og-kind').addEventListener('change', () => { $('og-entries').innerHTML = ''; });
  $('btn-og-preview').addEventListener('click', async () => {
    if (!needSwitch()) return;
    fieldError($('og-entries-error'), '');
    let name, members;
    try {
      name = V.groupIdent($('og-name').value, 'Object group name');
      members = collectOgEntries();
    } catch (err) { return fieldError($('og-entries-error'), err.message); }
    const kind = $('og-kind').value;
    const box = $('r-og-preview');
    box.innerHTML = skeleton(2);
    try {
      const d = await api('POST', '/api/write/object-group-preview',
        { switch_ids: [...S.swIds], name, kind, members });
      box.innerHTML = renderOgCreatePreview(d);
      revealResult(box);
    } catch (e) {
      box.innerHTML = `<div class="alert a-error">${esc(e.message)}</div>`;
      reportError(e, 'Could not preview the object group');
    }
  });

  /* ── REDUNDANCY ── */
  $('btn-red').addEventListener('click', refreshRedundant);
  $('btn-pick-red').addEventListener('click', () => pickAcl('red-acl'));

  /* ── SUMMARY ── */
  $('btn-sum').addEventListener('click', refreshSummary);
  $('btn-pick-sum').addEventListener('click', () => pickAcl('sum-acl'));

  /* ── VPC SYNC CHECK ── */
  $('btn-vpc-sync').addEventListener('click', refreshVpcSync);
  document.addEventListener('giga:switch-selection-change', applyAccessGating);
  document.addEventListener('giga:switch-selection-change', updateVpcSyncEligibility);
  document.addEventListener('giga:switch-selection-change', () => {
    if (templatesCache.length) $('r-templates').innerHTML = renderTemplatesList(templatesCache);
  });
  document.addEventListener('giga:switch-selection-change', refreshAclCreateForSwitchSelection);

  /* ── RULE ADD ── */
  $('btn-g-src').addEventListener('click', () => pickGroup('add-src', 'address'));
  $('btn-g-dst').addEventListener('click', () => pickGroup('add-dst', 'address'));
  $('btn-g-port').addEventListener('click', () => pickGroup('add-port', 'port'));
  $('btn-g-time-range').addEventListener('click', () => pickRuleTimeRange('add-time-range'));

  $('f-rule').addEventListener('submit', async e => {
    e.preventDefault();
    if (!needSwitch()) return;
    const box = $('r-rule');
    let src, dst, proto, port, icmpType, timeRange, remark, remarkSeq, seq;
    try {
      proto = $('add-proto').value;
      src = V.addr($('add-src').value, 'Source');
      dst = V.addr($('add-dst').value, 'Destination');
      if (src === 'any' && dst === 'any') throw new Error('Source and destination cannot both be "any".');
      port = V.port($('add-port').value, proto);
      icmpType = V.icmpType($('add-icmp-type').value, proto);
      timeRange = $('add-time-range').value.trim()
        ? V.ident($('add-time-range').value, 'Time range')
        : null;
      remark = $('add-remark').value.trim();
      if (remark) {
        V.cliSafe(remark, 'Remark');
        if (remark.length > 100) throw new Error('Remark is too long (maximum 100 characters).');
      }
      remarkSeq = V.seq($('add-remark-seq').value);
      if (remarkSeq !== null && !remark) {
        throw new Error('Enter remark text before setting a remark sequence.');
      }
      seq = V.seq($('add-seq').value);
    } catch (err) { return bad('Check your input', err.message); }

    const gen = S.dataGen;
    box.innerHTML = skeleton(3);
    try {
      const selectedSwitchIds = [...S.swIds];
      const d = await api('POST', '/api/write/rule-preview', {
        switch_ids: withConfiguredVpcPeer(selectedSwitchIds),
        src_ip: src, dst_ip: dst,
        protocol: proto, port, icmp_type: icmpType,
        established: proto === 'tcp' && !!port && $('add-established').checked,
        time_range: timeRange, remark: remark || null,
        remark_sequence_number: remarkSeq,
        sequence_number: seq });
      if (gen !== S.dataGen) return;
      d.selected_switch_ids = selectedSwitchIds;
      box.innerHTML = renderRulePreview(d);
      revealResult(box);
      const n = (d.switches || []).reduce((a, s) => a + (s.previews?.length || 0), 0);
      if (n) info('Preview ready', `${n} rule${n === 1 ? '' : 's'} generated across ${d.switches.length} switch(es).`);
    } catch (err) {
      if (gen !== S.dataGen) return;
      box.innerHTML = `<div class="alert a-error">${esc(err.message)}</div>`;
      reportError(err, 'Could not generate the preview');
    }
  });

  /* ── ADD ACL ── */
  $('aacl-acl-kind').addEventListener('change', populateAclCreateTemplateSelect);
  $('aacl-template').addEventListener('change', updateAclCreateDirectionVisibility);
  $('btn-aacl-create').addEventListener('click', createAclFlow);

  /* ── TIME RANGES ── */
  $('btn-load-tr').addEventListener('click', async () => {
    if (!needSwitch()) return;
    const box = $('r-tr-list');
    const gen = S.dataGen;
    box.innerHTML = skeleton(3);
    try {
      const d = await api('POST', '/api/analysis/time-ranges', { switch_ids: S.swIds });
      if (gen !== S.dataGen) return;
      box.innerHTML = renderTimeRanges(d);
    } catch (e) {
      if (gen !== S.dataGen) return;
      box.innerHTML = `<div class="alert a-error">${esc(e.message)}</div>`;
      reportError(e, 'Could not load time ranges');
    }
  });
  $('btn-tr-add').addEventListener('click', addTrEntry);
  $('tr-entries').addEventListener('click', e => {
    const d = e.target.closest('[data-tre-del]');
    if (d) $(`tre-${d.dataset.treDel}`)?.remove();
  });
  $('btn-tr-preview').addEventListener('click', async () => {
    if (!needSwitch()) return;
    let name, entries;
    try {
      name = V.ident($('tr-name').value, 'Time-range name');
      entries = collectTrEntries();
      if (!entries.length) throw new Error('Add at least one entry before generating a preview.');
    } catch (e) { return bad('Check your input', e.message); }
    const box = $('r-tr-preview');
    const gen = S.dataGen;
    box.innerHTML = skeleton(2);
    try {
      const selectedSwitchIds = [...S.swIds];
      const d = await api('POST', '/api/write/time-range-preview',
        { switch_ids: withConfiguredVpcPeer(selectedSwitchIds), name, entries });
      if (gen !== S.dataGen) return;
      d.selected_switch_ids = selectedSwitchIds;
      renderTrPreview(d);
      revealResult(box);
    } catch (e) {
      if (gen !== S.dataGen) return;
      box.innerHTML = `<div class="alert a-error">${esc(e.message)}</div>`;
      reportError(e, 'Could not build the preview');
    }
  });

  /* ── REVERSE DIRECTION ── */
  $('btn-pick-rev').addEventListener('click', () => pickAcl('rev-acl'));
  $('btn-rev-preview').addEventListener('click', refreshReverseDirection);

  /* ── TEMPLATES ── */
  $('btn-tpl-add-line').addEventListener('click', () => addTplLineRow());
  $('tpl-lines').addEventListener('click', e => {
    const del = e.target.closest('[data-tpl-line-del]');
    if (del) $(del.dataset.tplLineDel)?.remove();
  });
  $('tpl-switch-type').addEventListener('change', updateTplAclKindVisibility);
  $('tpl-acl-kind').addEventListener('change', updateTplAclKindVisibility);
  $('btn-tpl-cancel-edit').addEventListener('click', resetTemplateForm);
  $('tpl-share-btn').addEventListener('click', e => { e.stopPropagation(); openTplShareMenu(); });
  $('btn-tpl-save').addEventListener('click', async () => {
    const name = $('tpl-name').value.trim();
    const switchType = $('tpl-switch-type').value;
    const aclKind = switchType === 'ios' ? $('tpl-acl-kind').value : 'extended';
    const direction = $('tpl-direction').value;
    const lines = els('.tpl-line-input').map(i => i.value.trim()).filter(Boolean);
    const shareWith = isAdmin() ? [...tplShareSelected] : [];
    fieldError($('tpl-form-error'), '');
    if (!name) return fieldError($('tpl-form-error'), 'Enter a template name.');
    if (!lines.length) return fieldError($('tpl-form-error'), 'Add at least one rule line.');
    const btn = $('btn-tpl-save');
    setBusy(btn, true, 'Saving…');
    try {
      const payload = { name, switch_type: switchType, acl_kind: aclKind, direction, lines, share_with: shareWith };
      if (tplEditingId) {
        await api('PUT', `/api/templates/${tplEditingId}`, payload);
        ok('Template updated', `'${name}' was updated.`);
      } else {
        await api('POST', '/api/templates', payload);
        ok('Template created', `'${name}' was saved.`);
      }
      resetTemplateForm();
      await loadTemplates();
    } catch (e) {
      fieldError($('tpl-form-error'), e.message);
    } finally { setBusy(btn, false); }
  });

  /* ── LOGS ── */
  $('btn-logs-refresh').addEventListener('click', loadLogs);

  $('btn-dash-refresh').addEventListener('click', loadDashboard);
  // Wrapped, not passed by reference: the listener's MouseEvent would
  // otherwise arrive as switchIds and be sent as the switch list.
  $('btn-dash-scan').addEventListener('click', () => runDashScan());
  els('#dash-windows .dash-win').forEach(b => b.addEventListener('click', () => {
    DASH.window = b.dataset.window;
    els('#dash-windows .dash-win').forEach(x => x.classList.toggle('active', x === b));
    loadDashActivity();   // The window only affects activity; health is unscoped.
  }));
  $('log-lvl').addEventListener('change', renderLogs);
  $('log-q').addEventListener('input', renderLogs);
  $('log-site').addEventListener('change', () => { populateLogSwitchFilter(); renderLogs(); });
  $('log-switch').addEventListener('change', renderLogs);
  $('log-admin').addEventListener('change', renderLogs);
  /* The shared calendar writes straight to the hidden input, so it fires a
     synthetic 'change' for listeners like this one (see openDatePicker). */
  $('log-date-from').addEventListener('change', renderLogs);
  $('log-date-to').addEventListener('change', renderLogs);
  setupTimePickers();

  /* ── ADD USER ── */
  $('f-adduser').addEventListener('submit', async e => {
    e.preventDefault();
    const u = $('nu-name').value.trim();
    const p = $('nu-pass').value;
    const role = $('nu-role').value;
    if (!u) return bad('Check your input', 'Enter a username.');
    if (!/^[A-Za-z0-9._-]{2,64}$/.test(u)) {
      return bad('Check your input',
        'Username must be 2–64 characters using letters, digits, dot, dash or underscore.');
    }
    const pwErr = V.password(p);
    if (pwErr) return bad('Password too weak', pwErr);
    const btn = el('button[type=submit]', e.target);
    setBusy(btn, true, 'Creating…');
    try {
      await api('POST', '/api/auth/users', { username: u, password: p, role });
      $('nu-name').value = ''; $('nu-pass').value = '';
      ok('User created', `"${u}" was added as ${ROLE_TXT[role] || role}.`);
      await loadUsers();
    } catch (err) { reportError(err, 'Could not create the user'); }
    finally { setBusy(btn, false); }
  });

  /* ── IDLE TIMEOUT ──
     No setBusy()/spinner here on purpose: the save is a single tiny local
     write and the text+width swap it causes reads as a glitch rather than
     progress, so this just disables the button for the moment instead. */
  $('btn-idle-timeout-save').addEventListener('click', async () => {
    const minutes = +$('idle-timeout-select').value;
    const btn = $('btn-idle-timeout-save');
    btn.disabled = true;
    try {
      const r = await api('PUT', '/api/settings/idle-timeout',
        { idle_timeout_minutes: minutes });
      S.idleTimeoutMinutes = r.idle_timeout_minutes;
      resetIdleTimer();
      ok('Idle timeout updated', r.message);
    } catch (err) { reportError(err, 'Could not update the idle timeout'); }
    finally { btn.disabled = false; }
  });

  /* ── LOG RETENTION ── */
  $('btn-log-retention-save').addEventListener('click', async () => {
    const days = +$('log-auto-delete-select').value;
    const zip = $('log-auto-delete-zip').checked;
    const btn = $('btn-log-retention-save');
    btn.disabled = true;
    try {
      const r = await api('PUT', '/api/settings/log-retention',
        { auto_delete_days: days, auto_delete_zip: zip });
      S.logAutoDeleteDays = r.auto_delete_days;
      S.logAutoDeleteZip = r.auto_delete_zip;
      ok('Auto-delete updated', r.message);
    } catch (err) { reportError(err, 'Could not update auto-delete'); }
    finally { btn.disabled = false; }
  });

  $('btn-log-delete-now').addEventListener('click', async () => {
    const sel = $('log-delete-select');
    const days = +sel.value;
    const zip = $('log-delete-zip').checked;
    const label = sel.selectedOptions[0].textContent;
    const proceed = await confirmDialog({
      title: 'Delete old logs',
      message: `Permanently delete every activity log older than ${label}? This cannot be undone.`,
      okLabel: 'Delete Logs', okClass: 'btn-danger',
    });
    if (!proceed) return;
    const btn = $('btn-log-delete-now');
    btn.disabled = true;
    try {
      if (zip) {
        // Binary response (the zip itself), so this bypasses api() -- it only
        // ever parses JSON -- and speaks to fetch() directly instead.
        const res = await fetch('/api/logs/delete-older-than', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json',
                     Authorization: `Bearer ${S.token}` },
          body: JSON.stringify({ days, zip: true }),
        });
        if (!res.ok) {
          const data = await res.json().catch(() => null);
          throw new Error((data && data.detail) || `Request failed (HTTP ${res.status}).`);
        }
        const blob = await res.blob();
        const cd = res.headers.get('Content-Disposition') || '';
        const named = cd.match(/filename="([^"]+)"/);
        downloadBlob(named ? named[1] : 'audit_logs_backup.zip', blob, 'application/zip');
        ok('Logs deleted', 'The zip backup has downloaded, and matching logs were removed.');
      } else {
        const r = await api('POST', '/api/logs/delete-older-than', { days, zip: false });
        ok('Logs deleted', r.message);
      }
    } catch (err) { reportError(err, 'Could not delete logs'); }
    finally { btn.disabled = false; }
  });

  /* ── RENAME USER ── */
  $('btn-ru-save').addEventListener('click', async () => {
    const errEl = $('ru-err');
    fieldError(errEl, '');
    const username = $('ru-name').value.trim();
    if (!/^[A-Za-z0-9._-]{2,64}$/.test(username)) {
      return fieldError(errEl,
        'Username must be 2–64 characters using letters, digits, dot, dash or underscore.');
    }
    const duplicate = managedUsers.some(user =>
      user.id !== renameUserId &&
      String(user.username).toLowerCase() === username.toLowerCase());
    if (duplicate) {
      return fieldError(errEl, `The username '${username}' is already taken.`);
    }
    const button = $('btn-ru-save');
    setBusy(button, true, 'Renaming…');
    try {
      const r = await api('PUT', `/api/auth/users/${renameUserId}/username`,
        { username });
      closeModal('m-renameuser');
      if (r.changed === false) info('No change made', r.message);
      else ok('User renamed', r.message);
      if (r.token) setAuth(r.token, r.username, S.role, S.maga);
      await loadUsers();
    } catch (e) {
      fieldError(errEl, e.status === 405
        ? 'The running server is an older version. Restart GIGACL, then try again.'
        : e.message);
    } finally {
      setBusy(button, false);
    }
  });
  $('f-renameuser').addEventListener('submit', e => {
    e.preventDefault();
    $('btn-ru-save').click();
  });

  /* ── RESET PW ── */
  $('btn-rp-save').addEventListener('click', async () => {
    const errEl = $('rp-err');
    fieldError(errEl, '');
    const np = $('rp-new').value, cf = $('rp-cf').value;
    if (np !== cf) return fieldError(errEl, 'The two passwords do not match.');
    const pwErr = V.password(np);
    if (pwErr) return fieldError(errEl, pwErr);
    try {
      const r = await api('PUT', `/api/auth/users/${resetPwId}/password`, { new_password: np });
      closeModal('m-resetpw');
      ok('Password reset', r.message);
    } catch (e) { fieldError(errEl, e.message); }
  });

  /* ── TRUSTED HOSTS ── */
  let trustedHostsUserId = null;
  window.openTrustedHosts = function (id, username, currentHosts) {
    trustedHostsUserId = id;
    $('th-user').textContent = username;
    $('th-hosts').value = currentHosts || '';
    fieldError($('th-err'), '');
    openModal('m-trustedhosts');
  };

  $('btn-th-save').addEventListener('click', async () => {
    const errEl = $('th-err');
    fieldError(errEl, '');
    const hosts = $('th-hosts').value.trim();
    
    const isMe = trustedHostsUserId && S.username === $('th-user').textContent;
    const endpoint = isMe 
      ? '/api/auth/me/trusted-hosts'
      : `/api/auth/users/${trustedHostsUserId}/trusted-hosts`;
    
    try {
      const r = await api('PUT', endpoint, { trusted_hosts: hosts });
      closeModal('m-trustedhosts');
      ok('Trusted hosts updated', r.message);
      await loadUsers();
    } catch (e) { fieldError(errEl, e.message); }
  });

  /* ── CHANGE PW ── */
  $('f-chpw').addEventListener('submit', async e => {
    e.preventDefault();
    const cur = $('cp-cur').value, np = $('cp-new').value, cf = $('cp-cf').value;
    if (!cur) return bad('Check your input', 'Enter your current password.');
    if (np !== cf) return bad('Check your input', 'The new passwords do not match.');
    const pwErr = V.password(np);
    if (pwErr) return bad('Password too weak', pwErr);
    const btn = el('button[type=submit]', e.target);
    setBusy(btn, true, 'Updating…');
    try {
      const r = await api('PUT', '/api/auth/me/password',
        { current_password: cur, new_password: np });
      // Changing the password signs out every other session, so this tab
      // swaps to the token issued alongside the change rather than being
      // logged out for doing the right thing.
      if (r.access_token) {
        S.token = r.access_token;
        localStorage.setItem('giga_token', r.access_token);
      }
      ['cp-cur', 'cp-new', 'cp-cf'].forEach(i => { $(i).value = ''; });
      ok('Password updated', r.message);
    } catch (err) { reportError(err, 'Could not change your password'); }
    finally { setBusy(btn, false); }
  });

  /* ── picker delegation ── */
  $('pick-body').addEventListener('click', e => {
    const b = e.target.closest('[data-pick]');
    if (!b) return;
    const v = b.dataset.pick;
    closeModal('m-pick');
    if (pickResolve) { pickResolve(v); pickResolve = null; }
  });

  /* ── session restore ── */
  if (S.token) {
    api('GET', '/api/auth/me')
      .then(d => {
        S.username = d.username; S.role = d.role; S.maga = d.mega || 'byte';
        localStorage.setItem('giga_username', d.username);
        localStorage.setItem('giga_role', d.role);
        localStorage.setItem('giga_mega', S.maga);
        // Restoring a session re-reads the account's own preference, so a
        // reload agrees with a fresh sign-in.
        localStorage.setItem(megaVisibilityKey(), String(!!d.mega_visible));
        applyTheme(d.theme || DEFAULT_THEME);
        return showApp();
      })
      .catch(() => { clearAuth(); showLogin(); });
  } else {
    showLogin();
  }
});
