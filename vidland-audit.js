/* ============================================================
   GRAND DUCHY OF VIDLAND · Mobile access gate
   ------------------------------------------------------------
   Loaded FIRST on admin.html / entry.html, and it is the ONLY script on
   the standalone gate page. Two layers keep a LAN device from ever seeing
   register content before approval:

     1. serve.py does not deliver the real terminal page at all until the
        token is approved. An unapproved device receives gate.html, which
        contains no business DOM, no core script and no register data.
     2. If the real page IS open and authorisation is later withdrawn or
        expires, this gate wipes every business node and covers the whole
        viewport with a fully OPAQUE panel.

   The terminal itself holds NO key material: the Chancellery private key
   is used only by /api/vault/open, the audit vault key stays on the host,
   and the bearer token arrives as an HttpOnly cookie.

   The 1 s poll here is an ACCESS-GATE heartbeat only. It never takes part
   in inspection interruption or timeout decisions, and it calls the
   read-only /api/audit/status rather than re-submitting an entry.
   ============================================================ */
(function (global) {
  'use strict';
  var doc = global.document;
  var path = (global.location.pathname || '').toLowerCase();
  /* Strict mode gates all five terminals, not just Authority / Admission. */
  var terminal = path.indexOf('admin.html') >= 0 ? 'admin'
               : path.indexOf('entry.html') >= 0 ? 'entry'
               : path.indexOf('border.html') >= 0 ? 'border'
               : path.indexOf('interior.html') >= 0 ? 'interior'
               : 'portal';

  var GATE_PAGE = !!(doc.documentElement &&
      doc.documentElement.getAttribute('data-vdl-gate') === '1');
  var DEV_KEY = 'vdl.v1.device.id';       // device-local, shared by tabs
  var RID_KEY = 'vdl.v1.audit.rid';       // tab-local, survives a refresh
  var RELOAD_KEY = 'vdl.v1.audit.gateReload';
  var ENTERING_KEY = 'vdl.v1.audit.entering';
  var POLL_MS = 1000;

  /* English fallback keeps the panel readable if the lexicon is missing.
     EN is the source of record for every gt.* entry. */
  var EN_FALLBACK = {
    'gt.kicker': 'ACCESS AUDIT · APPROVAL REQUIRED',
    'gt.title.pending': 'Access request submitted',
    'gt.body.pending': 'The local audit authority is reviewing this access. ' +
      'No register data is loaded on this page until approval is granted.',
    'gt.title.granted': 'Access approved',
    'gt.body.granted': 'Loading the terminal now.',
    'gt.title.rejected': 'Access request not approved',
    'gt.body.rejected': 'The local audit authority did not approve this access.',
    'gt.title.revoked': 'Access terminated',
    'gt.body.revoked': 'The local audit authority has withdrawn this access. ' +
      'All register data previously shown on this page has been cleared.',
    'gt.title.expired': 'Authorisation no longer valid',
    'gt.body.expired': 'Reload the page to submit a new request.',
    'gt.title.unknown': 'Authorisation no longer recognised',
    'gt.body.unknown': 'Reload the page to submit a new access request.',
    'gt.title.offline': 'Audit service unavailable',
    'gt.body.offline': 'Cannot reach the local audit authority. Retrying.',
    'gt.meta.request': 'Request', 'gt.meta.device': 'Device',
    'gt.meta.reason': 'Reason', 'gt.language': 'Language',
    'gt.footer': 'Before approval this page contains no register data, ' +
      'no application records and no personal particulars.'
  };
  function t(k, v) {
    var I = global.VidlandI18N;
    if (I && I.t) return I.t(k, v);
    var s = EN_FALLBACK[k] || k;
    if (v) Object.keys(v).forEach(function (n) {
      s = s.split('{' + n + '}').join(String(v[n]));
    });
    return s;
  }

  function deviceId() {
    var id = null;
    try { id = global.localStorage.getItem(DEV_KEY); } catch (e) {}
    if (id) return id;
    var b = new Uint8Array(16);
    if (global.crypto && global.crypto.getRandomValues) {
      global.crypto.getRandomValues(b);
    } else {
      for (var i = 0; i < 16; i++) b[i] = Math.floor(Math.random() * 256);
    }
    var hex = '';
    for (var j = 0; j < b.length; j++) hex += ('0' + b[j].toString(16)).slice(-2);
    id = 'DEV-' + hex.toUpperCase();
    try { global.localStorage.setItem(DEV_KEY, id); } catch (e) {}
    return id;
  }
  var dev = deviceId();

  /* A home-screen web app (iOS "Add to Home Screen", Android standalone)
     can use a storage container separate from the browser tab: cookies,
     localStorage and HttpOnly tokens are not shared there. Report the
     launch mode with the request so the host can tell two records apart
     when they actually belong to the same physical device. */
  function displayMode() {
    try {
      if (global.navigator && global.navigator.standalone) return 'standalone';
      if (global.matchMedia) {
        if (global.matchMedia('(display-mode: standalone)').matches)
          return 'standalone';
        if (global.matchMedia('(display-mode: minimal-ui)').matches)
          return 'minimal-ui';
      }
    } catch (e) {}
    return 'browser';
  }
  var LAUNCH_MODE = displayMode();

  /* XHR header tagging lives in vidland-store.js, which all five terminals
     load. Only fetch needs patching here: the gate page has no store shim,
     and admin's /api/vault/open goes through fetch. */
  var origFetch = global.fetch;
  if (origFetch && !origFetch.__vdlAuditPatched) {
    var patchedFetch = function (url, opt) {
      var u = (typeof url === 'string') ? url
            : (url && typeof url.url === 'string') ? url.url : '';
      if (u.charAt(0) === '/' && u.indexOf('/api/') === 0) {
        opt = opt || {};
        var base = opt.headers || (typeof url === 'object' ? url.headers : null);
        try {
          var h = new Headers(base || {});
          h.set('X-VDL-Device', dev);
          h.set('X-VDL-Terminal', terminal);
          opt.headers = h;
        } catch (e) {}
        if (!opt.credentials) opt.credentials = 'same-origin';
      }
      return origFetch.call(global, url, opt);
    };
    patchedFetch.__vdlAuditPatched = true;
    global.fetch = patchedFetch;
  }

  /* ---- full-screen opaque panel -------------------------------------- */
  var box = null, desired = null, timer = null;

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;',
               "'": '&#39;' }[c];
    });
  }
  function ensureBox() {
    if (box) return box;
    if (!doc.body) return null;
    box = doc.createElement('div');
    box.id = 'vdl-audit-gate';
    /* Opaque, not translucent: nothing behind it can be seen. */
    box.setAttribute('style',
      'position:fixed;inset:0;z-index:2147483647;display:none;' +
      'align-items:center;justify-content:center;padding:24px;' +
      'background:#081420;color:#e8edf3;font-family:system-ui,' +
      '-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;' +
      'overflow:auto;-webkit-font-smoothing:antialiased');
    box.addEventListener('change', function (e) {
      if (e.target && e.target.id === 'vdlGateLang') {
        var I = global.VidlandI18N;
        if (I && I.setLang) I.setLang(e.target.value);
        paint();
      }
    });
    box.addEventListener('click', function (e) {
      if (e.target && e.target.id === 'vdlGateReapply') reapply();
    });
    doc.body.appendChild(box);
    return box;
  }
  function wipeBusinessDom() {
    /* Every business node is removed before the panel is drawn. On the
       standalone gate page the body is empty to begin with. */
    var b = ensureBox();
    if (!doc.body) return;
    Array.prototype.slice.call(doc.body.children).forEach(function (el) {
      if (el !== b) { try { el.parentNode.removeChild(el); } catch (e) {} }
    });
  }
  function langOptions() {
    var I = global.VidlandI18N;
    if (!I || !I.langs) return '<option value="en">English</option>';
    return I.langs().map(function (l) {
      return '<option value="' + esc(l.id) + '"' +
             (l.id === I.getLang() ? ' selected' : '') + '>' +
             esc(l.label) + ' · ' + esc(l.native) + '</option>';
    }).join('');
  }
  function paint() {
    if (!desired) return;
    var b = ensureBox();
    if (!b) return;
    if (desired.hidden) { b.style.display = 'none'; return; }
    /* Never wipe business nodes during a repaint. On a REAL terminal a
       transient PENDING / OFFLINE state only covers the viewport; if it
       deleted the DOM, a later GRANTED -> hide() would leave a blank page.
       Destructive erasure is done explicitly by hardCut() instead. */
    var tone = desired.tone === 'red' ? '#e05252'
             : desired.tone === 'amber' ? '#d8a13a' : '#6f9fd8';
    var m = desired.meta || {};
    var meta = [];
    if (m.requestId) meta.push(t('gt.meta.request') + ' ' + m.requestId);
    meta.push(t('gt.meta.device') + ' ' + dev);
    if (m.reason) meta.push(t('gt.meta.reason') + ' ' + m.reason);
    b.innerHTML =
      '<div style="width:min(480px,100%);border:1px solid #2b3d52;' +
      'border-top:3px solid ' + tone + ';background:#101d2c;padding:26px 28px;' +
      'border-radius:3px">' +
      '<div style="font-size:10px;letter-spacing:.18em;text-transform:uppercase;' +
      'color:#8fa5bd;margin-bottom:12px">' + esc(t('gt.kicker')) + '</div>' +
      '<div style="font-size:20px;font-weight:600;margin-bottom:10px">' +
      esc(t(desired.titleKey)) + '</div>' +
      '<div style="font-size:13.5px;line-height:1.75;color:#b8c7d8">' +
      esc(t(desired.bodyKey)) + '</div>' +
      '<div style="margin-top:16px;font-family:ui-monospace,Menlo,monospace;' +
      'font-size:11px;color:#7f97b0;word-break:break-all">' +
      esc(meta.join('  ·  ')) + '</div>' +
      '<div style="margin-top:20px;padding-top:14px;border-top:1px solid #24374e;' +
      'font-size:11px;color:#6a829c;line-height:1.6">' +
      esc(t('gt.footer')) + '</div>' +
      (desired.reapply
        ? '<div style="margin-top:16px"><button id="vdlGateReapply" ' +
          'style="background:#1b4470;border:1px solid #2d6299;color:#fff;' +
          'padding:8px 14px;border-radius:2px;cursor:pointer;font-size:12px">' +
          esc(t('gt.action.reapply')) + '</button></div>'
        : '') +
      '<div style="margin-top:16px;display:flex;align-items:center;gap:9px">' +
      '<label for="vdlGateLang" style="font-size:11px;color:#8fa5bd">' +
      esc(t('gt.language')) + '</label>' +
      '<select id="vdlGateLang" style="background:#0a1624;border:1px solid #24374e;' +
      'color:#e6edf5;padding:5px 8px;border-radius:2px;font-size:11.5px">' +
      langOptions() + '</select></div></div>';
    b.style.display = 'flex';
  }
  function show(titleKey, bodyKey, tone, meta, reapply, wipe) {
    desired = { titleKey: titleKey, bodyKey: bodyKey,
                tone: tone || 'blue', meta: meta || {},
                reapply: !!reapply };
    /* `wipe` is reserved for a real cut. A soft state must be reversible:
       hide() only removes the overlay, it cannot rebuild deleted nodes. */
    if (wipe) wipeBusinessDom();
    paint();
  }
  function hide() {
    desired = { hidden: true };
    var b = ensureBox();
    if (b) b.style.display = 'none';
    try { doc.documentElement.style.background = ''; } catch (e) {}
  }
  function revealWhenReady() {
    var done = function () {
      /* Two frames give V.init() time to finish its first render, so the
         card disappears only when the real UI is actually on screen. */
      try {
        global.requestAnimationFrame(function () {
          global.requestAnimationFrame(hide);
        });
      } catch (e) { hide(); }
    };
    if (doc.readyState === 'loading') {
      doc.addEventListener('DOMContentLoaded', done);
    } else {
      done();
    }
  }
  doc.addEventListener('DOMContentLoaded', paint);
  try { global.addEventListener('vdl:lang', paint); } catch (e) {}

  function getRid() {
    try { return global.sessionStorage.getItem(RID_KEY); } catch (e) { return null; }
  }
  function setRid(r) {
    try { global.sessionStorage.setItem(RID_KEY, r); } catch (e) {}
  }
  function clearRid() {
    try { global.sessionStorage.removeItem(RID_KEY); } catch (e) {}
  }
  function reloadCount() {
    try { return parseInt(global.sessionStorage.getItem(RELOAD_KEY) || '0', 10) || 0; }
    catch (e) { return 0; }
  }
  function setReloadCount(n) {
    try { global.sessionStorage.setItem(RELOAD_KEY, String(n)); } catch (e) {}
  }
  /* Hand-off between the gate document and the real terminal. Both draw the
     same opaque card, so approval looks like one continuous screen instead
     of "waiting -> blank -> waiting again". */
  function setEnteringFlag() {
    try { global.sessionStorage.setItem(ENTERING_KEY, '1'); } catch (e) {}
  }
  function clearEnteringFlag() {
    try { global.sessionStorage.removeItem(ENTERING_KEY); } catch (e) {}
  }
  function enteringFlag() {
    try { return global.sessionStorage.getItem(ENTERING_KEY) === '1'; }
    catch (e) { return false; }
  }
  function startPoll() {
    if (!timer) timer = global.setInterval(poll, POLL_MS);
  }
  function stopPoll() {
    if (timer) { global.clearInterval(timer); timer = null; }
  }

  function handle(j) {
    if (!j || !j.state) return;
    var s = j.state;
    if (s === 'LOCAL') { hide(); return; }
    if (s === 'GRANTED') {
      if (j.requestId) setRid(j.requestId);
      /* On the standalone gate page we must now fetch the REAL terminal:
         the approved cookie makes the server deliver it on reload. Guard
         against a reload loop if a proxy ever swallows that cookie. */
      if (GATE_PAGE) {
        /* Stop polling first. A poll in flight while Set-Cookie is being
           applied used to flip the gate back to a waiting state and, after
           a reload, submit a SECOND application for the same device. */
        stopPoll();
        /* Switch the card immediately and keep it opaque until the real
           terminal takes over. No blank frame, no second "waiting" card. */
        show('gt.title.granted', 'gt.body.granted', 'blue', {});
        setEnteringFlag();
        var n = reloadCount();
        if (n >= 2) {
          show('gt.title.granted', 'gt.body.granted', 'blue', {}, true);
          return;
        }
        setReloadCount(n + 1);
        /* Confirm the HttpOnly cookie is actually usable before leaving
           the gate. This read-only lookup never creates a new request. */
        global.fetch('/api/audit/status?rid=&dev=' +
                     encodeURIComponent(dev),
                     { credentials: 'same-origin' })
          .then(function (r) { return r.json(); })
          .then(function (st) {
            if (st && st.state === 'GRANTED') {
              global.location.replace(global.location.pathname);
            } else {
              clearEnteringFlag();
              setReloadCount(0);
              show('gt.title.pending', 'gt.body.pending', 'amber',
                   { requestId: getRid() || '' });
              startPoll();
            }
          })
          .catch(function () {
            clearEnteringFlag();
            setReloadCount(0);
            show('gt.title.pending', 'gt.body.pending', 'amber',
                 { requestId: getRid() || '' });
            startPoll();
          });
        return;
      }
      if (JUST_APPROVED) revealWhenReady();
      else hide();
      return;
    }
    if (s === 'PENDING') {
      if (j.requestId) setRid(j.requestId);
      setReloadCount(0);
      if (JUST_APPROVED) {
        /* Just approved a moment ago. Keep the loading card and keep
           polling; never redraw the waiting card (that was the "gate
           flashes again" symptom). Give up after 5 polls. */
        enteringPolls++;
        if (enteringPolls < 5) return;
        JUST_APPROVED = false;
      }
      show('gt.title.pending', 'gt.body.pending', 'amber',
           { requestId: j.requestId || '' });
      return;
    }
    if (s === 'REJECTED' || s === 'REVOKED' || s === 'EXPIRED' ||
        s === 'UNKNOWN') {
      hardCut(j.reason || s);
      return;
    }
  }

  function poll() {
    /* Read-only endpoint. With no request id the host looks the live
       cookie token up directly, so no audit record is written per poll. */
    global.fetch('/api/audit/status?rid=' +
                 encodeURIComponent(getRid() || '') +
                 '&dev=' + encodeURIComponent(dev),
                 { credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .then(handle)
      .catch(function () {
        show('gt.title.offline', 'gt.body.offline', 'amber', {});
      });
  }

  /* ---- cut: erase local state and destroy the JS context ------------- */
  var CUT_VIEWS = {
    REJECTED:        ['gt.title.rejected', 'gt.body.rejected'],
    UNKNOWN:         ['gt.title.unknown',  'gt.body.unknown'],
    EXPIRED:         ['gt.title.expired',  'gt.body.expired'],
    OUTSIDE_WINDOW:  ['gt.title.expired',  'gt.body.expired'],
    SESSION_LIMIT:   ['gt.title.expired',  'gt.body.expired'],
    DEVICE_MISMATCH: ['gt.title.expired',  'gt.body.expired'],
    TERMINAL_DENIED: ['gt.title.expired',  'gt.body.expired']
  };
  var cutDone = false;
  function cutView(reason) {
    var pair = CUT_VIEWS[reason] ||
               ['gt.title.revoked', 'gt.body.revoked'];
    return { titleKey: pair[0], bodyKey: pair[1] };
  }
  function cutReasonFromUrl() {
    try {
      return new URLSearchParams(global.location.search).get('cut') || '';
    } catch (e) { return ''; }
  }
  function hardCut(reason) {
    if (cutDone) return;
    cutDone = true;
    stopPoll();
    clearRid();
    clearEnteringFlag();
    var v = cutView(reason);
    /* 1. Drop the decrypted register mirror, buffered writes and timers. */
    try {
      if (global.VidlandStore && global.VidlandStore.purgeMemory)
        global.VidlandStore.purgeMemory();
    } catch (e) {}
    /* 2. Remove every business node and cover the viewport at once. */
    show(v.titleKey, v.bodyKey, 'red', { reason: reason }, GATE_PAGE, true);
    /* 3. Only navigating frees the JS heap (closures, the state projection,
          event handlers). The host now serves the content-free gate page,
          so the fresh document contains no register data at all. */
    if (!GATE_PAGE) {
      try {
        global.location.replace(global.location.pathname + '?cut=' +
                                encodeURIComponent(reason));
      } catch (e) {}
    }
  }
  function reapply() {
    try { global.history.replaceState(null, '', global.location.pathname); }
    catch (e) {}
    cutDone = false;
    clearRid();
    setReloadCount(0);
    boot();
  }
  function boot() {
    global.fetch('/api/audit/enter', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device: dev, terminal: terminal,
                             mode: LAUNCH_MODE })
    }).then(function (r) { return r.json(); }).then(function (j) {
      if (cutDone) return;
      if (j.state === 'LOCAL') { hide(); return; }  /* host itself: no gate */
      handle(j);
      if (!cutDone) startPoll();                   /* keep watching for a cut */
    }).catch(function () {
      if (cutDone) return;
      show('gt.title.offline', 'gt.body.offline', 'amber', {});
      startPoll();
    });
  }

  var enteringPolls = 0;
  var JUST_APPROVED = !GATE_PAGE && enteringFlag();
  if (GATE_PAGE) clearEnteringFlag();   /* never let a failed hand-off linger */
  if (JUST_APPROVED) {
    clearEnteringFlag();
    /* Match the gate page's dark background immediately, so the navigation
       never shows a white frame while the real terminal is parsing. */
    try { doc.documentElement.style.background = '#081420'; } catch (e) {}
    show('gt.title.granted', 'gt.body.granted', 'blue', {});
  }

  var initialCut = cutReasonFromUrl();
  if (initialCut) {
    /* Termination page: no enter request, no polling, no business markup.
       The operator cut access; re-applying is an explicit user action. */
    var cv = cutView(initialCut);
    show(cv.titleKey, cv.bodyKey, 'red', { reason: initialCut }, true, true);
  } else {
    boot();
  }
  /* A page restored from the back/forward cache must never bring a cut
     terminal back with live data or a stale authorisation. */
  try {
    global.addEventListener('pageshow', function (e) {
      if (e && e.persisted && (cutDone || cutReasonFromUrl()))
        global.location.reload();
    });
  } catch (e2) {}
})(window);
