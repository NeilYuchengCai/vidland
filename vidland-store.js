/* ============================================================
   GRAND DUCHY OF VIDLAND · Shared-register persistence shim
   ------------------------------------------------------------
   Replaces browser localStorage. The single canonical copy of
   every "vdl.v1.*" key lives on the host in:

       vidland-data/store.json   (written by serve.py)

   Every terminal — desktop, phone, tablet, any browser — talks to
   /api/store over the SAME origin. Writes are key-level deltas
   ({vdl:1, baseRev, set, del}); a revision poll keeps all open
   pages in sync. No folder picker, no File System Access grant,
   no browser-side permission prompt, and no forked archive.

   Reads go through a synchronous in-memory mirror; writes are
   async and debounced. Three storage tiers, each with a narrower
   sharing scope than the one before it:

     store.json     shared by EVERY device and EVERY tab
     localStorage   shared by all tabs of ONE device / profile
     sessionStorage private to ONE tab

   Account, language and device id are device-local. The live
   inspection walk (runner snapshot plus its active/interrupted
   flags) is tab-local, so two tabs of the same terminal on one
   device never see or retire each other's progress. Only the
   "in progress" marker lives in the shared register, keyed by
   device + terminal + tab.
   ============================================================ */
(function (global) {
  'use strict';

  var mem = {};                     /* synchronous in-memory mirror */
  var dirty = Object.create(null);  /* key -> {v: string|null, seq} */
  var seq = 0;
  var lastRev = '0';
  var flushTimer = null, pollTimer = null, externalCb = null;
  var flushing = false;

  var mode = 'memory';             /* 'xhr' | 'memory' */
  var serverUp = false;

  /* ---- device tag on every register call ------------------------------
     All five terminals share this shim. Tagging /api/* requests lets the
     host recognise a device disabled by the audit authority, without
     imposing a token on the three civil terminals. The value is an opaque
     identifier, not a credential and not a token. */
  var DEVICE_KEY = 'vdl.v1.device.id';
  function deviceTag() {
    var id = null;
    try { id = global.localStorage.getItem(DEVICE_KEY); } catch (e) {}
    if (id) return id;
    var b = new Uint8Array(16);
    if (global.crypto && global.crypto.getRandomValues) {
      global.crypto.getRandomValues(b);
    } else {
      for (var i = 0; i < 16; i++) b[i] = Math.floor(Math.random() * 256);
    }
    var h = '';
    for (var j = 0; j < b.length; j++) h += ('0' + b[j].toString(16)).slice(-2);
    id = 'DEV-' + h.toUpperCase();
    try { global.localStorage.setItem(DEVICE_KEY, id); } catch (e) {}
    return id;
  }
  var DEVICE_TAG = deviceTag();
  var TERMINAL_TAG = (function (p) {
    if (p.indexOf('admin.html') >= 0) return 'admin';
    if (p.indexOf('entry.html') >= 0) return 'entry';
    if (p.indexOf('border.html') >= 0) return 'border';
    if (p.indexOf('interior.html') >= 0) return 'interior';
    return 'portal';
  })((global.location && global.location.pathname || '').toLowerCase());
  if (global.XMLHttpRequest &&
      !global.XMLHttpRequest.prototype.__vdlDevicePatched) {
    var _dOpen = global.XMLHttpRequest.prototype.open;
    var _dSend = global.XMLHttpRequest.prototype.send;
    global.XMLHttpRequest.prototype.open = function (m, u) {
      this.__vdlDeviceUrl = String(u || '');
      return _dOpen.apply(this, arguments);
    };
    global.XMLHttpRequest.prototype.send = function () {
      try {
        var u = this.__vdlDeviceUrl || '';
        if (u.charAt(0) === '/' && u.indexOf('/api/') === 0) {
          this.setRequestHeader('X-VDL-Device', DEVICE_TAG);
          this.setRequestHeader('X-VDL-Terminal', TERMINAL_TAG);
        }
      } catch (e) {}
      return _dSend.apply(this, arguments);
    };
    global.XMLHttpRequest.prototype.__vdlDevicePatched = true;
  }
  var hostResponded = false;       /* boot received an HTTP status at all */

  /* ---- key routing ---------------------------------------------------
     Checked in this order: tab-local, then device-local, then shared
     register. A tab-local key must never fall through to store.json —
     that is exactly what made two tabs (and two devices) inherit each
     other's half-finished inspection. */
  var LOCAL_KEY_RE = /^vdl\.v1\.(session|lang|lang\.beacon|device\.id|runner\.[A-Z]+\.graded)$/;
  var TAB_KEY_RE = /^vdl\.v1\.runner\.[A-Z]+(?:\.active|\.interrupted)?$/;
  function isLocalKey(k) { return LOCAL_KEY_RE.test(k); }
  function isTabKey(k) { return TAB_KEY_RE.test(k); }
  function localGet(k) {
    try { return global.localStorage.getItem(k); } catch (e) { return null; }
  }
  function localSet(k, v) {
    try { global.localStorage.setItem(k, v); } catch (e) {}
  }
  function localRemove(k) {
    try { global.localStorage.removeItem(k); } catch (e) {}
  }
  function tabGet(k) {
    try { return global.sessionStorage.getItem(k); } catch (e) { return null; }
  }
  function tabSet(k, v) {
    try { global.sessionStorage.setItem(k, v); } catch (e) {}
  }
  function tabRemove(k) {
    try { global.sessionStorage.removeItem(k); } catch (e) {}
  }
  /* clearPrefix()/reset() must reach every tier. Only keys owned by this
     shim are swept; anything else in browser storage is left alone. */
  function scopedKeys(store, match) {
    var out = [];
    try {
      for (var i = 0; i < store.length; i++) {
        var k = store.key(i);
        if (k && match(k)) out.push(k);
      }
    } catch (e) {}
    return out;
  }
  function localKeys() {
    return scopedKeys(global.localStorage, function (k) { return k.indexOf('vdl.v1.') === 0; });
  }
  function tabKeys() {
    return scopedKeys(global.sessionStorage, function (k) { return k.indexOf('vdl.v1.') === 0; });
  }

  /* ---- connection status notices -------------------------------------- */
  var noticeState = { offline: 0, conflict: 0, wasOffline: false };
  var pendingOfflineNotice = false;
  /* Set by Vault.mutate() only. A state snapshot produced by replaying the
     event log is equivalent on every terminal and may safely be last-writer-
     wins; a discretionary Authority edit must be guarded against being
     overwritten by a stale revision. */
  var stateGuard = false;
  function lex(key, fallback) {
    try {
      var I = global.VidlandI18N;
      if (I && I.has && I.has(key)) return I.t(key);
    } catch (e) {}
    return fallback;
  }
  function showNotice(text, kind) {
    try {
      if (global.Vidland && global.Vidland.toast) global.Vidland.toast(text, kind);
    } catch (e) {}
    try {
      global.dispatchEvent(new CustomEvent('vdl:sync', {
        detail: { kind: kind, text: text, pending: Object.keys(dirty).length }
      }));
    } catch (e) {}
  }
  function notifyStatus(kind) {
    var n = Date.now();
    /* Publish the raw signal on EVERY detection, without throttling. The
       inspection runner must hear about a broken connection even when the
       visible toast is being rate-limited. */
    try {
      global.dispatchEvent(new CustomEvent('vdl:sync',
        { detail: { kind: kind, signal: true } }));
    } catch (e) {}
    if (kind === 'offline') {
      if (n - noticeState.offline < 20000) return;
      noticeState.offline = n;
      noticeState.wasOffline = true;
      showNotice(lex('x.syncOffline', '与登记处的连接已中断，本次变更尚未写入存档，请勿关闭页面。'), 'bad');
    } else if (kind === 'conflict') {
      if (n - noticeState.conflict < 8000) return;
      noticeState.conflict = n;
      showNotice(lex('x.syncConflict', '另一台终端已更新登记册，本次修改未保存，请刷新后重试。'), 'bad');
    } else if (kind === 'denied') {
      /* The host answered but refused the write (permission, throttling,
         bad request). The connection is alive, so this must NOT be reported
         as an outage: the inspection runner treats an offline signal as an
         interrupted check and would fail it. */
      showNotice(lex('x.syncDenied',
        '登记处拒绝了本次写入，变更仍保留在本页，请稍后重试。'), 'bad');
    } else if (kind === 'online' && noticeState.wasOffline) {
      noticeState.wasOffline = false;
      showNotice(lex('x.syncRestored', '与登记处的连接已恢复，未提交的变更正在补写。'), 'good');
    }
  }

  var readyPromise = null, readyResolve = null;
  readyPromise = new Promise(function (r) { readyResolve = r; });

  function reapplyDirty() {
    Object.keys(dirty).forEach(function (k) {
      if (dirty[k].v === null) delete mem[k]; else mem[k] = dirty[k].v;
    });
  }

  /* ---- synchronous XHR bootstrap (server present) ----------------- */
  function bootstrapServerSync() {
    try {
      var boot = new XMLHttpRequest();
      boot.open('GET', '/api/store', false);
      boot.send();
      hostResponded = boot.status > 0;
      if (boot.status === 200) {
        var data = JSON.parse(boot.responseText || '{}');
        if (data && typeof data === 'object' && !Array.isArray(data)) {
          mem = data; serverUp = true; mode = 'xhr';
        }
        var br = boot.getResponseHeader('X-Rev');
        if (br) lastRev = br;
      }
    } catch (e) { serverUp = false; }
    /* Only a genuine transport failure is an outage. An HTTP 4xx/5xx means
       the host is up and answered; keep probing, but never fire the offline
       signal, which the inspection runner interprets as an interrupted
       check. This also removes the spurious "connection lost" toast. */
    if (!serverUp && !hostResponded) pendingOfflineNotice = true;
  }

  /* ---- local change buffer ---------------------------------------- */
  function mark(k, v) {
    if (v === null) delete mem[k]; else mem[k] = v;
    dirty[k] = { v: v, seq: ++seq };
    scheduleFlush();
  }
  /* With no durable backend, retry slowly instead of spinning every 60 ms;
     buffered changes are kept so they can be replayed after a reconnect. */
  function scheduleFlush() {
    if (flushTimer) return;
    flushTimer = setTimeout(flush, (mode === 'memory' && !serverUp) ? 1000 : 60);
  }

  /* ---- real-time flush (async, non-blocking) ---------------------- */
  function flush() {
    flushTimer = null;
    if (flushing) { scheduleFlush(); return; }
    var keys = Object.keys(dirty);
    if (!keys.length) return;
    var snap = {};
    keys.forEach(function (k) { snap[k] = dirty[k].seq; });
    flushing = true;
    function finish(ok) {
      flushing = false;
      if (ok) {
        keys.forEach(function (k) { if (dirty[k] && dirty[k].seq === snap[k]) delete dirty[k]; });
      }
      if (Object.keys(dirty).length) scheduleFlush();
    }
    if (mode === 'xhr' && serverUp) {
      var payload = { vdl: 1, baseRev: lastRev, set: {}, del: [] };
      keys.forEach(function (k) {
        var d = dirty[k];
        snap[k] = d.seq;
        if (d.v === null) payload.del.push(k); else payload.set[k] = d.v;
      });
      if (stateGuard && Object.prototype.hasOwnProperty.call(payload.set, 'vdl.v1.state')) {
        payload.guard = true;
      }
      try {
        var x = new XMLHttpRequest();
        x.open('PUT', '/api/store', true);
        x.setRequestHeader('Content-Type', 'application/json');
        x.onload = function () {
          var rv = x.getResponseHeader('X-Rev');
          if (rv) lastRev = rv;
          if (x.status === 409) {
            /* A newer register exists. Never overwrite it with an older
               encrypted state snapshot; keep every independent key (event
               envelopes, drafts) queued for the next flush instead. */
            if (Object.prototype.hasOwnProperty.call(payload.set, 'vdl.v1.state')) {
              delete dirty['vdl.v1.state'];
            }
            finish(false);
            reload(function () {
              try { global.dispatchEvent(new Event('vdl:refresh')); } catch (e) {}
              if (externalCb) externalCb();
            });
            notifyStatus('conflict');
            return;
          }
          var ok = x.status >= 200 && x.status < 300;
          finish(ok);
          if (ok) { stateGuard = false; notifyStatus('online'); }
          else if (!x.status) notifyStatus('offline');
          else notifyStatus('denied');
        };
        x.onerror = function () { finish(false); notifyStatus('offline'); };
        x.ontimeout = function () { finish(false); notifyStatus('offline'); };
        x.send(JSON.stringify(payload));
      } catch (e) { finish(false); notifyStatus('offline'); }
    } else {
      /* No durable backend yet. KEEP the changes buffered so they can be
         written if the server comes back while this page is still open. */
      finish(false);
      notifyStatus(hostResponded ? 'denied' : 'offline');
    }
  }

  /* ---- cross-terminal reload -------------------------------------- */
  function reload(done) {
    try {
      var x = new XMLHttpRequest();
      x.open('GET', '/api/store', true);
      x.onload = function () {
        if (x.status === 200) {
          try {
            var data = JSON.parse(x.responseText || '{}');
            if (data && typeof data === 'object' && !Array.isArray(data)) {
              mem = data; reapplyDirty();
              var rv = x.getResponseHeader('X-Rev');
              if (rv) lastRev = rv;
            }
          } catch (e) {}
        }
        if (done) done();
      };
      x.onerror = function () { if (done) done(); };
      x.ontimeout = function () { if (done) done(); };
      x.send();
    } catch (e) { if (done) done(); }
  }
  function refresh() { return new Promise(function (resolve) { reload(resolve); }); }

  function pollServerRev() {
    try {
      var x = new XMLHttpRequest();
      x.open('GET', '/api/store/rev', true);
      x.timeout = 3000;
      x.onload = function () {
        /* 403 means the host has cut or blocked this device. Wipe the local
           mirror immediately; a cut is never an outage (the offline signal
           would fail a running inspection), so no offline notice here. */
        if (x.status === 403) { purgeMemory(); return; }
        /* A non-200 with a real status means the host answered. It is not
           a broken connection, so neither an outage toast nor an inspection
           interruption should be produced; just wait for the next poll. */
        if (x.status && x.status !== 200) return;
        var rev = x.responseText;
        if (rev && rev !== lastRev) { lastRev = rev; reload(function () { if (externalCb) externalCb(); }); }
      };
      /* A dead server must be reported even when nothing is being written:
         the revision poll is the only traffic an idle terminal produces. */
      x.onerror = function () { notifyStatus('offline'); };
      x.ontimeout = function () { notifyStatus('offline'); };
      x.send();
    } catch (e) {}
  }
  /* The server may have been started AFTER this page was opened. Keep
     probing gently so a terminal that booted in memory mode reconnects on
     its own instead of staying silently detached forever. */
  function probeReconnect() {
    if (mode === 'xhr') return;
    try {
      var x = new XMLHttpRequest();
      x.open('GET', '/api/store/rev', true);
      x.timeout = 1500;
      x.onload = function () {
        if (x.status !== 200) return;
        /* A state snapshot produced while the register was empty must not
           be replayed over the real register after reconnecting. */
        delete dirty['vdl.v1.state'];
        serverUp = true;
        mode = 'xhr';
        lastRev = x.responseText || '0';
        reload(function () {
          notifyStatus('online');
          try { global.dispatchEvent(new Event('vdl:refresh')); } catch (e) {}
          if (externalCb) externalCb();
        });
        startPolling();
      };
      x.send();
    } catch (e) {}
  }
  function startPolling() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    if (mode === 'xhr' && serverUp) pollTimer = setInterval(pollServerRev, 1000);
    else pollTimer = setInterval(probeReconnect, 2000);
  }

  /* ---- local erasure when access is cut ------------------------------
     A cut token must not leave the decrypted register sitting in JS memory
     while the page is still open. Drop the mirror, the pending write buffer
     and every timer; listeners then clear the rendered DOM. This is a
     client-side erasure only — a subsequent navigation destroys the whole
     JS context, which is what actually frees the retained objects. */
  /* A cut must reach EVERY tab of this origin, not just the one that
     happened to receive the 403. BroadcastChannel is event-driven (no
     timer, no heartbeat), so it does not interfere with inspection rules. */
  var cutChannel = null;
  try {
    if (global.BroadcastChannel) {
      cutChannel = new global.BroadcastChannel('vdl-audit-cut');
      cutChannel.onmessage = function (e) {
        if (e && e.data && e.data.type === 'cut') purgeMemory(false);
      };
    }
  } catch (e) {}
  function broadcastCut() {
    try {
      if (cutChannel) cutChannel.postMessage({ type: 'cut', at: Date.now() });
    } catch (e) {}
  }
  function purgeMemory(broadcast) {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; }
    mem = {};
    dirty = Object.create(null);
    serverUp = false;
    mode = 'memory';
    pendingOfflineNotice = false;
    hostResponded = false;
    if (broadcast !== false) broadcastCut();
    try {
      global.dispatchEvent(new CustomEvent('vdl:purge',
        { detail: { reason: 'ACCESS_CUT' } }));
    } catch (e) {}
  }

  var Store = {
    getItem: function (k) {
      if (isTabKey(k)) return tabGet(k);
      if (isLocalKey(k)) {
        var v = localGet(k);
        /* One-time migration for the account and language preference only.
           A runner snapshot describes a walk in progress on SOME OTHER
           device; inheriting it would hand this terminal somebody else's
           inspection. Leave those legacy shared keys as harmless orphans. */
        var migratable = (k === 'vdl.v1.session' || k === 'vdl.v1.lang');
        if (v === null && migratable && Object.prototype.hasOwnProperty.call(mem, k)) {
          v = mem[k];
          localSet(k, v);
        }
        return v === undefined ? null : v;
      }
      return Object.prototype.hasOwnProperty.call(mem, k) ? mem[k] : null;
    },
    setItem: function (k, v) {
      if (isTabKey(k)) { tabSet(k, String(v)); return; }
      if (isLocalKey(k)) { localSet(k, String(v)); return; }
      mark(k, String(v));
    },
    removeItem: function (k) {
      if (isTabKey(k)) { tabRemove(k); return; }
      if (isLocalKey(k)) { localRemove(k); return; }
      mark(k, null);
    },
    key: function (i) {
      var ks = Object.keys(mem);
      return (i >= 0 && i < ks.length) ? ks[i] : null;
    },
    get length() { return Object.keys(mem).length; },
    keys: function () { return Object.keys(mem); },
    clearPrefix: function (prefix) {
      Object.keys(mem).forEach(function (k) {
        if (k.indexOf(prefix) === 0) mark(k, null);
      });
      localKeys().forEach(function (k) {
        if (k.indexOf(prefix) === 0) localRemove(k);
      });
      tabKeys().forEach(function (k) {
        if (k.indexOf(prefix) === 0) tabRemove(k);
      });
    },
    /* Wipe EVERYTHING. Synchronous so the file is cleared before we
       navigate away. Also purges any legacy localStorage vault. */
    reset: function () {
      mem = {}; dirty = Object.create(null);
      if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; }
      if (serverUp) {
        try {
          var x = new XMLHttpRequest();
          x.open('POST', '/api/store/reset', false);
          x.send();
          var rv = x.getResponseHeader('X-Rev');
          if (rv) lastRev = rv;
        } catch (e) {}
      }
      try {
        if (global.localStorage) {
          for (var i = global.localStorage.length - 1; i >= 0; i--) {
            var k = global.localStorage.key(i);
            if (k && k.indexOf('vdl.v1.') === 0) global.localStorage.removeItem(k);
          }
        }
        if (global.sessionStorage) {
          for (var j = global.sessionStorage.length - 1; j >= 0; j--) {
            var sk = global.sessionStorage.key(j);
            if (sk && sk.indexOf('vdl.v1.') === 0) global.sessionStorage.removeItem(sk);
          }
        }
      } catch (e) {}
    },
    startSync: function () {
      if (pendingOfflineNotice) { pendingOfflineNotice = false; notifyStatus('offline'); }
      startPolling();
    },
    onExternalChange: function (fn) { externalCb = fn; },
    whenReady: function () { return readyPromise; },
    ready: function () { return readyPromise; },
    refresh: refresh,
    /* Retained for older callers. The folder grant is gone: the host writes
       vidland-data/store.json directly, so there is nothing to authorise. */
    requestGrant: function () { return Promise.resolve(true); },
    backend: function () { return mode; },
    /* Diagnostics used by the inspection runner so a locally generated
       result is never presented as already filed with the Authority. */
    isOnline: function () { return !!serverUp; },
    purgeMemory: purgeMemory,
    pendingWrites: function () { return Object.keys(dirty).length; },
    setStateGuard: function (on) { stateGuard = !!on; }
  };

  /* ---- bootstrap -------------------------------------------------- */
  bootstrapServerSync();
  readyResolve(mem);
  startPolling();

  global.VidlandStore = Store;
})(window);
