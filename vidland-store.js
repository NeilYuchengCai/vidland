/* ============================================================
   GRAND DUCHY OF VIDLAND · Local-disk persistence shim
   ------------------------------------------------------------
   Replaces browser localStorage. The canonical copy of every
   "vdl.v1.*" key lives in a REAL FILE on the host machine
   (vidland-data/store.json, or whichever folder the operator
   grants). No browser storage holds the archive.

   Two backends, chosen automatically:

     • File System Access API  (Chrome / Edge served from
       http://localhost). Writes the file DIRECTLY to disk, so
       persistence no longer depends on any long-lived server
       process — the archive survives the static host being
       recycled. A one-time folder grant is requested on the
       first user gesture and remembered thereafter.
     • Fallback: serve.py /api/store  (used when FSA is
       unavailable — Firefox — or before the folder is granted).

   Reads go through a synchronous in-memory mirror; writes are
   async and debounced. Cross-terminal sync = re-reading the
   single shared file on disk.
   ============================================================ */
(function (global) {
  'use strict';

  var mem = {};                     /* synchronous in-memory mirror */
  var dirty = Object.create(null);  /* key -> {v: string|null, seq} */
  var seq = 0;
  var lastRev = '0';
  var flushTimer = null, pollTimer = null, externalCb = null;
  var flushing = false;

  var mode = 'memory';             /* 'xhr' | 'fsa' | 'memory' */
  var serverUp = false;
  var granting = false;

  /* ---- FSA state -------------------------------------------------- */
  var dirHandle = null;            /* FileSystemDirectoryHandle */
  var fileHandle = null;           /* FileSystemFileHandle (store.json) */
  var STORE_NAME = 'store.json';
  var DIR_KEY = 'vdl.fsa.dirhandle';
  var lastWrittenJSON = '';
  var lastSeenJSON = '';

  var readyPromise = null, readyResolve = null;
  function makeReady() {
    if (!readyPromise) readyPromise = new Promise(function (r) { readyResolve = r; });
    return readyPromise;
  }
  makeReady();

  function fsaAvailable() { return typeof global.showDirectoryPicker === 'function'; }
  function reapplyDirty() {
    Object.keys(dirty).forEach(function (k) {
      if (dirty[k].v === null) delete mem[k]; else mem[k] = dirty[k].v;
    });
  }

  /* ---- IndexedDB: remember the granted directory handle ------------ */
  function idb() {
    return new Promise(function (res, rej) {
      try {
        var r = indexedDB.open('vdl-fsa', 1);
        r.onupgradeneeded = function () { try { r.result.createObjectStore('kv'); } catch (e) {} };
        r.onsuccess = function () { res(r.result); };
        r.onerror = function () { rej(r.error || new Error('idb-open')); };
      } catch (e) { rej(e); }
    });
  }
  function idbPut(k, v) {
    return idb().then(function (db) {
      return new Promise(function (res, rej) {
        var tx = db.transaction('kv', 'readwrite');
        tx.objectStore('kv').put(v, k);
        tx.oncomplete = function () { res(); };
        tx.onerror = function () { rej(tx.error); };
      });
    }).catch(function () {});
  }
  function idbGet(k) {
    return idb().then(function (db) {
      return new Promise(function (res, rej) {
        var tx = db.transaction('kv', 'readonly');
        var rq = tx.objectStore('kv').get(k);
        rq.onsuccess = function () { res(rq.result); };
        rq.onerror = function () { rej(rq.error); };
      });
    }).catch(function () { return undefined; });
  }

  /* ---- synchronous XHR bootstrap (server present) ----------------- */
  function bootstrapServerSync() {
    try {
      var boot = new XMLHttpRequest();
      boot.open('GET', '/api/store', false);
      boot.send();
      if (boot.status === 200) {
        var data = JSON.parse(boot.responseText || '{}');
        if (data && typeof data === 'object') { mem = data; serverUp = true; mode = 'xhr'; }
        var br = boot.getResponseHeader('X-Rev');
        if (br) lastRev = br;
      }
    } catch (e) { serverUp = false; }
  }

  /* ---- FSA: read / write the shared file on disk ------------------ */
  function fsaReadRaw() {
    if (!fileHandle) return Promise.resolve(null);
    return fileHandle.getFile().then(function (f) { return f.text(); }).catch(function () { return null; });
  }
  function fsaWrite() {
    if (mode !== 'fsa' || !fileHandle) return Promise.resolve(false);
    var json = JSON.stringify(mem);
    return fileHandle.createWritable().then(function (w) {
      return w.write(json).then(function () { return w.close(); }).then(function () {
        lastWrittenJSON = json; return true;
      });
    }).catch(function () { return false; });
  }
  function fsaLoad() {
    if (!dirHandle) return Promise.resolve(false);
    return dirHandle.getFileHandle(STORE_NAME, { create: true }).then(function (fh) {
      fileHandle = fh;
      return fsaReadRaw();
    }).then(function (text) {
      if (text === null) return false;
      lastSeenJSON = text; lastWrittenJSON = text;
      try {
        var data = JSON.parse(text || '{}');
        if (data && typeof data === 'object') {
          /* On the very first grant the disk file may be empty while the
             in-memory mirror already holds data pulled from the server.
             Seed the (canonical) disk file with that data instead of
             clobbering memory with an empty file. */
          if (Object.keys(data).length === 0 && Object.keys(mem).length) {
            reapplyDirty();
            mode = 'fsa';
            fsaWrite();
            return true;
          }
          mem = data; reapplyDirty(); mode = 'fsa'; return true;
        }
      } catch (e) {}
      return false;
    }).catch(function () { return false; });
  }
  function fsaGrant() {
    if (!fsaAvailable() || granting) return Promise.resolve(false);
    granting = true;
    return Promise.resolve()
      .then(function () {
        return idbGet(DIR_KEY).then(function (h) {
          if (h) {
            try {
              return h.requestPermission({ mode: 'readwrite' }).then(function (p) {
                return p === 'granted' ? h : null;
              });
            } catch (e) { return null; }
          }
          return null;
        });
      })
      .then(function (h) {
        if (h) { dirHandle = h; return true; }
        /* Fall through to the picker — must run inside a user gesture. */
        return global.showDirectoryPicker({ mode: 'readwrite' }).then(function (h2) {
          dirHandle = h2; idbPut(DIR_KEY, h2); return true;
        }).catch(function () { return false; });
      })
      .then(function (ok) {
        granting = false;
        if (!ok) return false;
        return fsaLoad().then(function (loaded) {
          if (loaded) { startPolling(); if (externalCb) externalCb(); }
          return loaded;
        });
      })
      .catch(function () { granting = false; return false; });
  }

  /* ---- one-time auto-grant on the first user gesture -------------- */
  function armAutoGrant() {
    if (!fsaAvailable()) return;
    function once() {
      try { document.removeEventListener('pointerdown', once, true); } catch (e) {}
      try { document.removeEventListener('keydown', once, true); } catch (e) {}
      fsaGrant();
    }
    try {
      document.addEventListener('pointerdown', once, true);
      document.addEventListener('keydown', once, true);
    } catch (e) {}
  }

  /* ---- local change buffer ---------------------------------------- */
  function mark(k, v) {
    if (v === null) delete mem[k]; else mem[k] = v;
    dirty[k] = { v: v, seq: ++seq };
    scheduleFlush();
  }
  function scheduleFlush() { if (flushTimer) return; flushTimer = setTimeout(flush, 60); }

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
    if (mode === 'fsa' && fileHandle) {
      fsaWrite().then(finish).catch(function () { finish(false); });
    } else if (mode === 'xhr' && serverUp) {
      var payload = { vdl: 1, baseRev: lastRev, set: {}, del: [] };
      keys.forEach(function (k) {
        var d = dirty[k];
        snap[k] = d.seq;
        if (d.v === null) payload.del.push(k); else payload.set[k] = d.v;
      });
      try {
        var x = new XMLHttpRequest();
        x.open('PUT', '/api/store', true);
        x.setRequestHeader('Content-Type', 'application/json');
        x.onload = function () {
          var rv = x.getResponseHeader('X-Rev');
          finish(x.status >= 200 && x.status < 300);
          if (rv) lastRev = rv;
        };
        x.onerror = function () { finish(false); };
        x.ontimeout = function () { finish(false); };
        x.send(JSON.stringify(payload));
      } catch (e) { finish(false); }
    } else {
      finish(true); /* memory mode: nothing durable to write */
    }
  }

  /* ---- cross-terminal reload -------------------------------------- */
  function reload(done) {
    if (mode === 'fsa') {
      fsaReadRaw().then(function (text) {
        if (text !== null && text !== lastWrittenJSON) {
          try {
            var data = JSON.parse(text || '{}');
            if (data && typeof data === 'object') { mem = data; reapplyDirty(); lastSeenJSON = text; }
          } catch (e) {}
        }
        if (done) done();
      }).catch(function () { if (done) done(); });
      return;
    }
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

  function pollDisk() {
    if (mode !== 'fsa' || !fileHandle) return;
    fsaReadRaw().then(function (text) {
      if (text === null) return;
      if (text === lastWrittenJSON) { lastSeenJSON = text; return; } /* our own write */
      if (text === lastSeenJSON) return;                            /* no change */
      lastSeenJSON = text;
      try {
        var data = JSON.parse(text || '{}');
        if (data && typeof data === 'object') { mem = data; reapplyDirty(); if (externalCb) externalCb(); }
      } catch (e) {}
    }).catch(function () {});
  }
  function pollServerRev() {
    try {
      var x = new XMLHttpRequest();
      x.open('GET', '/api/store/rev', true);
      x.onload = function () {
        var rev = x.responseText;
        if (rev && rev !== lastRev) { lastRev = rev; reload(function () { if (externalCb) externalCb(); }); }
      };
      x.send();
    } catch (e) {}
  }
  function startPolling() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    if (mode === 'fsa') pollTimer = setInterval(pollDisk, 1000);
    else if (mode === 'xhr' && serverUp) pollTimer = setInterval(pollServerRev, 1000);
  }

  var Store = {
    getItem: function (k) { return Object.prototype.hasOwnProperty.call(mem, k) ? mem[k] : null; },
    setItem: function (k, v) { mark(k, String(v)); },
    removeItem: function (k) { mark(k, null); },
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
    },
    /* Wipe EVERYTHING. Synchronous so the file is cleared before we
       navigate away. Also purges any legacy localStorage vault. */
    reset: function () {
      mem = {}; dirty = Object.create(null);
      if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; }
      if (mode === 'fsa' && fileHandle) { try { fsaWrite(); } catch (e) {} }
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
      } catch (e) {}
    },
    startSync: function () { startPolling(); },
    onExternalChange: function (fn) { externalCb = fn; },
    whenReady: function () { return readyPromise; },
    ready: function () { return readyPromise; },
    refresh: refresh,
    /* Force the folder grant now (must be called from a user gesture). */
    requestGrant: function () { return fsaGrant(); },
    backend: function () { return mode; }
  };

  /* ---- bootstrap -------------------------------------------------- */
  bootstrapServerSync();
  if (fsaAvailable()) {
    idbGet(DIR_KEY).then(function (h) {
      if (h) {
        dirHandle = h;
        return fsaLoad().then(function (loaded) {
          if (loaded) startPolling();
          readyResolve(mem);
          if (loaded && externalCb) externalCb();
          if (!loaded) armAutoGrant();
        });
      }
      readyResolve(mem);
      armAutoGrant();
    }).catch(function () { readyResolve(mem); armAutoGrant(); });
  } else {
    readyResolve(mem);
    if (mode === 'xhr') startPolling();
  }

  global.VidlandStore = Store;
})(window);
