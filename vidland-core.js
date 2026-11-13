/* ============================================================
   GRAND DUCHY OF VIDLAND · Chancellery Core  v1.0
   Grand Ducal Chancellery of Civil Affairs — sealed build
   ------------------------------------------------------------
   ARCHITECTURE (authoritative):
     * Three terminals (Civil Portal, Frontier, Interior) hold ONLY
       the Chancellery PUBLIC key. They seal submissions to the
       Authority alone. They never address one another.
     * The Authority (admin.html) alone holds the RSA private key
       and is the only party able to open a submission payload.
     * The Chancellery Relay performs deterministic registration of
       routing envelopes and broadcasts the canonical register over
       an AES-GCM sealed channel. Every terminal reads ONLY this
       broadcast. No terminal-to-terminal channel exists.
     * Ciphertext at rest: localStorage holds no plaintext PII.
   ============================================================ */
(function (global) {
  'use strict';

  var I = global.VidlandI18N;
  var t = I.t, L = I.L;
  /* Persistence now lives in a real file on the host (see vidland-store.js).
     Fall back to localStorage only if the shim failed to load. */
  var LS = global.VidlandStore || global.localStorage;
  var enc = new TextEncoder(), dec = new TextDecoder();
  var subtle = global.crypto && global.crypto.subtle;

  /* ------------------------------------------------------------
     0 · Constants — the high-strength fixed Chancellery material
     ------------------------------------------------------------ */
  var PUBLIC_JWK = {
    kty: "RSA",
    n: "txFC9dhh72jmh4xdiKKqMVY3PxjKWxVt4cxNixUiPAklJ8bKDbfAPkgr2B1D-Akh0nDqnYsPItbdVt7DyEVCNVMhBMZejStd0u2z2VIa57Ci3SBqB_p0sWNLRIE4bG6_0d6GGHdPzSx3OpfkCqpqUz7jY9xhYP_Ww8tizZTgR21HA2hacTbjF1BkbyEpDNRg-niOxWBc1zrELjTVCpxGtcWuwri15T-_KrKWadq1MoAF6iM1qHuZ33BR9s_IjLFHdQQs6NQcK0XksHDLFZyA5Y9fF1L7Tmq9XcQtIvjpS_DGMEVOMCtdZUsUZDJxTh22IoSEaufsYqmwkHegDLlJ4w",
    e: "AQAB"
  };
  /* The broadcast seed is no longer shipped with this script. The host
     issues it over the authenticated /api/vault/seed channel, so an
     unapproved device (and the repository) never holds it. vdl:purge
     clears it from memory when access is cut. */
  var BROADCAST_SEED = null;
  var _seedReady = null, _seedPurged = false;
  function fetchBroadcastSeed() {
    /* Asynchronous on purpose: a synchronous XHR here blocks parsing and
       rendering of the whole terminal right after an approval, which is
       exactly the visible stutter. Every consumer of the seed is async
       (sealBroadcast / openBroadcast), so awaiting this promise is enough. */
    try {
      _seedReady = global.fetch('/api/vault/seed',
        { credentials: 'same-origin' })
        .then(function (r) { return r.json(); })
        .then(function (j) {
          if (!_seedPurged && j && j.ok && j.seed) BROADCAST_SEED = j.seed;
        })
        .catch(function () {});
    } catch (e) {
      _seedReady = Promise.resolve();
    }
  }
  fetchBroadcastSeed();
  var SALT = enc.encode("VDL::GRAND-DUCAL-CHANCELLERY::CIVIL-REGISTER::v1::SALT::5f2a91");
  var PORT = 7431;

  var K = {
    STATE:  'vdl.v1.state',
    INBOX:  'vdl.v1.inbox',       /* legacy single-array key, migrated on read */
    LANG:   'vdl.v1.lang',
    SESSION:'vdl.v1.session',
    DRAFT:  'vdl.v1.draft.'
  };
  /* Each routing envelope is stored under its own key. Two terminals
     lodging a petition at the same instant can no longer overwrite one
     another's entry in a shared inbox array. */
  var ENV_PREFIX = 'vdl.v1.env.';
  /* One "in progress" marker per device + terminal + TAB. It is written
     when an inspection starts and removed only when a finding is submitted.
     If that tab is reloaded after an interruption, its marker is still there
     and is turned into a FAIL finding. No timers are involved: as long as
     the server is up and the page stays connected, a walk may take as long
     as it needs. */
  var ACTIVE_PREFIX = 'vdl.v1.insp.active.';
  var DEVICE_KEY = 'vdl.v1.device.id';
  function deviceId() {
    var v = null;
    try { v = global.localStorage.getItem(DEVICE_KEY); } catch (e) {}
    if (!v) {
      v = uid('DEV');
      try { global.localStorage.setItem(DEVICE_KEY, v); } catch (e) {}
    }
    return v;
  }

  /* ---- tab identity --------------------------------------------------
     A tab id lives in sessionStorage: private to this tab, retained across
     a reload (so a reload is still recognised as an interruption) and gone
     when the tab closes. Two tabs of the same station on one device get two
     different ids and therefore two independent walks. */
  var TAB_KEY = 'vdl.v1.tab.id';
  var TAB_ALIVE_PREFIX = 'vdl.v1.tab.alive.';
  function tabId() {
    var v = null;
    try { v = global.sessionStorage.getItem(TAB_KEY); } catch (e) {}
    if (!v) {
      v = uid('TAB');
      try { global.sessionStorage.setItem(TAB_KEY, v); } catch (e) {}
    }
    return v;
  }
  /* One localStorage key per live tab, so concurrent tabs never overwrite
     one another's presence flag. These are lifecycle events (mount /
     pagehide), not a heartbeat and not a timeout: a walk may run
     indefinitely while its tab stays open. */
  function tabAliveKey(tid) { return TAB_ALIVE_PREFIX + deviceId() + '.' + tid; }
  function tabRegister(tid) {
    try { global.localStorage.setItem(tabAliveKey(tid), '1'); } catch (e) {}
  }
  function tabUnregister(tid) {
    try { global.localStorage.removeItem(tabAliveKey(tid)); } catch (e) {}
  }
  function tabAlive(tid) {
    try { return global.localStorage.getItem(tabAliveKey(tid)) === '1'; } catch (e) { return false; }
  }

  /* ------------------------------------------------------------
     1 · Encoding helpers
     ------------------------------------------------------------ */
  function u8b64(u8) {
    var s = '';
    for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return btoa(s);
  }
  function b64u8(s) {
    var bin = atob(s), u8 = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return u8;
  }
  function rand(n) {
    var a = new Uint8Array(n); global.crypto.getRandomValues(a);
    var s = '';
    for (var i = 0; i < n; i++) s += '0123456789ABCDEFGHJKLMNPQRSTUVWXYZ'[a[i] % 34];
    return s;
  }
  function code(prefix) { return prefix + '-' + rand(4) + '-' + rand(4) + '-' + rand(2); }
  function uid(p) { return (p || 'ID') + '-' + Date.now().toString(36).toUpperCase() + '-' + rand(5); }
  function now() { return Date.now(); }

  /* ------------------------------------------------------------
     2 · Cryptography
     ------------------------------------------------------------ */
  var _pubKey = null, _broadcastKey = null;

  function pubKey() {
    if (!_pubKey) {
      _pubKey = subtle.importKey('jwk', PUBLIC_JWK,
        { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    }
    return _pubKey;
  }

  function broadcastKey() {
    if (!_broadcastKey) {
      _broadcastKey = (async function () {
        if (_seedReady) await _seedReady;
        if (!BROADCAST_SEED) throw new Error('Broadcast seed not issued by host');
        var base = await subtle.importKey('raw', enc.encode(BROADCAST_SEED),
          { name: 'PBKDF2' }, false, ['deriveKey']);
        return subtle.deriveKey(
          { name: 'PBKDF2', salt: SALT, iterations: 180000, hash: 'SHA-256' },
          base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
      })();
    }
    return _broadcastKey;
  }

  async function sealBroadcast(obj) {
    var key = await broadcastKey();
    var iv = global.crypto.getRandomValues(new Uint8Array(12));
    var ct = await subtle.encrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 },
      key, enc.encode(JSON.stringify(obj)));
    return { v: 1, alg: 'A256GCM/PBKDF2-SHA256', iv: u8b64(iv), ct: u8b64(new Uint8Array(ct)) };
  }

  async function openBroadcast(env) {
    if (!env || !env.ct) return null;
    var key = await broadcastKey();
    var plain = await subtle.decrypt({ name: 'AES-GCM', iv: b64u8(env.iv), tagLength: 128 },
      key, b64u8(env.ct));
    return JSON.parse(dec.decode(plain));
  }

  /* Hybrid envelope: AES-256-GCM payload + RSA-OAEP-2048 wrapped key.
     Only the holder of the Chancellery private key can open this. */
  async function sealForChancellery(obj) {
    var pub = await pubKey();
    var aes = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    var raw = new Uint8Array(await subtle.exportKey('raw', aes));
    var iv = global.crypto.getRandomValues(new Uint8Array(12));
    var ct = await subtle.encrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 },
      aes, enc.encode(JSON.stringify(obj)));
    var ek = await subtle.encrypt({ name: 'RSA-OAEP' }, pub, raw);
    return {
      v: 1, alg: 'RSA-OAEP-2048/SHA256 + AES-256-GCM',
      ek: u8b64(new Uint8Array(ek)), iv: u8b64(iv), ct: u8b64(new Uint8Array(ct))
    };
  }

  /* Registered by admin.html, which alone possesses the private JWK. */
  var _authorityOpener = null;
  function registerAuthorityOpener(fn) { _authorityOpener = fn; }
  async function openForChancellery(env) {
    if (!_authorityOpener) throw new Error('Master key not present on this terminal');
    return _authorityOpener(env);
  }

  async function digestHex(obj) {
    var buf = await subtle.digest('SHA-256', enc.encode(JSON.stringify(obj)));
    var a = new Uint8Array(buf), s = '';
    for (var i = 0; i < a.length; i++) s += ('0' + a[i].toString(16)).slice(-2);
    return s;
  }

  /* ------------------------------------------------------------
     3 · Encrypted local storage + sealed realtime channel
     ------------------------------------------------------------ */
  var CHANNEL = null;
  try { CHANNEL = new BroadcastChannel('vdl.chancellery.relay'); } catch (e) { }
  var listeners = [];
  var TERMINAL = 'UNSPECIFIED';
  function terminalId() { return TERMINAL; }
  function setTerminal(id) { TERMINAL = id; }

  function rawGet(k, fallback) {
    try {
      var v = LS.getItem(k);
      return v === null ? fallback : JSON.parse(v);
    } catch (e) { return fallback; }
  }
  function rawSet(k, v) {
    try { LS.setItem(k, JSON.stringify(v)); return true; }
    catch (e) { console.error('[Vault] storage write failed', e); return false; }
  }
  function announce(origin) {
    var msg = { at: now(), origin: origin || TERMINAL, nonce: rand(6) };
    try { if (CHANNEL) CHANNEL.postMessage(msg); } catch (e) { }
    try { LS.setItem('vdl.v1.beacon', JSON.stringify(msg)); } catch (e) { }
  }
  function on(fn) { listeners.push(fn); }
  function fire() { listeners.forEach(function (f) { try { f(); } catch (e) { console.warn(e); } }); }

  if (CHANNEL) CHANNEL.onmessage = function () { fire(); };
  /* Cross-terminal real-time sync now comes from the on-disk register
     (vidland-store.js polls the server revision) instead of the storage
     event, since the register is no longer kept in LS. */
  global.addEventListener('vdl:refresh', fire);

  function blankState() {
    return {
      v: 1, createdAt: now(),
      subjects: {}, applications: [], decisions: [], leaps: [],
      inspections: [], certificates: [], oaths: [], notices: {}, pending: {},
      protocol: { R: [], Z: [], A: [], M: [] },
      ledger: [], processed: {},
      counters: { app: 0, cert: 0, insp: 0, leap: 0, oath: 0, subject: 0 },
      config: { port: PORT }
    };
  }

  /* ---- routing envelopes: one key per event ----------------------------
     Legacy builds kept a single array under vdl.v1.inbox. Migrate it once
     into independent keys, then retire the array. Envelope ids are unique,
     so concurrent terminals can migrate safely at the same time. */
  function readInbox() {
    var legacy = null;
    try { legacy = rawGet(K.INBOX, null); } catch (e) {}
    if (legacy && Array.isArray(legacy) && legacy.length) {
      legacy.forEach(function (e) { if (e && e.id) rawSet(ENV_PREFIX + e.id, e); });
      try { LS.removeItem(K.INBOX); } catch (e) {}
    }
    var keys = [];
    try {
      if (LS.keys) keys = LS.keys();
      else for (var j = 0; j < LS.length; j++) { var k = LS.key(j); if (k) keys.push(k); }
    } catch (e) {}
    var out = [];
    keys.forEach(function (k) {
      if (k.indexOf(ENV_PREFIX) !== 0) return;
      var env = rawGet(k, null);
      if (env && env.id) out.push(env);
    });
    out.sort(function (a, b) { return (a.at || 0) - (b.at || 0); });
    return out;
  }

  /* Replaying an envelope twice must never duplicate a register entry.
     This matters when a terminal's state snapshot briefly lags behind: the
     event log is authoritative and will simply be replayed. */
  function alreadyApplied(state, ev) {
    switch (ev.type) {
      case 'APPLICATION':   return (state.applications || []).some(function (a) { return a.id === ev.id; });
      case 'LEAP':          return (state.leaps || []).some(function (a) { return a.id === ev.id; });
      case 'INSPECTION':    return (state.inspections || []).some(function (a) { return a.certCode === ev.certCode; });
      case 'IDENTITY_CERT': return (state.certificates || []).some(function (a) { return a.code === ev.certCode; });
      case 'OATH':          return (state.oaths || []).some(function (a) { return a.id === ev.id; });
      default: return false;   /* STAGE_INIT is idempotent (addPending dedupes) */
    }
  }

  async function readState() {
    var env = rawGet(K.STATE, null);
    if (!env) return blankState();
    try {
      var s = await openBroadcast(env);
      if (!s) return blankState();
      /* Older builds stored the action verb "APPROVE" as a status while the
         route state machine checks "APPROVED". Normalise on read so existing
         registers recover the oath / granted phase without a reset. */
      var fixed = false;
      (s.applications || []).forEach(function (a) {
        if (a.status === 'APPROVE') { a.status = 'APPROVED'; fixed = true; }
        if (a.status === 'REJECT') { a.status = 'REJECTED'; fixed = true; }
      });
      (s.leaps || []).forEach(function (l) {
        if (l.status === 'APPROVE') { l.status = 'APPROVED'; fixed = true; }
        if (l.status === 'REJECT') { l.status = 'REJECTED'; fixed = true; }
      });
      if (fixed) await writeState(s);
      return s;
    } catch (e) { return blankState(); }
  }
  async function writeState(s) {
    var env = await sealBroadcast(s);
    rawSet(K.STATE, env);
    return env;
  }

  function ledger(state, actor, key, vars) {
    state.ledger.push({ at: now(), actor: actor, event: t(key, vars) });
    if (state.ledger.length > 800) state.ledger = state.ledger.slice(-800);
  }
  function notice(state, ref, kind, data) {
    if (!ref) return;
    if (!state.notices[ref]) state.notices[ref] = [];
    state.notices[ref].push({ id: uid('NTC'), kind: kind, at: now(), data: data || {} });
  }
  function addPending(state, ref, level, purpose) {
    if (!ref || !level) return;
    if (!state.pending[ref]) state.pending[ref] = [];
    var exists = state.pending[ref].some(function (p) {
      return p.level === level && p.purpose === purpose && !p.done;
    });
    if (!exists) state.pending[ref].push({ id: uid('PND'), level: level, purpose: purpose, at: now(), done: false });
  }
  function clearPending(state, ref, level, purpose) {
    if (!state.pending[ref]) return;
    state.pending[ref].forEach(function (p) {
      if ((!level || p.level === level) && (!purpose || p.purpose === purpose)) p.done = true;
    });
  }

  /* ------------------------------------------------------------
     4 · The Chancellery Relay — deterministic registration only
     ------------------------------------------------------------ */
  function applyEvent(state, ev, inboxId) {
    switch (ev.type) {
      case 'APPLICATION': {
        var a = {
          id: ev.id, ref: ev.ref, stage: ev.stage, round: ev.round || 1,
          lodgedAt: ev.at, status: 'LODGED', reason: null, decidedAt: null,
          certRefs: ev.certRefs || [], inboxId: inboxId,
          subjectName: ev.identity && ev.identity.name || ''
        };
        state.applications.push(a);
        state.counters.app++;
        /* Identity particulars are entered at lodgement so that inspection
           terminals can verify the bearer against the central register. */
        if (ev.identity) {
          if (!state.subjects[ev.ref]) {
            state.subjects[ev.ref] = {
              ref: ev.ref, createdAt: now(), identity: ev.identity,
              credential: 'NONE', credentialCode: null, credentials: [],
              nationalId: null, retained: false, notes: ''
            };
            state.counters.subject++;
          } else {
            var s0 = state.subjects[ev.ref];
            Object.keys(ev.identity).forEach(function (k) {
              if (ev.identity[k]) s0.identity[k] = ev.identity[k];
            });
          }
        }
        notice(state, ev.ref, 'APP_LODGED', { stage: ev.stage, round: a.round, id: a.id });
        ledger(state, ev.origin || 'RELAY', 's.lodged');
        break;
      }
      case 'STAGE_INIT': {
        addPending(state, ev.ref, ev.level, ev.stage);
        notice(state, ev.ref, 'INSPECTION_DIRECTED', { level: ev.level, stage: ev.stage });
        ledger(state, ev.origin || 'RELAY', 'i.pendingHint');
        break;
      }
      case 'LEAP': {
        var lp = {
          id: ev.id, ref: ev.ref, lodgedAt: ev.at, status: 'LODGED',
          reason: null, directedLevel: null, decidedAt: null,
          inboxId: inboxId, target: ev.target || ''
        };
        state.leaps.push(lp);
        state.counters.leap++;
        if (ev.identity && !state.subjects[ev.ref]) {
          state.subjects[ev.ref] = {
            ref: ev.ref, createdAt: now(), identity: ev.identity,
            credential: 'NONE', credentialCode: null, credentials: [],
            nationalId: null, retained: false, notes: ''
          };
          state.counters.subject++;
        }
        notice(state, ev.ref, 'LEAP_LODGED', { id: lp.id });
        ledger(state, ev.origin || 'RELAY', 'p.leap.pending');
        break;
      }
      case 'INSPECTION': {
        var ins = {
          id: ev.id, ref: ev.ref, level: ev.level, purpose: ev.purpose || '',
          outcome: ev.outcome, at: ev.at, certCode: ev.certCode,
          steps: ev.steps || [], subject: ev.subject || {}, ts: ev.ts || {}
        };
        state.inspections.push(ins);
        state.counters.insp++;
        var grade = null, certStatus = 'VALID';
        if (ev.outcome === 'CLEARED') grade = 'PASS';
        else if (ev.outcome === 'ABORTED') grade = 'FAIL';
        else if (ev.outcome === 'PENDING_GRADE') { grade = null; certStatus = 'AWAITING_GRADE'; }
        var cert = {
          code: ev.certCode, ref: ev.ref, kind: 'CLEARANCE', level: ev.level,
          grade: grade, issuedAt: ev.at, ts: ev.ts || {}, steps: ev.steps || [],
          subject: ev.subject || {}, status: certStatus, purpose: ev.purpose || '',
          origin: ev.origin || 'INSPECTION'
        };
        state.certificates.push(cert);
        state.counters.cert++;
        clearPending(state, ev.ref, ev.level, ev.purpose);
        if (certStatus === 'VALID') notice(state, ev.ref, 'CERT_ISSUED', { code: cert.code, level: ev.level, grade: grade });
        else notice(state, ev.ref, 'M_AWAITING_GRADE', { code: cert.code, level: ev.level });
        ledger(state, ev.origin || 'RELAY', certStatus === 'VALID' ? 'i.certReady' : 's.awaitingGrade');
        break;
      }
      case 'IDENTITY_CERT': {
        state.certificates.push({
          code: ev.certCode, ref: ev.ref, kind: 'IDENTITY', level: null,
          grade: null, issuedAt: ev.at, ts: ev.ts || {}, steps: [],
          subject: ev.subject || {}, status: 'VALID', purpose: 'IDENTITY',
          origin: ev.origin || 'PORTAL'
        });
        state.counters.cert++;
        notice(state, ev.ref, 'IDENTITY_CERT_ISSUED', { code: ev.certCode });
        ledger(state, ev.origin || 'RELAY', 'p.certs.issued');
        break;
      }
      case 'OATH': {
        state.oaths.push({ id: ev.id, ref: ev.ref, at: ev.at, status: 'TAKEN', confirmedAt: null });
        state.counters.oath++;
        notice(state, ev.ref, 'OATH_TAKEN', {});
        ledger(state, ev.origin || 'RELAY', 's.oathDone');
        break;
      }
    }
  }

  var _syncing = null;
  async function synchronise() {
    if (_syncing) return _syncing;
    _syncing = (async function () {
      /* Always begin a read-modify-write cycle from the newest server
         register. The 1 s revision poll alone is too coarse for two
         consecutive actions on different terminals. */
      if (LS.refresh) await LS.refresh();
      var inbox = readInbox();
      var state = await readState();
      var changed = false;
      for (var i = 0; i < inbox.length; i++) {
        var env = inbox[i];
        if (!env || state.processed[env.id]) continue;
        try {
          var ev = await openBroadcast(env.meta);
          ev.inboxId = env.id;
          if (!alreadyApplied(state, ev)) applyEvent(state, ev, env.id);
          state.processed[env.id] = true;
          changed = true;
        } catch (e) { console.warn('[Relay] envelope skipped', env.id, e); }
      }
      if (changed) { await writeState(state); announce('RELAY'); }
      return state;
    })();
    try { return await _syncing; } finally { _syncing = null; }
  }

  var Vault = {
    /* Read-only canonical projection of the Chancellery register. */
    state: synchronise,
    /* Seal an uplink envelope and register it through the Relay. */
    async submit(meta, full) {
      var id = uid('ENV');
      var m = Object.assign({}, meta, { id: meta.id || id, at: meta.at || now(), origin: TERMINAL });
      var env = {
        id: id, at: now(), origin: TERMINAL,
        meta: await sealBroadcast(m),
        payload: await sealForChancellery(full !== undefined ? full : m)
      };
      /* One key per envelope: a concurrent submission on another terminal
         touches a different key and can no longer be overwritten. */
      rawSet(ENV_PREFIX + env.id, env);
      announce(TERMINAL);
      await synchronise();
      fire();
      return id;
    },
    inbox: readInbox,
    /* Discretionary act — Authority only (guarded by caller). */
    async mutate(fn) {
      var s = await synchronise();
      var r = fn(s);
      if (r !== false) {
        /* Discretionary Authority acts are not part of the event log, so a
           stale revision must never silently overwrite a newer register. */
        if (LS.setStateGuard) LS.setStateGuard(true);
        await writeState(s);
      } else if (LS.setStateGuard) LS.setStateGuard(false);
      announce(TERMINAL);
      fire();
      return s;
    },
    announce: function () { announce(TERMINAL); fire(); },
    on: on,
    reset: function () {
      LS.clearPrefix('vdl.v1.');
      announce('AUTHORITY'); fire();
    },
    async export() {
      var s = await synchronise();
      var env = await sealBroadcast({
        kind: 'VIDLAND-REGISTER-EXPORT', v: 1, at: now(),
        state: s, inbox: readInbox()
      });
      return JSON.stringify(env);
    },
    async import(text) {
      var env = JSON.parse(text);
      var obj = await openBroadcast(env);
      if (!obj || obj.kind !== 'VIDLAND-REGISTER-EXPORT') throw new Error('Invalid sealed export');
      try {
        var existing = LS.keys ? LS.keys() : [];
        existing.forEach(function (k) {
          if (k.indexOf(ENV_PREFIX) === 0 || k === K.INBOX) LS.removeItem(k);
        });
      } catch (e) {}
      (obj.inbox || []).forEach(function (e) {
        if (e && e.id) rawSet(ENV_PREFIX + e.id, e);
      });
      await writeState(obj.state);
      announce('AUTHORITY'); fire();
      return true;
    },
    blankState: blankState,
    ledger: ledger, notice: notice, addPending: addPending, clearPending: clearPending
  };

  /* ------------------------------------------------------------
     5 · Session / subject reference
     ------------------------------------------------------------ */
  function getSession() {
    var r = null;
    try { r = LS.getItem(K.SESSION); } catch (e) {}
    if (!r) {
      r = code('VDL-SUB');
      try { LS.setItem(K.SESSION, r); } catch (e) {}
    }
    return r;
  }
  function setSession(ref) {
    try { LS.setItem(K.SESSION, ref); } catch (e) {}
    announce(TERMINAL); fire();
  }
  function clearSession() {
    try { LS.removeItem(K.SESSION); } catch (e) {}
  }

  /* ------------------------------------------------------------
     6 · Statutory route & logic
     ------------------------------------------------------------ */
  var ORDER = ['C', 'D', 'TR', 'PR', 'NAT'];
  var CREDENTIAL_FOR = { C: 'C', D: 'D', TR: 'TR', PR: 'PR', NAT: 'CITIZEN' };
  var INSPECTION_FOR = { C: 'R', TR: 'Z', PR: 'A', NAT: 'M' };
  var REQUIRES = { C: null, D: 'C', TR: 'D', PR: 'TR', NAT: 'PR' };
  var CRED_RANK = { NONE: 0, C: 1, D: 2, TR: 3, PR: 4, CITIZEN: 5 };

  var FLOW = {
    C:   { rounds: 2, pre: true,  initFirst: false, actions1: ['PREAPPROVE','APPROVE','REJECT'], actions2: ['APPROVE','REJECT'] },
    D:   { rounds: 1, pre: false, initFirst: false, actions1: ['APPROVE','REJECT'],             actions2: [] },
    TR:  { rounds: 1, pre: false, initFirst: true,  actions1: ['APPROVE','REJECT'],             actions2: [] },
    PR:  { rounds: 2, pre: true,  initFirst: false, actions1: ['PREAPPROVE','REJECT'],          actions2: ['APPROVE','REJECT'] },
    NAT: { rounds: 2, pre: true,  initFirst: false, actions1: ['WAITLIST','REJECT'],            actions2: ['APPROVE','REJECT'] },
    LEAP:{ rounds: 1, pre: false, initFirst: false, actions1: ['APPROVE','REJECT'],             actions2: [] }
  };

  function appsFor(state, ref, stage) {
    return state.applications.filter(function (a) { return a.ref === ref && a.stage === stage; })
      .sort(function (a, b) { return a.lodgedAt - b.lodgedAt; });
  }
  function certsFor(state, ref, level, grade) {
    return state.certificates.filter(function (c) {
      if (c.ref !== ref || c.kind !== 'CLEARANCE' || c.status !== 'VALID') return false;
      if (level && c.level !== level) return false;
      if (grade && c.grade !== grade) return false;
      return true;
    }).sort(function (a, b) { return a.issuedAt - b.issuedAt; });
  }
  function subject(state, ref) { return state.subjects[ref] || null; }
  function credential(state, ref) {
    var s = state.subjects[ref];
    return s ? s.credential : 'NONE';
  }
  function nextStage(cred) {
    return { NONE:'C', C:'D', D:'TR', TR:'PR', PR:'NAT', CITIZEN:null }[cred] || null;
  }
  function isEligible(state, ref, stage) {
    if (stage === 'LEAP') return true;
    var req = REQUIRES[stage];
    if (!req) return true;
    return CRED_RANK[credential(state, ref)] >= CRED_RANK[req];
  }

  /* Returns a descriptive state object used by the portal and the Authority. */
  function stageState(state, ref, stage) {
    var out = {
      stage: stage, ref: ref, credential: credential(state, ref),
      eligible: isEligible(state, ref, stage),
      phase: 'READY', cert: null, app: null, reason: null,
      inspection: INSPECTION_FOR[stage] || null, round: 1
    };
    var achieved = CRED_RANK[credential(state, ref)] >= CRED_RANK[CREDENTIAL_FOR[stage] || 'NONE'];
    if (achieved && CREDENTIAL_FOR[stage]) { out.phase = 'DONE'; return out; }
    if (!out.eligible) { out.phase = 'NOT_ELIGIBLE'; return out; }
    var apps = appsFor(state, ref, stage);
    var last = apps.length ? apps[apps.length - 1] : null;
    out.app = last;

    var level = INSPECTION_FOR[stage];
    var certs = level ? certsFor(state, ref, level) : [];
    var cert = certs.length ? certs[certs.length - 1] : null;
    out.cert = cert;

    if (stage === 'TR') {
      /* Eligibility verified on invocation; inspection precedes the form. */
      if (!cert) {
        var initiated = (state.pending[ref] || []).some(function (p) {
          return p.level === 'Z' && p.purpose === 'TR' && !p.done;
        });
        out.phase = initiated ? 'AWAIT_INSPECTION' : 'INIT';
        return out;
      }
      out.round = 1;
    }

    if (stage === 'NAT') {
      var mCerts = certsFor(state, ref, 'M');
      var m = mCerts.length ? mCerts[mCerts.length - 1] : null;
      out.cert = m;
      var f2 = apps.find(function (a) { return a.round === 2; });
      if (f2) {
        out.app = f2; out.round = 2;
        if (f2.status === 'LODGED') { out.phase = 'AWAIT_DECISION'; return out; }
        if (f2.status === 'REJECTED') { out.phase = 'REJECTED'; out.reason = f2.reason; return out; }
        if (f2.status === 'APPROVED') { out.phase = 'OATH'; return out; }
      }
      var f1 = apps.find(function (a) { return a.round === 1; });
      if (f1) {
        out.app = f1;
        if (f1.status === 'LODGED') { out.phase = 'AWAIT_DECISION'; return out; }
        if (f1.status === 'REJECTED') { out.phase = 'REJECTED'; out.reason = f1.reason; return out; }
        if (f1.status === 'WAITLISTED') {
          if (!m) { out.phase = 'AWAIT_INSPECTION'; return out; }
          if (m.grade !== 'EXCELLENT') { out.phase = 'GRADE_NOT_EXCELLENT'; return out; }
          out.phase = 'SECONDARY'; out.round = 2; return out;
        }
      }
      out.phase = 'READY'; return out;
    }

    var r2 = apps.find(function (a) { return a.round === 2; });
    if (r2) {
      out.app = r2; out.round = 2;
      if (r2.status === 'LODGED') { out.phase = 'AWAIT_DECISION'; return out; }
      if (r2.status === 'APPROVED') { out.phase = 'DONE'; return out; }
      if (r2.status === 'REJECTED') { out.phase = 'REJECTED'; out.reason = r2.reason; return out; }
    }
    var r1 = apps.find(function (a) { return a.round === 1; });
    if (r1) {
      out.app = r1; out.round = 1;
      if (r1.status === 'LODGED') { out.phase = 'AWAIT_DECISION'; return out; }
      if (r1.status === 'REJECTED') { out.phase = 'REJECTED'; out.reason = r1.reason; return out; }
      if (r1.status === 'PREAPPROVED') {
        if (cert) { out.phase = 'SECONDARY'; out.round = 2; return out; }
        out.phase = 'AWAIT_INSPECTION'; return out;
      }
      if (r1.status === 'APPROVED') { out.phase = 'DONE'; return out; }
    }
    if (FLOW[stage] && FLOW[stage].rounds === 2 && cert && !r2) {
      out.phase = 'SECONDARY'; out.round = 2; return out;
    }
    out.phase = 'READY'; out.round = 1;
    return out;
  }

  function leapState(state, ref) {
    var list = state.leaps.filter(function (x) { return x.ref === ref; })
      .sort(function (a, b) { return a.lodgedAt - b.lodgedAt; });
    var last = list.length ? list[list.length - 1] : null;
    if (!last) return { phase: 'READY', leap: null };
    if (last.status === 'APPROVED') return { phase: 'GRANTED', leap: last };
    if (last.status === 'REJECTED') return { phase: 'REJECTED', leap: last, reason: last.reason };
    if (last.directedLevel) {
      var done = state.inspections.some(function (i) {
        return i.ref === ref && i.level === last.directedLevel && i.at >= last.directedAt;
      });
      return { phase: done ? 'CONTINUE' : 'AWAIT_INSPECTION', leap: last, level: last.directedLevel };
    }
    return { phase: 'AWAIT_DECISION', leap: last };
  }

  function oathState(state, ref) {
    var list = state.oaths.filter(function (o) { return o.ref === ref; });
    var last = list.length ? list[list.length - 1] : null;
    if (!last) return { phase: 'NONE' };
    if (last.status === 'CONFIRMED') return { phase: 'CONFIRMED', oath: last };
    if (last.status === 'TAKEN') return { phase: 'AWAIT_CONFIRM', oath: last };
    return { phase: 'SUMMONED', oath: last };
  }

  /* ------------------------------------------------------------
     7 · Official application form schema
     ------------------------------------------------------------ */
  var LAN = ['en','es','fr','zh','zht','ru'];
  var FIELDS = {
    surname:{req:1}, given:{req:1}, aliases:{}, 
    sex:{type:'select',req:1,opts:['o.sex.f','o.sex.m','o.sex.x']},
    dob:{type:'date',req:1}, birthCity:{req:1}, birthCountry:{req:1},
    natBirth:{req:1}, natCurrent:{req:1},
    marital:{type:'select',req:1,opts:['o.marital.single','o.marital.married','o.marital.partner','o.marital.divorced','o.marital.widowed']},
    passportNo:{req:1}, passportAuth:{req:1}, foreignId:{},
    email:{type:'email',req:1}, phone:{req:1},
    address:{req:1,span:2}, postcode:{}, country:{req:1},
    occupation:{req:1}, employer:{}, 
    education:{type:'select',opts:['o.edu.primary','o.edu.secondary','o.edu.vocational','o.edu.tertiary','o.edu.postgrad']},
    nativeLang:{req:1},

    portOfEntry:{req:1}, 
    arrivalPurpose:{type:'select',req:1,opts:['o.purpose.tourism','o.purpose.study','o.purpose.work','o.purpose.family','o.purpose.official','o.purpose.other']},
    intendedAddress:{span:2}, priorVisits:{type:'select',opts:['o.yesno.y','o.yesno.n']},
    priorRefusals:{type:'select',opts:['o.yesno.y','o.yesno.n']}, refusalDetails:{type:'textarea',span:3},
    sponsorName:{}, sponsorRef:{},

    spouseName:{}, spouseNat:{}, spouseDob:{type:'date'},
    children:{type:'textarea',span:3}, fatherName:{}, fatherNat:{}, motherName:{}, motherNat:{},
    dependants:{type:'textarea',span:3},

    criminal:{type:'select',req:1,opts:['o.yesno.y','o.yesno.n']},
    convictionDetail:{type:'textarea',span:3},
    pendingCharges:{type:'select',req:1,opts:['o.yesno.y','o.yesno.n']},
    priorRemoval:{type:'select',req:1,opts:['o.yesno.y','o.yesno.n']},
    military:{type:'textarea',span:3}, govEmployment:{type:'select',req:1,opts:['o.yesno.y','o.yesno.n']},
    affiliation:{type:'select',req:1,opts:['o.yesno.y','o.yesno.n']},
    health:{type:'textarea',span:3,req:1}, medical:{type:'textarea',span:3},
    witness1:{type:'textarea',span:3}, witness2:{type:'textarea',span:3},

    fundsSource:{type:'select',req:1,opts:['o.funds.salary','o.funds.savings','o.funds.sponsor','o.funds.investment','o.funds.other']},
    annualIncome:{}, bankName:{}, sponsorVidland:{type:'textarea',span:3},
    maintenance:{type:'select',req:1,opts:['o.yesno.y','o.yesno.n']},
    property:{}, taxCompliance:{type:'textarea',span:3},

    grounds:{type:'textarea',span:3,req:1}, contribution:{type:'textarea',span:3,req:1},
    tiesOrigin:{type:'textarea',span:3}, longTerm:{type:'textarea',span:3,req:1},
    integration:{type:'textarea',span:3},

    studyOrWork:{type:'select',req:1,opts:['o.purpose.study','o.purpose.work','o.purpose.family']},
    hostInstitution:{req:1}, programme:{}, contractRef:{},
    residenceBasis:{req:1}, accommodation:{span:2,req:1}, employerReg:{},
    taxUndertaking:{type:'select',opts:['o.yesno.y','o.yesno.n']}, accompanying:{type:'textarea',span:3},
    continuousRes:{type:'textarea',span:3,req:1},
    langProficiency:{type:'select',req:1,opts:['o.lang.native','o.lang.advanced','o.lang.intermediate','o.lang.basic','o.lang.none']},
    civicKnowledge:{type:'textarea',span:3,req:1}, taxProof:{type:'textarea',span:3},
    integrationEv:{type:'textarea',span:3},
    renunciation:{type:'textarea',span:3,req:1}, civicDuties:{type:'textarea',span:3,req:1},
    langAttest:{type:'textarea',span:3}, dualNationality:{type:'textarea',span:3,req:1},
    natReasons:{type:'textarea',span:3,req:1}, understanding:{type:'textarea',span:3,req:1},
    targetStatus:{type:'select',req:1,opts:['o.target.C','o.target.D','o.target.TR','o.target.PR','o.target.NAT']},
    exceptional:{type:'textarea',span:3,req:1}, justification:{type:'textarea',span:3,req:1},
    supportingRefs:{type:'textarea',span:3},

    certRef:{type:'cert',req:1,span:2}, supplementary:{type:'textarea',span:3,req:1},
    signature:{req:1}, place:{req:1}, sigDate:{type:'date',req:1},

    truth:{type:'check',req:1,lk:'fs.truth',span:3},
    consent:{type:'check',req:1,lk:'fs.consent',span:3},
    liability:{type:'check',req:1,lk:'fs.liability',span:3},
    instrumentRead:{type:'check',req:1,lk:'fs.instrumentRead',span:3},
    camera:{type:'camera',req:1,span:3,nolabel:1}
  };

  var SECTIONS = {
    personal: ['surname','given','aliases','sex','dob','birthCity','birthCountry','natBirth','natCurrent','marital','passportNo','passportAuth','foreignId','email','phone','address','postcode','country','occupation','employer','education','nativeLang'],
    travel: ['portOfEntry','arrivalPurpose','intendedAddress','priorVisits','priorRefusals','refusalDetails','sponsorName','sponsorRef'],
    family: ['spouseName','spouseNat','spouseDob','children','fatherName','fatherNat','motherName','motherNat','dependants'],
    background: ['criminal','convictionDetail','pendingCharges','priorRemoval','military','govEmployment','affiliation','health','medical','witness1','witness2'],
    financial: ['fundsSource','annualIncome','bankName','sponsorVidland','maintenance','property','taxCompliance'],
    grounds: ['grounds','contribution','tiesOrigin','longTerm','integration'],
    specific: [],
    secondary: ['certRef','supplementary'],
    declaration: ['truth','consent','liability','signature','place','sigDate']
  };

  var SPECIFIC = {
    C: [],
    D: ['studyOrWork','hostInstitution','programme','contractRef'],
    TR: ['residenceBasis','accommodation','employerReg','taxUndertaking','accompanying'],
    PR: ['continuousRes','langProficiency','civicKnowledge','taxProof','integrationEv'],
    NAT: ['renunciation','civicDuties','langAttest','dualNationality','natReasons','understanding','witness1','witness2'],
    LEAP: ['targetStatus','exceptional','justification','supportingRefs']
  };

  /* Build the ordered section list for a given stage and round. */
  function buildForm(stage, round, opts) {
    opts = opts || {};
    var sections = [];
    function add(key, fields) {
      if (fields && fields.length) sections.push({ key: key, title: 'fs.' + key, desc: 'fs.' + key + '.desc', fields: fields.slice() });
    }
    var personal = SECTIONS.personal.slice();
    /* Live facial capture is compulsory in Part A of EVERY petition. */
    personal.push('camera');
    add('personal', personal);
    if (stage === 'C' && round === 1) add('travel', SECTIONS.travel);
    add('family', SECTIONS.family);
    add('background', SECTIONS.background);
    add('financial', SECTIONS.financial);
    add('grounds', SECTIONS.grounds);
    var spec = (SPECIFIC[stage] || []).slice();
    if (spec.length) add('specific', spec);
    if (round === 2 || (stage === 'TR') || (stage === 'LEAP' && opts.continuation)) add('secondary', SECTIONS.secondary);
    var decl = SECTIONS.declaration.slice();
    if (stage === 'NAT') decl.splice(3, 0, 'instrumentRead');
    add('declaration', decl);
    return sections;
  }

  /* Render an application form into a container. Returns an API object. */
  function renderForm(container, stage, round, opts) {
    opts = opts || {};
    var sections = buildForm(stage, round, opts);
    var prefill = opts.prefill || {};
    var certOptions = opts.certOptions || [];
    var html = '';
    var LETTER = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J'];

    sections.forEach(function (sec, si) {
      html += '<div class="form-section" data-sec="' + sec.key + '">';
      /* The section letter is rendered once, as a language-neutral badge
         (A·B·C…). The title strings themselves no longer carry a letter, so
         there is exactly one serial number per section in every language. */
      html += '<h4><span class="idx">' + LETTER[si] + '</span>' + t(sec.title) + '</h4>';
      html += '<div class="desc">' + t(sec.desc) + '</div>';
      html += '<div class="fields">';
      sec.fields.forEach(function (fk) {
        var meta = FIELDS[fk] || {};
        var type = meta.type || 'text';
        var span = meta.span || 1;
        var label = meta.lk ? t(meta.lk) : t('f.' + fk);
        html += '<div class="field span' + span + '" data-field="' + fk + '">';
        if (type === 'check') {
          html += '<label class="checkline" style="text-transform:none;font-size:12.5px;letter-spacing:0;font-weight:400">' +
            '<input type="checkbox" data-k="' + fk + '"' + (meta.req ? ' data-req="1"' : '') + '> ' +
            '<span>' + esc(label) + (meta.req ? ' <span class="req">*</span>' : '') + '</span></label>';
        } else if (type === 'camera') {
          html += '<div class="biobox" data-bio="1" style="grid-column:1/-1"></div>';
        } else {
          if (!meta.nolabel) html += '<label>' + esc(label) + (meta.req ? ' <span class="req">*</span>' : '') + '</label>';
          if (type === 'textarea') {
            html += '<textarea data-k="' + fk + '"' + (meta.req ? ' data-req="1"' : '') + ' rows="3"></textarea>';
          } else if (type === 'select') {
            html += '<select data-k="' + fk + '"' + (meta.req ? ' data-req="1"' : '') + '><option value="">— ' + esc(t('a.select')) + ' —</option>';
            /* Values are language-neutral terminology keys so that a change
               of interface language never destroys a partially filled form. */
            (meta.opts || []).forEach(function (o) {
              html += '<option value="' + esc(o) + '">' + esc(t(o)) + '</option>';
            });
            html += '</select>';
          } else if (type === 'cert') {
            html += '<select data-k="' + fk + '"' + (meta.req ? ' data-req="1"' : '') + '><option value="">— ' + esc(t('a.select')) + ' —</option>';
            certOptions.forEach(function (c) {
              html += '<option value="' + esc(c.code) + '">' + esc(c.code) + ' · ' + esc(t('s.' + ({PASS:'cleared',FAIL:'aborted',EXCELLENT:'excellent'}[c.grade] || 'unknown'))) + '</option>';
            });
            html += '</select>';
          } else {
            html += '<input type="' + (type === 'date' ? 'date' : type === 'email' ? 'email' : 'text') + '" data-k="' + fk + '"' + (meta.req ? ' data-req="1"' : '') + '>';
          }
        }
        html += '</div>';
      });
      html += '</div></div>';
    });
    html += '<div class="errbox" data-err="1"></div>';
    container.innerHTML = html;

    /* Prefill from the central register. */
    container.querySelectorAll('[data-k]').forEach(function (el) {
      var k = el.getAttribute('data-k');
      if (prefill[k] === undefined || prefill[k] === null || prefill[k] === '') return;
      if (el.type === 'checkbox') el.checked = !!prefill[k];
      else el.value = prefill[k];
    });

    var bio = null;
    var bioBox = container.querySelector('[data-bio]');
    if (bioBox) bio = mountBiometrics(bioBox, opts.bioSeed);

    return {
      sections: sections,
      biometrics: function () { return bio ? bio.get() : { frames: [], attestation: null }; },
      validate: function () {
        var errs = [];
        container.querySelectorAll('[data-req="1"]').forEach(function (el) {
          var ok = el.type === 'checkbox' ? el.checked : String(el.value || '').trim().length > 0;
          var box = el.closest('.field');
          if (box) box.classList.toggle('invalid', !ok);
          if (!ok) errs.push(el.getAttribute('data-k'));
        });
        if (bio && !bio.get().frames.length) {
          errs.push('camera');
          if (bioBox) bioBox.classList.add('invalid');
        }
        var box = container.querySelector('[data-err]');
        if (errs.length) { box.classList.add('on'); box.textContent = t('p.form.invalid'); return false; }
        box.classList.remove('on');
        return true;
      },
      values: function () {
        var v = {};
        container.querySelectorAll('[data-k]').forEach(function (el) {
          v[el.getAttribute('data-k')] = el.type === 'checkbox' ? el.checked : el.value;
        });
        return v;
      },
      focusFirstError: function () {
        var f = container.querySelector('.field.invalid');
        if (f) f.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    };
  }

  /* ------------------------------------------------------------
     8 · Live biometrics — front-facing MediaStream ONLY
     ------------------------------------------------------------ */
  function mountBiometrics(root, seed) {
    seed = seed || {};
    var seeded = (seed.frames || []).slice();
    var state = {
      frames: seeded, attestation: seed.attestation || null, stream: null,
      stage: Math.min(seeded.length, 3), tag: null, running: false
    };
    var prompts = ['bio.step1', 'bio.step2', 'bio.step3'];
    root.innerHTML =
      '<div>' +
        '<div class="cam-shell"><video playsinline muted autoplay></video>' +
          '<div class="ph"></div><div class="reticle"></div>' +
          '<div class="live"><i></i><span data-live></span></div>' +
        '</div>' +
        '<div class="cam-frames"><canvas></canvas><canvas></canvas><canvas></canvas></div>' +
      '</div>' +
      '<div>' +
        '<div class="small strong" style="color:var(--navy);font-family:var(--serif);font-size:15px">' + esc(t('bio.title')) + '</div>' +
        '<div class="small muted" style="margin-bottom:10px">' + esc(t('bio.sub')) + '</div>' +
        '<div class="btn-row" style="margin-top:0"><button class="btn sm gold" data-start>' + esc(t('bio.start')) + '</button>' +
        '<button class="btn sm secondary" data-restart disabled>' + esc(t('bio.restart')) + '</button></div>' +
        '<div data-steps style="margin-top:12px"></div>' +
        '<div class="small muted" style="margin:10px 0;padding:9px 11px;border-left:2px solid var(--gold);background:#faf7ee;line-height:1.65">' + esc(t('bio.pace')) + '</div>' +
        '<div class="no-upload">' + esc(t('bio.noUpload')) + '</div>' +
        '<div class="bio-status" data-status style="margin-top:10px"></div>' +
      '</div>';

    var video = root.querySelector('video');
    var ph = root.querySelector('.ph');
    var live = root.querySelector('[data-live]');
    var stepsBox = root.querySelector('[data-steps]');
    var status = root.querySelector('[data-status]');
    var startBtn = root.querySelector('[data-start]');
    var restartBtn = root.querySelector('[data-restart]');
    var canvases = root.querySelectorAll('.cam-frames canvas');

    function paint() {
      live.textContent = t('bio.live');
      ph.textContent = t('bio.placeholder');
      var h = '';
      prompts.forEach(function (p, i) {
        var done = state.frames.length > i;
        var active = state.running && state.stage === i && !done;
        var tag = done ? t('s.completed') : active ? (state.tag || t('bio.ready')) : t('bio.pending');
        h += '<div class="liveness-step ' + (done ? 'done' : active ? 'active' : '') + '"><span>' +
          esc(t(p)) + '</span><span class="tag">' + esc(tag) + '</span></div>';
      });
      stepsBox.innerHTML = h;
      var full = state.frames.length === 3;
      status.innerHTML = full
        ? '<span class="ok">◈ ' + esc(t('bio.ok')) + '</span><br>' + esc(t('bio.facing')) + ': ' + esc(state.attestation || '')
        : state.running
          ? '<span class="pend">◈ ' + esc(t('s.inProgress')) + ' · ' + Math.min(state.stage + 1, 3) + ' / 3</span><br>' +
            esc(t('bio.facing')) + ': ' + esc(state.attestation || '')
          : '<span class="pend">◈ ' + esc(t('bio.pending')) + '</span>';
      canvases.forEach(function (c, i) {
        var ctx = c.getContext('2d');
        c.width = 160; c.height = 200;
        ctx.fillStyle = '#0d1822'; ctx.fillRect(0, 0, 160, 200);
        if (state.frames[i]) {
          var img = new Image();
          img.onload = function () { ctx.drawImage(img, 0, 0, 160, 200); };
          img.src = state.frames[i].data;
        }
      });
    }
    paint();
    I && global.addEventListener('vdl:lang', paint);

    function setTag(text) {
      var row = stepsBox.children[state.stage];
      if (row && row.querySelector('.tag')) row.querySelector('.tag').textContent = text;
    }
    function stop() {
      if (state.stream) { try { state.stream.getTracks().forEach(function (tr) { tr.stop(); }); } catch (e) {} }
      state.stream = null;
    }
    function captureFrame() {
      var w = 320, h = 400;
      var tmp = document.createElement('canvas');
      tmp.width = w; tmp.height = h;
      var ctx = tmp.getContext('2d');
      ctx.save(); ctx.translate(w, 0); ctx.scale(-1, 1);
      try { ctx.drawImage(video, 0, 0, w, h); } catch (e) {}
      ctx.restore();
      /* Overlay capture provenance directly into the sealed frame. */
      ctx.fillStyle = 'rgba(9,22,35,.62)'; ctx.fillRect(0, h - 26, w, 26);
      ctx.fillStyle = '#e8dcc0'; ctx.font = '10px monospace';
      ctx.fillText('VDL-LIVE ' + new Date().toISOString(), 8, h - 10);
      state.frames.push({ data: tmp.toDataURL('image/jpeg', 0.62), at: now(), iso: new Date().toISOString() });
      paint();
    }
    function delay(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

    /* Operator starts the sequence manually; the terminal then captures
       three frames AUTOMATICALLY on a deliberately slow, visible countdown
       (3 s per pose + 1.1 s pause between poses + 1.8 s warm-up). */
    async function run() {
      if (state.running) return;
      if (state.stream) stop();
      state.frames = []; state.stage = 0; state.tag = null; state.running = true;
      startBtn.disabled = true; restartBtn.disabled = true;
      try {
        state.stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: { ideal: 'user' }, width: { ideal: 640 }, height: { ideal: 800 } },
          audio: false
        });
      } catch (e) {
        state.running = false; startBtn.disabled = false;
        status.innerHTML = '<span style="color:var(--red)">' + esc(t('bio.err')) + '</span>';
        return;
      }
      video.srcObject = state.stream;
      ph.style.display = 'none';
      try { await video.play(); } catch (e) {}
      var tr = state.stream.getVideoTracks()[0];
      var settings = tr ? tr.getSettings() : {};
      state.attestation = [
        'facingMode=' + (settings.facingMode || 'user-requested'),
        (settings.width || '?') + 'x' + (settings.height || '?'),
        (tr && tr.label ? tr.label.slice(0, 34) : 'MediaStreamTrack'),
        'live=' + !!state.stream.active
      ].join(' · ');
      paint();
      setTag(t('bio.prepare'));
      await delay(1800);
      for (var i = 0; i < 3; i++) {
        if (!state.stream) break;
        state.stage = i; state.tag = t('bio.ready'); paint();
        for (var n = 3; n >= 1; n--) {
          if (!state.stream) break;
          setTag(t('bio.countdown', { n: n }));
          await delay(1000);
        }
        if (!state.stream) break;
        captureFrame();
        state.stage = i + 1; state.tag = null; paint();
        await delay(1100);
      }
      state.frames.forEach(function (f) { f.attestation = state.attestation; });
      state.running = false;
      startBtn.disabled = false;
      restartBtn.disabled = false;
      paint();
    }

    startBtn.addEventListener('click', run);
    restartBtn.addEventListener('click', run);

    return {
      get: function () { return { frames: state.frames.slice(), attestation: state.attestation }; },
      stop: stop
    };
  }

  /* ------------------------------------------------------------
     9 · Official instrument renderer (canvas long image)
     ------------------------------------------------------------ */
  var CERT_W = 1240, SCALE = 1.5;
  function font(size, weight, serif) {
    return (weight ? weight + ' ' : '') + size + 'px ' +
      (serif ? '"Georgia","Times New Roman","Songti SC","Noto Serif CJK SC",serif'
             : '"Segoe UI","Helvetica Neue","Microsoft YaHei",sans-serif');
  }
  function wrap(ctx, text, max) {
    var str = String(text == null ? '' : text).replace(/\r/g, '');
    var out = [];
    str.split('\n').forEach(function (para) {
      if (!para) { out.push(''); return; }
      var line = '', lastSpace = -1;
      for (var i = 0; i < para.length; i++) {
        var ch = para[i];
        var test = line + ch;
        if (ctx.measureText(test).width > max && line) {
          var cut = lastSpace > 0 ? lastSpace : line.length;
          out.push(line.slice(0, cut).replace(/\s+$/, ''));
          line = line.slice(cut).replace(/^\s+/, '') + ch;
          lastSpace = -1;
        } else {
          line = test;
          if (ch === ' ') lastSpace = line.length - 1;
        }
      }
      out.push(line);
    });
    return out;
  }
  function textBlock(ctx, text, x, y, max, lh, opt) {
    opt = opt || {};
    ctx.font = font(opt.size || 15, opt.weight || '', opt.serif !== false);
    ctx.fillStyle = opt.color || '#22303e';
    ctx.textAlign = opt.align || 'left';
    var lines = wrap(ctx, text, max);
    lines.forEach(function (ln, i) {
      ctx.fillText(ln, x, y + i * lh);
    });
    return y + lines.length * lh;
  }
  function line(ctx, x1, y1, x2, y2, color, width) {
    ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2);
    ctx.strokeStyle = color || '#c8c0ac'; ctx.lineWidth = width || 1; ctx.stroke();
  }
  function kvRow(ctx, label, value, x, y, w) {
    ctx.font = font(14, '', true);
    var lines = wrap(ctx, String(value == null ? '—' : value), w - 240);
    var h = Math.max(30, lines.length * 20 + 14);
    ctx.fillStyle = '#f7f4ec'; ctx.fillRect(x, y, w, h);
    line(ctx, x, y + h, x + w, y + h, '#ddd7c8', 1);
    ctx.font = font(11, '600', false); ctx.fillStyle = '#5c6772';
    ctx.textAlign = 'left'; ctx.fillText(String(label).toUpperCase(), x + 12, y + 19);
    ctx.font = font(14, '', true); ctx.fillStyle = '#16212e';
    lines.forEach(function (ln, i) { ctx.fillText(ln, x + 230, y + 19 + i * 20); });
    return y + h;
  }

  function drawCrest(ctx, cx, cy, s) {
    ctx.save(); ctx.translate(cx, cy); ctx.scale(s, s);
    ctx.fillStyle = '#10263f';
    ctx.beginPath();
    ctx.moveTo(-38, -46); ctx.lineTo(38, -46); ctx.lineTo(38, 6);
    ctx.quadraticCurveTo(38, 40, 0, 54);
    ctx.quadraticCurveTo(-38, 40, -38, 6); ctx.closePath(); ctx.fill();
    ctx.strokeStyle = '#b18b4c'; ctx.lineWidth = 2.4; ctx.stroke();
    ctx.fillStyle = '#b18b4c';
    ctx.fillRect(-6, -40, 12, 78);
    ctx.fillRect(-32, -20, 64, 12);
    ctx.fillStyle = '#10263f'; ctx.fillRect(-2, -36, 4, 70); ctx.fillRect(-28, -16, 56, 4);
    ctx.fillStyle = '#b18b4c';
    ctx.beginPath();
    ctx.moveTo(-30, -52); ctx.lineTo(-20, -66); ctx.lineTo(-10, -55); ctx.lineTo(0, -70);
    ctx.lineTo(10, -55); ctx.lineTo(20, -66); ctx.lineTo(30, -52); ctx.closePath(); ctx.fill();
    [-24, 0, 24].forEach(function (x) { ctx.beginPath(); ctx.arc(x, -70, 3.2, 0, 7); ctx.fill(); });
    ctx.restore();
  }

  /* ============================================================
     STATUTORY ELECTRONIC SEALS
     Legends are cut into the die in ENGLISH and are deliberately
     independent of the interface language: an official seal is a
     fixed image, not translated interface copy. Three distinct dies:
       chancellery — gold, radiant guilloche + grand-ducal crown
       ministry    — green, laurel wreath + open civic register
       security    — red, beaded state seal + shield and star
     ============================================================ */
  function sealRing(ctx, r, w, color) {
    ctx.strokeStyle = color; ctx.lineWidth = w;
    ctx.beginPath(); ctx.arc(0, 0, r, 0, Math.PI * 2); ctx.stroke();
  }
  function sealBeads(ctx, r, n, size, color) {
    ctx.fillStyle = color;
    for (var i = 0; i < n; i++) {
      var a = i * Math.PI * 2 / n;
      ctx.beginPath(); ctx.arc(Math.cos(a) * r, Math.sin(a) * r, size, 0, 7); ctx.fill();
    }
  }
  function sealRays(ctx, r1, r2, n, color) {
    ctx.save(); ctx.strokeStyle = color;
    for (var i = 0; i < n; i++) {
      var a = i * Math.PI * 2 / n;
      ctx.lineWidth = i % 2 ? 0.9 : 1.8;
      ctx.beginPath();
      ctx.moveTo(Math.cos(a) * r1, Math.sin(a) * r1);
      ctx.lineTo(Math.cos(a) * r2, Math.sin(a) * r2);
      ctx.stroke();
    }
    ctx.restore();
  }
  /* Banknote-style guilloche: two offset rosettes, unmistakably "grand". */
  function sealGuilloche(ctx, r, petals, color) {
    ctx.save(); ctx.strokeStyle = color; ctx.lineWidth = 0.85; ctx.globalAlpha = 0.62;
    [0, 1].forEach(function (phase) {
      ctx.beginPath();
      for (var i = 0; i <= 360; i++) {
        var a = i * Math.PI / 180;
        var rr = r * (0.90 + 0.085 * Math.cos(petals * a + phase * Math.PI / petals));
        var x = Math.cos(a) * rr, y = Math.sin(a) * rr;
        i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
      }
      ctx.closePath(); ctx.stroke();
    });
    ctx.restore();
  }
  function sealLaurel(ctx, r, color) {
    ctx.save(); ctx.strokeStyle = color; ctx.fillStyle = color; ctx.lineWidth = 1.35;
    for (var s = -1; s <= 1; s += 2) {
      ctx.beginPath();
      for (var i = 0; i <= 22; i++) {
        var t = i / 22, a = 1.44 - t * 1.62;
        var x = s * Math.cos(a) * r, y = Math.sin(a) * r;
        i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
      }
      ctx.stroke();
      for (var j = 0; j < 8; j++) {
        var f = j / 7, a2 = 1.39 - f * 1.50;
        var px = s * Math.cos(a2) * r, py = Math.sin(a2) * r;
        ctx.save(); ctx.translate(px, py);
        ctx.rotate((s > 0 ? a2 : Math.PI - a2) + 0.85);
        ctx.globalAlpha = 0.88;
        ctx.beginPath(); ctx.ellipse(0, 0, 6.4, 2.25, 0, 0, Math.PI * 2); ctx.fill();
        ctx.restore();
      }
    }
    ctx.restore();
  }
  function sealStar(ctx, cx, cy, rOut, rIn, color, points) {
    ctx.save(); ctx.translate(cx, cy); ctx.fillStyle = color;
    ctx.beginPath();
    for (var i = 0; i < points * 2; i++) {
      var a = -Math.PI / 2 + i * Math.PI / points;
      var rr = i % 2 ? rIn : rOut;
      var x = Math.cos(a) * rr, y = Math.sin(a) * rr;
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    }
    ctx.closePath(); ctx.fill(); ctx.restore();
  }
  function sealCrown(ctx, color) {
    ctx.save(); ctx.fillStyle = color;
    ctx.beginPath();
    ctx.moveTo(-21, 13); ctx.lineTo(-21, -7); ctx.lineTo(-10.5, 2.5);
    ctx.lineTo(0, -17); ctx.lineTo(10.5, 2.5); ctx.lineTo(21, -7);
    ctx.lineTo(21, 13); ctx.closePath(); ctx.fill();
    ctx.fillRect(-22, 12, 44, 5);
    [-21, 0, 21].forEach(function (x) {
      ctx.beginPath(); ctx.arc(x, -10, 2.7, 0, 7); ctx.fill();
    });
    ctx.strokeStyle = color; ctx.lineWidth = 1.4;
    ctx.beginPath(); ctx.moveTo(-14, 8); ctx.lineTo(14, 8); ctx.stroke();
    ctx.restore();
  }
  function sealBook(ctx, color) {
    ctx.save(); ctx.strokeStyle = color; ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(-22, -5); ctx.quadraticCurveTo(-11, -13, 0, -5);
    ctx.quadraticCurveTo(11, -13, 22, -5);
    ctx.lineTo(22, 13); ctx.quadraticCurveTo(11, 5, 0, 13);
    ctx.quadraticCurveTo(-11, 5, -22, 13); ctx.closePath(); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(0, -5); ctx.lineTo(0, 13); ctx.stroke();
    ctx.lineWidth = 0.9;
    [-16, -12, -8, 8, 12, 16].forEach(function (x) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x + (x < 0 ? 3 : -3), 7); ctx.stroke();
    });
    sealStar(ctx, 0, -25, 8.5, 3.6, color, 8);
    ctx.restore();
  }
  function sealShield(ctx, color) {
    ctx.save(); ctx.strokeStyle = color; ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(-19, -17); ctx.lineTo(19, -17); ctx.lineTo(19, 4);
    ctx.quadraticCurveTo(19, 19, 0, 26);
    ctx.quadraticCurveTo(-19, 19, -19, 4); ctx.closePath(); ctx.stroke();
    ctx.lineWidth = 3.1;
    ctx.beginPath();
    ctx.moveTo(0, -14); ctx.lineTo(0, 21);
    ctx.moveTo(-16, -2); ctx.lineTo(16, -2);
    ctx.stroke();
    ctx.restore();
  }
  /* Fixed English die legend, laid out character by character along the
     upper arc. Never translated — matches a real embossed seal. */
  function sealArcText(ctx, text, radius, color, size) {
    var chars = String(text).split('');
    /* Keep the legend on the UPPER arc only (roughly ±88°), otherwise the
       glyphs run under the seal and appear upside-down. */
    var step = (Math.PI * 0.98) / Math.max(chars.length, 1);
    var total = step * (chars.length - 1);
    var start = -Math.PI / 2 - total / 2;
    ctx.save();
    ctx.fillStyle = color; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.font = font(size, '700', true);
    chars.forEach(function (ch, i) {
      var a = start + i * step;
      ctx.save();
      ctx.translate(Math.cos(a) * radius, Math.sin(a) * radius);
      ctx.rotate(a + Math.PI / 2);
      ctx.fillText(ch, 0, 0);
      ctx.restore();
    });
    ctx.restore();
  }
  var SEAL_THEME = {
    chancellery: { ink: '#8a6622', soft: '#c39a4a',
      legend: 'GRAND DUCAL CHANCELLERY', foot: 'EST. MDCCCLXXI' },
    ministry:    { ink: '#1f6647', soft: '#4a9870',
      legend: 'MINISTRY OF NATURALISATION', foot: 'CIVIC INTEGRATION' },
    security:    { ink: '#a22121', soft: '#c4594b',
      legend: 'STATE SECURITY DEPARTMENT', foot: 'GRAND DUCHY OF VIDLAND' }
  };
  function drawOfficialSeal(ctx, cx, cy, r, kind, tilt) {
    var th = SEAL_THEME[kind], ink = th.ink, soft = th.soft;
    ctx.save();
    ctx.translate(cx, cy); ctx.rotate(tilt || 0);
    ctx.globalAlpha = kind === 'chancellery' ? 0.92 : 0.85;
    ctx.lineJoin = 'round'; ctx.lineCap = 'round';

    /* Grand-ducal die alone carries a struck-metal sheen. */
    if (kind === 'chancellery') {
      var g = ctx.createRadialGradient(-r * 0.30, -r * 0.34, 2, 0, 0, r - 6);
      g.addColorStop(0, 'rgba(230,196,116,0.44)');
      g.addColorStop(0.55, 'rgba(198,158,78,0.16)');
      g.addColorStop(1, 'rgba(198,158,78,0)');
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(0, 0, r - 6, 0, Math.PI * 2); ctx.fill();
    }

    sealRing(ctx, r, 3.3, ink);
    sealRing(ctx, r - 6, 1.05, ink);

    if (kind === 'chancellery') {
      sealRays(ctx, r - 10, r - 7, 36, soft);
      sealBeads(ctx, r - 25, 42, 1.45, ink);
      sealGuilloche(ctx, r * 0.60, 9, soft);
      sealRing(ctx, r * 0.44, 1.6, ink);
      sealCrown(ctx, ink);
    } else if (kind === 'ministry') {
      sealLaurel(ctx, r - 27, soft);
      ctx.save(); ctx.setLineDash([2, 3]);
      sealRing(ctx, r * 0.50, 1.15, ink);
      ctx.restore();
      sealBook(ctx, ink);
    } else {
      sealBeads(ctx, r - 25, 44, 1.35, ink);
      ctx.save(); ctx.strokeStyle = soft; ctx.lineWidth = 0.9;
      for (var i = 0; i < 72; i++) {
        var a = i * Math.PI / 36;
        ctx.beginPath();
        ctx.moveTo(Math.cos(a) * (r - 22), Math.sin(a) * (r - 22));
        ctx.lineTo(Math.cos(a) * (r - 19), Math.sin(a) * (r - 19));
        ctx.stroke();
      }
      ctx.restore();
      sealRing(ctx, r * 0.50, 1.5, ink);
      sealShield(ctx, ink);
      sealStar(ctx, 0, -2, 7.5, 3.1, ink, 5);
    }

    var fs = th.legend.length > 25 ? 8.2 : th.legend.length > 20 ? 8.9 : 9.6;
    sealArcText(ctx, th.legend, r - 15, ink, fs);
    ctx.fillStyle = ink; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.font = font(7.4, '700', false);
    ctx.fillText('★  ' + th.foot + '  ★', 0, r - 12);
    ctx.restore();
  }
  function drawSeals(ctx, triTop, triBottom) {
    /* Dies are struck perfectly upright, and set to the RIGHT of each
       signatory name so no institution name is obscured by the impression. */
    drawOfficialSeal(ctx, 470, triTop + 44, 52, 'ministry', 0);
    drawOfficialSeal(ctx, 1075, triTop + 44, 55, 'chancellery', 0);
    drawOfficialSeal(ctx, 782, triBottom + 44, 54, 'security', 0);
  }

  function tsRecord(ms) {
    var d = new Date(ms);
    var off = -d.getTimezoneOffset(), sign = off >= 0 ? '+' : '-';
    var oh = ('0' + Math.floor(Math.abs(off) / 60)).slice(-2);
    var om = ('0' + (Math.abs(off) % 60)).slice(-2);
    var pad = function (n, l) { return ('000' + n).slice(-l || -2); };
    var local = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' +
      pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()) + '.' + pad(d.getMilliseconds(), 3);
    return {
      local: local,
      utc: d.toISOString(),
      epoch: String(ms),
      iso: local.replace(' ', 'T') + sign + oh + ':' + om,
      tz: (Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC') + ' (UTC' + sign + oh + ':' + om + ')',
      weekday: d.toLocaleDateString(I.getLang(), { weekday: 'long' })
    };
  }

  async function renderCertificate(spec, targetCanvas) {
    var lang = I.getLang();
    var subj = spec.subject || {};
    var steps = spec.steps || [];
    var ts = spec.ts && spec.ts.local ? spec.ts : tsRecord(spec.issuedAt || now());
    var digest = await digestHex({ c: spec.code, r: spec.ref, a: spec.issuedAt, s: steps.length, l: lang });
    var kind = spec.kind || 'CLEARANCE';

    /* ---- step box heights (measured once, shared by both passes) ---- */
    var mc = document.createElement('canvas');
    mc.width = 8; mc.height = 8;
    var m = mc.getContext('2d');
    var stepH = [];
    steps.forEach(function (s) {
      m.font = font(15, '600', true);
      var tl = wrap(m, L(s.title), 900).length;
      m.font = font(13, '', true);
      var dl = wrap(m, L(s.detail), 950).length;
      stepH.push(78 + tl * 21 + dl * 19);
    });

    /* Two-pass layout: the first pass measures the true content height, the
       second draws into a canvas of exactly that height. The triangular
       signatories and the electronic seal can therefore never be clipped,
       regardless of how many steps the Authority has prescribed. */
    function draw(ctx, H) {

    /* ---- paper ---- */
    ctx.fillStyle = '#fffdf7'; ctx.fillRect(0, 0, CERT_W, H);
    ctx.fillStyle = '#faf6ea'; ctx.fillRect(0, 0, CERT_W, 12);
    ctx.strokeStyle = '#b18b4c'; ctx.lineWidth = 2;
    ctx.strokeRect(22, 22, CERT_W - 44, H - 44);
    ctx.lineWidth = 1; ctx.strokeRect(30, 30, CERT_W - 60, H - 60);

    /* ---- diagonal watermark ---- */
    ctx.save(); ctx.translate(CERT_W / 2, H / 2); ctx.rotate(-0.34);
    ctx.font = font(96, '700', true); ctx.fillStyle = 'rgba(16,38,63,.038)';
    ctx.textAlign = 'center'; ctx.fillText(t('c.watermark'), 0, 0);
    ctx.restore();

    var X = 66, W = CERT_W - 132;

    /* ---- letterhead ---- */
    drawCrest(ctx, 138, 122, 1.0);
    ctx.textAlign = 'left';
    ctx.fillStyle = '#a8894b'; ctx.font = font(11, '700', false);
    ctx.fillText(t('g.restricted'), X + 150, 78);
    ctx.fillStyle = '#10263f'; ctx.font = font(28, '600', true);
    ctx.fillText(t('g.state'), X + 150, 112);
    ctx.fillStyle = '#4a5764'; ctx.font = font(12, '', true);
    ctx.fillText(t('g.chancellery'), X + 150, 134);
    ctx.fillText(t('g.ministryShort') + '  ·  ' + t('g.securityShort'), X + 150, 152);
    ctx.textAlign = 'right';
    ctx.fillStyle = '#a8894b'; ctx.font = font(10, '700', false);
    ctx.fillText(t('g.motto'), CERT_W - X, 78);
    ctx.fillStyle = '#5c6772'; ctx.font = font(11, '', false);
    ctx.fillText(t('c.docNo') + ': ' + (spec.code || ''), CERT_W - X, 104);
    ctx.fillText(t('c.fileNo') + ': ' + (spec.ref || ''), CERT_W - X, 122);
    ctx.fillText(t('c.classification'), CERT_W - X, 140);
    ctx.textAlign = 'left';
    line(ctx, X, 182, CERT_W - X, 182, '#b18b4c', 2);
    line(ctx, X, 187, CERT_W - X, 187, '#d8c49a', 1);

    /* ---- title ---- */
    var titleKey = kind === 'IDENTITY' ? 'c.identity.title' : kind === 'VISA' ? 'c.visa.title' : 'c.clearance.title';
    ctx.textAlign = 'center'; ctx.fillStyle = '#10263f'; ctx.font = font(34, '700', true);
    wrap(ctx, t(titleKey), W).forEach(function (ln, i) { ctx.fillText(ln, CERT_W / 2, 238 + i * 40); });
    ctx.fillStyle = '#5c6772'; ctx.font = font(12.5, '', true);
    ctx.fillText(t('c.subtitle'), CERT_W / 2, 292);
    if (kind === 'CLEARANCE' && spec.level) {
      ctx.fillStyle = '#a8894b'; ctx.font = font(13, '700', false);
      ctx.fillText(t('i.level.' + spec.level), CERT_W / 2, 316);
    }

    /* ---- timestamp dossier ---- */
    var y = 344;
    ctx.fillStyle = '#10263f'; ctx.fillRect(X, y, W, 26);
    ctx.fillStyle = '#f0e8d5'; ctx.font = font(11, '700', false); ctx.textAlign = 'left';
    ctx.fillText(t('c.timeDetail'), X + 12, y + 18);
    y += 26;
    var tsRows = [
      [t('c.issued'), ts.local],
      [t('c.localTime'), ts.local + '  ·  ' + ts.weekday],
      [t('c.utcTime'), ts.utc],
      [t('c.iso'), ts.iso],
      [t('c.epoch'), ts.epoch + ' ms'],
      [t('c.tz'), ts.tz],
      [t('c.digest'), digest.toUpperCase()]
    ];
    tsRows.forEach(function (r, i) {
      ctx.fillStyle = i % 2 ? '#fffdf7' : '#f8f5ec';
      ctx.fillRect(X, y, W, 24);
      ctx.fillStyle = '#5c6772'; ctx.font = font(10.5, '600', false);
      ctx.fillText(r[0], X + 12, y + 16);
      ctx.fillStyle = '#1c2a38'; ctx.font = font(12, '', false);
      ctx.fillText(String(r[1]), X + 260, y + 16);
      line(ctx, X, y + 24, X + W, y + 24, '#e6e0d1', 1);
      y += 24;
    });
    y += 26;

    /* ---- Part I ---- */
    ctx.fillStyle = '#10263f'; ctx.fillRect(X, y, W, 28);
    ctx.fillStyle = '#f0e8d5'; ctx.font = font(12, '700', false);
    ctx.fillText(t('c.sec1'), X + 14, y + 19);
    y += 34;
    var rows = [
      [t('c.name'), subj.name],
      [t('c.dob'), subj.dob],
      [t('c.nationality'), subj.nationality],
      [t('c.passport'), subj.passportNo],
      [t('g.subjectRef'), spec.ref],
      [t('c.address'), subj.address],
      [t('c.credential'), subj.credentialLabel],
      [t('c.instrumentCode'), subj.credentialCode || subj.nationalId]
    ];
    rows.forEach(function (r) { y = kvRow(ctx, r[0], r[1], X, y, W); });
    y += 26;

    /* ---- Part II ---- */
    ctx.fillStyle = '#10263f'; ctx.fillRect(X, y, W, 28);
    ctx.fillStyle = '#f0e8d5'; ctx.font = font(12, '700', false);
    ctx.fillText(t('c.sec2'), X + 14, y + 19);
    y += 40;
    if (!steps.length) {
      ctx.fillStyle = '#77808b'; ctx.font = font(14, '', true);
      ctx.fillText(t('c.noSteps'), X + 10, y + 10);
      y += 46;
    } else {
      steps.forEach(function (s, i) {
        var hh = stepH[i];
        ctx.fillStyle = '#faf7ef'; ctx.fillRect(X, y, W, hh - 10);
        ctx.fillStyle = '#10263f'; ctx.fillRect(X, y, 5, hh - 10);
        ctx.fillStyle = '#a8894b'; ctx.font = font(11, '700', false);
        ctx.fillText(t('c.stepNo') + ' ' + (i + 1), X + 20, y + 22);
        ctx.fillStyle = '#10263f'; ctx.font = font(16, '600', true);
        var ny = textBlock(ctx, L(s.title), X + 20, y + 46, 900, 21, { size: 16, weight: '600', serif: true });
        ctx.fillStyle = '#4a5764';
        ny = textBlock(ctx, L(s.detail), X + 20, ny + 6, 950, 19, { size: 13, serif: true, color: '#3d4a57' });
        ctx.fillStyle = s.status === 'ABORTED' ? '#a22121' : '#1f6647';
        ctx.font = font(11.5, '700', false);
        ctx.fillText((s.status === 'ABORTED' ? t('c.notCompleted') : t('c.completed')), X + 20, ny + 18);
        y += hh;
      });
    }
    y += 18;

    /* ---- Part III ---- */
    ctx.fillStyle = '#10263f'; ctx.fillRect(X, y, W, 28);
    ctx.fillStyle = '#f0e8d5'; ctx.font = font(12, '700', false);
    ctx.fillText(t('c.sec3'), X + 14, y + 19);
    y += 40;
    var concl;
    if (kind === 'IDENTITY') concl = t('c.concl.identity');
    else if (kind === 'VISA') concl = t('c.concl.visa');
    else if (spec.grade === 'FAIL') concl = t('c.concl.fail');
    else if (spec.level === 'M') {
      concl = spec.grade === 'EXCELLENT' ? t('c.concl.excellent')
            : spec.grade === 'PASS' ? t('c.concl.pass') : t('c.concl.unsat');
    } else concl = t('c.concl.clear');
    ctx.fillStyle = '#f4f1e6'; ctx.fillRect(X, y, W, 66);
    line(ctx, X, y, X + 5, y, '#b18b4c', 4);
    ctx.fillStyle = '#16212e'; ctx.font = font(14, '', true);
    y = textBlock(ctx, concl, X + 18, y + 24, W - 36, 21, { size: 14, serif: true }) + 16;
    y = textBlock(ctx, t('c.legalText'), X + 8, y + 12, W - 16, 17, { size: 11, serif: false, color: '#5c6772' }) + 18;

    /* ---- signatories in a triangle ---- */
    y += 24;
    ctx.textAlign = 'center';
    ctx.fillStyle = '#a8894b'; ctx.font = font(10, '700', false);
    ctx.fillText(t('c.signatories'), CERT_W / 2, y);
    y += 22;
    var triTop = y;
    function signatory(cx, cy, titleKey, subKey) {
      line(ctx, cx - 175, cy + 50, cx + 175, cy + 50, '#8c8574', 1);
      ctx.fillStyle = '#10263f'; ctx.font = font(14, '600', true);
      wrap(ctx, t(titleKey), 350).forEach(function (ln, i) { ctx.fillText(ln, cx, cy + 8 + i * 19); });
      ctx.fillStyle = '#5c6772'; ctx.font = font(10.5, '', false);
      ctx.fillText(t(subKey), cx, cy + 68);
      ctx.fillStyle = '#8c8574'; ctx.font = font(9.5, '', false);
      ctx.fillText('…………………………………………', cx, cy + 44);
    }
    signatory(320, triTop, 'g.ministryShort', 'c.registrar');
    signatory(920, triTop, 'g.chancelleryShort', 'c.registrar');
    var triBottom = triTop + 136;
    signatory(620, triBottom, 'g.securityShort', 'c.registrar');
    /* Three distinct statutory seals, one over each signatory's line. */
    drawSeals(ctx, triTop, triBottom);
    y = triBottom + 132;

    /* ---- footer ---- */
    line(ctx, X, y, CERT_W - X, y, '#b18b4c', 1.4);
    y += 22;
    ctx.textAlign = 'left'; ctx.fillStyle = '#5c6772';
    y = textBlock(ctx, t('g.footer'), X, y, W - 240, 16, { size: 10.5, serif: false, color: '#6b7280' });
    ctx.textAlign = 'right'; ctx.fillStyle = '#8c8574'; ctx.font = font(10, '', false);
    ctx.fillText(t('c.voidIfAltered') + '  ·  ' + t('c.page') + ' 1/1  ·  ' + (spec.code || ''), CERT_W - X, y + 4);
    ctx.textAlign = 'left'; ctx.fillStyle = '#a22121'; ctx.font = font(9.5, '700', false);
    ctx.fillText(t('c.seals'), X, y + 22);
    ctx.textAlign = 'center'; ctx.fillStyle = '#b7ae99'; ctx.font = font(9, '', false);
    ctx.fillText('VDL / ' + lang.toUpperCase() + ' / ' + digest.slice(0, 16).toUpperCase() + ' / ' + t('x.port'), CERT_W / 2, y + 46);

    return y + 95;
    }

    /* pass 1 — measure on a purposely oversized canvas */
    var probe = document.createElement('canvas');
    probe.width = CERT_W * SCALE; probe.height = 6000 * SCALE;
    var pctx = probe.getContext('2d'); pctx.scale(SCALE, SCALE);
    var finalY = draw(pctx, 6000);

    /* pass 2 — final instrument */
    var H = Math.ceil(finalY);
    var canvas = targetCanvas || document.createElement('canvas');
    canvas.width = CERT_W * SCALE; canvas.height = Math.ceil(H * SCALE);
    canvas.style.width = CERT_W + 'px'; canvas.style.height = H + 'px';
    var ctx = canvas.getContext('2d'); ctx.scale(SCALE, SCALE);
    draw(ctx, H);
    return canvas;
  }

  async function downloadCertificate(spec, targetCanvas) {
    var canvas = await renderCertificate(spec, targetCanvas);
    var name = (spec.code || 'VDL-INSTRUMENT') + '.png';
    return new Promise(function (resolve) {
      if (canvas.toBlob) {
        canvas.toBlob(function (blob) {
          var url = URL.createObjectURL(blob);
          var a = document.createElement('a');
          a.href = url; a.download = name; document.body.appendChild(a); a.click();
          setTimeout(function () { URL.revokeObjectURL(url); a.remove(); }, 1500);
          resolve(canvas);
        }, 'image/png');
      } else {
        var a2 = document.createElement('a');
        a2.href = canvas.toDataURL('image/png'); a2.download = name;
        document.body.appendChild(a2); a2.click(); a2.remove();
        resolve(canvas);
      }
    });
  }

  /* Six-language examination entries printed on identity / visa instruments.
     Stored as language objects so any terminal may redraw the instrument in
     the reader's own language. */
  function instrumentSteps(kind) {
    var pairs = kind === 'VISA'
      ? [['c.docNo','c.concl.visa'], ['g.subjectRef','i.verify.ok'],
         ['c.credential','cr.issued'], ['c.legal','c.legalText']]
      : [['g.subjectRef','i.verify.ok'], ['c.credential','cr.issued'],
         ['bio.title','bio.verified'], ['c.legal','c.legalText']];
    return pairs.map(function (p) {
      return { title: I.multilingual(p[0]), detail: I.multilingual(p[1]), status: 'COMPLETED' };
    });
  }

  function certSpecFromRecord(rec, langSnapshot) {
    return {
      kind: rec.kind, code: rec.code, ref: rec.ref, level: rec.level,
      grade: rec.grade, issuedAt: rec.issuedAt, ts: rec.ts,
      steps: rec.steps || [], subject: rec.subject || {}
    };
  }

  /* ------------------------------------------------------------
     10 · Shared official chrome
     ------------------------------------------------------------ */
  function crestSVG() {
    return '<svg class="crest" viewBox="0 0 76 92" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">' +
      '<path d="M6 8 H70 V50 Q70 78 38 90 Q6 78 6 50 Z" fill="#10263f" stroke="#b18b4c" stroke-width="2.4"/>' +
      '<path d="M38 8 V86 M6 36 H70" stroke="#b18b4c" stroke-width="11"/>' +
      '<path d="M38 8 V86 M6 36 H70" stroke="#10263f" stroke-width="4.5"/>' +
      '<path d="M8 6 L18 -6 L28 5 L38 -10 L48 5 L58 -6 L68 6 Z" fill="#b18b4c" transform="translate(0,12)" opacity="0"/>' +
      '<path d="M8 4 L18 -8 L28 3 L38 -12 L48 3 L58 -8 L68 4 Z" fill="#b18b4c" transform="translate(0,14)"/>' +
      '<circle cx="16" cy="8" r="2.6" fill="#b18b4c"/><circle cx="38" cy="2" r="2.6" fill="#b18b4c"/><circle cx="60" cy="8" r="2.6" fill="#b18b4c"/>' +
      '</svg>';
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function fmt(ms, withTime) {
    if (!ms) return '—';
    var d = new Date(ms);
    var p = function (n) { return ('0' + n).slice(-2); };
    var base = d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
    return withTime === false ? base : base + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }

  /* Registry of the four INDEPENDENT stations. Deliberately holds no
     address or href: no terminal may navigate to another. Each must be
     opened directly at its own address (see quickstart.bat). */
  var PAGES = [
    { id: 'portal',   key: 'g.portalShort' },
    { id: 'border',   key: 'g.borderShort' },
    { id: 'entry',    key: 'g.entryShort' },
    { id: 'interior', key: 'g.interiorShort' },
    { id: 'admin',    key: 'g.authorityShort' }
  ];
  var TERMINAL_NAME = {
    portal: 'g.portal', border: 'g.border', entry: 'g.entry',
    interior: 'g.interior', admin: 'g.authority'
  };

  function mastheadHTML(page) {
    var opts = I.langs().map(function (l) {
      return '<option value="' + l.id + '"' + (l.id === I.getLang() ? ' selected' : '') + '>' + esc(l.native) + '</option>';
    }).join('');
    return '<div class="masthead"><div class="masthead-inner">' + crestSVG() +
      '<div class="mast-titles">' +
        '<div class="state">' + esc(t('g.state')) + '</div>' +
        '<div class="body">' + esc(t('g.chancelleryShort')) + '</div>' +
        '<div class="sub">' + esc(t(TERMINAL_NAME[page] || 'g.portal')) + ' &nbsp;·&nbsp; ' + esc(t('g.motto')) + '</div>' +
      '</div>' +
      '<div class="mast-right">' +
        '<div class="langbox"><label>' + esc(t('g.lang')) + '</label><select class="langsel" data-langsel>' + opts + '</select></div>' +
        '<div class="terminal-badge"><span class="seal-dot"></span>' + esc(t('g.terminal')) + ' <b>' + esc(page.toUpperCase()) + '</b> · 7431</div>' +
      '</div></div></div>';
  }
  function subbarHTML(page, ref) {
    /* The four terminals are independent sealed stations. No cross-terminal
       navigation is exposed here: a terminal can only be reached by opening
       its own address. Only the identity of THIS station is displayed. */
    var own = PAGES.find(function (p) { return p.id === page; }) || PAGES[0];
    var label = '<a class="active" style="cursor:default" aria-disabled="true">' + esc(t(own.key)) + '</a>';
    var refLabel = page === 'admin'
      ? esc(t('g.authorityShort')) + ' · <b>MASTER / 1</b>'
      : esc(t('g.subjectRef')) + ': <b data-subref>' + esc(ref || getSession()) + '</b>';
    return '<div class="subbar"><div class="subbar-inner">' + label +
      '<div class="spacer"></div><div class="ref">' + refLabel + ' &nbsp;|&nbsp; ' +
      '<span class="flag-secure">' + esc(t('g.sealed')) + '</span></div></div></div>';
  }
  function footerHTML() {
    return '<div class="footer"><div class="orgs">' + esc(t('g.ministryShort')) + ' &nbsp;·&nbsp; ' +
      esc(t('g.chancelleryShort')) + ' &nbsp;·&nbsp; ' + esc(t('g.securityShort')) + '</div>' +
      '<div>' + esc(t('g.official')) + ' &nbsp;·&nbsp; ' + esc(t('g.version')) + ' 1.0 &nbsp;·&nbsp; ' + esc(t('x.port')) + '</div>' +
      '<div>' + esc(t('g.footer')) + '</div></div>';
  }

  var _renderFn = null;
  function init(page, renderFn) {
    if (global.location && /[?&]reset\b/.test(global.location.search || '')) {
      /* A bare query parameter must never destroy the sealed register on
         its own (a bookmark, a shared link or a mistyped URL would do it).
         Require an explicit confirmation in the current UI language. */
      var clean = (global.location.pathname || '/') + (global.location.hash || '');
      confirmDialog(t('a.reset'), esc(t('m.sys.purgeAsk')), function () {
        if (LS.reset) LS.reset();
        else { try {
          [global.localStorage, global.sessionStorage].forEach(function (store) {
            Object.keys(store || {}).forEach(function (k) {
              if (k.indexOf('vdl.v1.') === 0) { try { LS.removeItem(k); } catch (e) {} }
            });
          });
        } catch (e) {} }
        global.location.replace(clean);
      });
      /* Fall through: the page stays usable while the dialog is open. */
    }
    setTerminal(page.toUpperCase());
    _renderFn = renderFn || function () {};
    var mh = document.getElementById('masthead');
    var sb = document.getElementById('subbar');
    var ft = document.getElementById('footer');
    function paintChrome() {
      if (mh) mh.innerHTML = mastheadHTML(page);
      if (sb) sb.innerHTML = subbarHTML(page, getSession());
      if (ft) ft.innerHTML = footerHTML();
      var sel = document.querySelector('[data-langsel]');
      if (sel) sel.addEventListener('change', function () { I.setLang(this.value); });
    }
    /* The subbar shows the currently selected subject reference. A switch
       through "核验身份" (or a switch broadcast from another tab of this
       device) must refresh it as well, otherwise the header keeps showing
       the previous file number while the file card below already shows the
       new one. Only this one text node is touched: rebuilding the chrome on
       every register update would re-bind the language selector repeatedly. */
    function syncSubRef() {
      var el = document.querySelector('[data-subref]');
      if (!el) return;
      var r = getSession();
      if (el.textContent !== r) el.textContent = r;
    }
    paintChrome();
    global.addEventListener('vdl:lang', function () { paintChrome(); _renderFn(); });
    Vault.on(function () { syncSubRef(); _renderFn(); });
    /* Real-time cross-terminal sync: poll the on-disk register revision. */
    LS.startSync();
    LS.onExternalChange(function () {
      var sl = LS.getItem('vdl.v1.lang');
      if (sl && I.IDX && I.IDX[sl] !== undefined && sl !== I.getLang()) I.applyLang(sl);
      fire();
    });
    return { paintChrome: paintChrome, refresh: function () { _renderFn(); } };
  }

  function toast(msg, kind) {
    var el = document.querySelector('.toast');
    if (!el) {
      el = document.createElement('div'); el.className = 'toast'; document.body.appendChild(el);
    }
    el.className = 'toast on' + (kind ? ' ' + kind : '');
    el.textContent = msg;
    clearTimeout(el._timer);
    el._timer = setTimeout(function () { el.className = 'toast'; }, 3600);
  }
  function confirmDialog(title, body, onYes) {
    var mask = document.getElementById('vdl-modal');
    if (!mask) {
      mask = document.createElement('div'); mask.id = 'vdl-modal'; mask.className = 'modal-mask';
      mask.innerHTML = '<div class="modal"><div class="mh"><h3 data-mt></h3><button class="xbtn" data-mx>×</button></div>' +
        '<div class="mb" data-mb></div><div class="mf"><button class="btn secondary" data-mc></button><button class="btn danger" data-my></button></div></div>';
      document.body.appendChild(mask);
    }
    mask.querySelector('[data-mt]').textContent = title;
    mask.querySelector('[data-mb]').innerHTML = body;
    mask.querySelector('[data-mc]').textContent = t('a.cancel');
    mask.querySelector('[data-my]').textContent = t('a.confirm');
    mask.classList.add('on');
    function close() { mask.classList.remove('on'); }
    mask.querySelector('[data-mx]').onclick = close;
    mask.querySelector('[data-mc]').onclick = close;
    mask.onclick = function (e) { if (e.target === mask) close(); };
    mask.querySelector('[data-my]').onclick = function () { close(); onYes && onYes(); };
  }
  function modal(title, bodyHTML, buttons) {
    var mask = document.getElementById('vdl-modal');
    if (!mask) {
      mask = document.createElement('div'); mask.id = 'vdl-modal'; mask.className = 'modal-mask';
      mask.innerHTML = '<div class="modal"><div class="mh"><h3 data-mt></h3><button class="xbtn" data-mx>×</button></div>' +
        '<div class="mb" data-mb></div><div class="mf" data-mf></div></div>';
      document.body.appendChild(mask);
    }
    mask.querySelector('[data-mt]').textContent = title;
    mask.querySelector('[data-mb]').innerHTML = bodyHTML;
    var mf = mask.querySelector('[data-mf]');
    mf.innerHTML = '';
    (buttons || []).forEach(function (b) {
      var btn = document.createElement('button');
      btn.className = 'btn ' + (b.cls || 'secondary'); btn.textContent = b.label;
      btn.onclick = function () { if (b.close !== false) mask.classList.remove('on'); b.onClick && b.onClick(); };
      mf.appendChild(btn);
    });
    mask.classList.add('on');
    mask.querySelector('[data-mx]').onclick = function () { mask.classList.remove('on'); };
    mask.onclick = function (e) { if (e.target === mask) mask.classList.remove('on'); };
    return mask;
  }
  function closeModal() {
    var m = document.getElementById('vdl-modal'); if (m) m.classList.remove('on');
  }

  /* ------------------------------------------------------------
     10b · Inspection runner (shared by Frontier and Interior)
     Emits only Chancellery-bound envelopes; reads only the sealed
     broadcast of the canonical register.
     ------------------------------------------------------------ */
  function mountInspectionRunner(root, opts) {
    opts = opts || {};
    var levels = opts.levels || ['R'];
    var page = opts.page || 'BORDER';
    var KEY = 'vdl.v1.runner.' + page;
    var GK = 'vdl.v1.runner.' + page + '.graded';
    /* Per device AND per terminal AND per TAB. Opening a second tab of the
       same station on one device must neither see nor retire the first
       tab's walk; opening the Interior station must not touch a Frontier
       walk either. Old builds keyed this by device + terminal only. */
    var TAB = tabId();
    tabRegister(TAB);
    var ACTIVE_KEY = ACTIVE_PREFIX + deviceId() + '.' + page + '.' + TAB;
    var LEGACY_ACTIVE_KEY = ACTIVE_PREFIX + deviceId() + '.' + page;
    var ACTIVE_FLAG = KEY + '.active';
    var INTERRUPT_FLAG = KEY + '.interrupted';
    var st = {
      refInput: '', ref: null, verified: false, subject: null,
      level: levels[0], protocol: [], idx: 0, attested: false,
      running: false, finished: false, outcome: null, grade: null,
      certCode: null, issuedAt: null, ts: null, steps: [], purpose: '',
      activeId: null, startedAt: null, log: []
    };
    var currentState = null;

    /* Synchronous tab-local flags survive a reload, and a shared "in
       progress" marker survives the tab going away. Routing through LS
       (rather than touching localStorage directly) is what keeps these
       flags in sessionStorage, private to this tab. Neither uses a timer:
       a walk can run indefinitely as long as the connection stays up. */
    function localFlagSet(k, on) {
      try {
        if (on) LS.setItem(k, '1');
        else LS.removeItem(k);
      } catch (e) {}
    }
    function localFlag(k) {
      try { return !!LS.getItem(k); } catch (e) { return false; }
    }
    function clearActive() {
      try { LS.removeItem(ACTIVE_KEY); } catch (e) {}
      localFlagSet(ACTIVE_FLAG, false);
      localFlagSet(INTERRUPT_FLAG, false);
    }
    function writeActive() {
      sealBroadcast({
        id: st.activeId, ref: st.ref, level: st.level, purpose: st.purpose,
        startedAt: st.startedAt, steps: (st.protocol || []).length,
        subject: st.subject || {}, page: page, tab: TAB
      }).then(function (env) {
        LS.setItem(ACTIVE_KEY, JSON.stringify(env));
      }).catch(function () {});
    }

    function gradedSet() { try { return JSON.parse(LS.getItem(GK) || '{}'); } catch (e) { return {}; } }
    function markGraded(c) { var g = gradedSet(); g[c] = true; try { LS.setItem(GK, JSON.stringify(g)); } catch (e) {} }
    function save() {
      sealBroadcast(st).then(function (env) {
        try { LS.setItem(KEY, JSON.stringify(env)); } catch (e) {}
      }).catch(function () {});
    }
    function restore() {
      try {
        var env = JSON.parse(LS.getItem(KEY) || 'null');
        if (!env) return Promise.resolve();
        return openBroadcast(env).then(function (o) {
          if (o && o.ref) Object.keys(st).forEach(function (k) { if (o[k] !== undefined) st[k] = o[k]; });
        }).catch(function () {});
      } catch (e) { return Promise.resolve(); }
    }

    /* Inspection quota: the Chancellery issues a pending inspection task for
       a level, or the subject holds a standing entitlement (citizenship).
       Without either, the terminal must refuse to start the walk. */
    function quotaFor(s, ref) {
      if (!s || !ref || !s.subjects[ref]) return { ok: false, reason: 'unknown' };
      var pend = ((s.pending || {})[ref] || []).filter(function (p) {
        return !p.done && levels.indexOf(p.level) >= 0;
      });
      if (pend.length) {
        return { ok: true, level: pend[0].level, purpose: pend[0].purpose, reason: 'task' };
      }
      var cred = s.subjects[ref].credential;
      if (cred === 'CITIZEN') {
        return { ok: true, level: levels[0], purpose: 'GENERAL', reason: 'citizen' };
      }
      return { ok: false, reason: 'noTask' };
    }

    function snapSubject(s, ref) {
      var x = s.subjects[ref];
      if (!x) return null;
      var i = x.identity || {};
      return {
        name: i.name || [i.surname, i.given].filter(Boolean).join(' ') || '—',
        dob: i.dob || '—',
        nationality: i.nationality || i.natCurrent || '—',
        passportNo: i.passportNo || '—',
        address: i.address || '—',
        credentialLabel: t(x.credential === 'NONE' ? 'cr.none' : x.credential === 'CITIZEN' ? 'cr.CITIZEN' : 'cr.' + x.credential),
        credentialCode: x.credentialCode || '—',
        nationalId: x.nationalId || '—',
        credential: x.credential
      };
    }

    function certSpec(grade) {
      return {
        kind: 'CLEARANCE', code: st.certCode, ref: st.ref, level: st.level,
        grade: grade === undefined ? st.grade : grade,
        issuedAt: st.issuedAt, ts: st.ts || tsRecord(st.issuedAt || now()),
        steps: st.steps.slice(), subject: st.subject || {}
      };
    }
    function download(grade) {
      return downloadCertificate(certSpec(grade)).then(function () {
        V_toast(t('i.certReady'), 'good');
      });
    }
    /* local alias avoids a dependency on UI.toast being initialised */
    function V_toast(msg, kind) {
      if (global.Vidland && global.Vidland.toast) global.Vidland.toast(msg, kind);
    }

    function sync() {
      return synchronise().then(function (s) {
        currentState = s;
        st.protocol = (s.protocol && s.protocol[st.level]) || [];
        if (st.ref && s.subjects[st.ref]) {
          st.verified = true;
          st.subject = snapSubject(s, st.ref);
        }
        /* Level M: a grade returned by the Chancellery triggers the instrument. */
        if (st.finished && st.level === 'M' && st.certCode && !st.grade) {
          var rec = s.certificates.find(function (c) { return c.code === st.certCode; });
          if (rec && rec.status === 'VALID' && rec.grade) {
            st.grade = rec.grade; save();
            var g = gradedSet();
            if (!g[st.certCode]) { markGraded(st.certCode); download(rec.grade); }
          }
        }
        paint();
      });
    }

    function paint() {
      if (!root) return;
      var s = currentState || {};
      var pending = st.ref && s.pending ? (s.pending[st.ref] || []).filter(function (p) { return !p.done; }) : [];
      var h = '';

      /* Identity attestation is the FIRST checkpoint of the inspection walk,
         not a separate form. See the auth stage below. */

      /* --- level selector --- */
      if (levels.length > 1) {
        h += '<div class="doc"><div class="doc-head"><div><div class="kicker">' + esc(t('g.securityShort')) +
          '</div><h2>' + esc(t('i.selectLevel')) + '</h2></div></div><div class="doc-body">' +
          '<div class="tabs">' + levels.map(function (lv) {
            return '<button data-ir="level" data-lv="' + lv + '" class="' + (st.level === lv ? 'on' : '') + '">' +
              esc(t('i.level.' + lv)) + '</button>';
          }).join('') + '</div>' +
          (!(st.protocol || []).length
            ? '<div class="notice warn"><span class="ttl">' + esc(t('i.noProtocolShort')) + '</span>' +
              esc(t('i.noProtocolSub')) + '</div>'
            : '');
        if (pending.length) h += '<div class="notice info"><span class="ttl">' + esc(t('i.pendingHint')) + '</span>' +
          pending.map(function (p) { return esc(t('i.level.' + p.level)) + ' · ' + esc(p.purpose); }).join(' &nbsp;|&nbsp; ') + '</div>';
        h += '</div></div>';
      } else if (pending.length) {
        /* Single-level terminals already display the level definition in the
           page letterhead — do not repeat it here. */
        h += '<div class="doc"><div class="doc-body"><div class="notice info"><span class="ttl">' +
          esc(t('i.pendingHint')) + '</span>' +
          pending.map(function (p) { return esc(t('i.level.' + p.level)) + ' · ' + esc(p.purpose); }).join(' &nbsp;|&nbsp; ') +
          '</div></div></div>';
      }

      /* --- runner : identity attestation is checkpoint 1, prescribed steps
         follow as checkpoints 2..N. Forward-only. --- */
      var proto = st.protocol || [];
      var quota = quotaFor(s, st.ref);
      var authed = st.verified && quota.ok;
      function railStatus(i) {
        if (st.finished) return (st.steps[i] && st.steps[i].status === 'ABORTED') ? 'aborted' : 'done';
        if (st.running) return i < st.idx ? 'done' : (i === st.idx ? 'active' : 'locked');
        return 'locked';
      }
      var rail = '<div class="walk-rail">';
      rail += '<div class="cp ' + (authed ? 'done' : 'active') + '"><span class="cp-n">' +
        (authed ? '✓' : '1') + '</span><span class="cp-l">' + esc(t('i.auth.title')) + '</span></div>';
      if (!proto.length) {
        rail += '<span class="cp-line"></span><div class="cp locked"><span class="cp-n">—</span>' +
          '<span class="cp-l">' + esc(t('i.noProtocol')) + '</span></div>';
      } else {
        proto.forEach(function (sp, i) {
          rail += '<span class="cp-line ' + (authed && (i <= st.idx || st.finished) ? 'on' : '') + '"></span>';
          var rs = authed ? railStatus(i) : 'locked';
          rail += '<div class="cp ' + rs + '"><span class="cp-n">' +
            (rs === 'done' ? '✓' : (rs === 'aborted' ? '!' : (i + 2))) + '</span>' +
            '<span class="cp-l">' + esc(L(sp.title)) + '</span></div>';
        });
      }
      rail += '</div>';

      h += '<div class="doc"><div class="doc-head"><div><div class="kicker">' + esc(t('g.securityShort')) +
        '</div><h2>' + esc(t('i.level.' + st.level)) + '</h2>' +
        '<div class="sub">' + esc(t('i.auto')) + '</div></div>' +
        '<span class="badge ' + (st.running ? 'pending' : st.finished ? (st.grade === 'FAIL' || st.outcome === 'ABORTED' ? 'bad' : 'ok') : 'neutral') + '">' +
        esc(st.running ? t('s.inProgress') : st.finished ? (st.outcome === 'ABORTED' ? t('s.aborted') : st.level === 'M' && !st.grade ? t('s.awaitingGrade') : t('s.cleared'))
          : (st.protocol || []).length ? t('s.ready') : t('i.noProtocolShort')) +
        '</span></div><div class="doc-body">';

      h += rail;
      h += '<div class="walk">';

      /* Checkpoint 1: identity attestation + quota decision. */
      if (!st.verified && !st.running && !st.finished) {
        h += '<div class="walk-stage check">' +
          '<div class="walk-counter">' + esc(t('i.checkpoint')) + ' · 1 ' + esc(t('i.of')) + ' ' + (proto.length + 1) + '</div>' +
          '<h2 class="walk-title">' + esc(t('i.auth.title')) + '</h2>' +
          '<div class="walk-body body-text">' + esc(t('i.auth.intro')) + '</div>' +
          '<div class="fields mt" style="grid-template-columns:1fr"><div class="field">' +
          '<label>' + esc(t('i.verify.input')) + '</label>' +
          '<input data-ir="ref" value="' + esc(st.refInput) + '" placeholder="VDL-SUB-XXXX-XXXX-XX"></div></div>' +
          '<div class="walk-foot"><button class="btn gold" data-ir="verify">' + esc(t('i.auth.submit')) + '</button></div>' +
          (st.ref ? '<div class="notice bad mt"><span class="ttl">' + esc(t('i.auth.failed')) + '</span>' +
            esc(t('i.verify.fail')) + '</div>' : '') +
          '</div>';
      } else if (st.verified && !quota.ok && !st.running && !st.finished) {
        h += '<div class="walk-stage check">' +
          '<div class="walk-counter">' + esc(t('i.checkpoint')) + ' · 1</div>' +
          '<h2 class="walk-title">' + esc(t('i.auth.noQuotaTitle')) + '</h2>' +
          '<div class="walk-body body-text">' + esc(t('i.auth.noQuota')) + '</div>' +
          '<div class="hairline"></div><div class="kv">' +
          [[t('g.subjectRef'), st.ref], [t('p.file.name'), st.subject ? st.subject.name : '—'],
           [t('i.verify.credential'), st.subject ? st.subject.credentialLabel : '—']].map(function (r) {
            return '<div class="k">' + esc(r[0]) + '</div><div class="v">' + esc(r[1]) + '</div>';
          }).join('') + '</div>' +
          '<div class="walk-foot"><button class="btn secondary sm" data-ir="unverify">' + esc(t('i.auth.retry')) + '</button></div>' +
          '</div>';
      } else if (!proto.length) {
        h += '<div class="walk-stage"><div class="empty"><span class="big">§</span>' + esc(t('i.noProtocol')) +
          '<br>' + esc(t('i.noProtocolSub')) + '</div></div>';
      } else if (st.finished) {
        var resTitle = st.outcome === 'ABORTED' ? t('s.aborted')
          : (st.level === 'M' && !st.grade ? t('s.awaitingGrade') : t('s.cleared'));
        var resMsg = st.outcome === 'ABORTED' ? t('i.aborted') : st.level === 'M' ? t('i.awaitGrade') : t('i.cleared');
        h += '<div class="walk-stage result">' +
          '<div class="kicker">' + esc(t('i.level.' + st.level)) + ' · ' + esc(t('c.sec3')) + '</div>' +
          '<h2 class="walk-title">' + esc(resTitle) + '</h2>' +
          '<div class="walk-body body-text">' + esc(resMsg) + '</div>';
        if (st.level === 'M' && st.grade) h += '<div class="notice info mt"><span class="ttl">' +
          esc(t('i.gradeReturned')) + '</span>' + esc(t('o.grade.' + String(st.grade).toLowerCase())) + '</div>';
        if (st.certCode) h += '<div class="kv mt"><div class="k">' + esc(t('c.docNo')) + '</div><div class="v mono">' + esc(st.certCode) + '</div>' +
          '<div class="k">' + esc(t('c.timeDetail')) + '</div><div class="v mono">' + esc(st.ts ? st.ts.iso : fmt(st.issuedAt)) + '</div></div>';
        h += '<div class="walk-foot">' +
          '<button class="btn secondary sm" data-ir="download"' + (st.level === 'M' && !st.grade ? ' disabled' : '') + '>' + esc(t('a.reissue')) + '</button>' +
          '<button class="btn sm" data-ir="restart">' + esc(t('i.restart')) + '</button>' +
          '</div></div>';
      } else if (!st.running) {
        h += '<div class="walk-stage lobby">' +
          '<div class="kicker">' + esc(t('i.level.' + st.level)) + ' · ' + esc(t('i.auth.done')) + '</div>' +
          '<h2 class="walk-title">' + esc(t('i.walkIntroTitle')) + '</h2>' +
          '<div class="walk-body body-text">' + esc(t('i.walkIntro')) + '</div>';
        if (st.subject) {
          h += '<div class="kv mt">' +
            [[t('g.subjectRef'), st.ref], [t('p.file.name'), st.subject.name],
             [t('p.file.dob'), st.subject.dob], [t('p.file.nationality'), st.subject.nationality],
             [t('f.passportNo'), st.subject.passportNo],
             [t('i.verify.credential'), st.subject.credentialLabel]].map(function (r) {
              return '<div class="k">' + esc(r[0]) + '</div><div class="v">' + esc(r[1]) + '</div>';
            }).join('') + '</div>';
        }
        h += '<div class="walk-foot">' +
          '<button class="btn gold" data-ir="start">' + esc(t('i.start')) + '</button>' +
          '<button class="btn secondary sm" data-ir="unverify">' + esc(t('i.auth.retry')) + '</button>' +
          '</div>' +
          '<div class="small muted walk-note">' + esc(t('i.walkForwardNote')) + '</div>' +
          '</div>';
      } else {
        var sp2 = proto[st.idx];
        var isLast = st.idx >= proto.length - 1;
        h += '<div class="walk-stage check">' +
          '<div class="walk-counter">' + esc(t('i.checkpoint')) + ' · ' + esc(t('i.step')) + ' ' + (st.idx + 1) + ' ' + esc(t('i.of')) + ' ' + proto.length + '</div>' +
          '<h2 class="walk-title">' + esc(L(sp2.title)) + '</h2>' +
          '<div class="walk-body body-text">' + esc(L(sp2.detail)) + '</div>' +
          '<label class="checkline-lg"><input type="checkbox" data-ir="attest"' + (st.attested ? ' checked' : '') + '>' +
          '<span>' + esc(t('i.attest')) + '</span></label>' +
          '<div class="walk-foot">' +
          '<button class="btn" data-ir="confirm">' + esc(isLast ? t('i.complete') : t('a.next')) +
            (isLast ? '' : ' <span class="next-name">· ' + esc(L(proto[st.idx + 1].title)) + '</span>') + '</button>' +
          '<button class="btn danger sm" data-ir="abort">' + esc(t('i.abort')) + '</button>' +
          '</div></div>';
      }

      h += '</div>';
      h += '</div><div class="doc-foot"><span>' + esc(t('i.auto')) + '</span><span class="docnum">' +
        esc(st.level) + ' / ' + proto.length + ' ' + esc(t('m.proto.steps')) + '</span></div></div>';


      root.innerHTML = h;
    }

    /* --- actions --- */
    function verify() {
      var v = String(st.refInput || '').trim().toUpperCase();
      if (!v) { V_toast(t('i.verify.fail'), 'bad'); return; }
      st.ref = v;
      synchronise().then(function (s) {
        if (!s.subjects[v]) {
          st.verified = false; st.subject = null; save(); paint();
          V_toast(t('i.verify.fail'), 'bad'); return;
        }
        st.verified = true; st.subject = snapSubject(s, v);
        var q = quotaFor(s, v);
        if (q.ok) {
          /* Only auto-select a level when a task was explicitly issued. */
          if (q.reason === 'task') { st.level = q.level; st.purpose = q.purpose; }
          else { st.purpose = q.purpose; }
          V_toast(t('i.auth.quotaOk'), 'good');
        } else {
          V_toast(t('i.auth.noQuotaTitle'), 'bad');
        }
        st.protocol = (s.protocol && s.protocol[st.level]) || [];
        save(); paint();
      });
    }
    function start() {
      if (!st.verified) { V_toast(t('i.auth.title'), 'bad'); return; }
      var q = quotaFor(currentState, st.ref);
      if (!q.ok) { V_toast(t('i.auth.noQuotaTitle'), 'bad'); paint(); return; }
      st.protocol = ((currentState && currentState.protocol) || {})[st.level] || [];
      if (!st.protocol.length) { V_toast(t('i.noProtocol'), 'bad'); return; }
      var pend = ((currentState && currentState.pending) || {})[st.ref] || [];
      var p = pend.filter(function (x) { return !x.done && x.level === st.level; }).pop();
      st.purpose = p ? p.purpose : 'GENERAL';
      st.running = true; st.finished = false; st.idx = 0; st.attested = false;
      st.steps = []; st.grade = null; st.certCode = null; st.outcome = null;
      st.activeId = uid('INA'); st.startedAt = now();
      st.subject = snapSubject(currentState, st.ref);
      localFlagSet(ACTIVE_FLAG, true);
      localFlagSet(INTERRUPT_FLAG, false);
      writeActive();
      save(); paint();
    }
    function confirmStep() {
      if (!st.attested) { V_toast(t('i.attest'), 'bad'); return; }
      var sp = st.protocol[st.idx];
      st.steps.push({ title: Object.assign({}, sp.title), detail: Object.assign({}, sp.detail),
        status: 'COMPLETED', at: now() });
      st.attested = false; st.idx++;
      if (st.idx >= st.protocol.length) finish(st.level === 'M' ? 'PENDING_GRADE' : 'CLEARED');
      else { save(); paint(); }
    }
    function abort() {
      var sp = st.protocol[st.idx];
      if (sp) st.steps.push({ title: Object.assign({}, sp.title), detail: Object.assign({}, sp.detail),
        status: 'ABORTED', at: now() });
      finish('ABORTED');
    }
    function finish(outcome, forcedCode, reason) {
      st.running = false; st.finished = true; st.outcome = outcome;
      st.issuedAt = now(); st.ts = tsRecord(st.issuedAt);
      st.certCode = forcedCode || code('VDL-SEC-' + st.level);
      st.grade = outcome === 'CLEARED' ? 'PASS' : outcome === 'ABORTED' ? 'FAIL' : null;
      var meta = {
        type: 'INSPECTION', id: uid('INS'), ref: st.ref, level: st.level,
        purpose: st.purpose, outcome: outcome, certCode: st.certCode,
        steps: st.steps.slice(), subject: st.subject, ts: st.ts, at: st.issuedAt,
        interrupted: !!reason, interruptReason: reason || null
      };
      /* A submitted finding is the ONLY thing that retires the marker. */
      clearActive();
      save();
      var submitted = Vault.submit(meta,
        Object.assign({}, meta, { terminal: page, protocolLength: st.protocol.length }))
        .then(function () {
          sync();
          if (outcome !== 'PENDING_GRADE') download(st.grade);
          else V_toast(t('i.awaitGrade'), 'good');
          /* The instrument is produced on this device. If the register is
             unreachable, do not let a local "cleared" screen imply that the
             Authority has already received the record. */
          setTimeout(function () {
            try {
              var S = global.VidlandStore;
              if (S && S.isOnline && (!S.isOnline() || (S.pendingWrites && S.pendingWrites() > 0))) {
                V_toast(t('i.pendingFiling'), 'bad');
              }
            } catch (e) {}
          }, 500);
        });
      paint();
      return submitted;
    }
    /* An inspection that started but never submitted a finding is a FAIL,
       whatever stopped it: lost connection, server outage, reload, closed
       tab, killed process or the operator abandoning the walk. The code is
       derived from the active record id, so replaying the finding is
       idempotent even when several terminals detect the same interruption. */
    function failInterrupted(reason, record) {
      if (st.finished) return Promise.resolve();
      var sp = (st.protocol || [])[st.idx];
      if (sp) st.steps.push({ title: Object.assign({}, sp.title),
        detail: Object.assign({}, sp.detail), status: 'ABORTED', at: now() });
      st.running = false;
      if (record) {
        if (!st.ref && record.ref) st.ref = record.ref;
        if (record.level) st.level = record.level;
        if (record.subject) st.subject = record.subject;
        if (record.purpose) st.purpose = record.purpose;
      }
      var rid = (record && record.id) || st.activeId || ('T' + (st.startedAt || now()));
      var forced = 'VDL-SEC-' + st.level + '-ABORT-' + rid;
      V_toast(t('i.aborted'), 'bad');
      return finish('ABORTED', forced, reason);
    }
    /* Another tab of this station was closed or killed before submitting.
       Its marker is still in the shared register, but its runner snapshot
       lived in that tab's sessionStorage and is gone. File the FAIL finding
       through the ordinary uplink WITHOUT importing that walk into this
       tab's state, then retire only that one marker. The document number is
       derived from the abandoned record id, so a retry is idempotent
       (alreadyApplied() matches on certCode). */
    function retireOrphan(key, env) {
      return openBroadcast(env).catch(function () { return null; }).then(function (rec) {
        if (!rec) {
          try { LS.removeItem(key); } catch (e) {}
          return;
        }
        var level = rec.level || levels[0];
        var rid = rec.id || ('T' + (rec.startedAt || now()));
        var at = now();
        var meta = {
          type: 'INSPECTION', id: uid('INS'), ref: rec.ref || '', level: level,
          purpose: rec.purpose || 'GENERAL', outcome: 'ABORTED',
          certCode: 'VDL-SEC-' + level + '-ABORT-' + rid,
          steps: [], subject: rec.subject || {}, ts: tsRecord(at), at: at,
          interrupted: true, interruptReason: 'interrupted'
        };
        return Vault.submit(meta, Object.assign({}, meta, {
          terminal: page, protocolLength: rec.steps || 0, retiredTab: rec.tab || null
        })).then(function () {
          try { LS.removeItem(key); } catch (e) {}
        }).catch(function (e) {
          /* Leave the marker in place: the next page load retries, and the
             derived document number prevents a duplicate finding. */
          console.warn('[Inspection] abandoned walk not yet filed', e);
        });
      });
    }
    function restart() {
      clearActive();
      st.running = false; st.finished = false; st.outcome = null; st.grade = null;
      st.certCode = null; st.issuedAt = null; st.ts = null; st.steps = [];
      st.activeId = null; st.startedAt = null;
      st.idx = 0; st.attested = false; st.log = [];
      save(); paint();
    }

    root.addEventListener('click', function (e) {
      var el = e.target.closest('[data-ir]'); if (!el) return;
      var a = el.dataset.ir;
      if (a === 'verify') verify();
      else if (a === 'unverify') { st.ref = null; st.refInput = ''; st.verified = false; st.subject = null; restart(); }
      else if (a === 'level' && !st.running) {
        var nextLv = el.dataset.lv;
        if (nextLv !== st.level) {
          st.level = nextLv;
          st.protocol = ((currentState && currentState.protocol) || {})[st.level] || [];
          /* A finding belongs to the level that produced it. Switching
             levels must not keep showing the previous level's result,
             certificate number and grade. */
          restart();
        }
        save(); paint();
      }
      else if (a === 'start') start();
      else if (a === 'confirm') confirmStep();
      else if (a === 'abort') confirmDialog(t('i.abort'), esc(t('i.abortConfirm')), abort);
      else if (a === 'restart') {
        /* Restarting an unfinished walk is itself an interruption. */
        if (st.running && !st.finished) failInterrupted('restart');
        else restart();
      }
      else if (a === 'download') download(st.grade);
    });
    root.addEventListener('input', function (e) {
      if (e.target.dataset.ir === 'ref') st.refInput = e.target.value;
      if (e.target.dataset.ir === 'attest') st.attested = e.target.checked;
    });
    root.addEventListener('change', function (e) {
      if (e.target.dataset.ir === 'attest') st.attested = e.target.checked;
    });
    Vault.on(function () { sync(); });
    global.addEventListener('vdl:lang', function () { paint(); });

    /* ---- interruption detection -------------------------------------
       No timers, no heartbeat, no background/visibility rules: switching
       tabs, locking the screen or taking a long time is fine as long as the
       register stays reachable. Only a broken connection, a server outage
       or the page going away counts as "stopped before submitting". */
    function onInterrupted(reason) {
      if (!st.running || st.finished) return;
      localFlagSet(INTERRUPT_FLAG, true);
      failInterrupted(reason);
    }
    global.addEventListener('offline', function () { onInterrupted('offline'); });
    global.addEventListener('pagehide', function () {
      if (st.running && !st.finished) localFlagSet(INTERRUPT_FLAG, true);
      tabUnregister(TAB);
    });
    /* A page restored from the back/forward cache did not re-run mount;
       re-declare this tab as live so another tab does not mistake its
       marker for an abandoned walk. This is a lifecycle event, not a
       heartbeat, and it does not start or reset any inspection timer. */
    global.addEventListener('pageshow', function () { tabRegister(TAB); });
    global.addEventListener('vdl:sync', function (e) {
      if (e && e.detail && e.detail.kind === 'offline') onInterrupted('connection');
    });

    restore().then(function () {
      if (levels.indexOf(st.level) < 0) st.level = levels[0];
      return sync();
    }).then(function () {
      /* Enumerate every in-progress marker this device left on this station
         in the shared register. Each tab owns exactly one key. */
      var prefix = ACTIVE_PREFIX + deviceId() + '.' + page + '.';
      var keys = [];
      try {
        keys = LS.keys ? LS.keys() : (function () {
          var a = [], i, k;
          for (i = 0; i < LS.length; i++) { k = LS.key(i); if (k) a.push(k); }
          return a;
        })();
      } catch (e) {}
      var mineKey = null, mineEnv = null, orphans = [];
      keys.forEach(function (k) {
        /* Pre-tab builds wrote one device+terminal marker. No live page
           uses that shape any more, so it is always an abandoned walk. */
        if (k === LEGACY_ACTIVE_KEY) {
          orphans.push({ key: k, env: rawGet(k, null) });
          return;
        }
        if (k.indexOf(prefix) !== 0) return;
        var tid = k.slice(prefix.length);
        var env = null;
        try { env = rawGet(k, null); } catch (e) {}
        if (tid === TAB) { mineKey = k; mineEnv = env; }
        else if (!tabAlive(tid)) orphans.push({ key: k, env: env });
        /* A tab still registered as live is running its own walk: leave
           both its marker and its progress completely alone. */
      });

      var steps = [];
      /* A completed walk may leave a stale marker if the process died just
         after finishing; retire OUR OWN marker instead of issuing a second
         FAIL. Never clear another tab's marker here. */
      if (st.finished) {
        steps.push(function () {
          /* clearActive() removes exactly ACTIVE_KEY (this tab's key) and
             this tab's flags; it cannot touch another tab's marker. */
          if (mineKey || localFlag(ACTIVE_FLAG) || localFlag(INTERRUPT_FLAG)) clearActive();
        });
      } else {
        var interrupted = st.running || localFlag(INTERRUPT_FLAG) ||
                          localFlag(ACTIVE_FLAG) || !!mineKey;
        if (interrupted) {
          steps.push(function () {
            var recP = mineEnv ? openBroadcast(mineEnv).catch(function () { return null; })
                              : Promise.resolve(null);
            return recP.then(function (rec) {
              return failInterrupted('interrupted', rec);
            }).then(function () { return sync(); });
          });
        }
      }
      /* Abandoned walks from other tabs are filed as FAIL findings too,
         without pulling their progress into this tab's runner. */
      orphans.forEach(function (o) {
        steps.push(function () {
          if (o.env) return retireOrphan(o.key, o.env);
          try { LS.removeItem(o.key); } catch (e) {}
          return Promise.resolve();
        });
      });
      /* Serialise: each Vault.submit() runs a synchronise() pass, and an
         already-filed certCode must be visible before the next one is
         derived. */
      return steps.reduce(function (p, fn) { return p.then(fn); }, Promise.resolve());
    });
    return { sync: sync, paint: paint, state: st };
  }

  /* ------------------------------------------------------------
     11 · Public surface
     ------------------------------------------------------------ */
  global.Vidland = {
    /* crypto */
    sealBroadcast: sealBroadcast, openBroadcast: openBroadcast,
    sealForChancellery: sealForChancellery, openForChancellery: openForChancellery,
    registerAuthorityOpener: registerAuthorityOpener, digestHex: digestHex,
    publicJwk: PUBLIC_JWK, port: PORT,
    /* store */
    Vault: Vault, synchronise: synchronise,
    getSession: getSession, setSession: setSession, clearSession: clearSession,
    /* logic */
    ORDER: ORDER, FLOW: FLOW, CREDENTIAL_FOR: CREDENTIAL_FOR, INSPECTION_FOR: INSPECTION_FOR,
    REQUIRES: REQUIRES, CRED_RANK: CRED_RANK, LAN: LAN,
    appsFor: appsFor, certsFor: certsFor, subject: subject, credential: credential,
    nextStage: nextStage, isEligible: isEligible, stageState: stageState,
    leapState: leapState, oathState: oathState,
    /* forms */
    FIELDS: FIELDS, SECTIONS: SECTIONS, SPECIFIC: SPECIFIC,
    buildForm: buildForm, renderForm: renderForm, mountBiometrics: mountBiometrics,
    mountInspectionRunner: mountInspectionRunner,
    /* instruments */
    renderCertificate: renderCertificate, downloadCertificate: downloadCertificate,
    certSpecFromRecord: certSpecFromRecord, instrumentSteps: instrumentSteps, tsRecord: tsRecord,
    /* chrome */
    init: init, toast: toast, esc: esc, fmt: fmt, modal: modal, closeModal: closeModal,
    confirmDialog: confirmDialog, crestSVG: crestSVG,
    /* misc */
    code: code, uid: uid, rand: rand, now: now, terminalId: terminalId,
    t: t, L: L
  };

  /* ------------------------------------------------------------
     12 · Local erasure when access is cut
     ------------------------------------------------------------
     vidland-store.js drops its decrypted mirror and pending writes on a
     403 and emits vdl:purge. Every terminal must also remove data that is
     ALREADY rendered. On admin / entry the audit gate draws its own opaque
     panel, so leave that node alone; on the three civil terminals replace
     the whole body with a content-free notice. */
  global.addEventListener('vdl:purge', function () {
    /* Drop the derived keys as well as the DOM: after a cut nothing in
       this JS context may still be able to decrypt the register. */
    _seedPurged = true;
    BROADCAST_SEED = null;
    _broadcastKey = null;
    try {
      if (!global.document || !global.document.body) return;
      var body = global.document.body;
      if (global.document.getElementById('vdl-audit-gate')) return;
      Array.prototype.slice.call(body.children).forEach(function (el) {
        try { body.removeChild(el); } catch (e) {}
      });
      var cover = global.document.createElement('div');
      cover.setAttribute('style',
        'position:fixed;inset:0;z-index:2147483647;background:#081420;' +
        'color:#e8edf3;display:flex;align-items:center;justify-content:center;' +
        'padding:24px;font:14px/1.7 system-ui,-apple-system,"Segoe UI",sans-serif');
      var card = global.document.createElement('div');
      card.setAttribute('style',
        'max-width:460px;border:1px solid #2b3d52;border-top:3px solid #e05252;' +
        'background:#101d2c;padding:24px 26px');
      var h = global.document.createElement('div');
      h.textContent = t('gt.title.revoked');
      h.setAttribute('style', 'font-size:19px;font-weight:600;margin-bottom:10px');
      var p = global.document.createElement('div');
      p.textContent = t('gt.body.revoked');
      p.setAttribute('style', 'font-size:13.5px;color:#b8c7d8');
      card.appendChild(h);
      card.appendChild(p);
      cover.appendChild(card);
      body.appendChild(cover);
    } catch (e) {}
  });
})(window);
