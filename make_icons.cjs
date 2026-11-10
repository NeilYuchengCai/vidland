#!/usr/bin/env node
/* Generate the four terminal icons (SVG master + PNG raster set) and their
   per-page web app manifests. No third-party dependencies: Chrome's own
   renderer via CDP does the SVG -> PNG rasterisation.

       node make_icons.cjs
       VDL_CHROME=C:\path\to\chrome.exe node make_icons.cjs

   Generated PNG/SVG/manifest files are committed; this script is only
   needed when the artwork or wording changes.
*/
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = __dirname;
const OUT = path.join(ROOT, 'icons');
fs.mkdirSync(OUT, { recursive: true });

const GOLD = 'url(#g)';
const LIGHT = '#e6cd95';

const TERMINALS = [
  {
    id: 'portal', file: 'index.html', name: '维兰德公国 · 政务门户', short: '政务门户',
    ribbon: 'VIDLAND',
    emblem: `
      <path d="M190 322 V244 A66 66 0 0 1 322 244 V322" fill="none" stroke="${GOLD}"
            stroke-width="11" stroke-linecap="round" stroke-linejoin="round"/>
      <rect x="182" y="316" width="148" height="12" fill="${GOLD}"/>
      <path d="M232 322 V272 M280 322 V272" stroke="${LIGHT}" stroke-width="4" opacity=".55"/>
      <path d="M256 200 L262 210 L256 220 L250 210 Z" fill="${LIGHT}"/>`
  },
  {
    id: 'border', file: 'border.html', name: '维兰德公国 · 入境安全检查署', short: '入境安检',
    ribbon: 'VIDLAND',
    emblem: `
      <rect x="180" y="186" width="152" height="14" fill="${GOLD}"/>
      <rect x="190" y="200" width="16" height="122" fill="${GOLD}"/>
      <rect x="306" y="200" width="16" height="122" fill="${GOLD}"/>
      <rect x="178" y="322" width="156" height="11" fill="${GOLD}"/>
      <path d="M212 262 H294 M274 242 L294 262 L274 282" fill="none" stroke="${LIGHT}"
            stroke-width="12" stroke-linecap="round" stroke-linejoin="round"/>`
  },
  {
    id: 'interior', file: 'interior.html', name: '维兰德公国 · 境内安全检查署', short: '境内安检',
    ribbon: 'VIDLAND',
    emblem: `
      <path d="M192 196 H320 V268 Q320 314 256 336 Q192 314 192 268 Z" fill="none"
            stroke="${GOLD}" stroke-width="9" stroke-linejoin="round"/>
      <path d="M214 220 H298 V266 Q298 296 256 312 Q214 296 214 266 Z" fill="none"
            stroke="${LIGHT}" stroke-width="7" stroke-linejoin="round" opacity=".9"/>
      <path d="M256 238 L272 262 L256 286 L240 262 Z" fill="${GOLD}"/>`
  },
  {
    id: 'entry', file: 'entry.html', name: '维兰德公国 · 入境核验处', short: '入境核验',
    ribbon: 'VIDLAND',
    emblem: `
      <rect x="194" y="182" width="124" height="150" rx="6" fill="none" stroke="${GOLD}"
            stroke-width="9" stroke-linejoin="round"/>
      <path d="M216 216 H296 M216 240 H296 M216 264 H272" stroke="${LIGHT}"
            stroke-width="6" stroke-linecap="round" opacity=".85"/>
      <circle cx="256" cy="300" r="20" fill="none" stroke="${GOLD}" stroke-width="7"/>
      <path d="M246 300 L254 308 L268 292" fill="none" stroke="${LIGHT}"
            stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>`
  },
  {
    id: 'admin', file: 'admin.html', name: '维兰德公国 · 政务署中央登记处', short: '中央登记',
    ribbon: 'VIDLAND',
    emblem: `
      <g fill="none" stroke="${GOLD}" stroke-width="10" stroke-linecap="round" stroke-linejoin="round">
        <path d="M182 214 H330"/>
        <path d="M256 214 V310"/>
        <path d="M226 310 H286"/>
        <path d="M236 326 H276"/>
        <path d="M196 214 V246"/>
        <path d="M316 214 V246"/>
        <path d="M172 246 Q196 276 220 246"/>
        <path d="M292 246 Q316 276 340 246"/>
      </g>
      <path d="M256 184 L264 198 L256 212 L248 198 Z" fill="${LIGHT}"/>`
  }
];

function corners() {
  /* Lower diamonds sit outside the ribbon (x 112..400) to avoid overlap. */
  return [[106, 106], [406, 106], [96, 430], [416, 430]].map(([x, y]) =>
    `<path d="M${x} ${y - 12} L${x + 12} ${y} L${x} ${y + 12} L${x - 12} ${y} Z" ` +
    `fill="${LIGHT}" opacity=".45"/>`).join('\n  ');
}

function svgFor(t) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
<defs>
  <!-- userSpaceOnUse is mandatory: a gradient in objectBoundingBox units
       cannot resolve on a straight line (zero-width/height bbox), which makes
       thin strokes silently disappear. -->
  <linearGradient id="bg" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="0" y2="512">
    <stop offset="0" stop-color="#16314e"/><stop offset="1" stop-color="#081626"/>
  </linearGradient>
  <linearGradient id="g" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="0" y2="512">
    <stop offset="0" stop-color="#e8d39e"/><stop offset=".5" stop-color="#c9a763"/>
    <stop offset="1" stop-color="#9c7838"/>
  </linearGradient>
</defs>
<rect width="512" height="512" fill="url(#bg)"/>
<rect x="52" y="52" width="408" height="408" rx="36" fill="none" stroke="url(#g)" stroke-width="4" opacity=".9"/>
<rect x="64" y="64" width="384" height="384" rx="28" fill="none" stroke="${LIGHT}" stroke-width="1.2" opacity=".3"/>
${corners()}
<path d="M181 106 L206 74 L231 101 L256 62 L281 101 L306 74 L331 106 Z" fill="url(#g)"/>
<circle cx="206" cy="68" r="4.6" fill="${LIGHT}"/>
<circle cx="256" cy="56" r="4.6" fill="${LIGHT}"/>
<circle cx="306" cy="68" r="4.6" fill="${LIGHT}"/>
<path d="M136 150 H376 V292 Q376 358 256 390 Q136 358 136 292 Z" fill="#122a44" stroke="url(#g)" stroke-width="5"/>
<path d="M146 160 H366 V290 Q366 350 256 380 Q146 350 146 290 Z" fill="none" stroke="${LIGHT}" stroke-width="1.2" opacity=".3"/>
${t.emblem}
<path d="M112 408 H400 L384 430 L400 452 H112 L128 430 Z" fill="#081626" stroke="url(#g)" stroke-width="2"/>
<text x="256" y="440" font-family="Georgia,'Times New Roman',serif" font-size="26"
      letter-spacing="9" fill="url(#g)" text-anchor="middle">${t.ribbon}</text>
</svg>`;
}

function manifestFor(t) {
  return {
    name: t.name,
    short_name: t.short,
    description: '维兰德公国政务模拟终端（虚构公国游戏 / 模拟器）',
    lang: 'zh-CN',
    start_url: '/' + t.file,
    scope: '/',
    display: 'browser',
    background_color: '#081626',
    theme_color: '#0a1b2e',
    icons: [192, 512].map(s => ({
      src: '/icons/' + t.id + '-' + s + '.png',
      sizes: s + 'x' + s,
      type: 'image/png',
      purpose: 'any'
    }))
  };
}

function findChrome() {
  if (process.env.VDL_CHROME && fs.existsSync(process.env.VDL_CHROME)) return process.env.VDL_CHROME;
  /* Prefer a clean automation Chrome. Edge may open a first-run / sync
     consent page that replaces about:blank and silently corrupts captures. */
  const bd = path.join(os.homedir(), '.agent-browser', 'browsers');
  if (fs.existsSync(bd)) {
    for (const d of fs.readdirSync(bd).sort().reverse()) {
      const p = path.join(bd, d, 'chrome.exe');
      if (fs.existsSync(p)) return p;
    }
  }
  const candidates = [
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
    'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
    'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'
  ];
  for (const c of candidates) if (fs.existsSync(c)) return c;
  return null;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
const SIZES = [32, 180, 192, 512];
const PORT = 9341;

async function cdp(ws, id, method, params = {}) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('CDP timeout ' + method)), 25000);
    const h = ev => {
      let m; try { m = JSON.parse(ev.data); } catch { return; }
      if (m.id !== id) return;
      clearTimeout(timer); ws.removeEventListener('message', h);
      m.error ? reject(new Error(method + ': ' + JSON.stringify(m.error))) : resolve(m.result);
    };
    ws.addEventListener('message', h);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function rasterise(chrome) {
  const profile = path.join(os.tmpdir(), 'vdl_icon_profile');
  try { fs.rmSync(profile, { recursive: true, force: true }); } catch {}
  const proc = spawn(chrome, [
    '--headless=old', '--disable-gpu', '--no-sandbox', '--no-proxy-server',
    '--no-first-run', '--no-default-browser-check', '--disable-sync',
    '--disable-features=msEdgeSyncConsent,EdgeFirstRun',
    '--remote-debugging-port=' + PORT, '--user-data-dir=' + profile, 'about:blank'
  ], { stdio: 'ignore' });
  await sleep(2500);
  let targets;
  for (let i = 0; i < 12; i++) {
    try { targets = await (await fetch('http://127.0.0.1:' + PORT + '/json/list')).json(); break; }
    catch { await sleep(500); }
  }
  if (!targets) throw new Error('Chrome CDP not reachable');
  const page = targets.find(t => t.type === 'page');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise(r => ws.addEventListener('open', r, { once: true }));
  let id = 0;
  const call = (m, p) => cdp(ws, ++id, m, p);
  await call('Page.enable');
  await call('Runtime.enable');

  for (const t of TERMINALS) {
    const svg = svgFor(t);
    const doc = '<!doctype html><html><head><meta charset="utf-8"><style>' +
      'html,body{margin:0;padding:0;width:100%;height:100%;background:#081626}' +
      'svg{display:block}</style></head><body>' + svg + '</body></html>';
    const url = 'data:text/html;charset=utf-8,' + encodeURIComponent(doc);
    for (const size of SIZES) {
      await call('Emulation.setDeviceMetricsOverride', {
        width: size, height: size, deviceScaleFactor: 1, mobile: false,
        screenWidth: size, screenHeight: size
      });
      await call('Page.navigate', { url });
      await sleep(180);
      /* Guard against a first-run/consent page replacing our document. */
      const ok = await call('Runtime.evaluate', {
        expression: '!!document.querySelector("svg")', returnByValue: true
      });
      if (!ok.result.value) throw new Error('SVG missing in raster document for ' + t.id);
      const shot = await call('Page.captureScreenshot', {
        format: 'png', captureBeyondViewport: false,
        clip: { x: 0, y: 0, width: size, height: size, scale: 1 }
      });
      fs.writeFileSync(path.join(OUT, t.id + '-' + size + '.png'),
        Buffer.from(shot.data, 'base64'));
    }
    console.log('  rasterised ' + t.id + ': ' + SIZES.join(', '));
  }
  ws.close(); proc.kill();
}

(async () => {
  for (const t of TERMINALS) {
    fs.writeFileSync(path.join(OUT, t.id + '.svg'), svgFor(t), 'utf-8');
    fs.writeFileSync(path.join(OUT, 'manifest-' + t.id + '.json'),
      JSON.stringify(manifestFor(t), null, 2), 'utf-8');
  }
  console.log('  wrote 4 SVG masters + 4 manifests');
  const chrome = findChrome();
  if (!chrome) {
    console.log('  Chrome not found: PNG rasterisation skipped (set VDL_CHROME).');
    return;
  }
  console.log('  rasterising with ' + chrome);
  await rasterise(chrome);
  console.log('  done -> icons/');
})().catch(e => { console.error('ICON GENERATION FAILED:', e); process.exit(1); });
