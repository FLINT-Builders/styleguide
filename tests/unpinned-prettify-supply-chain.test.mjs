/**
 * Supply-chain execution of the syntax highlighter.
 *
 * The guide pages load https://cdn.jsdelivr.net/gh/google/code-prettify@master/loader/run_prettify.js
 * with no integrity attribute (include/jsguide.js, javaguide.html,
 * angularjs-google-style.html). jsDelivr documents `@branch` URLs as branch
 * aliases refreshed on a 12 hour cache, and the live response labels this URL
 * as a branch. These tests load the published pages in Chrome and answer that
 * script request with a different body. They fail while that body runs in the
 * page and rewrites the heading. They pass once the pages no longer execute a
 * response the CDN (or the master branch) can change: a vendored same-origin
 * copy, or a pinned URL whose subresource integrity hash rejects this body.
 *
 * Run:
 *   node --test tests/unpinned-prettify-supply-chain.test.mjs
 *
 * These tests are expected to fail until the vulnerability is fixed.
 */

import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import fs from 'node:fs';
import path from 'node:path';
import {test} from 'node:test';
import {fileURLToPath} from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CHROME = process.env.CHROME_BIN || '/usr/bin/google-chrome';

const PAYLOAD = `
window.__prettifySupplyChain = window.__prettifySupplyChain || {
  ran: true,
  origin: location.origin,
  href: location.href
};
fetch('/include/styleguide.js').then(function (response) {
  window.__prettifySupplyChain.sameOriginStatus = response.status;
}).catch(function (error) {
  window.__prettifySupplyChain.sameOriginError = String(error);
});
function rewriteGuideText() {
  var heading = document.querySelector('h1');
  if (!heading || heading.getAttribute('data-rewritten') === '1') return;
  heading.setAttribute('data-original', heading.textContent);
  heading.textContent = 'SUBSTITUTED BY UNTRUSTED PRETTIFY';
  heading.setAttribute('data-rewritten', '1');
}
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', rewriteGuideText);
} else {
  rewriteGuideText();
}
`;

const PAYLOAD_SRI = 'sha384-' + createHash('sha384').update(PAYLOAD).digest('base64');
const MISMATCH_SRI =
  'sha384-' + createHash('sha384').update('not-the-payload').digest('base64');

const GUIDE_PAGES = [
  {
    name: 'javaguide.html static script tag',
    path: '/javaguide.html',
    expectedHeading: 'Google Java Style Guide',
  },
  {
    name: 'angularjs-google-style.html static script tag and jsguide.js',
    path: '/angularjs-google-style.html',
    expectedHeading: 'An AngularJS Style Guide for Closure Users at Google',
  },
  {
    name: 'jsguide.html via include/jsguide.js',
    path: '/jsguide.html',
    expectedHeading: 'Google JavaScript Style Guide',
  },
  {
    name: 'tsguide.html via include/jsguide.js',
    path: '/tsguide.html',
    expectedHeading: 'Google TypeScript Style Guide',
  },
  {
    name: 'htmlcssguide.html via include/jsguide.js',
    path: '/htmlcssguide.html',
    expectedHeading: 'Google HTML/CSS Style Guide',
  },
];

function contentType(filePath) {
  switch (path.extname(filePath)) {
    case '.html':
      return 'text/html; charset=utf-8';
    case '.js':
      return 'text/javascript; charset=utf-8';
    case '.css':
      return 'text/css; charset=utf-8';
    case '.svg':
      return 'image/svg+xml';
    case '.png':
      return 'image/png';
    case '.ico':
      return 'image/x-icon';
    default:
      return 'application/octet-stream';
  }
}

function startSite() {
  const calibration = new Map([
    [
      '/__calibration/matching-sri.html',
      `<!DOCTYPE html>
<html><head>
<script src="https://cdn.jsdelivr.net/gh/google/code-prettify@master/loader/run_prettify.js"
  integrity="${PAYLOAD_SRI}" crossorigin="anonymous"></script>
</head><body><h1>Calibration matching</h1></body></html>`,
    ],
    [
      '/__calibration/mismatch-sri.html',
      `<!DOCTYPE html>
<html><head>
<script src="https://cdn.jsdelivr.net/gh/google/code-prettify@master/loader/run_prettify.js"
  integrity="${MISMATCH_SRI}" crossorigin="anonymous"></script>
</head><body><h1>Calibration mismatch</h1></body></html>`,
    ],
    [
      '/__calibration/no-integrity.html',
      `<!DOCTYPE html>
<html><head>
<script src="https://cdn.jsdelivr.net/gh/google/code-prettify@master/loader/run_prettify.js"></script>
</head><body><h1>Calibration open</h1></body></html>`,
    ],
  ]);

  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const pathname = decodeURIComponent(url.pathname);
    if (calibration.has(pathname)) {
      res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
      res.end(calibration.get(pathname));
      return;
    }
    const relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
    const filePath = path.resolve(ROOT, relative);
    if (filePath !== ROOT && !filePath.startsWith(ROOT + path.sep)) {
      res.writeHead(403);
      res.end();
      return;
    }
    fs.readFile(filePath, (error, data) => {
      if (error) {
        res.writeHead(404);
        res.end('not found');
        return;
      }
      res.writeHead(200, {'Content-Type': contentType(filePath)});
      res.end(data);
    });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const {port} = server.address();
      resolve({
        origin: `http://127.0.0.1:${port}`,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

class Cdp {
  constructor(ws) {
    this.ws = ws;
    this.next = 0;
    this.pending = new Map();
    this.listeners = [];
    ws.addEventListener('message', (event) => {
      const message = JSON.parse(event.data);
      if (message.id && this.pending.has(message.id)) {
        const {resolve, reject} = this.pending.get(message.id);
        this.pending.delete(message.id);
        if (message.error) {
          reject(new Error(message.error.message || JSON.stringify(message.error)));
        } else {
          resolve(message.result || {});
        }
        return;
      }
      if (message.method) {
        for (const listener of this.listeners) listener(message);
      }
    });
  }

  send(method, params = {}, sessionId) {
    const id = ++this.next;
    const message = {id, method, params};
    if (sessionId) message.sessionId = sessionId;
    this.ws.send(JSON.stringify(message));
    return new Promise((resolve, reject) => {
      this.pending.set(id, {resolve, reject});
    });
  }

  on(listener) {
    this.listeners.push(listener);
    return () => {
      const index = this.listeners.indexOf(listener);
      if (index !== -1) this.listeners.splice(index, 1);
    };
  }
}

async function launchChrome() {
  const profile = fs.mkdtempSync('/tmp/prettify-chrome-');
  const chrome = spawn(CHROME, [
    '--headless=new',
    '--no-sandbox',
    '--disable-gpu',
    '--disable-dev-shm-usage',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-background-networking',
    '--remote-debugging-port=0',
    `--user-data-dir=${profile}`,
    'about:blank',
  ], {stdio: ['ignore', 'pipe', 'pipe']});

  let stderr = '';
  chrome.stderr.on('data', (chunk) => {
    stderr += chunk.toString();
  });

  const port = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error('Chrome did not open a DevTools port. ' + stderr.slice(-500)));
    }, 15000);
    chrome.stderr.on('data', () => {
      const match = stderr.match(/DevTools listening on ws:\/\/127\.0\.0\.1:(\d+)\//);
      if (match) {
        clearTimeout(timer);
        resolve(Number(match[1]));
      }
    });
    chrome.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`Chrome exited ${code}. ${stderr.slice(-500)}`));
    });
  });

  const version = await fetch(`http://127.0.0.1:${port}/json/version`).then((response) => response.json());
  const ws = new WebSocket(version.webSocketDebuggerUrl);
  await once(ws, 'open');
  const cdp = new Cdp(ws);
  return {
    cdp,
    async close() {
      try {
        ws.close();
      } catch {}
      chrome.kill('SIGKILL');
      await once(chrome, 'exit').catch(() => {});
      fs.rmSync(profile, {recursive: true, force: true});
    },
  };
}

async function loadPage(cdp, url) {
  const {targetId} = await cdp.send('Target.createTarget', {url: 'about:blank'});
  const {sessionId} = await cdp.send('Target.attachToTarget', {targetId, flatten: true});
  const crossOriginScripts = [];
  const exceptions = [];
  const detach = [];

  detach.push(cdp.on((message) => {
    if (message.sessionId !== sessionId) return;
    if (message.method === 'Runtime.exceptionThrown') {
      exceptions.push(message.params.exceptionDetails?.exception?.description
        || message.params.exceptionDetails?.text
        || 'exception');
    }
    if (message.method !== 'Fetch.requestPaused') return;
    const request = message.params.request;
    const requestUrl = new URL(request.url);
    const pageUrl = new URL(url);
    const sameOrigin = requestUrl.origin === pageUrl.origin;
    if (sameOrigin) {
      cdp.send('Fetch.continueRequest', {requestId: message.params.requestId}, sessionId).catch(() => {});
      return;
    }
    crossOriginScripts.push(request.url);
    cdp.send('Fetch.fulfillRequest', {
      requestId: message.params.requestId,
      responseCode: 200,
      responseHeaders: [
        {name: 'Content-Type', value: 'application/javascript; charset=utf-8'},
        {name: 'Access-Control-Allow-Origin', value: '*'},
        {name: 'Cache-Control', value: 'no-store'},
      ],
      body: Buffer.from(PAYLOAD).toString('base64'),
    }, sessionId).catch(() => {});
  }));

  await cdp.send('Runtime.enable', {}, sessionId);
  await cdp.send('Page.enable', {}, sessionId);
  await cdp.send('Fetch.enable', {
    patterns: [{urlPattern: '*', resourceType: 'Script', requestStage: 'Request'}],
  }, sessionId);

  const loaded = new Promise((resolve) => {
    const timer = setTimeout(() => resolve('timeout'), 20000);
    detach.push(cdp.on((message) => {
      if (message.sessionId === sessionId && message.method === 'Page.loadEventFired') {
        clearTimeout(timer);
        resolve('load');
      }
    }));
  });
  await cdp.send('Page.navigate', {url}, sessionId);
  const loadState = await loaded;

  let observed = null;
  for (let attempt = 0; attempt < 30; attempt++) {
    const evaluated = await cdp.send('Runtime.evaluate', {
      expression: `({
        ran: !!(window.__prettifySupplyChain && window.__prettifySupplyChain.ran),
        origin: window.__prettifySupplyChain && window.__prettifySupplyChain.origin || null,
        href: window.__prettifySupplyChain && window.__prettifySupplyChain.href || null,
        sameOriginStatus: window.__prettifySupplyChain
          ? window.__prettifySupplyChain.sameOriginStatus ?? null
          : null,
        sameOriginError: window.__prettifySupplyChain
          ? window.__prettifySupplyChain.sameOriginError || null
          : null,
        heading: document.querySelector('h1') ? document.querySelector('h1').textContent : null,
        scripts: Array.from(document.scripts).map((script) => ({
          src: script.src,
          integrity: script.integrity,
          crossOrigin: script.crossOrigin
        }))
      })`,
      returnByValue: true,
    }, sessionId);
    observed = evaluated.result.value;
    if (observed.ran && (observed.sameOriginStatus !== null || observed.sameOriginError)) break;
    if (!observed.ran && attempt > 10) break;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  for (const remove of detach) remove();
  await cdp.send('Target.closeTarget', {targetId});
  return {loadState, crossOriginScripts, exceptions, ...observed};
}

test('unpinned code-prettify supply chain', {concurrency: 1}, async (t) => {
  const site = await startSite();
  const browser = await launchChrome();
  t.after(async () => {
    await browser.close();
    await site.close();
  });

  await t.test('harness: a matching integrity hash still executes the response', async () => {
    const result = await loadPage(browser.cdp, `${site.origin}/__calibration/matching-sri.html`);
    assert.equal(result.ran, true, JSON.stringify(result, null, 2));
    assert.equal(result.heading, 'SUBSTITUTED BY UNTRUSTED PRETTIFY');
    assert.equal(result.sameOriginStatus, 200);
  });

  await t.test('harness: a mismatched integrity hash rejects the substituted response', async () => {
    const result = await loadPage(browser.cdp, `${site.origin}/__calibration/mismatch-sri.html`);
    assert.equal(result.ran, false, JSON.stringify(result, null, 2));
    assert.equal(result.heading, 'Calibration mismatch');
  });

  await t.test('harness: the same URL with no integrity executes the substituted response', async () => {
    const result = await loadPage(browser.cdp, `${site.origin}/__calibration/no-integrity.html`);
    assert.equal(result.ran, true, JSON.stringify(result, null, 2));
    assert.equal(result.origin, site.origin);
    assert.equal(result.sameOriginStatus, 200);
    assert.equal(result.heading, 'SUBSTITUTED BY UNTRUSTED PRETTIFY');
  });

  await t.test('cppguide.html does not load the highlighter', async () => {
    const result = await loadPage(browser.cdp, `${site.origin}/cppguide.html`);
    assert.equal(result.ran, false, JSON.stringify(result, null, 2));
    assert.equal(result.heading, 'Google C++ Style Guide');
    assert.deepEqual(result.crossOriginScripts, []);
  });

  for (const page of GUIDE_PAGES) {
    await t.test(`${page.name} does not execute a substituted highlighter`, async () => {
      const result = await loadPage(browser.cdp, `${site.origin}${page.path}`);
      assert.equal(
        result.ran,
        false,
        [
          `${page.path} executed the body served for its cross-origin script.`,
          `origin=${result.origin} sameOriginStatus=${result.sameOriginStatus}`,
          `heading=${JSON.stringify(result.heading)}`,
          `scripts=${JSON.stringify(result.crossOriginScripts)}`,
          `elements=${JSON.stringify(result.scripts)}`,
          `load=${result.loadState} exceptions=${JSON.stringify(result.exceptions)}`,
        ].join('\n'),
      );
      assert.equal(result.heading, page.expectedHeading);
      assert.ok(
        !String(result.heading).includes('SUBSTITUTED BY UNTRUSTED PRETTIFY'),
        `${page.path} replaced the heading visitors read`,
      );
    });
  }
});
