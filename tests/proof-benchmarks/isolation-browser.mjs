// CI fixture: two real HTTPS origins and browser WebAuthn in a vault popup.
// Uses Chromium's virtual authenticator; never substitutes for Keyhole checks,
// production custody, Safari, or a physical-device acceptance test.
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { spawn, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { join, isAbsolute } from 'node:path';
import { tmpdir } from 'node:os';
import { isolationHeaders, vaultFrameAllow } from '../../.g2-vault/hosting/isolation.mjs';

if (!process.env.CI) throw new Error('CI only');
const output = process.argv[2];
if (process.argv.length !== 3 || !isAbsolute(output ?? '')) throw new Error('Absolute report path required');
const scratch = await mkdtemp(join(tmpdir(), 'proof-isolation-'));
const browserBin = process.env.BROWSER_BIN ?? 'chromium';
const report = { schema: 1, browser: null,
  backend: 'Chromium CDP virtual authenticator', productionKeyholeVerified: false,
  physicalDeviceTested: false, provingPerformed: false, adopted: false, cases: [] };
let browser, server, community, vault, mode;
const connections = new Set();
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(read, description) {
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    const value = await read();
    if (value) return value;
    await delay(100);
  }
  throw new Error(`${description} timeout`);
}
async function connect(url) {
  const socket = new WebSocket(url);
  await once(socket, 'open');
  let sequence = 0;
  const pending = new Map();
  socket.addEventListener('message', event => {
    const data = JSON.parse(event.data), waiter = pending.get(data.id);
    if (!waiter) return;
    pending.delete(data.id); clearTimeout(waiter.timer);
    if (data.error) waiter.reject(new Error(data.error.message)); else waiter.resolve(data.result);
  });
  socket.addEventListener('close', () => {
    for (const waiter of pending.values()) { clearTimeout(waiter.timer); waiter.reject(new Error('CDP closed')); }
    pending.clear(); connections.delete(socket);
  });
  connections.add(socket);
  return { close: () => socket.close(), command(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = ++sequence;
      const timer = setTimeout(() => { pending.delete(id); reject(new Error(`CDP ${method} timeout`)); }, 30000);
      pending.set(id, { resolve, reject, timer });
      socket.send(JSON.stringify({ id, method, params }));
    });
  } };
}
async function evaluate(client, expression, userGesture = false) {
  const result = await client.command('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true, userGesture });
  if (result.exceptionDetails) throw new Error('Browser fixture script failed');
  return result.result?.value;
}
function topPage() {
  const allow = mode === 'no-frame-delegation' ? '' : `allow="${vaultFrameAllow}"`;
  return `<!doctype html><style>body{margin:0}iframe{width:600px;height:300px;border:0}</style>
    <iframe id="vault" ${allow} src="${vault}/frame"></iframe><script>
    addEventListener('message', e => {
      if (e.origin !== ${JSON.stringify(vault)} || e.source !== document.getElementById('vault').contentWindow) return;
      if (e.data?.type === 'capability') window.capability = e.data;
      if (e.data?.type === 'popup-result') window.popupResult = e.data;
    });</script>`;
}
function framePage() {
  return `<!doctype html><button style="width:500px;height:200px" id="open">Open passkey fixture</button><script>
    const channel = new BroadcastChannel('proof-isolation-fixture');
    channel.onmessage = e => {
      const value = e.data;
      if (value?.type === 'popup-result' && typeof value.registration === 'boolean' && typeof value.assertion === 'boolean')
        parent.postMessage(value, ${JSON.stringify(community)});
    };
    document.getElementById('open').onclick = () => window.open('/popup', '_blank');
    parent.postMessage({type:'capability', isolated:crossOriginIsolated,
      sharedArrayBuffer:typeof SharedArrayBuffer === 'function'}, ${JSON.stringify(community)});
    </script>`;
}
function popupPage() {
  return `<!doctype html><script>
    window.runCeremony = async () => {
      const channel = new BroadcastChannel('proof-isolation-fixture');
      const first = crypto.getRandomValues(new Uint8Array(32));
      const registration = await navigator.credentials.create({publicKey:{
        rp:{id:'community.example.test',name:'Fictional CI community'},
        user:{id:crypto.getRandomValues(new Uint8Array(32)),name:'fixture',displayName:'Fixture'},
        challenge:crypto.getRandomValues(new Uint8Array(32)), pubKeyCredParams:[{type:'public-key',alg:-7}],
        authenticatorSelection:{residentKey:'required',userVerification:'required'},
        extensions:{prf:{eval:{first}}},timeout:20000
      }});
      const assertion = await navigator.credentials.get({publicKey:{
        rpId:'community.example.test',challenge:crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials:[{type:'public-key',id:registration.rawId}],userVerification:'required',
        extensions:{prf:{eval:{first}}},timeout:20000
      }});
      const prf = assertion.getClientExtensionResults().prf?.results?.first;
      // Only booleans leave the popup. Neither PRF bytes nor credentials enter the top page.
      const result = {type:'popup-result',registration:!!registration,assertion:!!assertion,
        prfEnabled:prf instanceof ArrayBuffer && prf.byteLength === 32,
        openerNull:window.opener === null,topLevel:window === window.top,isolated:crossOriginIsolated};
      channel.postMessage(result);
      return result;
    };</script>`;
}
try {
  report.browser = execFileSync(browserBin, ['--version'], { encoding: 'utf8', timeout: 10000 }).trim();
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(scratch, 'key.pem'),
    '-out', join(scratch, 'cert.pem'), '-days', '1', '-subj', '/CN=community.example.test'], { stdio: 'ignore', timeout: 10000 });
  server = createServer({ key: await readFile(join(scratch, 'key.pem')), cert: await readFile(join(scratch, 'cert.pem')) }, (req, res) => {
    const isVault = req.headers.host === new URL(vault).host;
    if (!isVault && req.headers.host !== new URL(community).host) { res.writeHead(421).end(); return; }
    let headers = isolationHeaders(community, vault, { vault: isVault });
    if (mode === 'no-top-headers' && !isVault) headers = {};
    const body = !isVault && req.url === '/' ? topPage() : isVault && req.url === '/frame' ? framePage()
      : isVault && req.url === '/popup' ? popupPage() : undefined;
    res.writeHead(body === undefined ? 404 : 200, { ...headers, 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
    res.end(body ?? 'Not found');
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const port = server.address().port;
  community = `https://community.example.test:${port}`; vault = `https://vault.community.example.test:${port}`;
  for (mode of ['isolated', 'no-top-headers', 'no-frame-delegation']) {
    browser = spawn(browserBin, ['--headless', '--no-sandbox', '--disable-dev-shm-usage', '--disable-background-networking',
      '--no-proxy-server', '--ignore-certificate-errors', '--host-resolver-rules=MAP community.example.test 127.0.0.1, MAP vault.community.example.test 127.0.0.1',
      '--remote-debugging-port=0', '--user-data-dir=' + join(scratch, mode), 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
    const debug = await new Promise((resolve, reject) => {
      let stderr = '';
      const timer = setTimeout(() => reject(new Error('Browser startup timeout')), 15000);
      browser.once('exit', () => { clearTimeout(timer); reject(new Error('Browser exited')); });
      browser.stderr.on('data', chunk => {
        stderr = (stderr + chunk).slice(-16384);
        const found = /DevTools listening on (ws:\/\/[^\s]+)/.exec(stderr);
        if (found) { clearTimeout(timer); resolve(found[1]); }
      });
    });
    const endpoint = `http://${new URL(debug).host}`;
    const page = await (await fetch(`${endpoint}/json/new?${encodeURIComponent(community)}`, { method: 'PUT', signal: AbortSignal.timeout(5000) })).json();
    const top = await connect(page.webSocketDebuggerUrl);
    const capability = await until(() => evaluate(top, 'window.capability'), 'Frame capability');
    assert.equal(capability.isolated, mode === 'isolated');
    assert.equal(capability.sharedArrayBuffer, mode === 'isolated');
    const observation = { mode, ...capability, popup: null };
    if (mode === 'isolated') {
      // A real click in the visible frame opens its popup with a user gesture.
      await top.command('Input.dispatchMouseEvent', { type: 'mousePressed', x: 100, y: 80, button: 'left', clickCount: 1 });
      await top.command('Input.dispatchMouseEvent', { type: 'mouseReleased', x: 100, y: 80, button: 'left', clickCount: 1 });
      const target = await until(async () => (await (await fetch(endpoint + '/json/list', { signal: AbortSignal.timeout(5000) })).json())
        .find(target => target.type === 'page' && target.url === vault + '/popup'), 'Vault popup');
      const popup = await connect(target.webSocketDebuggerUrl);
      await until(() => evaluate(popup, 'typeof window.runCeremony === "function"'), 'Popup script');
      await popup.command('WebAuthn.enable');
      const authenticator = await popup.command('WebAuthn.addVirtualAuthenticator', { options: {
        protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true,
        hasUserVerification: true, hasPrf: true, automaticPresenceSimulation: true, isUserVerified: true } });
      const ceremony = await evaluate(popup, 'window.runCeremony()', true);
      for (const key of ['registration', 'assertion', 'prfEnabled', 'openerNull', 'topLevel', 'isolated']) assert.equal(ceremony[key], true, key);
      const delivered = await until(() => evaluate(top, 'window.popupResult'), 'Same-origin popup channel');
      assert.deepEqual(delivered, ceremony);
      observation.popup = ceremony;
      await popup.command('WebAuthn.removeVirtualAuthenticator', { authenticatorId: authenticator.authenticatorId });
      popup.close();
    }
    report.cases.push(observation); top.close();
    const exited = once(browser, 'exit'); browser.kill('SIGKILL'); await exited; browser = undefined;
  }
  report.ok = true;
} catch (error) {
  report.ok = false; report.error = String(error.message); process.exitCode = 1;
} finally {
  for (const socket of connections) socket.close();
  if (browser && browser.exitCode === null) { const exited = once(browser, 'exit'); browser.kill('SIGKILL'); await exited; }
  if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  await writeFile(output, JSON.stringify(report, null, 2) + '\n');
  await rm(scratch, { recursive: true, force: true });
}
