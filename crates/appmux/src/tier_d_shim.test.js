const assert = require('assert');
const { spawn } = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const test = require('node:test');

test('waits for Slack second-instance listener before dispatch', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'appmux-tier-d-'));
  const profile = path.join(root, 'profile');
  const target = path.join(root, 'fake.app.asar');
  const status = path.join(root, 'status.jsonl');
  const marker = path.join(root, 'dispatches.txt');
  fs.mkdirSync(profile);
  fs.mkdirSync(target);
  fs.writeFileSync(
    path.join(target, 'index.js'),
    `const { app } = require('electron'); const fs = require('fs'); setTimeout(() => app.on('second-instance', () => { fs.appendFileSync(${JSON.stringify(marker)}, 'dispatch\\n'); setTimeout(() => process.exit(0), 500); }), 100);`
  );
  const shim = path.join(__dirname, 'tier_d_shim.js');
  const bootstrap = `
    const { EventEmitter } = require('events');
    const Module = require('module');
    const app = new EventEmitter();
    app.setPath = () => {};
    app.requestSingleInstanceLock = () => true;
    app.setAppPath = () => {};
    app.whenReady = () => Promise.resolve();
    app.exit = code => process.exit(code);
    const electron = { app, shell: { openExternal: () => Promise.resolve() } };
    const crypto = require('crypto');
    const fakeCrypto = { ...crypto, randomBytes: () => Buffer.alloc(24, 0xab) };
    const load = Module._load;
    Module._load = function(request, parent, isMain) {
      if (request === 'electron') return electron;
      if (request === 'crypto') return fakeCrypto;
      return load.call(this, request, parent, isMain);
    };
    require(${JSON.stringify(shim)});
  `;
  const args = [
    '-e', bootstrap,
    '--',
    `--shim-target=${target}`,
    `--profile=${profile}`,
    `--auth-host=${process.execPath}`,
    `--auth-app=${shim}`,
    `--helper=${process.execPath}`,
    `--icon=${shim}`,
    '--app-user-model-id=AppMux.slack.test',
    `--status=${status}`,
    '--callback-stdin'
  ];
  const code = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, { stdio: ['pipe', 'ignore', 'inherit'] });
    child.once('error', reject);
    child.once('exit', resolve);
    child.stdin.end('slack://test/magic-login/synthetic');
  });
  try {
    assert.strictEqual(code, 0);
    const events = fs.readFileSync(status, 'utf8').trim().split(/\r?\n/).map(JSON.parse);
    assert(events.some(event => event.event === 'callback-dispatched'));
    assert(!events.some(event => event.event === 'callback-dispatch-error'));
    assert.strictEqual(fs.readFileSync(marker, 'utf8').trim().split(/\r?\n/).length, 1);
    assert(!fs.readFileSync(status, 'utf8').includes('synthetic'));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('routes one callback to an existing Slack shim through its private pipe', { skip: process.platform !== 'win32' }, async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'appmux-tier-d-pipe-'));
  const profile = path.join(root, 'profile');
  const target = path.join(root, 'fake.app.asar');
  const status = path.join(root, 'status.jsonl');
  const marker = path.join(root, 'dispatches.txt');
  const appId = `AppMux.slack.test.${process.pid}`;
  const pipeSuffix = 'ab'.repeat(24);
  const callbackPipe = `\\\\.\\pipe\\AppMux.Slack.${appId}.${pipeSuffix}`;
  fs.mkdirSync(profile);
  fs.mkdirSync(target);
  fs.writeFileSync(
    path.join(target, 'index.js'),
    `const { app } = require('electron'); const fs = require('fs'); setTimeout(() => app.on('second-instance', () => { fs.appendFileSync(${JSON.stringify(marker)}, 'dispatch\\n'); setTimeout(() => process.exit(0), 500); }), 100);`
  );
  const shim = path.join(__dirname, 'tier_d_shim.js');
  const bootstrap = `
    const { EventEmitter } = require('events');
    const Module = require('module');
    const app = new EventEmitter();
    app.setPath = () => {};
    app.requestSingleInstanceLock = () => true;
    app.setAsDefaultProtocolClient = () => true;
    app.setAppPath = () => {};
    app.whenReady = () => Promise.resolve();
    app.exit = code => process.exit(code);
    const electron = { app, shell: { openExternal: () => Promise.resolve() } };
    const crypto = require('crypto');
    const fakeCrypto = { ...crypto, randomBytes: () => Buffer.alloc(24, 0xab) };
    const load = Module._load;
    Module._load = function(request, parent, isMain) {
      if (request === 'electron') return electron;
      if (request === 'crypto') return fakeCrypto;
      return load.call(this, request, parent, isMain);
    };
    require(${JSON.stringify(shim)});
  `;
  const child = spawn(process.execPath, [
    '-e', bootstrap, '--',
    `--shim-target=${target}`,
    `--profile=${profile}`,
    `--auth-host=${process.execPath}`,
    `--auth-app=${shim}`,
    `--helper=${process.execPath}`,
    `--icon=${shim}`,
    `--app-user-model-id=${appId}`,
    `--status=${status}`
  ], { stdio: ['ignore', 'ignore', 'inherit'] });
  try {
    const deadline = Date.now() + 5000;
    while ((!fs.existsSync(status) || !fs.readFileSync(status, 'utf8').includes('callback-pipe-listening')) && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    assert(fs.readFileSync(status, 'utf8').includes('callback-pipe-listening'));
    const response = await new Promise((resolve, reject) => {
      const socket = net.createConnection(callbackPipe);
      let data = '';
      socket.once('connect', () => {
        const payload = Buffer.from('slack://test/magic-login/synthetic');
        const frame = Buffer.allocUnsafe(payload.length + 4);
        frame.writeUInt32LE(payload.length, 0);
        payload.copy(frame, 4);
        socket.write(frame);
      });
      socket.on('data', chunk => { data += chunk.toString('utf8'); });
      socket.once('end', () => resolve(data));
      socket.once('error', reject);
    });
    assert.strictEqual(response, 'ok');
    const code = child.exitCode ?? await new Promise((resolve, reject) => {
      child.once('exit', resolve);
      child.once('error', reject);
    });
    assert.strictEqual(code, 0);
    assert.strictEqual(fs.readFileSync(marker, 'utf8').trim().split(/\r?\n/).length, 1);
    const events = fs.readFileSync(status, 'utf8');
    assert(events.includes('callback-pipe-dispatched'));
    assert(!events.includes('synthetic'));
  } finally {
    child.kill();
    fs.rmSync(root, { recursive: true, force: true });
  }
});
