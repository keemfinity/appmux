const electron = require('electron');
const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const path = require('path');
const value = name => process.argv.find(arg => arg.startsWith(`--${name}=`))?.slice(name.length + 3);
const target = value('shim-target');
const icon = value('icon');
const appId = value('app-user-model-id');
const authBroker = value('auth-broker');
const authProfile = value('auth-profile');
const waitingDir = value('waiting-dir');
const status = value('status');
const report = event => { if (status) try { fs.appendFileSync(status, `${JSON.stringify({ event, timestamp: Date.now() })}\n`); } catch {} };
if (!target?.endsWith('app.asar') || !path.isAbsolute(target) || !path.isAbsolute(icon)
  || !path.isAbsolute(authBroker) || !path.isAbsolute(authProfile) || !path.isAbsolute(waitingDir) || !appId) electron.app.exit(2);
const launchArgs = process.argv.slice(1);
const originalRelaunch = electron.app.relaunch.bind(electron.app);
process.defaultApp = false;
electron.app.setAsDefaultProtocolClient = () => true;
electron.app.removeAsDefaultProtocolClient = () => true;
electron.app.relaunch = options => originalRelaunch({ ...(options || {}), args: options?.args?.length ? options.args : launchArgs });
electron.app.setAppUserModelId(appId);
electron.app.on('browser-window-created', (_, window) => { try { window.setIcon(icon); } catch {} });
const validCallback = candidate => typeof candidate === 'string' && candidate.length > 6
  && Buffer.byteLength(candidate, 'utf8') <= 8192 && candidate.startsWith('figma:')
  && !/[\u0000-\u001f\u007f]/.test(candidate);
const dispatch = candidate => {
  const originalArgs = [process.execPath, candidate];
  const deadline = Date.now() + 30000;
  const attempt = () => {
    if (electron.app.listenerCount('second-instance') === 0) {
      if (Date.now() >= deadline) return report('callback-listener-timeout');
      return setTimeout(attempt, 50);
    }
    const handled = electron.app.emit('second-instance', {}, originalArgs, process.cwd(), { originalArgs });
    report(handled ? 'callback-dispatched' : 'callback-not-handled');
  };
  electron.app.whenReady().then(attempt, () => report('callback-ready-error'));
};
let authActive = false;
const launchAuth = url => {
  if (authActive) return Promise.resolve();
  authActive = true;
  fs.mkdirSync(waitingDir, { recursive: true });
  const nonce = crypto.randomBytes(24).toString('hex');
  const callbackName = `AppMux.Callback.${appId.replace(/[^A-Za-z0-9_.-]/g, '_')}.${nonce}`;
  const authName = `AppMux.AuthRequest.${appId.replace(/[^A-Za-z0-9_.-]/g, '_')}.${crypto.randomBytes(24).toString('hex')}`;
  const descriptor = path.join(waitingDir, `${nonce}.json`);
  const cleanup = () => { authActive = false; try { fs.unlinkSync(descriptor); } catch {} };
  let authProcess;
  const callbackServer = net.createServer({ allowHalfOpen: true }, socket => {
    let input = Buffer.alloc(0);
    socket.on('data', chunk => {
      input = Buffer.concat([input, chunk]);
      if (input.length < 4) return;
      const length = input.readUInt32LE(0);
      if (length > 8192 || input.length > length + 4) return socket.destroy();
      if (input.length < length + 4) return;
      const candidate = input.subarray(4).toString('utf8');
      if (!validCallback(candidate)) return socket.destroy();
      dispatch(candidate);
      socket.end('ok');
      callbackServer.close();
      if (authProcess) authProcess.kill();
      cleanup();
    });
  });
  callbackServer.once('error', () => { cleanup(); report('callback-pipe-error'); });
  callbackServer.listen(`\\\\.\\pipe\\${callbackName}`, () => {
    fs.writeFileSync(descriptor, JSON.stringify({ pipeName: callbackName, protocol: 'figma', created: Date.now() }), { flag: 'wx' });
    const authServer = net.createServer(socket => {
      const request = Buffer.from(JSON.stringify({ url, profile: authProfile, icon, appId }), 'utf8');
      const frame = Buffer.allocUnsafe(request.length + 4);
      frame.writeUInt32LE(request.length, 0);
      request.copy(frame, 4);
      socket.end(frame);
      authServer.close();
    });
    authServer.once('error', () => { callbackServer.close(); cleanup(); report('auth-pipe-error'); });
    authServer.listen(`\\\\.\\pipe\\${authName}`, () => {
      authProcess = spawn(authBroker, ['isolated-auth', '--pipe', authName], { detached: true, windowsHide: false, stdio: 'ignore' });
      authProcess.once('error', () => { callbackServer.close(); cleanup(); report('auth-broker-error'); });
      authProcess.unref();
      report('auth-broker-started');
    });
  });
  return Promise.resolve();
};
const originalOpenExternal = electron.shell.openExternal.bind(electron.shell);
electron.shell.openExternal = (url, options) => typeof url === 'string' && /^https:\/\//i.test(url)
  ? launchAuth(url) : originalOpenExternal(url, options);
electron.app.setAppPath(target);
process.argv = [process.execPath];
require(target);
