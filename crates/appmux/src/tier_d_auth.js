const { app, BrowserWindow, dialog, session } = require('electron');
const fs = require('fs');
const net = require('net');
const value = name => process.argv.find(arg => arg.startsWith(`--${name}=`))?.slice(name.length + 3);
const url = value('url');
const profile = value('profile');
const callbackPipe = value('callback-pipe');
const icon = value('icon');
const appId = value('app-user-model-id');
const status = value('status');
const pipePrefix = '\\\\.\\pipe\\AppMux.Slack.';
const pipeIdentity = callbackPipe?.startsWith(pipePrefix) ? callbackPipe.slice(pipePrefix.length) : '';
if (!url?.startsWith('https://')
  || !profile
  || !icon
  || !appId
  || !status
  || !pipeIdentity
  || callbackPipe.length > 256
  || !/^[A-Za-z0-9_.-]+\.[a-f0-9]{48}$/.test(pipeIdentity)) app.exit(2);
const report = (event, detail = '') => {
  try { fs.writeFileSync(status, JSON.stringify({ event, detail, timestamp: Date.now() })); } catch {}
};
const errorCode = error => {
  const code = typeof error?.code === 'string' ? error.code : typeof error?.name === 'string' ? error.name : 'UNKNOWN';
  return /^[A-Za-z0-9_-]{1,64}$/.test(code) ? code : 'UNKNOWN';
};
const sendToExistingSlack = target => new Promise((resolve, reject) => {
  let settled = false;
  let response = '';
  const socket = net.createConnection(callbackPipe);
  const finish = error => {
    if (settled) return;
    settled = true;
    socket.destroy();
    error ? reject(error) : resolve();
  };
  socket.setTimeout(3000, () => finish(Object.assign(new Error('pipe timeout'), { code: 'TIMEOUT' })));
  socket.once('connect', () => {
    const payload = Buffer.from(target, 'utf8');
    const frame = Buffer.allocUnsafe(payload.length + 4);
    frame.writeUInt32LE(payload.length, 0);
    payload.copy(frame, 4);
    socket.write(frame);
  });
  socket.on('data', chunk => {
    response += chunk.toString('utf8');
    if (response === 'ok') finish();
  });
  socket.once('error', finish);
  socket.once('close', () => {
    if (!settled) finish(Object.assign(new Error('pipe closed'), { code: 'CLOSED' }));
  });
});
app.setPath('userData', profile);
app.setAppUserModelId(appId);
let handled = false;
let authWindow;
const callback = target => {
  if (handled
    || typeof target !== 'string'
    || target.length <= 'slack:'.length
    || Buffer.byteLength(target, 'utf8') > 8192
    || !target.startsWith('slack:')
    || /[\u0000-\u001f\u007f]/.test(target)) return false;
  handled = true;
  report('callback-detected');
  session.defaultSession.cookies.flushStore().then(
    () => report('cookies-flushed'),
    error => report('cookies-flush-error', errorCode(error))
  ).finally(() => {
    sendToExistingSlack(target).then(
      () => {
        report('callback-pipe-sent');
        setTimeout(() => app.quit(), 250);
      },
      error => {
        report('callback-pipe-error', errorCode(error));
        handled = false;
        dialog.showErrorBox('AppMux', 'The running isolated Slack instance did not accept the sign-in callback. Keep Slack open and try again.');
      }
    );
  });
  return true;
};
app.whenReady().then(() => {
  report('window-creating');
  authWindow = new BrowserWindow({ width: 1100, height: 760, title: 'Slack sign in', icon, webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true } });
  const navigate = (event, target) => { if (callback(target)) event.preventDefault(); };
  authWindow.webContents.on('will-navigate', navigate);
  authWindow.webContents.on('will-redirect', navigate);
  authWindow.webContents.on('did-start-navigation', (event, target) => { if (callback(target)) event.preventDefault(); });
  authWindow.webContents.on('will-frame-navigate', (event, details) => { if (callback(typeof details === 'string' ? details : details?.url)) event.preventDefault(); });
  authWindow.webContents.on('did-fail-load', (event, code, description, target) => callback(target));
  authWindow.webContents.setWindowOpenHandler(({ url: target }) => {
    if (callback(target)) return { action: 'deny' };
    if (target.startsWith('https://')) { authWindow.loadURL(target); return { action: 'deny' }; }
    return { action: 'deny' };
  });
  authWindow.webContents.on('did-finish-load', () => report('page-loaded'));
  authWindow.on('closed', () => report(handled ? 'window-closed-after-callback' : 'window-closed-without-callback'));
  authWindow.loadURL(url);
});
app.on('window-all-closed', () => app.quit());
