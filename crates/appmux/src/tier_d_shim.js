const electron = require('electron');
const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const path = require('path');
const { TextDecoder } = require('util');
const value = name => process.argv.find(arg => arg.startsWith(`--${name}=`))?.slice(name.length + 3);
const target = value('shim-target');
const profile = value('profile');
const callbackStdin = process.argv.includes('--callback-stdin');
const authHost = value('auth-host');
const authApp = value('auth-app');
const helper = value('helper');
const icon = value('icon');
const appId = value('app-user-model-id');
const status = value('status');
const report = (event, detail = '') => {
  if (!status) return;
  try { fs.appendFileSync(status, `${JSON.stringify({ event, detail, timestamp: Date.now() })}\n`); } catch {}
};
const errorCode = error => {
  const code = typeof error?.code === 'string' ? error.code : typeof error?.name === 'string' ? error.name : 'UNKNOWN';
  return /^[A-Za-z0-9_-]{1,64}$/.test(code) ? code : 'UNKNOWN';
};
const missing = Object.entries({ target, profile, authHost, authApp, helper, icon, appId, status }).filter(([, item]) => !item).map(([name]) => name);
if (missing.length || !target.endsWith('app.asar') || !path.isAbsolute(profile)) {
  report('shim-invalid', missing.join(','));
  process.exit(2);
}
const callbackPipe = `\\\\.\\pipe\\AppMux.Slack.${appId.replace(/[^A-Za-z0-9_.-]/g, '_')}.${crypto.randomBytes(24).toString('hex')}`;
const validCallback = candidate => typeof candidate === 'string'
  && candidate.length > 'slack:'.length
  && Buffer.byteLength(candidate, 'utf8') <= 8192
  && candidate.startsWith('slack:')
  && !/[\u0000-\u001f\u007f]/.test(candidate);
const readCallbackStdin = () => {
  const input = Buffer.alloc(8193);
  let length = 0;
  while (length < input.length) {
    const count = fs.readSync(0, input, length, input.length - length, null);
    if (count === 0) break;
    length += count;
  }
  if (length > 8192) throw Object.assign(new Error('oversize callback'), { code: 'OVERSIZE' });
  return new TextDecoder('utf-8', { fatal: true }).decode(input.subarray(0, length));
};
let callback;
if (callbackStdin) {
  try {
    callback = readCallbackStdin();
  } catch (error) {
    report('callback-invalid', errorCode(error));
    process.exit(2);
  }
}
const callbackMode = callbackStdin;
if (callbackMode && !validCallback(callback)) {
  report('callback-invalid');
  process.exit(2);
}
const CALLBACK_LOCK_NAME = '.appmux-callback.lock';
const CALLBACK_LOCK_STALE_MS = 5 * 60 * 1000;
const resolvedProfile = path.resolve(profile);
const callbackLockPath = path.resolve(resolvedProfile, CALLBACK_LOCK_NAME);
if (path.dirname(callbackLockPath) !== resolvedProfile || path.basename(callbackLockPath) !== CALLBACK_LOCK_NAME) {
  report('callback-lock-invalid');
  process.exit(2);
}
let callbackLockFd;
let callbackLockIdentity;
let callbackLockTimer;
let ownsCallbackLock = false;
const releaseCallbackLock = () => {
  if (callbackLockTimer) clearTimeout(callbackLockTimer);
  callbackLockTimer = undefined;
  if (!ownsCallbackLock) return;
  let removeOwnedLock = false;
  try {
    const current = fs.lstatSync(callbackLockPath);
    removeOwnedLock = !current.isSymbolicLink()
      && current.isFile()
      && current.dev === callbackLockIdentity.dev
      && current.ino === callbackLockIdentity.ino;
  } catch {}
  try { fs.closeSync(callbackLockFd); } catch {}
  if (removeOwnedLock) {
    try { fs.unlinkSync(callbackLockPath); } catch {}
  }
  callbackLockFd = undefined;
  callbackLockIdentity = undefined;
  ownsCallbackLock = false;
};
const acquireCallbackLock = () => {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      callbackLockFd = fs.openSync(callbackLockPath, 'wx');
      callbackLockIdentity = fs.fstatSync(callbackLockFd);
      ownsCallbackLock = true;
      process.once('exit', releaseCallbackLock);
      callbackLockTimer = setTimeout(() => {
        report('callback-dispatch-error', 'TIMEOUT');
        releaseCallbackLock();
        electron.app.exit(1);
      }, CALLBACK_LOCK_STALE_MS);
      callbackLockTimer.unref();
      return true;
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      let existing;
      try {
        existing = fs.lstatSync(callbackLockPath);
      } catch (statError) {
        if (statError?.code === 'ENOENT') continue;
        throw statError;
      }
      const age = Date.now() - existing.mtimeMs;
      if (existing.isSymbolicLink() || !existing.isFile() || age < CALLBACK_LOCK_STALE_MS) return false;
      try {
        fs.unlinkSync(callbackLockPath);
      } catch (unlinkError) {
        if (unlinkError?.code !== 'ENOENT') throw unlinkError;
      }
    }
  }
  return false;
};
if (callbackMode) {
  try {
    if (!acquireCallbackLock()) {
      report('callback-duplicate');
      process.exit(0);
    }
  } catch (error) {
    report('callback-lock-error', errorCode(error));
    process.exit(1);
  }
}
report('shim-started');
electron.app.setPath('userData', profile);
process.defaultApp = false;
electron.app.requestSingleInstanceLock = () => true;
electron.app.setAsDefaultProtocolClient = () => true;
Object.defineProperty(electron.app, 'isPackaged', { configurable: true, get: () => true });
const openExternal = electron.shell.openExternal.bind(electron.shell);
const hookedOpenExternal = (url, options) => {
  if (typeof url === 'string' && /^https?:\/\//i.test(url)) {
    report('open-external-http');
    const child = spawn(authHost, [authApp, `--url=${url}`, `--profile=${profile}`, `--helper=${helper}`, `--host=${authHost}`, `--hosted-app=${__dirname}`, `--shim-target=${target}`, `--auth-app=${authApp}`, `--callback-pipe=${callbackPipe}`, `--status=${status}`, `--icon=${icon}`, `--app-user-model-id=${appId}`], { detached: true, windowsHide: false, stdio: 'ignore' });
    child.once('error', error => report('auth-browser-error', errorCode(error)));
    child.once('spawn', () => report('auth-browser-spawned'));
    child.unref();
    return Promise.resolve();
  }
  return openExternal(url, options);
};
electron.shell.openExternal = hookedOpenExternal;
global.appmuxOpen = hookedOpenExternal;
report(
  'hook-installed',
  electron.shell.openExternal === hookedOpenExternal && global.appmuxOpen === hookedOpenExternal
    ? 'active'
    : 'rejected'
);
electron.app.setAppPath(target);
process.argv = [process.execPath];
try {
  require(target);
  report(
    'slack-required',
    electron.shell.openExternal === hookedOpenExternal && global.appmuxOpen === hookedOpenExternal
      ? 'active'
      : 'replaced'
  );
} catch (error) {
  report('require-error', errorCode(error));
  releaseCallbackLock();
  if (callbackMode) process.exit(1);
  throw error;
}
const dispatchCallback = (candidate, successEvent, onSuccess, onFailure) => {
  const listenerDeadline = Date.now() + 30000;
  const dispatch = () => {
    try {
      if (electron.app.listenerCount('second-instance') === 0) {
        if (Date.now() >= listenerDeadline) {
          const error = new Error('Second-instance listener timed out');
          error.code = 'LISTENER_TIMEOUT';
          throw error;
        }
        setTimeout(dispatch, 50);
        return;
      }
      const emitted = electron.app.emit('second-instance', {}, [process.execPath, candidate], process.cwd(), {});
      if (!emitted) {
        const error = new Error('Second-instance dispatch was not handled');
        error.code = 'NOT_HANDLED';
        throw error;
      }
      report(successEvent);
      onSuccess();
    } catch (error) {
      onFailure(error);
    }
  };
  electron.app.whenReady().then(dispatch, onFailure);
};
if (callbackMode) {
  dispatchCallback(
    callback,
    'callback-dispatched',
    releaseCallbackLock,
    error => {
      report('callback-dispatch-error', errorCode(error));
      releaseCallbackLock();
      electron.app.exit(1);
    }
  );
} else {
  let pipeDispatchActive = false;
  const server = net.createServer(socket => {
    if (pipeDispatchActive) {
      socket.destroy();
      return;
    }
    let input = Buffer.alloc(0);
    let dispatched = false;
    socket.on('data', chunk => {
      if (dispatched) return;
      input = Buffer.concat([input, chunk]);
      if (input.length > 8196) {
        socket.destroy();
        return;
      }
      if (input.length < 4) return;
      const expected = input.readUInt32LE(0);
      if (expected === 0 || expected > 8192 || input.length > expected + 4) {
        socket.destroy();
        return;
      }
      if (input.length < expected + 4) return;
      let candidate;
      try {
        candidate = new TextDecoder('utf-8', { fatal: true }).decode(input.subarray(4));
      } catch (error) {
        report('callback-pipe-invalid', errorCode(error));
        socket.destroy();
        return;
      }
      if (!validCallback(candidate)) {
        report('callback-pipe-invalid');
        socket.destroy();
        return;
      }
      dispatched = true;
      pipeDispatchActive = true;
      dispatchCallback(
        candidate,
        'callback-pipe-dispatched',
        () => {
          socket.end('ok');
          pipeDispatchActive = false;
        },
        error => {
          report('callback-pipe-error', errorCode(error));
          socket.destroy();
          pipeDispatchActive = false;
        }
      );
    });
  });
  server.once('error', error => report('callback-pipe-error', errorCode(error)));
  server.listen(callbackPipe, () => report('callback-pipe-listening'));
}
