# AppMux

<p align="center">
  <img src="assets/appmux-brand.png" alt="AppMux — Layered app instances, simplified." width="900" />
</p>

<p align="center"><strong>Layered app instances, simplified.</strong></p>

Run multiple isolated instances of Windows apps — separate logins, separate
settings, side by side. Right-click a shortcut or exe, pick an instance
("Work", "Personal", "Client A"), and it launches with its own private data.

AppMux is a *launcher*, not a sandbox. It uses documented Windows APIs and does
not modify installed vendor files. Curated Tier D adapters may alter only an
AppMux-managed copy after explicit consent and exact version/hash checks. Apps
with anti-cheat, DRM, licensing controls, or kernel components remain unsupported.

> Running multiple copies of a program may breach that program's own terms of
> service. Checking whether that is allowed is your responsibility. AppMux
> shows this notice once and requires acknowledgment.

## How it works

Isolation is tiered per app, driven by a recipe database:

- **Tier A — native flags.** Many apps support multi-instance/profile flags
  (Chrome/Edge `--user-data-dir`, VS Code `--user-data-dir --extensions-dir`,
  Telegram `-many -workdir`, Firefox `-profile -no-remote`, Discord
  `--multi-instance` + `DISCORD_USER_DATA_DIR`). Complete isolation, zero
  privilege.
- **Tier B — environment redirection.** `APPDATA`, `LOCALAPPDATA`, `TEMP`,
  `USERPROFILE` are pointed into a per-instance directory. Works for apps that
  resolve paths through the environment. **Known limitation:** apps that use
  the Windows shell API (`SHGetKnownFolderPath`) ignore environment variables —
  most Electron apps do this, which is why Electron apps need Tier A recipes.
  Unverified apps get a warning.
- **Tier C — hidden local user account per instance** *(experimental)*: real
  separate HKCU registry and user profile for classic Win32 apps. Per-user-only
  installations are mirrored into the hidden account's matching profile path so
  the app sees the directory structure it expects without accessing the owner's profile.
- **Tier D — curated Compatibility Shim**: for exceptional apps that still enforce
  cross-profile singleton or callback behavior. Each adapter is built in, requires
  explicit consent, and is gated to exact executable/resource hashes and patch
  signatures. Unknown versions fail closed instead of receiving a best-effort patch.

## Manager app

`AppMux.Manager.exe` (WPF, Fluent design with an acrylic "glass" look) lists
your instances as consumer-friendly app cards with the real application logo,
friendly product name, named identity, storage, and last-used time; it launches or removes them,
creates named instances via a dialog, and installs the Explorer menu. The
settings gear centralizes System/Dark/Light appearance, shell/protocol repair,
developer mode, data-folder access, and product information. Theme selection is
persisted in `%LOCALAPPDATA%\AppMux\manager.json` and applies to every window.
When the manager sits next to `appmuxw.exe`, the right-click "New instance..." verb
opens its naming dialog; without it, instances are auto-named.

Build it with `dotnet publish manager/AppMux.Manager -c Release -r win-x64
--self-contained true -o manager/publish` and copy `appmux.exe`/`appmuxw.exe`
into the output folder.

## Automatic route selection

The manager analyzes every target before creating an instance and chooses the
lightest viable route:

1. verified native/profile recipe,
2. verified environment profile,
3. Package Lab (service-free when that is the only removable blocker),
4. a version-gated Tier D adapter when an exact built-in compatibility profile matches,
5. Tier C Windows-user isolation for unknown unpackaged apps,
6. verified official App Web fallback when the desktop route is prohibited or incompatible,
7. unsupported with an exact reason.

Use `appmux analyze --target <exe-or-lnk>` to inspect the JSON decision without
making changes. Account creation, package signing/trust, sideloading, and
service removal always retain explicit consent/UAC boundaries.

App Web mode opens the vendor's verified HTTPS app in Edge/Chrome `--app` mode
(no browser chrome) with one persistent browser profile per named instance. It
supports cards, Stop, retain/wipe removal, and pinnable shortcuts without
copying the prohibited desktop package. ChatGPT (`chatgpt.com`) and Spotify Web
(`open.spotify.com`) are verified fallback recipes. Two disposable ChatGPT web
instances were tested simultaneously with 14 Edge processes each and completely
separate profile roots.

For packaged desktop apps, this is structural rather than app-name-specific:
AppMux identifies the selected manifest `Application`, preserves nested
executable paths, detects Electron/Chromium assets, generates a private
`--user-data-dir` when no curated recipe exists, scopes protocol rewriting to
the selected application, and removes only service-linked declarations when
service-free mode is approved. This broadens support to similar apps but cannot
guarantee compatibility when a service is essential or a vendor adds its own
global singleton/licensing checks.

## OAuth and deep-link callbacks

Package Lab rewrites copied protocol declarations so callbacks keep the named
instance's private profile and labels handlers as `App (Instance)`. AppMux also
registers an optional protocol router:

```
appmux protocol sync
```

When selected as the handler, the glass picker lists matching named instances
and routes the callback directly through the chosen package AUMID. Sensitive
OAuth callback URLs are never displayed, logged, or persisted. Profile-aware
direct callback handling is verified with simultaneous original Claude +
`ClaudeOAuth`: selecting `Claude (ClaudeOAuth)` returned Google login to that
private profile. The AppMux picker startup/selection UI is smoke-tested. Older base
`uap:Protocol` manifests cannot legally carry profile parameters; AppMux removes
that handler only from the clone and routes its callbacks through the named
router instead. Generated Electron/Chromium profile arguments are persisted on
the instance and used for both normal launches and callbacks.

## Usage

```
appmux run --target "C:\...\Discord.lnk" --instance Work   # create/launch
appmux run --target <exe-or-lnk> --new                     # fresh auto-named instance
appmux web create --target <licensed-app> --instance Work  # isolated official web app
appmux list                                                 # show instances
appmux stop --app package-openai_codex --instance Work      # stop one clone family
appmux remove --app discord --instance Work --purge         # delete incl. data
appmux recipes                                              # show recipe database
appmux menu sync                                            # install Explorer right-click menu
appmux menu remove                                          # uninstall it
```

### Developer mode

`appmux dev on` enables `run --force`, which bypasses the anti-cheat/DRM
guardrail *heuristics* — strictly for testing false positives while writing
recipes. Packaged apps cannot use ordinary `run --force`; eligible free apps
require Package Lab to build and sign a separate Windows package identity.

### Tier C — strong isolation (experimental)

Existing instances can be upgraded from recipe isolation to a genuine separate
HKCU hive and Windows profile:

```
appmux tier-c prepare --app <app-id> --instance <name>  # run elevated
appmux tier-c status  --app <app-id> --instance <name>
```

The manager's shield button performs the same operation with a UAC prompt. It
creates one hidden **standard** local account per instance, generates a random
password protected with Windows DPAPI, initializes Windows Shell known folders,
and corrects the alternate-user environment before launch. Per-user applications
are mirrored to the equivalent path in the hidden profile. Managed launches use
a named Windows job so Stop terminates only that instance and all of its child
processes. It does not change target-app or WindowsApps ACLs and installs no
service or driver.

Slack 4.51.191 is the first verified Tier D adapter. AppMux verifies exact
`slack.exe`, `app.asar`, Electron archive, and runtime hashes before changing only
the managed copy. The adapter applies fixed-length singleton and external-link
patches, hosts Slack with its matching Electron 43.4.0 runtime, and routes native
sign-in callbacks to the already-running instance through a private randomized
named pipe. Tier D never registers Slack callbacks in the owner's profile, so the
original Slack installation and its `slack://` handler remain independent.

### Package Lab (experimental packaged-app instances)

Package Lab can clone eligible free MSIX/Appx desktop apps under a unique local
Windows identity. It copies files to `%LOCALAPPDATA%\AppMux\PackageLab`, changes
only the copied manifest identity, packs and locally signs an MSIX, then
sideloads it after explicit consent. It never modifies the Store-installed app
or takes ownership/changes ACLs under `WindowsApps`.

```
appmux package-lab inspect --target <path-inside-package>
appmux dev on
appmux package-lab prepare --target <path> --instance Work --confirm-free-no-drm
appmux package-lab pack --target <path> --instance Work
appmux package-lab sign --target <path> --instance Work --confirm-trust-dev-cert
# Run elevated; imports only the public cert into LocalMachine\TrustedPeople:
appmux package-lab trust-machine --target <path> --instance Work --confirm-machine-trust
appmux package-lab install --target <path> --instance Work --confirm-sideload
appmux package-lab adopt --target <path> --instance Work
```

The manager performs this flow when a packaged process is selected. Every
package requires manual licensing review; services, drivers, DRM, anti-cheat,
and the restricted `appLicensing` capability are hard blockers. Restricted capabilities, packaged COM,
background tasks, notifications, and protocols are compatibility warnings.
Clones do not receive Store updates and can consume hundreds of MB each. The
manager's Stop action terminates only one clone package family, including its
background processes. Removing a Package Lab card now stops and uninstalls that
clone before removing the record; the user separately chooses whether to retain
or wipe the external login/profile data, so installed packages cannot be
silently orphaned.
Package Lab is not universal: apps can retain a Win32 singleton across package
identities. Spotify is a verified example—it works as a persistent alternate
identity when vendor Spotify is closed, but does not run side by side. For
simultaneous Spotify accounts, use isolated browser/web-player instances.
Codex/ChatGPT is also declined by Package Lab because its package declares
`appLicensing`; it additionally stores authentication in `CODEX_HOME` and
unvirtualized `%LOCALAPPDATA%\OpenAI`, outside Chromium's user-data directory.
Use isolated browser profiles for multiple ChatGPT accounts.

Packages whose only hard blocker is a Windows service can be cloned in explicit
`--strip-services` mode. This removes only copied manifest service registration,
`localSystemServices`/`packagedServices`, and service-specific firewall rules;
service-dependent features will not work. Claude is verified: original Claude
and a service-free clone run simultaneously with separate Electron profile
data, while Cowork/VM is intentionally unavailable in the clone.

Two binaries are built: `appmux.exe` (console CLI) and `appmuxw.exe`
(windowless; used by Explorer menu verbs so launches never flash a console).

## Explorer integration

`appmux menu sync` writes a cascading "AppMux" menu for `.lnk` and `.exe`
files under `HKCU\Software\Classes` — plain registry verbs, so **no code ever
loads into Explorer** and a AppMux bug can never crash the shell. On
Windows 11 the menu appears under "Show more options"; native top-level menu
support (sparse MSIX + IExplorerCommand) is planned.

Run `menu sync` again after moving the binaries; the verbs embed absolute paths.

## Custom recipes

Drop overrides into `%LOCALAPPDATA%\AppMux\recipes.json` (same schema as
[builtin_recipes.json](crates/appmux/src/builtin_recipes.json)):

```json
[{
  "id": "myapp",
  "display": "My App",
  "match_exe": ["myapp.exe"],
  "status": "verified",
  "args": ["--profile-dir", "{data}\\Profile"],
  "redirect_env": ["APPDATA", "TEMP"],
  "env": { "MYAPP_HOME": "{data}\\Home" }
}]
```

`{data}` expands to the instance's data directory. User recipes take
precedence over builtins.

## Building

```
cargo build --release   # binaries in target\release\
cargo test
```

## Data locations

Everything lives under `%LOCALAPPDATA%\AppMux\`: `instances.json`,
`config.json`, optional `recipes.json`, and `Instances\<app>\<name>\` for
per-instance data.
