mod account;
mod console;
mod guard;
mod launch;
mod lnk;
mod package_lab;
mod paths;
mod recipes;
mod shellmenu;
mod shortcut;
mod store;
mod web_app;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;
use store::{Config, Db, Instance};

#[derive(Parser)]
#[command(
    name = "appmux",
    version,
    about = "AppMux: run multiple isolated instances of Windows apps"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Launch an app (exe or .lnk) inside a named instance
    Run {
        /// Path to an .exe or .lnk
        #[arg(long)]
        target: String,
        /// Instance name (created for this app if it doesn't exist yet)
        #[arg(long, conflicts_with = "new")]
        instance: Option<String>,
        /// Exact stored app ID (manager/shortcut use; prevents re-deriving a
        /// Package Lab identity from its protected executable filename)
        #[arg(long, requires = "instance")]
        app: Option<String>,
        /// Create a fresh auto-named instance
        #[arg(long)]
        new: bool,
        /// Dev mode only: bypass the anti-cheat/DRM guardrail heuristics
        /// for false positives during recipe testing. Packaged apps use
        /// Package Lab instead of direct executable launch.
        #[arg(long)]
        force: bool,
        /// Create/update the instance record without launching it
        #[arg(long)]
        create_only: bool,
    },
    /// Analyze a target and print the recommended automatic isolation route
    Analyze {
        #[arg(long)]
        target: String,
    },
    /// List known instances
    List,
    /// Stop all processes belonging to one Package Lab clone
    Stop {
        #[arg(long)]
        app: String,
        #[arg(long)]
        instance: String,
    },
    /// Remove an instance from the registry of instances
    Remove {
        #[arg(long)]
        app: String,
        #[arg(long)]
        instance: String,
        /// Also delete the instance's data directory on disk
        #[arg(long)]
        purge: bool,
    },
    /// Manage the Explorer right-click menu
    Menu {
        #[command(subcommand)]
        cmd: MenuCmd,
    },
    /// Create a desktop shortcut for an instance (pinnable to the taskbar)
    Shortcut {
        #[arg(long)]
        app: String,
        #[arg(long)]
        instance: String,
    },
    /// List launch recipes
    Recipes,
    /// Accept the multi-instance notice non-interactively
    AcceptTos,
    /// Toggle developer mode (enables `run --force` guardrail override)
    Dev {
        #[command(subcommand)]
        cmd: DevCmd,
    },
    /// Tier C: real HKCU/AppData isolation through a hidden local account
    TierC {
        #[command(subcommand)]
        cmd: TierCCmd,
    },
    /// Experimental local cloning of eligible free MSIX/Appx packages
    PackageLab {
        #[command(subcommand)]
        cmd: PackageLabCmd,
    },
    /// Register and route OAuth/deep-link callbacks to named instances
    Protocol {
        #[command(subcommand)]
        cmd: ProtocolCmd,
    },
    /// Create isolated app-like browser windows for verified official web apps
    Web {
        #[command(subcommand)]
        cmd: WebCmd,
    },
}

#[derive(Subcommand)]
enum WebCmd {
    /// Create and launch a persistent App Web instance from a verified recipe
    Create {
        #[arg(long)]
        target: String,
        #[arg(long)]
        instance: String,
    },
}

#[derive(Subcommand)]
enum ProtocolCmd {
    /// Register AppMux as an available handler for protocols used by instances
    Sync,
    /// Route a callback URI directly to one named Package Lab instance
    Route {
        #[arg(long)]
        uri: String,
        #[arg(long)]
        app: String,
        #[arg(long)]
        instance: String,
    },
}

#[derive(Subcommand)]
enum PackageLabCmd {
    /// Inspect the package containing an exe and print an eligibility report
    Inspect {
        #[arg(long)]
        target: String,
    },
    SdkTools {
        #[arg(long)]
        accept_windows_sdk_license: bool,
    },
    /// Write a dry-run inspection plan (requires developer mode)
    Plan {
        #[arg(long)]
        target: String,
        #[arg(long)]
        instance: String,
    },
    /// Copy an eligible free package into an isolated workspace and change
    /// only its manifest publisher (never edits WindowsApps)
    Prepare {
        #[arg(long)]
        target: String,
        #[arg(long)]
        instance: String,
        /// Confirm you checked that the app is free and has no DRM/licensing restriction
        #[arg(long)]
        confirm_free_no_drm: bool,
        /// Remove copied manifest service registrations/capabilities/firewall
        /// rules. Service-dependent app features will not work.
        #[arg(long)]
        strip_services: bool,
    },
    /// Pack a prepared workspace into an unsigned MSIX (does not sign/install)
    Pack {
        #[arg(long)]
        target: String,
        #[arg(long)]
        instance: String,
    },
    /// Create/trust a local dev certificate and sign a packed clone
    Sign {
        #[arg(long)]
        target: String,
        #[arg(long)]
        instance: String,
        #[arg(long)]
        confirm_trust_dev_cert: bool,
    },
    /// Trust the Package Lab public certificate machine-wide (requires elevation)
    TrustMachine {
        #[arg(long)]
        target: String,
        #[arg(long)]
        instance: String,
        #[arg(long)]
        confirm_machine_trust: bool,
    },
    /// Sideload a signed clone for the current user
    Install {
        #[arg(long)]
        target: String,
        #[arg(long)]
        instance: String,
        #[arg(long)]
        confirm_sideload: bool,
    },
    /// Uninstall an adopted clone and remove its AppMux record
    Uninstall {
        #[arg(long)]
        app: String,
        #[arg(long)]
        instance: String,
        #[arg(long)]
        purge: bool,
        #[arg(long)]
        confirm_uninstall: bool,
    },
    /// Add an installed Package Lab clone to AppMux's named instances
    Adopt {
        #[arg(long)]
        target: String,
        #[arg(long)]
        instance: String,
    },
}

#[derive(Subcommand)]
enum TierCCmd {
    #[command(hide = true)]
    InitProfile {
        #[arg(long)]
        protocol: Option<String>,
        #[arg(long)]
        helper: Option<String>,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        hosted_app: Option<String>,
        #[arg(long)]
        shim_target: Option<String>,
        #[arg(long)]
        auth_app: Option<String>,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        icon: Option<String>,
        #[arg(long)]
        app_user_model_id: Option<String>,
        #[arg(long)]
        status: Option<String>,
    },
    #[command(hide = true)]
    HostElectron {
        #[arg(long)]
        host: String,
        #[arg(long)]
        hosted_app: String,
        #[arg(long)]
        shim_target: Option<String>,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        auth_app: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        icon: String,
        #[arg(long)]
        app_user_model_id: String,
        #[arg(long)]
        job_name: Option<String>,
        #[arg(long)]
        uri: Option<String>,
    },
    #[command(hide = true)]
    Broker {
        #[arg(long)]
        app: String,
        #[arg(long)]
        instance: String,
    },
    #[command(hide = true)]
    DeferHostElectron {
        #[arg(long)]
        wait_pid: u32,
        #[arg(long)]
        host: String,
        #[arg(long)]
        hosted_app: String,
        #[arg(long)]
        shim_target: String,
        #[arg(long)]
        profile: String,
        #[arg(long)]
        auth_app: String,
        #[arg(long)]
        status: String,
        #[arg(long)]
        icon: String,
        #[arg(long)]
        app_user_model_id: String,
        #[arg(long)]
        job_name: Option<String>,
    },
    /// Provision the instance account (requires elevation; no app ACL changes)
    Prepare {
        #[arg(long)]
        app: String,
        #[arg(long)]
        instance: String,
    },
    /// Show Tier C status for an instance
    Status {
        #[arg(long)]
        app: String,
        #[arg(long)]
        instance: String,
    },
    Stop {
        #[arg(long)]
        app: String,
        #[arg(long)]
        instance: String,
    },
    /// Delete an AppMux-managed hidden account and remove its instance record
    Remove {
        #[arg(long)]
        app: String,
        #[arg(long)]
        instance: String,
        #[arg(long)]
        purge: bool,
        #[arg(long)]
        confirm_remove: bool,
    },
}

#[derive(Subcommand)]
enum DevCmd {
    /// Enable developer mode
    On,
    /// Disable developer mode
    Off,
    /// Show whether developer mode is enabled
    Status,
}

#[derive(Subcommand)]
enum MenuCmd {
    /// Install/refresh the context menu entries
    Sync,
    /// Remove the context menu entries
    Remove,
}

const TOS_NOTICE: &str = "AppMux runs multiple copies of a program with separate settings.\n\
Running multiple copies may breach that program's own terms of service.\n\
Checking whether that is allowed is your responsibility.";

/// Shared entry point for both the console binary (appmux.exe) and the
/// windowless binary used by Explorer verbs (appmuxw.exe). With
/// `gui_fallback`, messages use MessageBox when no console is attached.
pub fn run_cli(gui_fallback: bool) {
    console::set_gui_fallback(gui_fallback);
    console::attach_parent_console();
    let cli = Cli::parse();
    if let Err(e) = real_main(cli) {
        console::error(&format!("{e:#}"));
        std::process::exit(1);
    }
}

fn real_main(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Run {
            target,
            instance,
            app,
            new,
            force,
            create_only,
        } => run(
            &target,
            instance.as_deref(),
            app.as_deref(),
            new,
            force,
            create_only,
        ),
        Cmd::Analyze { target } => analyze_command(&target),
        Cmd::List => list(),
        Cmd::Stop { app, instance } => stop(&app, &instance),
        Cmd::Remove {
            app,
            instance,
            purge,
        } => remove(&app, &instance, purge),
        Cmd::Menu { cmd: MenuCmd::Sync } => {
            shellmenu::sync(&Db::load()?)?;
            console::info("Context menu installed for shortcuts and executables.");
            Ok(())
        }
        Cmd::Menu {
            cmd: MenuCmd::Remove,
        } => {
            shellmenu::remove()?;
            console::info("Context menu removed.");
            Ok(())
        }
        Cmd::Shortcut { app, instance } => make_shortcut(&app, &instance),
        Cmd::Recipes => list_recipes(),
        Cmd::AcceptTos => {
            let mut cfg = Config::load()?;
            cfg.tos_accepted = true;
            cfg.save()?;
            console::info("Notice accepted.");
            Ok(())
        }
        Cmd::TierC { cmd } => tier_c(cmd),
        Cmd::PackageLab { cmd } => package_lab_command(cmd),
        Cmd::Protocol { cmd } => protocol_command(cmd),
        Cmd::Web { cmd } => web_command(cmd),
        Cmd::Dev { cmd } => {
            let mut cfg = Config::load()?;
            match cmd {
                DevCmd::On => {
                    cfg.dev_mode = true;
                    cfg.save()?;
                    console::info(
                        "Developer mode ON. `run --force` now bypasses the anti-cheat/DRM \
                         guardrail heuristics and Package Lab. Use only for local testing; \
                         packaged apps require a new signed identity and explicit consent.",
                    );
                }
                DevCmd::Off => {
                    cfg.dev_mode = false;
                    cfg.save()?;
                    console::info("Developer mode OFF.");
                }
                DevCmd::Status => {
                    console::info(if cfg.dev_mode {
                        "Developer mode: ON"
                    } else {
                        "Developer mode: OFF"
                    });
                }
            }
            Ok(())
        }
    }
}

#[derive(Serialize)]
struct AutoAnalysis {
    app_id: String,
    display: String,
    route: String,
    confidence: String,
    packaged: bool,
    requires_elevation: bool,
    requires_package_consent: bool,
    strip_services: bool,
    web_url: Option<String>,
    reason: String,
    warnings: Vec<String>,
}

fn unpackaged_route(status: &str, has_args: bool) -> (&'static str, bool) {
    let known = matches!(status, "verified" | "partial");
    if !known {
        ("tier-c", false)
    } else if has_args {
        ("recipe-a", true)
    } else {
        ("recipe-b", true)
    }
}

fn web_analysis(plan: &launch::LaunchPlan, reason: String) -> AutoAnalysis {
    AutoAnalysis {
        app_id: format!("web-{}", plan.app_id),
        display: format!("{} Web", plan.display),
        route: "web-app".into(),
        confidence: "verified-fallback".into(),
        packaged: false,
        requires_elevation: false,
        requires_package_consent: false,
        strip_services: false,
        web_url: plan.recipe.web_url.clone(),
        reason,
        warnings: vec![
            "Runs the vendor's verified official web app in a dedicated persistent browser profile; native-only desktop features are unavailable."
                .into(),
        ],
    }
}

fn analyze(target: &str) -> Result<AutoAnalysis> {
    let plan = launch::plan(target)?;
    if let Some(reason) = guard::check(&plan.exe, &plan.hint) {
        return Ok(AutoAnalysis {
            app_id: plan.app_id,
            display: plan.display,
            route: "unsupported".into(),
            confidence: "blocked".into(),
            packaged: false,
            requires_elevation: false,
            requires_package_consent: false,
            strip_services: false,
            web_url: None,
            reason,
            warnings: Vec::new(),
        });
    }
    if plan.recipe.prefer_web && plan.recipe.web_url.is_some() {
        return Ok(web_analysis(&plan, plan.recipe.notes.clone()));
    }
    if plan.recipe.tier_d_patch.is_some() {
        let preflight = account::preflight_tier_d(&plan);
        return Ok(AutoAnalysis {
            app_id: plan.app_id,
            display: plan.display,
            route: if preflight.is_ok() { "tier-d" } else { "unsupported" }.into(),
            confidence: if preflight.is_ok() {
                "version-gated"
            } else {
                "adapter-update-required"
            }
            .into(),
            packaged: false,
            requires_elevation: preflight.is_ok(),
            requires_package_consent: false,
            strip_services: false,
            web_url: None,
            reason: preflight.err().map_or(plan.recipe.notes, |error| error.to_string()),
            warnings: vec![
                "Tier D modifies only an AppMux-managed copy; the vendor installation remains unchanged."
                    .into(),
            ],
        });
    }
    if plan.recipe.prefer_tier_c {
        return Ok(AutoAnalysis {
            app_id: plan.app_id,
            display: plan.display,
            route: "tier-c".into(),
            confidence: plan.recipe.status,
            packaged: false,
            requires_elevation: true,
            requires_package_consent: false,
            strip_services: false,
            web_url: None,
            reason: plan.recipe.notes,
            warnings: Vec::new(),
        });
    }
    if plan.recipe.status == "blocked" {
        return Ok(AutoAnalysis {
            app_id: plan.app_id,
            display: plan.display,
            route: "unsupported".into(),
            confidence: "blocked".into(),
            packaged: false,
            requires_elevation: false,
            requires_package_consent: false,
            strip_services: false,
            web_url: None,
            reason: plan.recipe.notes,
            warnings: Vec::new(),
        });
    }
    if let Ok(report) = package_lab::inspect(&plan.exe) {
        let services = report
            .blockers
            .iter()
            .any(|b| b == "declares a Windows service");
        let hard: Vec<_> = report
            .blockers
            .iter()
            .filter(|b| b.as_str() != "declares a Windows service")
            .cloned()
            .collect();
        let unsupported = !hard.is_empty();
        if unsupported && plan.recipe.web_url.is_some() {
            return Ok(web_analysis(&plan, hard.join("; ")));
        }
        return Ok(AutoAnalysis {
            app_id: plan.app_id,
            display: plan.display,
            route: if unsupported {
                "unsupported"
            } else if services {
                "package-lab-service-free"
            } else {
                "package-lab"
            }
            .into(),
            confidence: if unsupported {
                "blocked"
            } else {
                "experimental"
            }
            .into(),
            packaged: true,
            requires_elevation: !unsupported,
            requires_package_consent: !unsupported,
            strip_services: services && !unsupported,
            web_url: None,
            reason: if unsupported {
                hard.join("; ")
            } else if services {
                "Package service conflicts are removable; service-dependent features will be disabled."
                    .into()
            } else {
                "A separate signed package identity is the lightest viable route.".into()
            },
            warnings: report.warnings,
        });
    }
    let (route, known) = unpackaged_route(&plan.recipe.status, !plan.recipe.args.is_empty());
    Ok(AutoAnalysis {
        app_id: plan.app_id,
        display: plan.display,
        route: route.into(),
        confidence: plan.recipe.status.clone(),
        packaged: false,
        requires_elevation: !known,
        requires_package_consent: false,
        strip_services: false,
        web_url: None,
        reason: if known {
            plan.recipe.notes.clone()
        } else {
            "No verified cooperative recipe; a real Windows user profile is safer than partial environment redirection."
                .into()
        },
        warnings: if plan.recipe.status == "partial" {
            vec!["Recipe is only partially verified; check account/settings separation after launch.".into()]
        } else {
            Vec::new()
        },
    })
}

fn analyze_command(target: &str) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&analyze(target)?)?);
    Ok(())
}

fn quote_windows_argument(value: &str) -> String {
    if !value.is_empty() && !value.contains([' ', '\t', '"']) {
        return value.to_string();
    }
    let mut output = String::from("\"");
    let mut slashes = 0;
    for character in value.chars() {
        if character == '\\' {
            slashes += 1;
        } else if character == '"' {
            output.push_str(&"\\".repeat(slashes * 2 + 1));
            output.push('"');
            slashes = 0;
        } else {
            output.push_str(&"\\".repeat(slashes));
            slashes = 0;
            output.push(character);
        }
    }
    output.push_str(&"\\".repeat(slashes * 2));
    output.push('"');
    output
}

fn package_arguments(plan: &launch::LaunchPlan, inst: &Instance) -> Result<String> {
    let data_dir = inst.data_dir();
    std::fs::create_dir_all(&data_dir)?;
    let data = data_dir.to_string_lossy();
    let arguments = if inst.profile_args.is_empty() {
        &plan.recipe.args
    } else {
        &inst.profile_args
    };
    Ok(arguments
        .iter()
        .map(|a| a.replace("{data}", &data))
        .map(|argument| quote_windows_argument(&argument))
        .collect::<Vec<_>>()
        .join(" "))
}

fn run(
    target: &str,
    instance: Option<&str>,
    app_override: Option<&str>,
    new: bool,
    force: bool,
    create_only: bool,
) -> Result<()> {
    if let (Some(app), Some(name)) = (app_override, instance) {
        let mut db = Db::load()?;
        if let Some(stored) = db.find(app, name) {
            if stored.isolation == "web" {
                stored.last_used = store::now();
                let selected = stored.clone();
                db.save()?;
                web_app::launch(&selected)?;
                return Ok(());
            }
        }
    }
    let plan = launch::plan(target)?;
    let cfg_probe = Config::load()?;

    if force && !cfg_probe.dev_mode {
        bail!("--force requires developer mode; enable it with: appmux dev on");
    }
    let bypass = force && cfg_probe.dev_mode;

    if let Some(reason) = guard::check(&plan.exe, &plan.hint) {
        if bypass {
            console::warn(&format!(
                "dev override: guardrail bypassed for '{}' ({reason}). Test use only.",
                plan.display
            ));
        } else {
            bail!(
                "Declining to run '{}' in an instance: {reason}.\n\
                 Programs with anti-cheat, DRM, or kernel components are not supported.\n\
                 (False positive while testing? `appmux dev on` then `run --force`.)",
                plan.display
            );
        }
    }
    if plan.recipe.status == "blocked" && !bypass {
        bail!(
            "'{}' is marked as blocked: {}",
            plan.display,
            plan.recipe.notes
        );
    }

    let mut cfg = Config::load()?;
    if !cfg.tos_accepted {
        if !console::confirm(TOS_NOTICE) {
            bail!("notice was not accepted; nothing was launched");
        }
        cfg.tos_accepted = true;
        cfg.save()?;
    }

    let mut db = Db::load()?;
    let app_id = app_override.unwrap_or(&plan.app_id);
    let name = match (instance, new) {
        (Some(n), _) => n.to_string(),
        (None, true) => db.next_auto_name(app_id),
        (None, false) => db.next_auto_name(app_id),
    };
    store::validate_instance_name(&name)?;
    if app_override.is_some()
        && !db
            .instances
            .iter()
            .any(|i| i.app_id == app_id && i.name.eq_ignore_ascii_case(&name))
    {
        bail!("no stored instance '{name}' for app '{app_id}'");
    }

    let created;
    // Store the original target (shortcut preferred over resolved exe) so
    // relaunching from the manager re-resolves shortcut args (Squirrel stubs
    // like Discord's Update.exe need --processStart from the .lnk).
    let inst = match db.find(app_id, &name) {
        Some(i) => {
            created = false;
            i.last_used = store::now();
            i.app_path = target.to_string();
            i.display_name = Some(plan.display.clone());
            i.clone()
        }
        None => {
            created = true;
            let inst = Instance {
                name: name.clone(),
                app_id: app_id.to_string(),
                app_path: target.to_string(),
                display_name: Some(plan.display.clone()),
                created: store::now(),
                last_used: store::now(),
                isolation: "recipe".to_string(),
                windows_user: None,
                tier_d_adapter: None,
                package_aumid: None,
                protocols: Vec::new(),
                profile_args: Vec::new(),
                web_url: None,
            };
            db.instances.push(inst.clone());
            inst
        }
    };
    db.save()?;
    // Keep the Explorer menu in sync with the instance list (best effort).
    let _ = shellmenu::sync(&db);
    if create_only {
        console::info(&format!(
            "Prepared instance '{}' for app '{}' without launching.",
            inst.name, inst.app_id
        ));
        return Ok(());
    }

    if plan.recipe.prefer_tier_c && inst.isolation != "account" {
        bail!(
            "'{}' requires its verified private Windows-profile route; complete Tier C setup in AppMux Manager",
            plan.display
        );
    }
    if plan.recipe.status == "unverified" && console::has_console() {
        console::warn(&format!(
            "no verified recipe for '{}'; using generic environment redirection. {}",
            plan.display, plan.recipe.notes
        ));
    }

    let pid = if inst.isolation == "account" {
        account::launch(&inst, &plan)?
    } else if inst.isolation == "package" {
        package_lab::ensure_launch_allowed(&plan.exe)?;
        package_lab::activate(
            inst.package_aumid
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("Package Lab instance has no AUMID"))?,
            &package_arguments(&plan, &inst)?,
        )?
    } else {
        launch::launch(&plan, &inst.data_dir())?
    };
    if console::has_console() {
        console::info(&format!(
            "{} '{}' instance '{}' started (pid {pid}, tier: {}, status: {}).",
            if created {
                "Created and launched"
            } else {
                "Launched"
            },
            plan.display,
            inst.name,
            match inst.isolation.as_str() {
                "account" => "C (Windows account)",
                "package" => "Package Lab",
                _ if plan.recipe.args.is_empty() => "B (env redirect)",
                _ => "A (native flags)",
            },
            plan.recipe.status,
        ));
    }
    Ok(())
}

fn list() -> Result<()> {
    let db = Db::load()?;
    if db.instances.is_empty() {
        console::info("No instances yet. Use: appmux run --target <app> --new");
        return Ok(());
    }
    println!("{:<20} {:<20} {}", "APP", "INSTANCE", "DATA DIR");
    for i in &db.instances {
        println!("{:<20} {:<20} {}", i.app_id, i.name, i.data_dir().display());
    }
    Ok(())
}

fn stop(app: &str, instance: &str) -> Result<()> {
    let mut db = Db::load()?;
    let stored = db
        .find(app, instance)
        .ok_or_else(|| anyhow::anyhow!("no instance '{instance}' for app '{app}'"))?
        .clone();
    match stored.isolation.as_str() {
        "package" => package_lab::stop_instance(&stored)?,
        "web" => web_app::stop(&stored)?,
        "account" => account::stop(&stored, &launch::plan(&stored.app_path)?)?,
        _ => bail!(
            "Stop is currently supported for isolated Package, Web, and Windows-profile instances"
        ),
    }
    console::info(&format!("Stopped all processes for {app} / {instance}."));
    Ok(())
}

fn remove(app: &str, instance: &str, purge: bool) -> Result<()> {
    let mut db = Db::load()?;
    let before = db.instances.len();
    let mut removed = None;
    db.instances.retain(|i| {
        if i.app_id == app && i.name.eq_ignore_ascii_case(instance) {
            removed = Some(i.clone());
            false
        } else {
            true
        }
    });
    if db.instances.len() == before {
        bail!("no instance '{instance}' for app '{app}'");
    }
    if let Some(stored) = &removed {
        if stored.isolation == "account" {
            bail!("managed Windows-profile instances must be removed with 'appmux tier-c remove'");
        }
        if stored.isolation == "web" {
            web_app::stop(stored)?;
        }
    }
    let data_dir = removed.as_ref().map(Instance::data_dir);
    db.save()?;
    let _ = shellmenu::sync(&db);
    if purge {
        if let Some(dir) = data_dir {
            if dir.starts_with(paths::instances_dir()) && dir.exists() {
                std::fs::remove_dir_all(&dir)?;
                console::info(&format!("Removed instance and deleted {}", dir.display()));
                return Ok(());
            }
        }
    }
    console::info("Instance removed (data directory kept; use --purge to delete it).");
    Ok(())
}

fn require_package_lab_dev(instance: &str) -> Result<()> {
    if !Config::load()?.dev_mode {
        bail!("Package Lab requires developer mode: appmux dev on");
    }
    store::validate_instance_name(instance)
}

fn web_command(cmd: WebCmd) -> Result<()> {
    match cmd {
        WebCmd::Create { target, instance } => {
            store::validate_instance_name(&instance)?;
            let plan = launch::plan(&target)?;
            let url = plan
                .recipe
                .web_url
                .clone()
                .context("this app has no verified official web fallback")?;
            let app_id = format!("web-{}", plan.app_id);
            let mut db = Db::load()?;
            let value = Instance {
                name: instance.clone(),
                app_id: app_id.clone(),
                app_path: target,
                display_name: Some(format!("{} Web", plan.display)),
                created: store::now(),
                last_used: store::now(),
                isolation: "web".into(),
                windows_user: None,
                tier_d_adapter: None,
                package_aumid: None,
                protocols: Vec::new(),
                profile_args: Vec::new(),
                web_url: Some(url),
            };
            let stored = if let Some(existing) = db.find(&app_id, &instance) {
                *existing = value;
                existing.clone()
            } else {
                db.instances.push(value.clone());
                value
            };
            db.save()?;
            let _ = shellmenu::sync(&db);
            web_app::launch(&stored)?;
            console::info(&format!("Created App Web instance {app_id} / {instance}."));
            Ok(())
        }
    }
}

fn owner_routed_protocols(_recipe: &recipes::Recipe) -> Vec<String> {
    Vec::new()
}

fn protocol_command(cmd: ProtocolCmd) -> Result<()> {
    match cmd {
        ProtocolCmd::Sync => {
            let mut db = Db::load()?;
            let mut changed = false;
            for instance in &mut db.instances {
                if instance.isolation != "account" {
                    continue;
                }
                if let Ok(plan) = launch::plan(&instance.app_path) {
                    let protocols = owner_routed_protocols(&plan.recipe);
                    if instance.protocols != protocols {
                        instance.protocols = protocols;
                        changed = true;
                    }
                    if instance.tier_d_adapter != plan.recipe.tier_d_patch {
                        instance.tier_d_adapter = plan.recipe.tier_d_patch;
                        changed = true;
                    }
                }
            }
            if changed {
                db.save()?;
            }
            let count = shellmenu::sync_protocols(&db)?;
            console::info(&format!(
                "Registered AppMux router for {count} protocol(s)."
            ));
            Ok(())
        }
        ProtocolCmd::Route { uri, app, instance } => {
            anyhow::ensure!(uri.len() <= 8192, "callback URI is too long");
            anyhow::ensure!(
                !uri.chars().any(char::is_control),
                "callback URI contains control characters"
            );
            let scheme = uri
                .split_once(':')
                .map(|(scheme, _)| scheme.to_ascii_lowercase())
                .context("callback URI has no scheme")?;
            let mut db = Db::load()?;
            let stored = db
                .find(&app, &instance)
                .ok_or_else(|| anyhow::anyhow!("no instance '{instance}' for app '{app}'"))?;
            anyhow::ensure!(
                stored
                    .protocols
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(&scheme)),
                "instance '{instance}' is not registered for the '{scheme}' protocol"
            );
            anyhow::ensure!(
                stored.isolation == "package",
                "protocol routing requires a Package Lab instance"
            );
            let selected = stored.clone();
            stored.last_used = store::now();
            db.save()?;
            let plan = launch::plan(&selected.app_path)?;
            let mut arguments = package_arguments(&plan, &selected)?;
            if !arguments.is_empty() {
                arguments.push(' ');
            }
            arguments.push_str(&quote_windows_argument(&uri));
            package_lab::activate(
                selected
                    .package_aumid
                    .as_deref()
                    .context("Package Lab instance has no AUMID")?,
                &arguments,
            )?;
            Ok(())
        }
    }
}

fn package_lab_command(cmd: PackageLabCmd) -> Result<()> {
    match cmd {
        PackageLabCmd::Inspect { target } => {
            let report = package_lab::inspect(std::path::Path::new(&target))?;
            package_lab::print_report(&report)
        }
        PackageLabCmd::SdkTools {
            accept_windows_sdk_license,
        } => {
            package_lab::ensure_sdk_tools(accept_windows_sdk_license)?;
            console::info("Windows SDK packaging tools are ready.");
            Ok(())
        }
        PackageLabCmd::Plan { target, instance } => {
            require_package_lab_dev(&instance)?;
            let file = package_lab::write_plan(std::path::Path::new(&target), &instance)?;
            console::info(&format!(
                "Read-only Package Lab inspection written to {}. No package or ACL was changed.",
                file.display()
            ));
            Ok(())
        }
        PackageLabCmd::Prepare {
            target,
            instance,
            confirm_free_no_drm,
            strip_services,
        } => {
            require_package_lab_dev(&instance)?;
            if !confirm_free_no_drm {
                bail!(
                    "refusing to copy/re-identify the package without \
                     --confirm-free-no-drm after manual license/DRM review"
                );
            }
            let dir = package_lab::prepare_workspace(
                std::path::Path::new(&target),
                &instance,
                strip_services,
            )?;
            console::info(&format!(
                "Package workspace prepared at {}. Installed package untouched; clone is not signed or installed.",
                dir.display()
            ));
            Ok(())
        }
        PackageLabCmd::Pack { target, instance } => {
            require_package_lab_dev(&instance)?;
            let file = package_lab::pack_workspace(std::path::Path::new(&target), &instance)?;
            console::info(&format!(
                "Unsigned test package created: {}. Nothing was signed, trusted, or installed.",
                file.display()
            ));
            Ok(())
        }
        PackageLabCmd::Sign {
            target,
            instance,
            confirm_trust_dev_cert,
        } => {
            require_package_lab_dev(&instance)?;
            if !confirm_trust_dev_cert {
                bail!("signing requires --confirm-trust-dev-cert");
            }
            let file = package_lab::sign_workspace(std::path::Path::new(&target), &instance)?;
            console::info(&format!("Signed test package: {}", file.display()));
            Ok(())
        }
        PackageLabCmd::TrustMachine {
            target,
            instance,
            confirm_machine_trust,
        } => {
            require_package_lab_dev(&instance)?;
            if !confirm_machine_trust {
                bail!("machine trust requires --confirm-machine-trust");
            }
            package_lab::trust_machine_certificate(std::path::Path::new(&target), &instance)?;
            console::info(
                "Package Lab public certificate trusted under LocalMachine\\TrustedPeople.",
            );
            Ok(())
        }
        PackageLabCmd::Install {
            target,
            instance,
            confirm_sideload,
        } => {
            require_package_lab_dev(&instance)?;
            if !confirm_sideload {
                bail!("installation requires --confirm-sideload");
            }
            package_lab::install_workspace(std::path::Path::new(&target), &instance)?;
            console::info("Test package sideloaded for the current user.");
            Ok(())
        }
        PackageLabCmd::Uninstall {
            app,
            instance,
            purge,
            confirm_uninstall,
        } => {
            if !confirm_uninstall {
                bail!("package removal requires --confirm-uninstall");
            }
            let mut db = Db::load()?;
            let stored = db
                .find(&app, &instance)
                .ok_or_else(|| anyhow::anyhow!("no instance '{instance}' for app '{app}'"))?
                .clone();
            package_lab::uninstall_instance(&stored)?;
            remove(&app, &instance, purge)
        }
        PackageLabCmd::Adopt { target, instance } => {
            require_package_lab_dev(&instance)?;
            let target_path = std::path::Path::new(&target);
            let report = package_lab::inspect(target_path)?;
            let (aumid, clone_exe) = package_lab::installed_clone(target_path, &instance)?;
            let app_id = format!("package-{}", paths::sanitize(&report.identity_name));
            let mut db = Db::load()?;
            let value = Instance {
                name: instance.clone(),
                app_id: app_id.clone(),
                app_path: clone_exe.display().to_string(),
                display_name: Some(report.display_name.clone()),
                created: store::now(),
                last_used: store::now(),
                isolation: "package".to_string(),
                windows_user: None,
                tier_d_adapter: None,
                package_aumid: Some(aumid.clone()),
                protocols: report.protocols.clone(),
                profile_args: package_lab::profile_arguments(&report, target_path),
                web_url: None,
            };
            if let Some(existing) = db.find(&app_id, &instance) {
                *existing = value;
            } else {
                db.instances.push(value);
            }
            db.save()?;
            let _ = shellmenu::sync(&db);
            let _ = shellmenu::sync_protocols(&db);
            console::info(&format!(
                "Package Lab instance adopted: {app_id} / {instance} ({aumid})"
            ));
            Ok(())
        }
    }
}

fn tier_c(cmd: TierCCmd) -> Result<()> {
    match &cmd {
        TierCCmd::InitProfile {
            protocol,
            helper,
            host,
            hosted_app,
            shim_target,
            auth_app,
            profile,
            icon,
            app_user_model_id,
            status,
        } => {
            return account::initialize_profile(
                protocol.as_deref(),
                helper.as_deref().map(std::path::Path::new),
                host.as_deref().map(std::path::Path::new),
                hosted_app.as_deref().map(std::path::Path::new),
                shim_target.as_deref().map(std::path::Path::new),
                profile.as_deref().map(std::path::Path::new),
                auth_app.as_deref().map(std::path::Path::new),
                status.as_deref().map(std::path::Path::new),
                icon.as_deref().map(std::path::Path::new),
                app_user_model_id.as_deref(),
            );
        }
        TierCCmd::HostElectron {
            host,
            hosted_app,
            shim_target,
            profile,
            auth_app,
            status,
            icon,
            app_user_model_id,
            job_name,
            uri,
        } => {
            return account::host_electron(
                std::path::Path::new(host),
                std::path::Path::new(hosted_app),
                shim_target.as_deref().map(std::path::Path::new),
                profile.as_deref().map(std::path::Path::new),
                auth_app.as_deref().map(std::path::Path::new),
                status.as_deref().map(std::path::Path::new),
                std::path::Path::new(icon),
                app_user_model_id,
                job_name.as_deref(),
                uri.as_deref(),
            );
        }
        TierCCmd::DeferHostElectron {
            wait_pid,
            host,
            hosted_app,
            shim_target,
            profile,
            auth_app,
            status,
            icon,
            app_user_model_id,
            job_name,
        } => {
            return account::defer_host_electron(
                *wait_pid,
                std::path::Path::new(host),
                std::path::Path::new(hosted_app),
                std::path::Path::new(shim_target),
                std::path::Path::new(profile),
                std::path::Path::new(auth_app),
                std::path::Path::new(status),
                std::path::Path::new(icon),
                app_user_model_id,
                job_name.as_deref(),
            );
        }
        _ => {}
    }
    let mut db = Db::load()?;
    match cmd {
        TierCCmd::InitProfile { .. }
        | TierCCmd::HostElectron { .. }
        | TierCCmd::DeferHostElectron { .. } => unreachable!(),
        TierCCmd::Broker { app, instance } => {
            let inst = db
                .find(&app, &instance)
                .ok_or_else(|| anyhow::anyhow!("no instance '{instance}' for app '{app}'"))?;
            let plan = launch::plan(&inst.app_path)?;
            account::broker_launch(inst, &plan)?;
            Ok(())
        }
        TierCCmd::Prepare { app, instance } => {
            let inst = db
                .find(&app, &instance)
                .ok_or_else(|| anyhow::anyhow!("no instance '{instance}' for app '{app}'"))?
                .clone();
            if inst.isolation == "package" {
                bail!(
                    "Tier C cannot be combined with Package Lab in the current interactive \
                     session; Windows denies cross-user package activation"
                );
            }
            let plan = launch::plan(&inst.app_path)?;
            let username = account::provision(&inst, &plan)?;
            let saved = db.find(&app, &instance).expect("instance disappeared");
            saved.isolation = "account".to_string();
            saved.windows_user = Some(username.clone());
            saved.tier_d_adapter = plan.recipe.tier_d_patch.clone();
            saved.protocols = owner_routed_protocols(&plan.recipe);
            db.save()?;
            let _ = shellmenu::sync_protocols(&db);
            if console::has_console() {
                console::info(&format!(
                    "Tier C ready for {app} / {instance} (hidden account: {username})."
                ));
            }
            Ok(())
        }
        TierCCmd::Status { app, instance } => {
            let inst = db
                .find(&app, &instance)
                .ok_or_else(|| anyhow::anyhow!("no instance '{instance}' for app '{app}'"))?;
            if inst.isolation == "account" {
                console::info(&format!(
                    "Tier C: ready (account: {})",
                    inst.windows_user.as_deref().unwrap_or("missing")
                ));
            } else {
                console::info("Tier C: not provisioned (recipe isolation active)");
            }
            Ok(())
        }
        TierCCmd::Stop { app, instance } => {
            let inst = db
                .find(&app, &instance)
                .ok_or_else(|| anyhow::anyhow!("no instance '{instance}' for app '{app}'"))?;
            let plan = launch::plan(&inst.app_path)?;
            account::stop(inst, &plan)
        }
        TierCCmd::Remove {
            app,
            instance,
            purge,
            confirm_remove,
        } => {
            anyhow::ensure!(
                confirm_remove,
                "Tier C account removal requires --confirm-remove"
            );
            let inst = db
                .find(&app, &instance)
                .ok_or_else(|| anyhow::anyhow!("no instance '{instance}' for app '{app}'"))?
                .clone();
            anyhow::ensure!(
                inst.isolation == "account",
                "instance is not using a managed Windows profile"
            );
            account::remove(&inst)?;
            let saved = db.find(&app, &instance).expect("instance disappeared");
            saved.isolation = "recipe".to_string();
            saved.windows_user = None;
            saved.tier_d_adapter = None;
            db.save()?;
            drop(db);
            remove(&app, &instance, purge)
        }
    }
}

fn make_shortcut(app: &str, instance: &str) -> Result<()> {
    let mut db = Db::load()?;
    let inst = db
        .find(app, instance)
        .ok_or_else(|| anyhow::anyhow!("no instance '{instance}' for app '{app}'"))?
        .clone();
    // Resolve the target so the shortcut carries the real app icon.
    let plan = launch::plan(&inst.app_path)?;
    let path = shortcut::create(&inst, &plan.display, &plan.exe)?;
    console::info(&format!(
        "Shortcut created: {}\nRight-click it and choose 'Pin to taskbar' for one-click access.",
        path.display()
    ));
    Ok(())
}

fn list_recipes() -> Result<()> {
    println!("{:<12} {:<22} {:<10} {}", "ID", "APP", "STATUS", "TIER");
    for r in recipes::all() {
        let tier = if r.tier_d_patch.is_some() {
            "D (shim)"
        } else if !r.args.is_empty() && !r.redirect_env.is_empty() {
            "A+B"
        } else if !r.args.is_empty() {
            "A (flags)"
        } else {
            "B (env)"
        };
        println!("{:<12} {:<22} {:<10} {}", r.id, r.display, r.status, tier);
    }
    Ok(())
}

#[cfg(test)]
mod auto_route_tests {
    use super::{owner_routed_protocols, unpackaged_route};

    #[test]
    fn auto_uses_lightest_known_route_and_escalates_unknown_apps() {
        assert_eq!(unpackaged_route("verified", true), ("recipe-a", true));
        assert_eq!(unpackaged_route("verified", false), ("recipe-b", true));
        assert_eq!(unpackaged_route("partial", true), ("recipe-a", true));
        assert_eq!(unpackaged_route("unverified", false), ("tier-c", false));
        assert_eq!(unpackaged_route("blocked", true), ("tier-c", false));
    }

    #[test]
    fn tier_d_callbacks_are_not_registered_in_the_owner_profile() {
        let slack = crate::recipes::builtin()
            .into_iter()
            .find(|recipe| recipe.id == "slack")
            .unwrap();
        assert!(slack.tier_d_patch.is_some());
        assert!(owner_routed_protocols(&slack).is_empty());
    }
}
