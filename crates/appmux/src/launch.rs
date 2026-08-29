use crate::{lnk, paths, recipes, recipes::Recipe};
use anyhow::{ensure, Context, Result};
use std::path::{Path, PathBuf};

pub struct LaunchPlan {
    pub exe: PathBuf,
    /// Raw argument string carried over from the shortcut, if any.
    pub lnk_args: String,
    pub workdir: Option<PathBuf>,
    pub recipe: Recipe,
    pub app_id: String,
    pub display: String,
    /// Lowercase shortcut stem + args, used for guardrail checks.
    pub hint: String,
}

/// Generic stub exe names that never identify an app by themselves.
const GENERIC_STUBS: &[&str] = &["update", "launcher", "app", "start", "run"];

pub fn plan(target: &str) -> Result<LaunchPlan> {
    let target_path = PathBuf::from(target);
    ensure!(
        target_path.exists(),
        "target does not exist: {}",
        target_path.display()
    );

    let is_lnk = target_path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("lnk"))
        .unwrap_or(false);

    let (exe, lnk_args, workdir, lnk_stem) = if is_lnk {
        let info = lnk::resolve(&target_path)
            .with_context(|| format!("resolving shortcut {}", target_path.display()))?;
        let stem = target_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        (info.target, info.args, info.workdir, stem)
    } else {
        (target_path, String::new(), None, String::new())
    };

    ensure!(
        exe.extension()
            .map(|e| e.eq_ignore_ascii_case("exe"))
            .unwrap_or(false),
        "target is not an executable: {}",
        exe.display()
    );
    ensure!(
        exe.exists(),
        "resolved target does not exist: {}",
        exe.display()
    );

    let exe_name = exe
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let exe_stem = exe
        .file_stem()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let hint = format!(
        "{} {}",
        lnk_stem.to_ascii_lowercase(),
        lnk_args.to_ascii_lowercase()
    );

    let recipe = recipes::find(&exe_name, &hint);
    let (app_id, display) = match &recipe {
        Some(r) => (r.id.clone(), r.display.clone()),
        None => {
            // Prefer the shortcut name over generic stub exe names (Update.exe etc).
            let stem_lower = exe_stem.to_ascii_lowercase();
            let name = if GENERIC_STUBS.contains(&stem_lower.as_str()) && !lnk_stem.is_empty() {
                lnk_stem.clone()
            } else {
                exe_stem.clone()
            };
            (paths::sanitize(&name), name)
        }
    };
    let recipe = recipe.unwrap_or_else(|| recipes::generic(&app_id, &display));

    Ok(LaunchPlan {
        exe,
        lnk_args,
        workdir,
        recipe,
        app_id,
        display,
        hint,
    })
}

/// Materialize the instance data dir and spawn the target. Returns the PID.
pub fn launch(plan: &LaunchPlan, data_dir: &Path) -> Result<u32> {
    std::fs::create_dir_all(data_dir)?;

    let data = data_dir.to_string_lossy().to_string();
    let mut cmd = std::process::Command::new(&plan.exe);

    if !plan.lnk_args.trim().is_empty() {
        use std::os::windows::process::CommandExt;
        cmd.raw_arg(plan.lnk_args.trim());
    }

    let recipe_args: Vec<String> = plan
        .recipe
        .args
        .iter()
        .map(|a| a.replace("{data}", &data))
        .collect();
    // Squirrel stubs (Discord, classic Teams, ...) forward args to the real
    // app only when wrapped in --process-start-args.
    let is_squirrel_stub = plan
        .exe
        .file_name()
        .map(|n| n.eq_ignore_ascii_case("update.exe"))
        .unwrap_or(false)
        && plan
            .lnk_args
            .to_ascii_lowercase()
            .contains("--processstart");
    if is_squirrel_stub && !recipe_args.is_empty() {
        cmd.arg("--process-start-args");
        cmd.arg(recipe_args.join(" "));
    } else {
        cmd.args(recipe_args);
    }

    for key in &plan.recipe.redirect_env {
        let (vars, sub): (&[&str], &str) = match key.to_ascii_uppercase().as_str() {
            "APPDATA" => (&["APPDATA"], "Roaming"),
            "LOCALAPPDATA" => (&["LOCALAPPDATA"], "Local"),
            "TEMP" | "TMP" => (&["TEMP", "TMP"], "Temp"),
            "USERPROFILE" | "HOME" => (&["USERPROFILE", "HOME"], "Profile"),
            other => anyhow::bail!("recipe redirects unsupported env var '{other}'"),
        };
        let dir = data_dir.join(sub);
        std::fs::create_dir_all(&dir)?;
        for v in vars {
            cmd.env(v, &dir);
        }
    }

    for (key, value) in &plan.recipe.env {
        let value = value.replace("{data}", &data);
        // Create the directory if the value looks like a path under the data dir.
        if value.starts_with(&data) {
            let _ = std::fs::create_dir_all(&value);
        }
        cmd.env(key, value);
    }

    let cwd = plan
        .workdir
        .clone()
        .filter(|d| d.exists())
        .or_else(|| plan.exe.parent().map(|p| p.to_path_buf()));
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }

    let child = cmd
        .spawn()
        .with_context(|| format!("launching {}", plan.exe.display()))?;
    Ok(child.id())
}
