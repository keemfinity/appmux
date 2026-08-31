use crate::paths;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A per-app launch recipe. Tier A recipes use `args`; Tier B recipes use
/// `redirect_env`. A recipe may combine both.
#[derive(Clone, Serialize, Deserialize)]
pub struct Recipe {
    pub id: String,
    pub display: String,
    /// Exe file names (lowercase) this recipe applies to.
    #[serde(default)]
    pub match_exe: Vec<String>,
    /// Substrings (lowercase) matched against the shortcut name + arguments,
    /// for apps launched through generic stubs like Squirrel's Update.exe.
    #[serde(default)]
    pub match_name: Vec<String>,
    /// verified | partial | unverified | blocked
    pub status: String,
    /// Extra command-line arguments; `{data}` expands to the instance data dir.
    #[serde(default)]
    pub args: Vec<String>,
    /// Env vars to redirect into the instance data dir:
    /// APPDATA, LOCALAPPDATA, TEMP, USERPROFILE, HOME.
    #[serde(default)]
    pub redirect_env: Vec<String>,
    /// Arbitrary env vars to set; values may use `{data}`.
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub web_url: Option<String>,
    #[serde(default)]
    pub prefer_web: bool,
    #[serde(default)]
    pub prefer_tier_c: bool,
    #[serde(default)]
    pub tier_c_user_data_dir: Option<String>,
    #[serde(default)]
    pub tier_c_electron_host: Option<String>,
    #[serde(default)]
    pub tier_c_electron_app: Option<String>,
    #[serde(default)]
    pub tier_c_electron_sha256: Option<String>,
    #[serde(default)]
    pub tier_c_electron_exe_sha256: Option<String>,
    #[serde(default)]
    pub tier_c_protocol: Option<String>,
    #[serde(default)]
    pub tier_d_patch: Option<String>,
    #[serde(default)]
    pub tier_d_owner_host: bool,
    #[serde(default)]
    pub notes: String,
}

const BUILTIN: &str = include_str!("builtin_recipes.json");

pub fn builtin() -> Vec<Recipe> {
    serde_json::from_str(BUILTIN).expect("builtin_recipes.json is invalid")
}

pub fn user() -> Result<Vec<Recipe>> {
    match std::fs::read_to_string(paths::user_recipes_file()) {
        Ok(s) => Ok(serde_json::from_str(&s)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

pub fn all() -> Vec<Recipe> {
    // User recipes come first so they can override builtins by matching earlier.
    let mut v = user().unwrap_or_default();
    v.extend(builtin());
    v
}

/// Find the recipe for a target. `exe_name` is the lowercase exe file name;
/// `hint` is the lowercase shortcut stem plus shortcut arguments.
pub fn find(exe_name: &str, hint: &str) -> Option<Recipe> {
    let recipes = all();
    recipes
        .iter()
        .find(|r| r.match_exe.iter().any(|m| m == exe_name))
        .or_else(|| {
            recipes.iter().find(|r| {
                !r.match_name.is_empty() && r.match_name.iter().any(|m| hint.contains(m.as_str()))
            })
        })
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_parses() {
        let recipes = builtin();
        assert!(recipes.iter().any(|r| r.id == "discord"));
        let chatgpt = recipes.iter().find(|r| r.id == "chatgpt").unwrap();
        assert_eq!(chatgpt.web_url.as_deref(), Some("https://chatgpt.com/"));
        assert!(chatgpt.prefer_web);
        let slack = recipes.iter().find(|r| r.id == "slack").unwrap();
        assert!(slack.prefer_tier_c);
        assert_eq!(slack.tier_c_electron_host.as_deref(), Some("43.4.0"));
        assert_eq!(slack.tier_c_electron_app.as_deref(), Some("slack.exe"));
        assert_eq!(slack.tier_c_protocol.as_deref(), Some("slack"));
        let figma = recipes.iter().find(|r| r.id == "figma").unwrap();
        assert!(figma.tier_d_owner_host);
        assert_eq!(figma.tier_d_patch.as_deref(), Some("figma-owner-host-v1"));
        assert_eq!(figma.tier_c_electron_host.as_deref(), Some("42.9.2"));
        for r in &recipes {
            assert!(
                matches!(
                    r.status.as_str(),
                    "verified" | "partial" | "unverified" | "blocked"
                ),
                "recipe {} has invalid status {}",
                r.id,
                r.status
            );
        }
    }

    #[test]
    fn find_by_exe_and_hint() {
        assert_eq!(find("discord.exe", "").unwrap().id, "discord");
        assert_eq!(find("chrome.exe", "").unwrap().id, "chrome");
        // Squirrel stub resolved through the shortcut-name hint.
        assert_eq!(
            find("update.exe", "discord --processstart discord.exe")
                .unwrap()
                .id,
            "discord"
        );
        assert!(find("unknownapp.exe", "unknownapp").is_none());
    }
}

/// Generic Tier B fallback for unknown apps.
pub fn generic(app_id: &str, display: &str) -> Recipe {
    Recipe {
        id: app_id.to_string(),
        display: display.to_string(),
        match_exe: Vec::new(),
        match_name: Vec::new(),
        status: "unverified".to_string(),
        args: Vec::new(),
        redirect_env: vec!["APPDATA".into(), "LOCALAPPDATA".into(), "TEMP".into()],
        env: Default::default(),
        web_url: None,
        prefer_web: false,
        prefer_tier_c: false,
        tier_c_user_data_dir: None,
        tier_c_electron_host: None,
        tier_c_electron_app: None,
        tier_c_electron_sha256: None,
        tier_c_electron_exe_sha256: None,
        tier_c_protocol: None,
        tier_d_patch: None,
        tier_d_owner_host: false,
        notes: "Generic environment redirection. Isolation may be partial: apps that resolve \
                known folders through the Windows shell API ignore environment variables."
            .to_string(),
    }
}
