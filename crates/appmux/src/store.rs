use crate::paths;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Serialize, Deserialize)]
pub struct Instance {
    pub name: String,
    pub app_id: String,
    pub app_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub created: u64,
    pub last_used: u64,
    /// "recipe" (Tier A/B) or "account" (Tier C). Defaults preserve v0.1 data.
    #[serde(default = "default_isolation")]
    pub isolation: String,
    /// Hidden local account used by Tier C or a Tier D compatibility adapter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier_d_adapter: Option<String>,
    /// Package Family AppUserModelID used by Package Lab instances.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_aumid: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocols: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profile_args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_pid: Option<u32>,
}

fn default_isolation() -> String {
    "recipe".to_string()
}

impl Instance {
    pub fn data_dir(&self) -> PathBuf {
        paths::instances_dir()
            .join(paths::sanitize(&self.app_id))
            .join(paths::sanitize(&self.name))
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct Db {
    #[serde(default)]
    pub instances: Vec<Instance>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub tos_accepted: bool,
    /// Enables `run --force` (guardrail bypass for testing false positives).
    #[serde(default)]
    pub dev_mode: bool,
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_json<T: Default + for<'de> Deserialize<'de>>(path: &PathBuf) -> Result<T> {
    match fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn save_json<T: Serialize>(path: &PathBuf, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(value)?)
        .with_context(|| format!("writing {}", path.display()))
}

impl Db {
    pub fn load() -> Result<Db> {
        load_json(&paths::instances_file())
    }

    pub fn save(&self) -> Result<()> {
        save_json(&paths::instances_file(), self)
    }

    pub fn find(&mut self, app_id: &str, name: &str) -> Option<&mut Instance> {
        self.instances
            .iter_mut()
            .find(|i| i.app_id == app_id && i.name.eq_ignore_ascii_case(name))
    }

    /// Unique instance names across all apps, most recently used first.
    pub fn menu_names(&self, cap: usize) -> Vec<String> {
        let mut sorted: Vec<&Instance> = self.instances.iter().collect();
        sorted.sort_by(|a, b| b.last_used.cmp(&a.last_used));
        let mut names: Vec<String> = Vec::new();
        for i in sorted {
            if !names.iter().any(|n| n.eq_ignore_ascii_case(&i.name)) {
                names.push(i.name.clone());
            }
            if names.len() >= cap {
                break;
            }
        }
        names
    }

    pub fn next_auto_name(&self, app_id: &str) -> String {
        let mut n = self.instances.iter().filter(|i| i.app_id == app_id).count() + 1;
        loop {
            let name = format!("Instance-{n}");
            if self
                .instances
                .iter()
                .all(|i| !(i.app_id == app_id && i.name.eq_ignore_ascii_case(&name)))
            {
                return name;
            }
            n += 1;
        }
    }
}

impl Config {
    pub fn load() -> Result<Config> {
        load_json(&paths::config_file())
    }

    pub fn save(&self) -> Result<()> {
        save_json(&paths::config_file(), self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inst(app: &str, name: &str, last_used: u64) -> Instance {
        Instance {
            name: name.into(),
            app_id: app.into(),
            app_path: String::new(),
            display_name: None,
            created: 0,
            last_used,
            isolation: default_isolation(),
            windows_user: None,
            tier_d_adapter: None,
            package_aumid: None,
            protocols: Vec::new(),
            profile_args: Vec::new(),
            web_url: None,
            last_pid: None,
        }
    }

    #[test]
    fn auto_names_do_not_collide() {
        let mut db = Db::default();
        db.instances.push(inst("app", "Instance-1", 0));
        db.instances.push(inst("app", "Instance-3", 0));
        let n = db.next_auto_name("app");
        assert!(db.find("app", &n).is_none());
        assert_eq!(db.next_auto_name("other"), "Instance-1");
    }

    #[test]
    fn menu_names_dedupe_and_order_by_recency() {
        let mut db = Db::default();
        db.instances.push(inst("a", "Work", 10));
        db.instances.push(inst("b", "work", 50));
        db.instances.push(inst("a", "Personal", 30));
        assert_eq!(db.menu_names(10), vec!["work", "Personal"]);
        assert_eq!(db.menu_names(1), vec!["work"]);
    }

    #[test]
    fn name_validation() {
        assert!(validate_instance_name("Work").is_ok());
        assert!(validate_instance_name("Client A.2").is_ok());
        assert!(validate_instance_name("").is_err());
        assert!(validate_instance_name("bad\"quote").is_err());
        assert!(validate_instance_name(&"x".repeat(40)).is_err());
    }
}

/// Instance names go into registry menu entries and command lines; keep them tame.
pub fn validate_instance_name(name: &str) -> Result<()> {
    let ok = !name.trim().is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_' || c == '.');
    anyhow::ensure!(
        ok,
        "instance name must be 1-32 chars: letters, digits, space, '-', '_', '.'"
    );
    Ok(())
}
