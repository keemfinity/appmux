//! Package Lab (experimental): clone eligible free MSIX/Appx packages under a
//! new local test identity. Installed vendor files and WindowsApps ACLs are
//! never modified; signing, machine trust, and sideloading require separate
//! explicit confirmation flags.

use crate::{paths, store::Instance};
use anyhow::{bail, Context, Result};
use roxmltree::Document;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

const TRANSFORM_VERSION: u64 = 2;
const SDK_BUILD_TOOLS_VERSION: &str = "10.0.22621.3233";
const SDK_BIN_VERSION: &str = "10.0.22621.0";
const SDK_BUILD_TOOLS_URL: &str = "https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.buildtools/10.0.22621.3233/microsoft.windows.sdk.buildtools.10.0.22621.3233.nupkg";
const SDK_BUILD_TOOLS_SHA256: &str =
    "333109862e342aa04c217c91ebb2d550d8a5decdcb0a7e8b83f115623c830e0b";
const MAKEAPPX_SHA256: &str = "1053b2f7f5047385b389d16d5e0d2892d8fd6d9b7f273e641d89c75b273d3633";
const SIGNTOOL_SHA256: &str = "8cfd7441d53c3418ec4ca4436644020f7a1a4a9ccb7d102aed53a61e2a89e405";
const UAP3_NAMESPACE: &str = "http://schemas.microsoft.com/appx/manifest/uap/windows10/3";

#[derive(Serialize)]
pub struct Report {
    pub target: String,
    pub package_root: String,
    pub identity_name: String,
    pub publisher: String,
    pub version: String,
    pub architecture: String,
    pub display_name: String,
    pub framework: Option<String>,
    pub profile_strategy: String,
    pub applications: Vec<String>,
    pub application_id: String,
    pub protocols: Vec<String>,
    pub capabilities: Vec<String>,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
    pub verdict: String,
}

fn manifest_for(target: &Path) -> Result<PathBuf> {
    let start = if target.is_dir() {
        target.to_path_buf()
    } else {
        target
            .parent()
            .context("package target has no parent directory")?
            .to_path_buf()
    };
    for dir in start.ancestors() {
        let manifest = dir.join("AppxManifest.xml");
        if manifest.exists() {
            return Ok(manifest);
        }
    }
    bail!("no AppxManifest.xml found above {}", target.display())
}

fn attr(node: roxmltree::Node<'_, '_>, name: &str) -> String {
    node.attribute(name).unwrap_or_default().to_string()
}

fn detect_framework(target: &Path) -> Option<String> {
    let dir = target.parent()?;
    let resources = dir.join("resources");
    if resources.join("app.asar").exists()
        || (dir.join("resources.pak").exists()
            && dir.join("icudtl.dat").exists()
            && dir.join("v8_context_snapshot.bin").exists())
    {
        Some("electron".into())
    } else if dir.join("chrome_elf.dll").exists()
        || (dir.join("resources.pak").exists() && dir.join("icudtl.dat").exists())
    {
        Some("chromium".into())
    } else {
        None
    }
}

fn hard_blockers(manifest: &str) -> Vec<String> {
    let lower_manifest = manifest.to_ascii_lowercase();
    let mut blockers = Vec::new();
    if lower_manifest.contains("desktop6:service") || lower_manifest.contains("windows.service") {
        blockers.push("declares a Windows service".into());
    }
    if lower_manifest.contains("windows.driver") || lower_manifest.contains("driverdependency") {
        blockers.push("declares a driver or driver dependency".into());
    }
    if lower_manifest.contains("name=\"applicensing\"")
        || lower_manifest.contains("name='applicensing'")
    {
        blockers.push(
            "declares the restricted appLicensing capability; AppMux does not clone or redirect licensed application state"
                .into(),
        );
    }
    if lower_manifest.contains("easyanticheat")
        || lower_manifest.contains("battleye")
        || lower_manifest.contains("anticheat")
    {
        blockers.push("contains an anti-cheat marker".into());
    }
    blockers
}

pub fn inspect(target: &Path) -> Result<Report> {
    let manifest = manifest_for(target)?;
    let xml = std::fs::read_to_string(&manifest).with_context(|| {
        format!(
            "reading {} (Windows may deny package access)",
            manifest.display()
        )
    })?;
    let doc = Document::parse(&xml).context("parsing AppxManifest.xml")?;
    let identity = doc
        .descendants()
        .find(|n| n.has_tag_name("Identity"))
        .context("manifest has no Identity element")?;

    let display_name = doc
        .descendants()
        .find(|n| {
            n.is_element()
                && n.tag_name().name() == "DisplayName"
                && n.parent()
                    .map(|p| p.tag_name().name() == "Properties")
                    .unwrap_or(false)
        })
        .and_then(|n| n.text())
        .unwrap_or_else(|| identity.attribute("Name").unwrap_or("Package"))
        .to_string();
    let app_nodes: Vec<_> = doc
        .descendants()
        .filter(|n| n.tag_name().name() == "Application")
        .collect();
    let target_relative = target
        .strip_prefix(manifest.parent().unwrap())
        .ok()
        .map(|p| p.to_string_lossy().replace('/', "\\"));
    let selected_app = target_relative
        .as_deref()
        .and_then(|relative| {
            app_nodes.iter().find(|app| {
                app.attribute("Executable")
                    .map(|exe| exe.eq_ignore_ascii_case(relative))
                    .unwrap_or(false)
            })
        })
        .copied()
        .or_else(|| app_nodes.first().copied());
    let applications: Vec<String> = app_nodes
        .iter()
        .filter_map(|n| n.attribute("Id").map(str::to_string))
        .collect();
    let selected_id = selected_app.and_then(|app| app.attribute("Id"));
    let protocol_nodes: Vec<_> = doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "Protocol")
        .filter(|n| {
            n.ancestors()
                .find(|ancestor| ancestor.tag_name().name() == "Application")
                .and_then(|app| app.attribute("Id"))
                == selected_id
        })
        .collect();
    let protocols: Vec<String> = protocol_nodes
        .iter()
        .filter_map(|n| n.attribute("Name").map(str::to_string))
        .collect();
    let needs_protocol_router = protocol_nodes
        .iter()
        .any(|node| node.tag_name().namespace() != Some(UAP3_NAMESPACE));
    let capabilities: Vec<String> = doc
        .descendants()
        .filter(|n| n.is_element())
        .filter(|n| {
            n.parent()
                .map(|p| p.tag_name().name() == "Capabilities")
                .unwrap_or(false)
        })
        .map(|n| {
            let name = n.attribute("Name").unwrap_or_default();
            format!("{}:{name}", n.tag_name().name())
        })
        .collect();

    let lower = xml.to_ascii_lowercase();
    let blockers = hard_blockers(&lower);
    let mut warnings = Vec::new();
    if lower.contains("rescap:") || lower.contains("restrictedcapabilities") {
        warnings.push(
            "uses restricted capabilities; each declaration requires manual compatibility review"
                .into(),
        );
    }
    if lower.contains("runfulltrust") {
        warnings.push(
            "declares runFullTrust; identity-sensitive desktop behavior requires manual testing"
                .into(),
        );
    }
    if lower.contains("windows.comserver") {
        warnings.push(
            "declares packaged COM servers; duplicate CLSIDs require deployment testing".into(),
        );
    }
    if lower.contains("windows.backgroundtasks") {
        warnings.push("declares background tasks; push and background activation may remain tied to vendor services".into());
    }
    warnings.push("changing package identity breaks Microsoft Store updates for the clone".into());
    warnings.push(
        "license/DRM eligibility cannot be inferred from a manifest; manual review is mandatory"
            .into(),
    );
    warnings.push("the vendor signature cannot be preserved after changing identity".into());
    let framework = detect_framework(target);
    let exe_name = target
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let has_recipe_profile = crate::recipes::find(&exe_name, "")
        .map(|recipe| !recipe.args.is_empty())
        .unwrap_or(false);
    let profile_strategy = if has_recipe_profile {
        "recipe"
    } else if framework.is_some() {
        warnings.push(
            "generated a framework-level --user-data-dir profile; runtime verification is required"
                .into(),
        );
        "generated-user-data-dir"
    } else {
        "package-identity"
    };
    if needs_protocol_router {
        warnings.push(
            "legacy protocol schema cannot carry profile arguments; AppMux Protocol Router will handle callbacks"
                .into(),
        );
    }

    let verdict = if blockers.is_empty() {
        "manual-review" // Never auto-eligible: licensing cannot be established mechanically.
    } else {
        "blocked"
    };
    Ok(Report {
        target: target.display().to_string(),
        package_root: manifest.parent().unwrap().display().to_string(),
        identity_name: attr(identity, "Name"),
        publisher: attr(identity, "Publisher"),
        version: attr(identity, "Version"),
        architecture: attr(identity, "ProcessorArchitecture"),
        display_name,
        framework,
        profile_strategy: profile_strategy.into(),
        applications,
        application_id: selected_id.unwrap_or("App").to_string(),
        protocols,
        capabilities,
        blockers,
        warnings,
        verdict: verdict.into(),
    })
}

pub fn print_report(report: &Report) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}

pub fn ensure_launch_allowed(target: &Path) -> Result<()> {
    let report = inspect(target)?;
    anyhow::ensure!(
        report.blockers.is_empty(),
        "Package Lab launch blocked: {}",
        report.blockers.join("; ")
    );
    Ok(())
}

/// Writes a dry-run plan only. No package files are copied or changed.
fn lab_dir(report: &Report, instance: &str) -> PathBuf {
    paths::root()
        .join("PackageLab")
        .join(crate::paths::sanitize(&report.identity_name))
        .join(crate::paths::sanitize(instance))
}

pub fn write_plan(target: &Path, instance: &str) -> Result<PathBuf> {
    let report = inspect(target)?;
    let dir = lab_dir(&report, instance);
    std::fs::create_dir_all(&dir)?;
    let file = dir.join("inspection.json");
    std::fs::write(&file, serde_json::to_string_pretty(&report)?)?;
    Ok(file)
}

fn copy_tree(source: &Path, destination: &Path, force: bool) -> Result<u64> {
    std::fs::create_dir_all(destination)?;
    let mut bytes = 0;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        let lower = name.to_string_lossy().to_ascii_lowercase();
        let path = entry.path();
        let target = destination.join(&name);
        if entry.file_type()?.is_dir() {
            if lower == "microsoft.system.package.metadata" {
                continue;
            }
            bytes += copy_tree(&path, &target, force)?;
        } else {
            if matches!(
                lower.as_str(),
                "appxsignature.p7x" | "appxblockmap.xml" | "codeintegrity.cat"
            ) {
                continue;
            }
            let source_len = entry.metadata()?.len();
            if !force
                && lower != "appxmanifest.xml"
                && target
                    .metadata()
                    .map(|m| m.len() == source_len)
                    .unwrap_or(false)
            {
                bytes += source_len;
            } else {
                bytes += std::fs::copy(&path, &target)
                    .with_context(|| format!("copying {}", path.display()))?;
            }
        }
    }
    Ok(bytes)
}

fn replace_attribute(element: &str, name: &str, value: &str) -> Result<String> {
    let marker = format!("{name}=");
    let marker_start = element
        .find(&marker)
        .with_context(|| format!("attribute {name} is missing"))?;
    let quote_start = marker_start + marker.len();
    let quote = element[quote_start..]
        .chars()
        .next()
        .filter(|c| *c == '"' || *c == '\'')
        .with_context(|| format!("attribute {name} is not quoted"))?;
    let value_start = quote_start + quote.len_utf8();
    let relative_end = element[value_start..]
        .find(quote)
        .with_context(|| format!("attribute {name} has no closing quote"))?;
    let mut output = element.to_string();
    output.replace_range(value_start..value_start + relative_end, value);
    Ok(output)
}

fn set_attribute(element: &str, name: &str, value: &str) -> Result<String> {
    if element.contains(&format!("{name}=")) {
        return replace_attribute(element, name, value);
    }
    let insert = element
        .find('>')
        .context("XML element has no closing angle bracket")?;
    let insert = if element.as_bytes().get(insert.wrapping_sub(1)) == Some(&b'/') {
        insert - 1
    } else {
        insert
    };
    let mut output = element.to_string();
    output.insert_str(insert, &format!(" {name}=\"{value}\""));
    Ok(output)
}

fn xml_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn profile_arguments(report: &Report, target: &Path) -> Vec<String> {
    let exe_name = target
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    crate::recipes::find(&exe_name, "")
        .map(|recipe| recipe.args)
        .filter(|args| !args.is_empty())
        .unwrap_or_else(|| {
            if report.profile_strategy == "generated-user-data-dir" {
                vec!["--user-data-dir={data}\\UserData".into()]
            } else {
                Vec::new()
            }
        })
}

fn configure_instance_activation(
    xml: &str,
    target: &Path,
    report: &Report,
    instance: &str,
) -> Result<String> {
    let data = paths::instances_dir()
        .join(format!(
            "package-{}",
            crate::paths::sanitize(&report.identity_name)
        ))
        .join(crate::paths::sanitize(instance));
    let recipe_args = profile_arguments(report, target)
        .iter()
        .map(|arg| arg.replace("{data}", &data.to_string_lossy()))
        .map(|arg| {
            if arg.contains(' ') {
                format!("\"{arg}\"")
            } else {
                arg
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let protocol_parameters = if recipe_args.is_empty() {
        "\"%1\"".to_string()
    } else {
        format!("{recipe_args} \"%1\"")
    };
    let label = format!("{} ({instance})", report.display_name);
    let doc = Document::parse(xml)?;
    let target_relative = target
        .strip_prefix(Path::new(&report.package_root))
        .ok()
        .map(|path| path.to_string_lossy().replace('/', "\\"));
    let app_nodes: Vec<_> = doc
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "Application")
        .collect();
    let selected_app = target_relative
        .as_deref()
        .and_then(|relative| {
            app_nodes.iter().find(|app| {
                app.attribute("Executable")
                    .map(|exe| exe.eq_ignore_ascii_case(relative))
                    .unwrap_or(false)
            })
        })
        .copied()
        .or_else(|| app_nodes.first().copied());
    let selected_range = selected_app.map(|app| app.range());
    let mut replacements: Vec<(std::ops::Range<usize>, String)> = Vec::new();
    for node in doc.descendants().filter(|n| n.is_element()) {
        let node_range = node.range();
        let in_selected_app = selected_range
            .as_ref()
            .map(|range| node_range.start >= range.start && node_range.end <= range.end)
            .unwrap_or(false);
        if node.tag_name().name() == "Protocol" && in_selected_app {
            if node.tag_name().namespace() == Some(UAP3_NAMESPACE) {
                replacements.push((
                    node.range(),
                    set_attribute(
                        &xml[node.range()],
                        "Parameters",
                        &xml_attribute(&protocol_parameters),
                    )?,
                ));
            } else if let Some(extension) = node.ancestors().find(|ancestor| {
                ancestor.is_element()
                    && ancestor.tag_name().name() == "Extension"
                    && ancestor.attribute("Category") == Some("windows.protocol")
            }) {
                if !replacements
                    .iter()
                    .any(|(range, _)| range.start == extension.range().start)
                {
                    replacements.push((extension.range(), String::new()));
                }
            }
        } else if node.tag_name().name() == "VisualElements" && in_selected_app {
            if node
                .attribute("DisplayName")
                .map(|name| !name.starts_with("ms-resource:"))
                .unwrap_or(false)
            {
                replacements.push((
                    node.range(),
                    replace_attribute(&xml[node.range()], "DisplayName", &xml_attribute(&label))?,
                ));
            }
        } else if node.tag_name().name() == "DisplayName"
            && node
                .parent()
                .map(|p| p.tag_name().name() == "Properties")
                .unwrap_or(false)
        {
            if let Some(text) = node.first_child().filter(|child| child.is_text()) {
                if !text.text().unwrap_or_default().starts_with("ms-resource:") {
                    replacements.push((text.range(), label.clone()));
                }
            }
        }
    }
    replacements.sort_by(|a, b| b.0.start.cmp(&a.0.start));
    let mut output = xml.to_string();
    for (range, replacement) in replacements {
        output.replace_range(range, &replacement);
    }
    Ok(output)
}

fn clone_identity_name(original: &str, instance: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for b in instance.to_ascii_lowercase().bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let suffix = format!(".AppMux.{:08x}", hash as u32);
    let prefix: String = original.chars().take(50 - suffix.len()).collect();
    format!("{prefix}{suffix}")
}

fn remove_service_declarations(xml: &str) -> Result<(String, Vec<String>)> {
    let doc = Document::parse(xml)?;
    let services: Vec<_> = doc
        .descendants()
        .filter(|n| {
            n.is_element()
                && n.tag_name().name() == "Extension"
                && n.attribute("Category") == Some("windows.service")
        })
        .collect();
    let service_executables: Vec<String> = services
        .iter()
        .filter_map(|n| n.attribute("Executable"))
        .map(str::to_string)
        .collect();
    let mut ranges: Vec<_> = services.iter().map(|n| n.range()).collect();
    ranges.extend(doc.descendants().filter_map(|n| {
        if n.is_element()
            && n.tag_name().name() == "Capability"
            && matches!(
                n.attribute("Name"),
                Some("localSystemServices" | "packagedServices")
            )
        {
            Some(n.range())
        } else {
            None
        }
    }));
    ranges.extend(doc.descendants().filter_map(|n| {
        if !n.is_element()
            || n.tag_name().name() != "Extension"
            || n.attribute("Category") != Some("windows.firewallRules")
        {
            return None;
        }
        let belongs_to_service = n.descendants().any(|child| {
            child
                .attribute("Executable")
                .map(|exe| {
                    service_executables
                        .iter()
                        .any(|s| s.eq_ignore_ascii_case(exe))
                })
                .unwrap_or(false)
        });
        belongs_to_service.then(|| n.range())
    }));
    ranges.sort_by(|a, b| b.start.cmp(&a.start));
    let mut output = xml.to_string();
    for range in ranges {
        output.replace_range(range, "");
    }
    Ok((output, service_executables))
}

pub fn prepare_workspace(target: &Path, instance: &str, strip_services: bool) -> Result<PathBuf> {
    let report = inspect(target)?;
    let service_blocker = report
        .blockers
        .iter()
        .any(|b| b == "declares a Windows service");
    let other_blockers: Vec<_> = report
        .blockers
        .iter()
        .filter(|b| b.as_str() != "declares a Windows service")
        .collect();
    if !other_blockers.is_empty() {
        bail!(
            "package has non-removable hard blockers: {}",
            other_blockers
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    if service_blocker && !strip_services {
        bail!(
            "package declares a Windows service; reduced-functionality mode requires \
             --strip-services and disables service-dependent features"
        );
    }
    let dir = lab_dir(&report, instance);
    let source = dir.join("source");
    let metadata_path = dir.join("workspace.json");
    let existing_metadata = std::fs::read_to_string(&metadata_path)
        .ok()
        .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok());
    let existing_version = existing_metadata
        .as_ref()
        .and_then(|meta| meta.get("source_version"))
        .and_then(|value| value.as_str());
    let current = existing_metadata.as_ref().is_some_and(|meta| {
        meta.get("transform_version")
            .and_then(|value| value.as_u64())
            == Some(TRANSFORM_VERSION)
            && existing_version == Some(report.version.as_str())
            && meta.get("service_free").and_then(|value| value.as_bool()) == Some(strip_services)
    });
    if current && source.join("AppxManifest.xml").exists() {
        return Ok(source);
    }
    let force_copy = existing_version.is_some_and(|version| version != report.version);
    std::fs::create_dir_all(&dir)?;
    let bytes = copy_tree(Path::new(&report.package_root), &source, force_copy)?;
    let _ = std::fs::remove_file(dir.join("packed.json"));

    let manifest_path = source.join("AppxManifest.xml");
    let xml = std::fs::read_to_string(&manifest_path)?;
    let doc = Document::parse(&xml)?;
    let identity = doc
        .descendants()
        .find(|n| n.has_tag_name("Identity"))
        .context("manifest has no Identity")?;
    let range = identity.range();
    let new_name = clone_identity_name(&report.identity_name, instance);
    let identity_text = &xml[range.clone()];
    let rewritten_identity = replace_attribute(
        &replace_attribute(identity_text, "Name", &new_name)?,
        "Publisher",
        "CN=AppMux Package Lab",
    )?;
    let mut rewritten = String::with_capacity(xml.len() + 32);
    rewritten.push_str(&xml[..range.start]);
    rewritten.push_str(&rewritten_identity);
    rewritten.push_str(&xml[range.end..]);

    let target_exe = target
        .strip_prefix(Path::new(&report.package_root))
        .ok()
        .and_then(|p| p.to_str())
        .map(|p| p.replace('/', "\\"))
        .filter(|p| p.to_ascii_lowercase().ends_with(".exe"))
        .context("Package Lab target must be an executable inside the package")?;
    let rewritten_doc = Document::parse(&rewritten)?;
    let main_app = rewritten_doc
        .descendants()
        .find(|node| {
            node.tag_name().name() == "Application"
                && node
                    .attribute("Executable")
                    .map(|exe| exe.eq_ignore_ascii_case(&target_exe))
                    .unwrap_or(false)
        })
        .or_else(|| {
            rewritten_doc
                .descendants()
                .find(|node| node.tag_name().name() == "Application")
        })
        .context("manifest has no Application element")?;
    let app_range = main_app.range();
    let manifest_exe = main_app.attribute("Executable").unwrap_or_default();
    if !manifest_exe.eq_ignore_ascii_case(&target_exe) {
        let app_text = &rewritten[app_range.clone()];
        let old_exe = format!("Executable=\"{manifest_exe}\"");
        if !app_text.contains(&old_exe) {
            bail!("could not locate main Application executable safely");
        }
        let changed_app = app_text.replacen(&old_exe, &format!("Executable=\"{target_exe}\""), 1);
        rewritten.replace_range(app_range, &changed_app);
    }
    let stripped_service_executables = if strip_services {
        let (service_free, executables) = remove_service_declarations(&rewritten)?;
        rewritten = service_free;
        executables
    } else {
        Vec::new()
    };
    rewritten = configure_instance_activation(&rewritten, target, &report, instance)?;
    std::fs::write(&manifest_path, rewritten)?;

    #[derive(Serialize)]
    struct Workspace<'a> {
        transform_version: u64,
        instance: &'a str,
        source_package: &'a str,
        source_version: &'a str,
        source_publisher: &'a str,
        clone_name: &'a str,
        clone_publisher: &'static str,
        copied_bytes: u64,
        service_free: bool,
        stripped_service_executables: &'a [String],
        status: &'static str,
    }
    let meta = Workspace {
        transform_version: TRANSFORM_VERSION,
        instance,
        source_package: &report.identity_name,
        source_version: &report.version,
        source_publisher: &report.publisher,
        clone_name: &new_name,
        clone_publisher: "CN=AppMux Package Lab",
        copied_bytes: bytes,
        service_free: strip_services,
        stripped_service_executables: &stripped_service_executables,
        status: "prepared-not-signed-not-installed",
    };
    std::fs::write(
        dir.join("workspace.json"),
        serde_json::to_string_pretty(&meta)?,
    )?;
    std::fs::write(
        dir.join("inspection.json"),
        serde_json::to_string_pretty(&report)?,
    )?;
    Ok(source)
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn installed_sdk_tool(name: &str) -> Option<PathBuf> {
    let root = PathBuf::from(std::env::var_os("ProgramFiles(x86)")?)
        .join("Windows Kits")
        .join("10")
        .join("bin");
    let mut versions: Vec<PathBuf> = std::fs::read_dir(root)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    versions.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
    versions
        .into_iter()
        .map(|v| v.join("x64").join(name))
        .find(|p| p.is_file())
}

fn sdk_cache_root() -> PathBuf {
    paths::root()
        .join("Tools")
        .join(format!("WindowsSDK-BuildTools-{SDK_BUILD_TOOLS_VERSION}"))
}

fn sdk_expected_hash(name: &str) -> Result<&'static str> {
    match name.to_ascii_lowercase().as_str() {
        "makeappx.exe" => Ok(MAKEAPPX_SHA256),
        "signtool.exe" => Ok(SIGNTOOL_SHA256),
        _ => bail!("unsupported Windows SDK tool '{name}'"),
    }
}

fn cached_sdk_tool(name: &str) -> Result<Option<PathBuf>> {
    let tool = sdk_cache_root()
        .join("bin")
        .join(SDK_BIN_VERSION)
        .join("x64")
        .join(name);
    if !tool.exists() {
        return Ok(None);
    }
    anyhow::ensure!(
        tool.is_file() && sha256_file(&tool)?.eq_ignore_ascii_case(sdk_expected_hash(name)?),
        "managed Windows SDK tool failed integrity verification: {}",
        tool.display()
    );
    Ok(Some(tool))
}

fn sdk_tool(name: &str) -> Result<PathBuf> {
    if let Some(tool) = installed_sdk_tool(name) {
        return Ok(tool);
    }
    cached_sdk_tool(name)?.with_context(|| {
        format!(
            "Windows SDK {name} is unavailable; accept the Microsoft SDK license in Package Lab to download the verified build tools"
        )
    })
}

pub fn sdk_tools_available() -> Result<bool> {
    Ok(
        (installed_sdk_tool("makeappx.exe").is_some()
            || cached_sdk_tool("makeappx.exe")?.is_some())
            && (installed_sdk_tool("signtool.exe").is_some()
                || cached_sdk_tool("signtool.exe")?.is_some()),
    )
}

pub fn ensure_sdk_tools(accept_windows_sdk_license: bool) -> Result<()> {
    if sdk_tools_available()? {
        return Ok(());
    }
    anyhow::ensure!(
        accept_windows_sdk_license,
        "Microsoft Windows SDK license acceptance is required before downloading SDK Build Tools"
    );
    let cache = sdk_cache_root();
    anyhow::ensure!(
        !cache.exists(),
        "managed Windows SDK cache exists but is incomplete; remove it before retrying: {}",
        cache.display()
    );
    let parent = cache
        .parent()
        .context("Windows SDK cache has no parent directory")?;
    std::fs::create_dir_all(parent)?;
    let staging = parent.join(format!(
        ".WindowsSDK-BuildTools-{SDK_BUILD_TOOLS_VERSION}-{}",
        std::process::id()
    ));
    anyhow::ensure!(
        !staging.exists(),
        "Windows SDK staging directory already exists"
    );
    std::fs::create_dir_all(&staging)?;
    let result = (|| -> Result<()> {
        let package = staging.join("sdk.nupkg");
        let system_root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        let curl = PathBuf::from(system_root).join("System32").join("curl.exe");
        anyhow::ensure!(curl.is_file(), "Windows curl.exe is unavailable");
        let output = std::process::Command::new(curl)
            .args(["--fail", "--location", "--retry", "3", "--retry-delay", "2"])
            .arg("--output")
            .arg(&package)
            .arg(SDK_BUILD_TOOLS_URL)
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "Windows SDK Build Tools download failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let package_hash = sha256_file(&package)?;
        anyhow::ensure!(
            package_hash.eq_ignore_ascii_case(SDK_BUILD_TOOLS_SHA256),
            "Windows SDK Build Tools package hash mismatch: expected {SDK_BUILD_TOOLS_SHA256}, got {package_hash}"
        );
        let extracted = staging.join("package");
        let expand = staging.join("expand.ps1");
        std::fs::write(
            &expand,
            "param([string]$Package,[string]$Destination)\n$ErrorActionPreference='Stop'\n$zip=[IO.Path]::ChangeExtension($Package,'.zip')\nCopy-Item -LiteralPath $Package -Destination $zip -Force\nExpand-Archive -LiteralPath $zip -DestinationPath $Destination -Force\n",
        )?;
        let output = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&expand)
            .arg("-Package")
            .arg(&package)
            .arg("-Destination")
            .arg(&extracted)
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "Windows SDK Build Tools extraction failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        for (name, expected) in [
            ("makeappx.exe", MAKEAPPX_SHA256),
            ("signtool.exe", SIGNTOOL_SHA256),
        ] {
            let tool = extracted
                .join("bin")
                .join(SDK_BIN_VERSION)
                .join("x64")
                .join(name);
            anyhow::ensure!(
                tool.is_file() && sha256_file(&tool)?.eq_ignore_ascii_case(expected),
                "downloaded Windows SDK {name} failed integrity verification"
            );
        }
        std::fs::write(
            extracted.join("appmux-sdk-tools.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "package": "Microsoft.Windows.SDK.BuildTools",
                "version": SDK_BUILD_TOOLS_VERSION,
                "sha256": SDK_BUILD_TOOLS_SHA256,
                "license_accepted": true
            }))?,
        )?;
        std::fs::rename(&extracted, &cache)?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&staging);
    result?;
    anyhow::ensure!(
        sdk_tools_available()?,
        "Windows SDK tools remain unavailable after setup"
    );
    Ok(())
}

fn package_file(report: &Report, instance: &str) -> PathBuf {
    lab_dir(report, instance).join(format!(
        "{}-{}.msix",
        crate::paths::sanitize(&report.identity_name),
        crate::paths::sanitize(instance)
    ))
}

pub fn pack_workspace(target: &Path, instance: &str) -> Result<PathBuf> {
    let report = inspect(target)?;
    let dir = lab_dir(&report, instance);
    let source = dir.join("source");
    if !source.join("AppxManifest.xml").exists() {
        bail!("workspace is not prepared: {}", source.display());
    }
    let makeappx = sdk_tool("makeappx.exe")?;
    let output = package_file(&report, instance);
    let marker = dir.join("packed.json");
    let marker_current = std::fs::read_to_string(&marker)
        .ok()
        .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok())
        .and_then(|value| value.get("transform_version").and_then(|v| v.as_u64()))
        == Some(TRANSFORM_VERSION);
    if output.exists() && marker_current {
        return Ok(output);
    }
    if output.exists() {
        std::fs::remove_file(&output)?;
    }
    let result = std::process::Command::new(makeappx)
        .args(["pack", "/d"])
        .arg(&source)
        .arg("/p")
        .arg(&output)
        .arg("/o")
        .output()?;
    if !result.status.success() {
        let _ = std::fs::remove_file(&output);
        bail!(
            "MakeAppx failed:\n{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
    std::fs::write(
        marker,
        serde_json::to_string_pretty(&serde_json::json!({
            "transform_version": TRANSFORM_VERSION,
            "source_version": report.version,
            "package_bytes": std::fs::metadata(&output)?.len()
        }))?,
    )?;
    Ok(output)
}

pub fn sign_workspace(target: &Path, instance: &str) -> Result<PathBuf> {
    let report = inspect(target)?;
    let package = package_file(&report, instance);
    if !package.exists() {
        bail!("packed MSIX not found: {}", package.display());
    }
    let sign_tool = sdk_tool("signtool.exe")?;
    let dir = lab_dir(&report, instance);
    let script = dir.join("sign-local-test-package.ps1");
    std::fs::write(
        &script,
        r#"param([string]$Package,[string]$SignTool,[string]$CertFile)
$ErrorActionPreference = 'Stop'
$subject = 'CN=AppMux Package Lab'
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object Subject -eq $subject | Where-Object { $_.NotAfter -gt (Get-Date).AddDays(7) } | Select-Object -First 1
if (-not $cert) {
  $cert = New-SelfSignedCertificate -Type Custom -Subject $subject -FriendlyName 'AppMux Package Lab (local test only)' -CertStoreLocation Cert:\CurrentUser\My -KeyUsage DigitalSignature -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3')
}
Export-Certificate -Cert $cert -FilePath $CertFile -Force | Out-Null
$trusted = Get-ChildItem Cert:\CurrentUser\TrustedPeople | Where-Object Thumbprint -eq $cert.Thumbprint
if (-not $trusted) { Import-Certificate -FilePath $CertFile -CertStoreLocation Cert:\CurrentUser\TrustedPeople | Out-Null }
& $SignTool sign /fd SHA256 /s My /sha1 $cert.Thumbprint $Package
if ($LASTEXITCODE -ne 0) { throw "SignTool failed with exit code $LASTEXITCODE" }
"#,
    )?;
    let cert_file = dir.join("appmux-package-lab.cer");
    let result = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&script)
        .arg("-Package")
        .arg(&package)
        .arg("-SignTool")
        .arg(&sign_tool)
        .arg("-CertFile")
        .arg(&cert_file)
        .output()?;
    if !result.status.success() {
        bail!(
            "local signing failed:\n{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
    Ok(package)
}

pub fn installed_clone(target: &Path, instance: &str) -> Result<(String, PathBuf)> {
    let report = inspect(target)?;
    let dir = lab_dir(&report, instance);
    let script = dir.join("find-installed-test-package.ps1");
    std::fs::write(
        &script,
        "param([string]$Name,[string]$LegacyName)\n$ErrorActionPreference = 'Stop'\n$p = Get-AppxPackage -Name $Name | Where-Object Publisher -eq 'CN=AppMux Package Lab' | Select-Object -First 1\nif (-not $p) { $p = Get-AppxPackage -Name $LegacyName | Where-Object Publisher -eq 'CN=AppMux Package Lab' | Select-Object -First 1 }\nif (-not $p) { throw 'AppMux test package is not installed' }\nWrite-Output $p.PackageFamilyName\nWrite-Output $p.InstallLocation\n",
    )?;
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&script)
        .arg("-Name")
        .arg(clone_identity_name(&report.identity_name, instance))
        .arg("-LegacyName")
        .arg(&report.identity_name)
        .output()?;
    if !output.status.success() {
        bail!(
            "finding installed clone failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if lines.len() < 2 {
        bail!("installed clone query returned incomplete data");
    }
    let aumid = format!("{}!{}", lines[0], report.application_id);
    let relative_exe = target
        .strip_prefix(Path::new(&report.package_root))
        .context("target is outside its package root")?;
    Ok((aumid, PathBuf::from(lines[1]).join(relative_exe)))
}

fn installed_package_full_name(inst: &Instance) -> Result<String> {
    let manifest = manifest_for(Path::new(&inst.app_path))?;
    manifest
        .parent()
        .and_then(|path| path.file_name())
        .map(|name| name.to_string_lossy().to_string())
        .context("installed package has no package full name")
}

pub fn stop_instance(inst: &Instance) -> Result<()> {
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::UI::Shell::{IPackageDebugSettings, PackageDebugSettings};

    anyhow::ensure!(
        inst.isolation == "package",
        "instance is not a Package Lab clone"
    );
    let package = installed_package_full_name(inst)?;
    let package_w: Vec<u16> = package.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let settings: IPackageDebugSettings =
            CoCreateInstance(&PackageDebugSettings, None, CLSCTX_INPROC_SERVER)?;
        settings
            .TerminateAllProcesses(windows::core::PCWSTR(package_w.as_ptr()))
            .with_context(|| format!("stopping package {package}"))
    }
}

pub fn uninstall_instance(inst: &Instance) -> Result<()> {
    let package = installed_package_full_name(inst)?;
    stop_instance(inst)?;
    let script = paths::root().join("package-lab-uninstall.ps1");
    std::fs::write(
        &script,
        "param([string]$Package)\n$ErrorActionPreference='Stop'\nRemove-AppxPackage -Package $Package\n",
    )?;
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&script)
        .arg("-Package")
        .arg(&package)
        .output()?;
    if !output.status.success() {
        bail!(
            "package uninstall failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

pub fn activate(aumid: &str, arguments: &str) -> Result<u32> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::UI::Shell::{
        ApplicationActivationManager, IApplicationActivationManager, AO_NONE,
    };

    let aumid_w: Vec<u16> = aumid.encode_utf16().chain(std::iter::once(0)).collect();
    let args_w: Vec<u16> = arguments.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let manager: IApplicationActivationManager =
            CoCreateInstance(&ApplicationActivationManager, None, CLSCTX_INPROC_SERVER)?;
        manager
            .ActivateApplication(PCWSTR(aumid_w.as_ptr()), PCWSTR(args_w.as_ptr()), AO_NONE)
            .context("activating Package Lab AUMID")
    }
}

pub fn trust_machine_certificate(target: &Path, instance: &str) -> Result<()> {
    let report = inspect(target)?;
    let cert = lab_dir(&report, instance).join("appmux-package-lab.cer");
    if !cert.exists() {
        bail!("public certificate not found; sign the package first");
    }
    let script = lab_dir(&report, instance).join("trust-machine-test-certificate.ps1");
    std::fs::write(
        &script,
        "param([string]$CertFile)\n$ErrorActionPreference = 'Stop'\nImport-Certificate -FilePath $CertFile -CertStoreLocation Cert:\\LocalMachine\\TrustedPeople | Out-Null\n",
    )?;
    let result = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&script)
        .arg("-CertFile")
        .arg(&cert)
        .output()?;
    if !result.status.success() {
        bail!(
            "machine certificate trust failed (run elevated):\n{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
    Ok(())
}

pub fn install_workspace(target: &Path, instance: &str) -> Result<()> {
    let report = inspect(target)?;
    let package = package_file(&report, instance);
    if !package.exists() {
        bail!("signed MSIX not found: {}", package.display());
    }
    let script = lab_dir(&report, instance).join("install-local-test-package.ps1");
    std::fs::write(
        &script,
        "param([string]$Package)\n$ErrorActionPreference = 'Stop'\nAdd-AppxPackage -Path $Package -ForceApplicationShutdown\n",
    )?;
    let result = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&script)
        .arg("-Package")
        .arg(&package)
        .output()?;
    if !result.status.success() {
        bail!(
            "sideload failed:\n{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_exe_is_not_a_package() {
        assert!(manifest_for(Path::new(r"C:\Windows\System32\notepad.exe")).is_err());
    }

    #[test]
    fn app_licensing_is_a_non_overridable_blocker() {
        let blockers = hard_blockers(
            r#"<Capabilities><rescap:Capability Name="appLicensing" /></Capabilities>"#,
        );
        assert_eq!(blockers.len(), 1);
        assert!(blockers[0].contains("appLicensing"));
    }

    #[test]
    fn identity_attributes_handle_xml_entities() {
        let input = r#"<Identity Name="Claude" Publisher="CN=&quot;Anthropic, PBC&quot;" />"#;
        let changed = replace_attribute(input, "Publisher", "CN=AppMux Package Lab").unwrap();
        assert!(changed.contains("Publisher=\"CN=AppMux Package Lab\""));
        assert!(changed.contains("Name=\"Claude\""));
    }

    #[test]
    fn service_remediation_is_scoped() {
        let input = r#"<Package><Applications><Application><Extensions><desktop6:Extension xmlns:desktop6="urn:d" Category="windows.service" Executable="svc.exe"><desktop6:Service /></desktop6:Extension></Extensions></Application></Applications><Capabilities><rescap:Capability xmlns:rescap="urn:r" Name="runFullTrust"/><rescap:Capability xmlns:rescap="urn:r" Name="localSystemServices"/><rescap:Capability xmlns:rescap="urn:r" Name="packagedServices"/></Capabilities><Extensions><desktop2:Extension xmlns:desktop2="urn:d2" Category="windows.firewallRules"><desktop2:FirewallRules Executable="svc.exe"/></desktop2:Extension><desktop2:Extension xmlns:desktop2="urn:d2" Category="windows.firewallRules"><desktop2:FirewallRules Executable="app.exe"/></desktop2:Extension></Extensions></Package>"#;
        let (output, executables) = remove_service_declarations(input).unwrap();
        assert_eq!(executables, vec!["svc.exe"]);
        assert!(!output.contains("windows.service"));
        assert!(!output.contains("localSystemServices"));
        assert!(!output.contains("packagedServices"));
        assert!(!output.contains("Executable=\"svc.exe\""));
        assert!(output.contains("runFullTrust"));
        assert!(output.contains("Executable=\"app.exe\""));
    }

    #[test]
    fn protocol_activation_keeps_instance_profile_and_label() {
        let root = PathBuf::from(r"C:\Package");
        let report = Report {
            target: root.join(r"app\Claude.exe").display().to_string(),
            package_root: root.display().to_string(),
            identity_name: "Claude".into(),
            publisher: "CN=Anthropic".into(),
            version: "1.0.0.0".into(),
            architecture: "x64".into(),
            display_name: "Claude".into(),
            framework: Some("electron".into()),
            profile_strategy: "recipe".into(),
            applications: vec!["Claude".into()],
            application_id: "Claude".into(),
            protocols: vec!["claude".into()],
            capabilities: Vec::new(),
            blockers: Vec::new(),
            warnings: Vec::new(),
            verdict: "manual-review".into(),
        };
        let input = r#"<Package><Properties><DisplayName>Claude</DisplayName></Properties><Applications><Application Id="Claude" Executable="app\Claude.exe"><uap:VisualElements xmlns:uap="urn:u" DisplayName="Claude"/><Extensions><uap3:Extension xmlns:uap3="http://schemas.microsoft.com/appx/manifest/uap/windows10/3" Category="windows.protocol"><uap3:Protocol Name="claude" Parameters="&quot;%1&quot;"/></uap3:Extension></Extensions></Application></Applications></Package>"#;
        let output =
            configure_instance_activation(input, &root.join(r"app\Claude.exe"), &report, "Work")
                .unwrap();
        assert!(output.contains("Claude (Work)"));
        assert!(output.contains("--user-data-dir="));
        assert!(output.contains("&quot;%1&quot;"));
        assert!(output.contains("package-claude"));
    }

    #[test]
    fn unknown_electron_protocol_gets_generated_private_profile() {
        let root = PathBuf::from(r"C:\Package");
        let report = Report {
            target: root.join("Generic.exe").display().to_string(),
            package_root: root.display().to_string(),
            identity_name: "GenericElectron".into(),
            publisher: "CN=Vendor".into(),
            version: "1.0.0.0".into(),
            architecture: "x64".into(),
            display_name: "Generic App".into(),
            framework: Some("electron".into()),
            profile_strategy: "generated-user-data-dir".into(),
            applications: vec!["Main".into()],
            application_id: "Main".into(),
            protocols: vec!["generic".into()],
            capabilities: Vec::new(),
            blockers: Vec::new(),
            warnings: Vec::new(),
            verdict: "manual-review".into(),
        };
        let input = r#"<Package><Properties><DisplayName>Generic App</DisplayName></Properties><Applications><Application Id="Main" Executable="Generic.exe"><uap:VisualElements xmlns:uap="urn:u" DisplayName="Generic App"/><Extensions><uap3:Extension xmlns:uap3="http://schemas.microsoft.com/appx/manifest/uap/windows10/3" Category="windows.protocol"><uap3:Protocol Name="generic"/></uap3:Extension></Extensions></Application></Applications></Package>"#;
        let output =
            configure_instance_activation(input, &root.join("Generic.exe"), &report, "Personal")
                .unwrap();
        assert!(output.contains("Generic App (Personal)"));
        assert!(output.contains("--user-data-dir="));
        assert!(output.contains("package-genericelectron"));
        assert!(output.contains("&quot;%1&quot;"));
    }

    #[test]
    fn legacy_protocol_schema_is_removed_for_router_fallback() {
        let root = PathBuf::from(r"C:\Package");
        let report = Report {
            target: root.join("Generic.exe").display().to_string(),
            package_root: root.display().to_string(),
            identity_name: "GenericElectron".into(),
            publisher: "CN=Vendor".into(),
            version: "1.0.0.0".into(),
            architecture: "x64".into(),
            display_name: "Generic App".into(),
            framework: Some("electron".into()),
            profile_strategy: "generated-user-data-dir".into(),
            applications: vec!["Main".into()],
            application_id: "Main".into(),
            protocols: vec!["generic".into()],
            capabilities: Vec::new(),
            blockers: Vec::new(),
            warnings: Vec::new(),
            verdict: "manual-review".into(),
        };
        let input = r#"<Package><Properties><DisplayName>Generic App</DisplayName></Properties><Applications><Application Id="Main" Executable="Generic.exe"><uap:VisualElements xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10" DisplayName="Generic App"/><Extensions><uap:Extension xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10" Category="windows.protocol"><uap:Protocol Name="generic"/></uap:Extension></Extensions></Application></Applications></Package>"#;
        let output =
            configure_instance_activation(input, &root.join("Generic.exe"), &report, "Personal")
                .unwrap();
        assert!(!output.contains("windows.protocol"));
        assert!(!output.contains("Parameters="));
        assert!(output.contains("Generic App (Personal)"));
    }

    #[test]
    fn sdk_build_tools_are_exactly_pinned_and_allowlisted() {
        assert_eq!(SDK_BUILD_TOOLS_VERSION, "10.0.22621.3233");
        assert!(SDK_BUILD_TOOLS_URL.starts_with("https://api.nuget.org/"));
        for hash in [SDK_BUILD_TOOLS_SHA256, MAKEAPPX_SHA256, SIGNTOOL_SHA256] {
            assert_eq!(hash.len(), 64);
            assert!(hash.chars().all(|character| character.is_ascii_hexdigit()));
        }
        assert_eq!(sdk_expected_hash("makeappx.exe").unwrap(), MAKEAPPX_SHA256);
        assert_eq!(sdk_expected_hash("SIGNTOOL.EXE").unwrap(), SIGNTOOL_SHA256);
        assert!(sdk_expected_hash("powershell.exe").is_err());
    }

    #[test]
    fn clone_names_are_stable_distinct_and_valid_length() {
        let a = clone_identity_name("5319275A.WhatsAppDesktop", "Work");
        let b = clone_identity_name("5319275A.WhatsAppDesktop", "Personal");
        assert_eq!(a, clone_identity_name("5319275A.WhatsAppDesktop", "work"));
        assert_ne!(a, b);
        assert!(a.len() <= 50);
        assert!(clone_identity_name(&"x".repeat(50), "test").len() <= 50);
    }
}
