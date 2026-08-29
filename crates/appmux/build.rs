fn main() {
    println!("cargo:rerun-if-changed=../../manager/AppMux.Manager/Assets/AppMux.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut resource = winres::WindowsResource::new();
    resource
        .set_icon("../../manager/AppMux.Manager/Assets/AppMux.ico")
        .set("ProductName", "AppMux")
        .set("FileDescription", "Layered app instances, simplified.")
        .set("CompanyName", "AppMux")
        .set("LegalCopyright", "Copyright © 2026 AppMux");
    resource
        .compile()
        .expect("failed to compile AppMux resources");
}
