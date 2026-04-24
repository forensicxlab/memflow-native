fn main() {
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rustc-check-cfg=cfg(memflow_plugin_api, values(\"1\", \"2\"))");

    match memflow::plugins::MEMFLOW_PLUGIN_VERSION {
        1 => println!("cargo:rustc-cfg=memflow_plugin_api=\"1\""),
        2 => println!("cargo:rustc-cfg=memflow_plugin_api=\"2\""),
        other => panic!("Unsupported MEMFLOW_PLUGIN_VERSION: {other}"),
    }
}
