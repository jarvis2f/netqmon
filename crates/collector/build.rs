fn main() {
    println!("cargo:rustc-check-cfg=cfg(ndpi_available)");
    println!("cargo:rerun-if-changed=src/dpi/ndpi_shim.c");
    // Keep pure-Rust development builds possible; runtime exposes unavailability.
    // Release images install pinned nDPI before building the Collector.
    match pkg_config::Config::new()
        .range_version("4.14".."5")
        .statik(false)
        .probe("libndpi")
    {
        Ok(lib) => {
            cc::Build::new()
                .file("src/dpi/ndpi_shim.c")
                .includes(lib.include_paths)
                .compile("netqmon_ndpi_shim");
            println!("cargo:rustc-cfg=ndpi_available");
        }
        Err(_) => println!(
            "cargo:warning=nDPI 4.14 unavailable; DPI startup requires libndpi or NETQMON_DPI_ENABLED=false"
        ),
    }
}
