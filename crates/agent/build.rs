#[cfg(target_os = "linux")]
mod linux {
    use std::env;
    use std::ffi::OsString;
    use std::path::PathBuf;

    use libbpf_cargo::SkeletonBuilder;

    pub fn build() {
        let manifest_dir = PathBuf::from(
            env::var_os("CARGO_MANIFEST_DIR")
                .expect("CARGO_MANIFEST_DIR must be set for the agent build"),
        );
        let workspace_dir = manifest_dir
            .parent()
            .and_then(|path| path.parent())
            .expect("agent crate must be inside the workspace crates directory");
        let source = workspace_dir.join("bpf/flow.bpf.c");
        let include_dir = workspace_dir.join("bpf/include");
        let output =
            PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set for the agent build"))
                .join("flow.skel.rs");

        let target_arch = env::var("CARGO_CFG_TARGET_ARCH")
            .expect("CARGO_CFG_TARGET_ARCH must be set for the agent build");
        let target_arch_define = match target_arch.as_str() {
            "aarch64" => "-D__TARGET_ARCH_arm64",
            "x86_64" => "-D__TARGET_ARCH_x86",
            "arm" => "-D__TARGET_ARCH_arm",
            "riscv64" => "-D__TARGET_ARCH_riscv",
            "mips" | "mipsel" => "-D__TARGET_ARCH_mips",
            "powerpc64" | "powerpc" => "-D__TARGET_ARCH_powerpc",
            _ => "-D__TARGET_ARCH_unknown",
        };

        SkeletonBuilder::new()
            .source(&source)
            .clang_args([
                OsString::from("-I"),
                include_dir.into_os_string(),
                OsString::from("-Wall"),
                OsString::from("-mcpu=v3"),
                OsString::from("-Werror"),
                OsString::from("-Wno-error=unused-command-line-argument"),
                OsString::from(target_arch_define),
            ])
            .reference_obj(true)
            .build_and_generate(&output)
            .expect("failed to compile flow.bpf.c and generate its Rust skeleton");

        println!("cargo:rerun-if-changed={}", source.display());
        println!(
            "cargo:rerun-if-changed={}",
            workspace_dir.join("bpf/include").display()
        );
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-lib=zstd");
        println!("cargo:rustc-link-lib=z");
        println!("cargo:rustc-link-lib=elf");
        linux::build();
    }

    #[cfg(not(target_os = "linux"))]
    println!("cargo:warning=eBPF compilation is skipped on non-Linux build hosts");
}
