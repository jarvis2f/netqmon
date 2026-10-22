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

        let mut clang_args = vec![
            OsString::from("-I"),
            include_dir.into_os_string(),
            OsString::from("-Wall"),
            OsString::from("-mcpu=v3"),
            OsString::from("-Werror"),
            OsString::from("-Wno-error=unused-command-line-argument"),
            OsString::from(target_arch_define),
        ];
        if env::var_os("CARGO_FEATURE_QOS_COMPATIBILITY_POC").is_some() {
            clang_args.push(OsString::from("-DNETQMON_QOS_POC=1"));
        }
        if env::var_os("CARGO_FEATURE_QOS_CLIENT_PATH_PROBE").is_some() {
            clang_args.push(OsString::from("-DNETQMON_QOS_PATH_PROBE=1"));
        }
        if env::var_os("CARGO_FEATURE_QOS_CLIENT_PRIORITY").is_some() {
            clang_args.push(OsString::from("-DNETQMON_QOS_PRIORITY=1"));
        }
        SkeletonBuilder::new()
            .source(&source)
            .clang_args(clang_args)
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
    generate_classids();
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

fn generate_classids() {
    use std::{env, fs, path::PathBuf};
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let header = manifest.join("../../bpf/include/netqmon_classid.h");
    let source = fs::read_to_string(&header).expect("read canonical QoS class IDs");
    let mut rust = String::from("// Generated from netqmon_classid.h. Do not edit.\n");
    for line in source.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() == 3 && fields[0] == "#define" {
            if let Some(name) = fields[1].strip_prefix("NETQMON_QOS_") {
                let value = fields[2]
                    .strip_prefix("0x")
                    .expect("classid literal must be hex");
                let value = u32::from_str_radix(value, 16).expect("valid classid literal");
                rust.push_str(&format!("pub(crate) const {name}: u32 = 0x{value:08x};\n"));
            }
        }
    }
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("qos_classid.rs");
    fs::write(output, rust).expect("write generated QoS class IDs");
    println!("cargo:rerun-if-changed={}", header.display());
}
