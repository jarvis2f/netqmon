use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let schema = "proto/netqmon/v1/telemetry.proto";
    println!("cargo:rerun-if-changed={schema}");

    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    config.skip_debug(["netqmon.v1.SamplePacket"]);
    config.compile_protos(&[schema], &["proto"])?;
    Ok(())
}
