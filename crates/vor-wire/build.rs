use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let protobuf_include = protoc_bin_vendored::include_path()?;
    let proto_root = PathBuf::from("../../proto");
    let proto = proto_root.join("v1/commander.proto");

    // SAFETY: build scripts run as isolated Cargo processes; no other threads in this
    // process read PROTOC before prost-build consumes it.
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    prost_build::Config::new().compile_protos(
        std::slice::from_ref(&proto),
        &[proto_root, protobuf_include],
    )?;
    println!("cargo:rerun-if-changed={}", proto.display());
    Ok(())
}
