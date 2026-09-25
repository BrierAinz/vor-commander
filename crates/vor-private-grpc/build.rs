use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let protobuf_include = protoc_bin_vendored::include_path()?;
    let proto_root = PathBuf::from("../../proto");
    let proto = proto_root.join("v1/commander.proto");

    // SAFETY: Cargo runs this build script in its own process and tonic-prost-build
    // reads PROTOC only after this assignment.
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    tonic_prost_build::configure()
        .build_transport(false)
        .extern_path(".vor.commander.v1", "::vor_wire::v1")
        .compile_protos(
            std::slice::from_ref(&proto),
            &[proto_root, protobuf_include],
        )?;
    println!("cargo:rerun-if-changed={}", proto.display());
    Ok(())
}
