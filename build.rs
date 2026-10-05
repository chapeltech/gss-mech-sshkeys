use std::env;
use std::path::PathBuf;

use rasn_compiler::prelude::*;
use rasn_compiler::OutputMode;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let asn_path = PathBuf::from("sshkey.asn1");
    let out_path = out_dir.join("sshkey_asn1.rs");

    // A GSS plugin exports generic gss_* names while also referencing them
    // from its MIT dispatch table.  Keep those references inside the plugin.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-Bsymbolic-functions");
    }

    println!("cargo:rerun-if-changed={}", asn_path.display());

    match Compiler::<RasnBackend, _>::new()
        .add_asn_by_path(asn_path)
        .set_output_mode(OutputMode::SingleFile(out_path))
        .compile()
    {
        Ok(warnings) => {
            for warning in warnings {
                println!("cargo:warning={warning}");
            }
        }
        Err(error) => {
            panic!("rasn-compiler failed: {error}");
        }
    }
}
