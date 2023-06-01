//! Rust Scull Driver

use kernel::prelude::*;

module! {
    type: Scull,
    name: "rust_scull",
    author: "Mukesh Kumar Chaurasiya",
    description: "Scull Module",
    license: "GPL",
}

struct Scull;

impl kernel::Module for Scull {
    fn init(_name: &'static CStr, _module: &'static ThisModule) -> Result<Self> {
        pr_info!("Scull Driver Loaded\n");
        Ok(Scull{})
    }
}

