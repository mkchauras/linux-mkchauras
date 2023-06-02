//! Rust Scull Driver

use kernel::{prelude::*, file, miscdev};
use kernel::file::File;

module! {
    type: Scull,
    name: "rust_scull",
    author: "Mukesh Kumar Chaurasiya",
    description: "Scull Module",
    license: "GPL",
}

struct Scull {
    _dev: Pin<Box<miscdev::Registration<Scull>>>,
}

#[vtable]
impl file::Operations for Scull {

    fn open(_context: &Self::OpenData, _file: &File) -> Result<Self::Data> {
        pr_info!("File Opened\n");
        Ok(())
    }
}

impl kernel::Module for Scull {
    fn init(_name: &'static CStr, _module: &'static ThisModule) -> Result<Self> {
        pr_info!("Scull Driver Loaded\n");
        let reg = miscdev::Registration::new_pinned(fmt!("scull"), ())?;

        Ok(Scull{
            _dev: reg
        })
    }
}

