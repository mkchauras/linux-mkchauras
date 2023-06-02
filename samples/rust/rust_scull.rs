//! Rust Scull Driver

use kernel::{prelude::*, file, miscdev};
use kernel::file::File;
use kernel::io_buffer::{IoBufferReader, IoBufferWriter};

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
    
    fn release(_data: Self::Data, _file: &File) {
        pr_info!("File is closed\n");
    }

    fn read(
        _data: (), 
        _file: &file::File,
        _writer: &mut impl IoBufferWriter,
        _offset: u64,
    ) -> Result<usize> {
        pr_info!("File is Read\n");
        Ok(0)
    }

    fn write(
        _data: (),
        _file: &file::File,
        reader: &mut impl IoBufferReader,
        _offset: u64,
    ) -> Result<usize> {
        pr_info!("File is written\n");
        Ok(reader.len())
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

