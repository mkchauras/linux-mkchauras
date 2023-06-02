//! Rust Scull Driver

use kernel::sync::{Arc, ArcBorrow, UniqueArc};
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

#[derive(Debug)]
struct Device {
    num: usize,
    contents: Vec<u8>,
}

struct Scull {
    _dev: Pin<Box<miscdev::Registration<Scull>>>,
}

#[vtable]
impl file::Operations for Scull {
    type OpenData = Arc<Device>;
    type Data = Arc<Device>;
    fn open(context: &Self::OpenData, _file: &File) -> Result<Self::Data> {
        pr_info!("File Opened for device {}\n", context.num);
        Ok(context.clone())
    }
    
    fn release(_data: Self::Data, _file: &File) {
        pr_info!("File is closed\n");
    }

    fn read(
        data: ArcBorrow<'_, Device>, 
        _file: &file::File,
        _writer: &mut impl IoBufferWriter,
        _offset: u64,
    ) -> Result<usize> {
        pr_info!("File being Read from {}\n", data.num);
        Ok(0)
    }

    fn write(
        data: ArcBorrow<'_, Device>,
        _file: &file::File,
        reader: &mut impl IoBufferReader,
        _offset: u64,
    ) -> Result<usize> {
        pr_info!("File being Written {}\n", data.num);
        Ok(reader.len())
    }
}

impl kernel::Module for Scull {
    fn init(_name: &'static CStr, _module: &'static ThisModule) -> Result<Self> {
        pr_info!("Scull Driver Loaded\n");
        let dev = Arc::try_new(Device{
            num: 123,
            contents: Vec::new(),
        })?;

        let reg = miscdev::Registration::new_pinned(fmt!("scull"), dev)?;

        Ok(Scull{
            _dev: reg
        })
    }
}

