//! Rust Scull Driver

use kernel::file::File;
use kernel::io_buffer::{IoBufferReader, IoBufferWriter};
use kernel::sync::smutex::Mutex;
use kernel::sync::{Arc, ArcBorrow};
use kernel::{file, miscdev, prelude::*};

module! {
    type: Scull,
    name: "rust_scull",
    author: "Mukesh Kumar Chaurasiya",
    description: "Scull Module",
    license: "GPL",
    params: {
        nr_devs: u8 {
            default: 10,
            permissions: 0o644,
            description: "Number of Scull Devices",
        },
    },
}

struct Device {
    num: usize,
    contents: Mutex<Vec<u8>>,
}

struct Scull {
    _devs: Vec<Pin<Box<miscdev::Registration<Scull>>>>,
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
    fn init(_name: &'static CStr, module: &'static ThisModule) -> Result<Self> {
        pr_info!("Scull Driver Loaded\n");
        let count = (*nr_devs.read(&module.kernel_param_lock())).try_into()?;
        let mut devs = Vec::try_with_capacity(count)?;
        for i in 0..count {
            let state = Arc::try_new(Device {
                num: i,
                contents: Mutex::new(Vec::new()),
            })?;

            let reg = miscdev::Registration::new_pinned(fmt!("scull{i}"), state)?;
            devs.try_push(reg)?;
        }
        Ok(Scull { _devs: devs })
    }
}
