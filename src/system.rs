use std::cmp::min;
use std::cmp::Ordering;
use std::convert::TryInto;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::{DWORD, FALSE, FARPROC, HMODULE, LPCVOID, LPVOID};
use winapi::um::minwinbase::{LPTHREAD_START_ROUTINE, SECURITY_ATTRIBUTES};
use winapi::um::psapi::{LIST_MODULES_DEFAULT, MODULEINFO};
use winapi::um::winnt::HANDLE;

mod win32;

pub use win32::SystemError;
pub use win32::Win32Error;

pub struct Process {
    handle: HANDLE,
}

impl Process {
    pub fn new(desired_access: DWORD, pid: u32) -> Result<Process, win32::Win32Error> {
        win32::open_process(desired_access, FALSE, pid).map(|handle| Process { handle })
    }

    pub fn current(desired_access: DWORD) -> Result<Process, win32::Win32Error> {
        Self::new(desired_access, win32::get_current_process_id())
    }

    pub fn filename(&self) -> Result<PathBuf, win32::Win32Error> {
        win32::query_full_process_image_name(self.handle).map(PathBuf::from)
    }

    pub fn modules(&'_ self) -> Result<impl Iterator<Item = Module<'_>>, win32::Win32Error> {
        let module =
            win32::enum_process_modules(self.handle, LIST_MODULES_DEFAULT)?.map(move |handle| {
                Module {
                    process: self,
                    handle,
                }
            });
        Ok(module)
    }

    pub fn create_thread(
        &self,
        thread_attributes: Option<SECURITY_ATTRIBUTES>,
        stack_size: SIZE_T,
        start_address: LPTHREAD_START_ROUTINE,
        parameter: LPVOID,
        creation_flags: DWORD,
    ) -> Result<Thread, win32::Win32Error> {
        win32::create_remote_thread(
            self.handle,
            thread_attributes,
            stack_size,
            start_address,
            parameter,
            creation_flags,
        )
        .map(|(thread_id, handle)| Thread { thread_id, handle })
    }

    pub fn virtual_alloc(
        &self,
        address: LPVOID,
        size: SIZE_T,
        allocation_type: DWORD,
        protect: DWORD,
    ) -> Result<MemoryRegion, win32::Win32Error> {
        win32::virtual_alloc(self.handle, address, size, allocation_type, protect).map(|addr| {
            MemoryRegion {
                start_address: addr as usize,
                size,
            }
        })
    }

    pub fn memory_stream(
        &'_ self,
        memory_region: &MemoryRegion,
    ) -> anyhow::Result<MemoryStream<'_>> {
        MemoryStream::new(self, memory_region.start_address, memory_region.size)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // TODO: warn an error
        let _ = win32::close_handle(self.handle);
    }
}

pub struct Module<'p> {
    process: &'p Process,
    handle: HMODULE,
}

impl<'p> Module<'p> {
    pub fn filename(&self) -> Result<PathBuf, win32::Win32Error> {
        win32::get_module_file_name(self.process.handle, self.handle).map(PathBuf::from)
    }

    pub fn info(&self) -> Result<MODULEINFO, win32::Win32Error> {
        win32::get_module_information(self.process.handle, self.handle)
    }

    pub fn proc_address(&self, name: &str) -> Result<FARPROC, win32::Win32Error> {
        win32::get_proc_address(self.handle, name)
    }
}

pub trait ModuleIteratorExt<'a, 'p: 'a>: Iterator<Item = &'a Module<'p>> {
    fn try_find_module(&'p mut self, name: &str) -> anyhow::Result<Option<&'a Module<'p>>> {
        for module in self {
            let filename = module.filename()?;
            let filename = match filename.file_name() {
                Some(f) => f,
                None => return Ok(None),
            };
            if filename == name {
                return Ok(Some(module))
            }
        }
        Ok(None)
    }
}

impl<'a, 'p, T> ModuleIteratorExt<'a, 'p> for T where 'p: 'a, T: Iterator<Item = &'a Module<'p>> {}

pub struct Thread {
    thread_id: DWORD,
    handle: HANDLE,
}

impl Thread {
    pub fn get_id(&self) -> DWORD {
        self.thread_id
    }

    pub fn wait(&self, duration: Duration) -> Result<DWORD, win32::Win32Error> {
        win32::wait_for_single_object(self.handle, duration)
    }

    pub fn exit_code(&self) -> Result<DWORD, win32::Win32Error> {
        win32::get_exit_code_thread(self.handle)
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        // TODO: warn error
        let _ = win32::close_handle(self.handle);
    }
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    start_address: usize,
    size: usize,
}

impl MemoryRegion {
    pub fn start_address(&self) -> usize {
        self.start_address
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

pub struct MemoryStream<'p> {
    process: &'p Process,
    start_address: usize,
    end_address: usize,
    current_address: usize,
}

impl MemoryStream<'_> {
    fn new(process: &Process, start_address: usize, size: usize) -> anyhow::Result<MemoryStream> {
        let end_address = start_address
            .checked_add(size)
            .ok_or_else(|| anyhow::anyhow!("Overflow occurred"))?;
        Ok(MemoryStream {
            process,
            start_address,
            end_address,
            current_address: start_address,
        })
    }

    fn seek_from(address: usize, offset: i64) -> io::Result<usize> {
        match offset.cmp(&0i64) {
            Ordering::Less => {
                let offset: usize = offset
                    .checked_abs()
                    .map_or_else(|| i64::MAX as u64 + 1u64, |o| o as u64)
                    .try_into()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                address.checked_sub(offset).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        anyhow::anyhow!("Underflow occurred"),
                    )
                })
            }
            Ordering::Equal => Ok(address),
            Ordering::Greater => {
                let offset: usize = offset
                    .try_into()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                address.checked_add(offset).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        anyhow::anyhow!("Overflow occurred"),
                    )
                })
            }
        }
    }
}

impl io::Write for MemoryStream<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        debug_assert!(self.current_address <= self.end_address);
        let buf = &buf[0..min(self.end_address - self.current_address, buf.len())];
        let bytes_written =
            win32::write_process_memory(self.process.handle, self.current_address as LPVOID, buf)
                .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        self.current_address = self
            .current_address
            .checked_add(bytes_written)
            .expect("Overflow could not happen");
        Ok(bytes_written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Read for MemoryStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug_assert!(self.current_address <= self.end_address);
        let len = buf.len();
        let buf = &mut buf[0..min(self.end_address - self.current_address, len)];
        let bytes_read =
            win32::read_process_memory(self.process.handle, self.current_address as LPCVOID, buf)
                .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        self.current_address = self
            .current_address
            .checked_add(bytes_read)
            .expect("Overflow could not happen");
        Ok(bytes_read)
    }
}

impl io::Seek for MemoryStream<'_> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let current_address = match pos {
            io::SeekFrom::Start(offset) => {
                let offset: usize = offset
                    .try_into()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                self.start_address.checked_add(offset).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        anyhow::anyhow!("Overflow occurred"),
                    )
                })?
            }
            io::SeekFrom::End(offset) => Self::seek_from(self.end_address, offset)?,
            io::SeekFrom::Current(offset) => Self::seek_from(self.current_address, offset)?,
        };
        if current_address < self.start_address || current_address > self.end_address {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                anyhow::anyhow!("Address out of bounds"),
            ));
        }
        self.current_address = current_address;
        Ok((self.current_address - self.start_address)
            .try_into()
            .expect("Cannot occur with current processor architectures (x64)"))
    }
}
