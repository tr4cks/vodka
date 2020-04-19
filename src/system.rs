use winapi::shared::minwindef::{FALSE, FARPROC, HMODULE};
use winapi::um::psapi::{LIST_MODULES_DEFAULT, MODULEINFO};
use winapi::um::winnt::{HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

mod win32;

pub use win32::SystemError;
pub use win32::Win32Error;

pub struct Process {
    handle: HANDLE,
}

// TODO: cache variables -> Option?
impl Process {
    pub fn new(pid: u32) -> Result<Process, win32::Win32Error> {
        let handle = win32::open_process(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)?;
        Ok(Process { handle })
    }

    pub fn current() -> Result<Process, win32::Win32Error> {
        Self::new(win32::get_current_process_id())
    }

    pub fn filename(&self) -> Result<String, win32::Win32Error> {
        win32::query_full_process_image_name(self.handle)
    }

    pub fn modules<'p>(
        &'p self,
    ) -> Result<impl Iterator<Item = Module<'p>> + 'p, win32::Win32Error> {
        let module =
            win32::enum_process_modules(self.handle, LIST_MODULES_DEFAULT)?.map(move |handle| {
                Module {
                    process: self,
                    handle,
                }
            });
        Ok(module)
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

// TODO: cache variables -> Option?
impl<'p> Module<'p> {
    pub fn filename(&self) -> Result<String, win32::Win32Error> {
        win32::get_module_file_name(self.process.handle, self.handle)
    }

    pub fn info(&self) -> Result<MODULEINFO, win32::Win32Error> {
        win32::get_module_information(self.process.handle, self.handle)
    }

    pub fn proc_address(&self, name: &str) -> Result<FARPROC, win32::Win32Error> {
        win32::get_proc_address(self.handle, name)
    }
}
