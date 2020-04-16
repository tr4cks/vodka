use std::cmp::min;
use std::ffi::{CString, NulError, OsString};
use std::mem::{size_of, MaybeUninit};
use std::os::windows::ffi::OsStringExt;

use winapi::shared::minwindef::{DWORD, FALSE, FARPROC, HMODULE, MAX_PATH};
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::GetProcAddress;
use winapi::um::processthreadsapi::{GetCurrentProcessId};
use winapi::um::psapi::{
    EnumProcessModules, GetModuleFileNameExW, GetModuleInformation, MODULEINFO,
};
use winapi::um::winbase::QueryFullProcessImageNameW;
use winapi::um::winnt::{HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, WCHAR};

mod syscalls {
    use std::convert::TryInto;
    use std::error::Error;
    use std::ffi::OsString;
    use std::fmt;
    use std::os::windows::ffi::OsStringExt;
    use std::ptr;

    use winapi::shared::minwindef::{DWORD, BOOL};
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::winbase::{FormatMessageW, FORMAT_MESSAGE_FROM_SYSTEM};
    use winapi::um::winnt::HANDLE;

    #[derive(Debug)]
    pub struct SystemError {
        code: DWORD,
        message: Option<String>,
    }

    impl SystemError {
        pub fn from_last_error() -> SystemError {
            let code = unsafe { GetLastError() };
            // TODO: consider formatting the error code on demand ?
            let message = SystemError::format_message(code);
            SystemError { code, message }
        }

        fn format_message(code: DWORD) -> Option<String> {
            // Arbitrary capacity was chosen to store the error message. Can go up to 64KB as per
            // https://docs.microsoft.com/fr-fr/windows/win32/api/winbase/nf-winbase-formatmessagew
            let mut buf = Vec::<u16>::with_capacity(4096);
            let length = unsafe {
                FormatMessageW(
                    FORMAT_MESSAGE_FROM_SYSTEM,
                    ptr::null(),
                    code,
                    0,
                    buf.as_mut_ptr(),
                    buf.capacity().try_into().unwrap(),
                    ptr::null_mut()
                )
            };
            if length == 0 {
                // TODO: handle FormatMessageW failures
                panic!("FormatMessageW errored");
            }
            OsString::from_wide(&buf[..length as usize])
                .into_string()
                .map(Some)
                .unwrap_or(None)
        }
    }

    impl fmt::Display for SystemError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let message = self.message.as_ref()
                .map(|s| s.as_str())
                .unwrap_or("Couldn't format error message");
            write!(f, "Error code {}: {}", self.code, message)
        }
    }

    impl Error for SystemError {}

    #[inline(always)]
    pub fn open_process(dw_desired_access: DWORD, b_inherit_handle: BOOL, dw_process_id: DWORD) -> Result<HANDLE, SystemError> {
        match unsafe {
            OpenProcess(dw_desired_access, b_inherit_handle, dw_process_id)
        } {
            handle if handle.is_null() => Err(SystemError::from_last_error()),
            handle => Ok(handle)
        }
    }
}

use syscalls::SystemError;

pub struct Process {
    handle: HANDLE,
}

#[derive(Debug)]
pub enum ProcessError {
    SystemError(SystemError),
    Utf8Error,
}

impl Process {
    fn new(pid: u32) -> Result<Process, SystemError> {
        let handle = syscalls::open_process(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)?;
        Ok(Process { handle })
    }

    pub fn current() -> Result<Process, SystemError> {
        Self::new(unsafe { GetCurrentProcessId() })
    }

    pub fn filename(&self) -> Result<String, ProcessError> {
        // TODO: doubtful!
        // unicode(UTF-16) - LPWSTR
        let mut filename: [WCHAR; MAX_PATH * size_of::<WCHAR>() * 2 /* unicode */ ] = unsafe {
            MaybeUninit::uninit().assume_init()
        };
        let mut length: DWORD = filename.len() as DWORD;
        let return_value = unsafe {
            QueryFullProcessImageNameW(self.handle, 0, filename.as_mut_ptr(), &mut length)
        };
        if return_value == 0 {
            return Err(ProcessError::SystemError(SystemError::from_last_error()));
        }
        // from UTF-16 to UTF-8
        OsString::from_wide(&filename[..length as usize])
            .to_str()
            .map(String::from)
            .ok_or_else(|| ProcessError::Utf8Error)
    }

    pub fn modules<'p>(&'p self) -> Result<impl Iterator<Item = Module<'p>> + 'p, SystemError> {
        let mut handles = Vec::<HMODULE>::new();
        let mut needed_capacity: DWORD = unsafe { MaybeUninit::uninit().assume_init() };
        let return_value = unsafe {
            // do not call CloseHandle on any of the handles returned by this function
            EnumProcessModules(
                self.handle,
                handles.as_mut_ptr(),
                (handles.capacity() * size_of::<HMODULE>()) as DWORD,
                &mut needed_capacity,
            )
        };
        if return_value == 0 {
            return Err(SystemError::from_last_error());
        }
        handles.reserve_exact(needed_capacity as usize / size_of::<HMODULE>());
        let return_value = unsafe {
            EnumProcessModules(
                self.handle,
                handles.as_mut_ptr(),
                (handles.capacity() * size_of::<HMODULE>()) as DWORD,
                &mut needed_capacity,
            )
        };
        if return_value == 0 {
            return Err(SystemError::from_last_error());
        }
        unsafe {
            handles.set_len(min(
                needed_capacity as usize / size_of::<HMODULE>(),
                handles.capacity(),
            ));
        }
        Ok(handles.into_iter().map(move |handle| Module {
            process: self,
            handle,
        }))
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

pub struct Module<'p> {
    process: &'p Process,
    handle: HMODULE,
}

#[derive(Debug)]
pub enum ModuleError {
    SystemError(SystemError),
    AsciiError,
    Utf8Error,
    NulError(NulError),
}

// TODO: cache variables -> Option?
impl<'p> Module<'p> {
    pub fn filename(&self) -> Result<String, ModuleError> {
        // TODO: doubtful!
        // unicode(UTF-16) - LPWSTR
        let mut filename: [WCHAR; MAX_PATH * size_of::<WCHAR>() * 2 /* unicode */] = unsafe {
            MaybeUninit::uninit().assume_init()
        };
        let length = unsafe {
            GetModuleFileNameExW(
                self.process.handle,
                self.handle,
                filename.as_mut_ptr(),
                filename.len() as DWORD,
            )
        };
        if length == 0 {
            return Err(ModuleError::SystemError(SystemError::from_last_error()));
        }
        // from UTF-16 to UTF-8
        OsString::from_wide(&filename[..length as usize])
            .to_str()
            .map(String::from)
            .ok_or_else(|| ModuleError::Utf8Error)
    }

    pub fn info(&self) -> Result<MODULEINFO, ModuleError> {
        let mut mod_info: MODULEINFO = unsafe { MaybeUninit::uninit().assume_init() };
        let return_value = unsafe {
            GetModuleInformation(
                self.process.handle,
                self.handle,
                &mut mod_info,
                size_of::<MODULEINFO>() as DWORD,
            )
        };
        if return_value == 0 {
            return Err(ModuleError::SystemError(SystemError::from_last_error()));
        }
        Ok(mod_info)
    }

    // TODO: return another type than FARPROC?; why FARPROC is a pointer to an enum?
    pub fn proc_address(&self, name: &str) -> Result<FARPROC, ModuleError> {
        // ANSI - LPCSTR
        // according to windows, the code values 0x00 through 0x7F
        // correspond to the 7-bit ASCII character set
        if !name.is_ascii() {
            return Err(ModuleError::AsciiError);
        }
        let name = CString::new(name).map_err(ModuleError::NulError)?;
        let address: FARPROC = unsafe { GetProcAddress(self.handle, name.as_ptr()) };
        if address.is_null() {
            Err(ModuleError::SystemError(SystemError::from_last_error()))
        } else {
            Ok(address)
        }
    }
}
