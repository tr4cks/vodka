use std::cmp::min;
use std::convert::TryInto;
use std::error::Error;
use std::ffi::{CString, NulError, OsString};
use std::mem::{size_of, MaybeUninit};
use std::os::windows::ffi::OsStringExt;
use std::{fmt, ptr};

use winapi::shared::minwindef::{BOOL, DWORD, FARPROC, HMODULE, MAX_PATH};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::GetProcAddress;
use winapi::um::processthreadsapi::{GetCurrentProcessId, OpenProcess};
use winapi::um::psapi::{
    EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, MODULEINFO,
};
use winapi::um::winbase::{FormatMessageW, QueryFullProcessImageNameW, FORMAT_MESSAGE_FROM_SYSTEM};
use winapi::um::winnt::{HANDLE, WCHAR};

#[derive(Debug)]
pub enum Win32Error {
    SystemError(SystemError),
    AsciiError,
    Utf8Error(OsString),
    NulError(NulError),
}

impl fmt::Display for Win32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Win32Error::SystemError(_) => write!(f, "System error"),
            Win32Error::AsciiError => write!(f, "Some characters do not fit the ascii characters"),
            Win32Error::Utf8Error(_) => write!(f, "Couldn't convert string to utf-8 encoding"),
            Win32Error::NulError(_) => write!(
                f,
                "A null character shouldn't be present in the middle of the string."
            ),
        }
    }
}

impl Error for Win32Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Win32Error::SystemError(e) => Some(e),
            Win32Error::NulError(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct SystemError {
    code: DWORD,
    message: Option<String>,
}

impl SystemError {
    pub fn from_last_error() -> SystemError {
        let code = unsafe { GetLastError() };
        let message = SystemError::format_message(code);
        SystemError { code, message }
    }

    fn format_message(code: DWORD) -> Option<String> {
        // Unicode(UTF-16) - LPWSTR
        // Arbitrary capacity was chosen to store the error message.
        // This buffer message cannot be larger than 64K bytes.
        // https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-formatmessage
        let mut buffer = Vec::<u16>::with_capacity(4096 * 2 /* unicode */);
        let length = unsafe {
            FormatMessageW(
                FORMAT_MESSAGE_FROM_SYSTEM,
                ptr::null(),
                code,
                0,
                buffer.as_mut_ptr(),
                buffer.capacity().try_into().unwrap(),
                ptr::null_mut(),
            )
        };
        if length == 0 {
            return None;
        }
        unsafe {
            buffer.set_len(length as usize);
        }
        // From UTF-16 to UTF-8
        OsString::from_wide(&buffer[..length as usize])
            .into_string()
            .map(Some)
            .unwrap_or(None)
    }
}

impl fmt::Display for SystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = self
            .message
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("Couldn't format error message");
        write!(f, "Error code {}: {}", self.code, message)
    }
}

impl Error for SystemError {}

#[inline(always)]
pub fn open_process(
    dw_desired_access: DWORD,
    b_inherit_handle: BOOL,
    dw_process_id: DWORD,
) -> Result<HANDLE, Win32Error> {
    match unsafe { OpenProcess(dw_desired_access, b_inherit_handle, dw_process_id) } {
        handle if handle.is_null() => Err(Win32Error::SystemError(SystemError::from_last_error())),
        handle => Ok(handle),
    }
}

#[inline(always)]
pub fn close_handle(h_object: HANDLE) -> Result<(), Win32Error> {
    match unsafe { CloseHandle(h_object) } {
        0 => Err(Win32Error::SystemError(SystemError::from_last_error())),
        _ => Ok(()),
    }
}

#[inline(always)]
pub fn get_current_process_id() -> DWORD {
    unsafe { GetCurrentProcessId() }
}

pub fn query_full_process_image_name(h_process: HANDLE) -> Result<String, Win32Error> {
    // Unicode(UTF-16) - LPWSTR
    let mut filename: [WCHAR; MAX_PATH * 2 /* unicode */] = unsafe {
        MaybeUninit::uninit().assume_init()
    };
    let mut length: DWORD = filename.len().try_into().unwrap();
    let return_value =
        unsafe { QueryFullProcessImageNameW(h_process, 0, filename.as_mut_ptr(), &mut length) };
    if return_value == 0 {
        return Err(Win32Error::SystemError(SystemError::from_last_error()));
    }
    // From UTF-16 to UTF-8
    OsString::from_wide(&filename[..length as usize])
        .into_string()
        .map_err(Win32Error::Utf8Error)
}

pub fn enum_process_modules(
    h_process: HANDLE,
    dw_filter_flag: DWORD,
) -> Result<impl Iterator<Item = HMODULE>, Win32Error> {
    let mut module_handles = Vec::<HMODULE>::new();
    let mut needed_capacity: DWORD = unsafe { MaybeUninit::uninit().assume_init() };
    let return_value = unsafe {
        // Do not call CloseHandle on any of the handles returned by this function
        EnumProcessModulesEx(
            h_process,
            module_handles.as_mut_ptr(),
            (module_handles.capacity() * size_of::<HMODULE>())
                .try_into()
                .unwrap(),
            &mut needed_capacity,
            dw_filter_flag,
        )
    };
    if return_value == 0 {
        return Err(Win32Error::SystemError(SystemError::from_last_error()));
    }
    module_handles.reserve_exact(needed_capacity as usize / size_of::<HMODULE>());
    let return_value = unsafe {
        EnumProcessModulesEx(
            h_process,
            module_handles.as_mut_ptr(),
            (module_handles.capacity() * size_of::<HMODULE>())
                .try_into()
                .unwrap(),
            &mut needed_capacity,
            dw_filter_flag,
        )
    };
    if return_value == 0 {
        return Err(Win32Error::SystemError(SystemError::from_last_error()));
    }
    unsafe {
        module_handles.set_len(min(
            needed_capacity as usize / size_of::<HMODULE>(),
            module_handles.capacity(),
        ));
    }
    Ok(module_handles.into_iter())
}

pub fn get_module_file_name(h_process: HANDLE, h_module: HMODULE) -> Result<String, Win32Error> {
    // Unicode(UTF-16) - LPWSTR
    let mut filename: [WCHAR; MAX_PATH * 2 /* unicode */] = unsafe {
        MaybeUninit::uninit().assume_init()
    };
    let length = unsafe {
        GetModuleFileNameExW(
            h_process,
            h_module,
            filename.as_mut_ptr(),
            filename.len().try_into().unwrap(),
        )
    };
    if length == 0 {
        return Err(Win32Error::SystemError(SystemError::from_last_error()));
    }
    // From UTF-16 to UTF-8
    OsString::from_wide(&filename[..length as usize])
        .into_string()
        .map_err(Win32Error::Utf8Error)
}

pub fn get_module_information(
    h_process: HANDLE,
    h_module: HMODULE,
) -> Result<MODULEINFO, Win32Error> {
    let mut mod_info: MODULEINFO = unsafe { MaybeUninit::uninit().assume_init() };
    let return_value = unsafe {
        GetModuleInformation(
            h_process,
            h_module,
            &mut mod_info,
            size_of::<MODULEINFO>().try_into().unwrap(),
        )
    };
    if return_value == 0 {
        return Err(Win32Error::SystemError(SystemError::from_last_error()));
    }
    Ok(mod_info)
}

pub fn get_proc_address(h_module: HMODULE, lp_proc_name: &str) -> Result<FARPROC, Win32Error> {
    // ANSI - LPCSTR
    // According to windows, the code values 0x00 through 0x7F
    // correspond to the 7-bit ASCII character set
    if !lp_proc_name.is_ascii() {
        return Err(Win32Error::AsciiError);
    }
    let name = CString::new(lp_proc_name).map_err(Win32Error::NulError)?;
    let address: FARPROC = unsafe { GetProcAddress(h_module, name.as_ptr()) };
    if address.is_null() {
        Err(Win32Error::SystemError(SystemError::from_last_error()))
    } else {
        Ok(address)
    }
}
