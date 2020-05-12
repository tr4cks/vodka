use std::convert::TryInto;
use std::ffi::{OsStr, OsString};
use std::io::{BufWriter, Write};
use std::mem::transmute;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::time::Duration;

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register,
};
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{BOOL, FARPROC, HMODULE, LPVOID};
use winapi::um::minwinbase::LPTHREAD_START_ROUTINE;
use winapi::um::winnt::{
    LPCSTR, LPCWSTR, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE,
    WCHAR,
};

use crate::system::{Module, ModuleIteratorExt, Process};

pub type LoadLibraryW = unsafe extern "system" fn(lp_lib_file_name: LPCWSTR) -> HMODULE;
pub type SetDllDirectoryW = unsafe extern "system" fn(lp_path_name: LPCWSTR) -> BOOL;

fn label(id: u64, mut instruction: Instruction) -> Instruction {
    instruction.set_ip(id);
    instruction
}

/// The sequence of instructions included in the `preloader_instructions` function is equivalent
/// to the pseudo code written in C below:
///
/// ```
/// #include <Windows.h>
///
/// typedef BOOL    (__stdcall *SetDllDirectoryW_repr)(LPCWSTR lpPathName);
/// typedef HMODULE (__stdcall *LoadLibraryW_repr)(LPCWSTR lpLibFileName);
///
/// DWORD __stdcall thread_start_routine(LPVOID lpThreadParameter) {
///     if (((SetDllDirectoryW_repr) ${set_dll_directory_fn})(${set_dll_directory_arg}) == 0) {
///         return 1;
///     }
///     if (((LoadLibraryW_repr) ${load_library_fn})(${load_library_arg}) == NULL) {
///         return 2;
///     }
///     return 0;
/// }
/// ```
#[rustfmt::skip]
fn preloader_instructions(
    set_dll_directory_fn: SetDllDirectoryW, set_dll_directory_arg: u64, // TODO: use LPCWSTR in place?
    load_library_fn: LoadLibraryW, load_library_arg: u64,
) -> Vec<Instruction> {
    enum Label {
        SetDllDirectoryOk = 1,
        LoadLibraryOk,
        Err,
    }

    vec![
        Instruction::with_mem_reg(
            Code::Mov_rm64_r64, MemoryOperand::with_base_displ(Register::RSP, 0x8), Register::RCX
        ),
        Instruction::with_reg_u32(
            Code::Sub_rm64_imm8, Register::RSP, 0x28
        ),
        Instruction::with_reg_u64(
            Code::Mov_r64_imm64, Register::RCX, set_dll_directory_arg
        ),
        Instruction::with_reg_u64(
            Code::Mov_r64_imm64, Register::RAX, (set_dll_directory_fn as usize).try_into().unwrap()
        ),
        Instruction::with_reg(
            Code::Call_rm64, Register::RAX
        ),
        Instruction::with_reg_reg(
            Code::Test_rm32_r32, Register::EAX, Register::EAX
        ),
        Instruction::with_branch(
            Code::Jne_rel32_64, Label::SetDllDirectoryOk as u64
        ),
        Instruction::with_reg_u32(
            Code::Mov_r32_imm32, Register::EAX, 1
        ),
        Instruction::with_branch(
            Code::Jmp_rel32_64, Label::Err as u64
        ),
        label(Label::SetDllDirectoryOk as u64, Instruction::with_reg_u64(
            Code::Mov_r64_imm64, Register::RCX, load_library_arg
        )),
        Instruction::with_reg_u64(
            Code::Mov_r64_imm64, Register::RAX, (load_library_fn as usize).try_into().unwrap()
        ),
        Instruction::with_reg(
            Code::Call_rm64, Register::RAX
        ),
        Instruction::with_reg_reg(
            Code::Test_rm64_r64, Register::RAX, Register::RAX
        ),
        Instruction::with_branch(
            Code::Jne_rel32_64, Label::LoadLibraryOk as u64
        ),
        Instruction::with_reg_u32(
            Code::Mov_r32_imm32, Register::EAX, 2
        ),
        Instruction::with_branch(
            Code::Jmp_rel32_64, Label::Err as u64
        ),
        label(Label::LoadLibraryOk as u64, Instruction::with_reg_reg(
            Code::Xor_r32_rm32, Register::EAX, Register::EAX
        )),
        label(Label::Err as u64, Instruction::with_reg_u32(
            Code::Add_rm64_imm8, Register::RSP, 0x28
        )),
        Instruction::with(
            Code::Retnq
        ),
    ]
}

fn preloader_bytecode(
    set_dll_directory_fn: SetDllDirectoryW,
    set_dll_directory_arg: u64,
    load_library_fn: LoadLibraryW,
    load_library_arg: u64,
) -> anyhow::Result<Vec<u8>> {
    let instructions = preloader_instructions(
        set_dll_directory_fn,
        set_dll_directory_arg,
        load_library_fn,
        load_library_arg,
    );
    let block = InstructionBlock::new(&instructions, 0);
    Ok(BlockEncoder::encode(64, block, BlockEncoderOptions::NONE)
        .map_err(anyhow::Error::msg)?
        .code_buffer)
}

pub fn inject_dll_into_process(
    process: &Process,
    search_path: Option<impl AsRef<Path>>,
    dll_path: impl AsRef<Path>,
) -> anyhow::Result<()> {
    let modules: Vec<Module> = process.modules()?.collect();
    let mut modules = modules.iter();
    let kernel32 = modules.try_find_module("KERNEL32.DLL")?.ok_or_else(|| {
        anyhow::anyhow!("Couldn't find the KERNEL32.DLL library in the targeted process")
    })?;

    let set_dll_directory_addr = kernel32.proc_address("SetDllDirectoryW")?;
    let set_dll_directory_fn =
        unsafe { transmute::<FARPROC, SetDllDirectoryW>(set_dll_directory_addr) };
    let load_library_addr = kernel32.proc_address("LoadLibraryW")?;
    let load_library_fn = unsafe { transmute::<FARPROC, LoadLibraryW>(load_library_addr) };

    let search_path: Option<Vec<u16>> = search_path.map(|p| {
        p.as_ref()
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect()
    });
    let search_path = match search_path {
        Some(p) => unsafe {
            Some(std::slice::from_raw_parts(
                p.as_ptr() as *const u8,
                p.len() * 2,
            ))
        },
        None => None,
    };
    let search_path_len = search_path.map_or(0, |p| p.len());

    let dll_path: Vec<u16> = dll_path
        .as_ref()
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let dll_path =
        unsafe { std::slice::from_raw_parts(dll_path.as_ptr() as *const u8, dll_path.len() * 2) };

    let region = process.virtual_alloc(
        std::ptr::null_mut::<c_void>(),
        search_path_len + dll_path.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    )?;
    let stream = process.memory_stream(&region)?;
    let mut buf_writer = BufWriter::new(stream);
    if let Some(buffer) = search_path {
        buf_writer.write_all(buffer)?;
    }
    buf_writer.write_all(dll_path)?;
    buf_writer.flush()?;

    let search_path_addr = search_path.map_or(std::ptr::null::<WCHAR>(), |p| {
        region.start_address() as LPCWSTR
    });
    let dll_path_addr = (region.start_address() + search_path_len) as LPCWSTR;

    let bytecode = preloader_bytecode(
        set_dll_directory_fn,
        search_path_addr as u64,
        load_library_fn,
        dll_path_addr as u64,
    )?;
    let region = process.virtual_alloc(
        std::ptr::null_mut::<c_void>(),
        bytecode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READ,
    )?;
    let mut stream = process.memory_stream(&region)?;
    stream.write_all(&bytecode)?;
    stream.flush()?;

    let start_routine_fn =
        unsafe { transmute::<usize, LPTHREAD_START_ROUTINE>(region.start_address()) };
    let thread =
        process.create_thread(None, 0, start_routine_fn, std::ptr::null_mut::<c_void>(), 0)?;
    thread.wait(Duration::from_secs(10))?;
    thread.exit_code().map_or_else(
        |e| Err(anyhow::Error::new(e)),
        |code| {
            if code != 0 {
                Err(anyhow::anyhow!(
                    "thread terminated with error code {}",
                    code
                ))
            } else {
                Ok(())
            }
        },
    )
}
