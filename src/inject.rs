use std::convert::TryInto;

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register,
};
use winapi::shared::minwindef::{BOOL, HMODULE};
use winapi::um::winnt::LPCSTR;

pub type LoadLibraryA = unsafe extern "system" fn(lp_lib_file_name: LPCSTR) -> HMODULE;
pub type SetDllDirectoryA = unsafe extern "system" fn(lp_path_name: LPCSTR) -> BOOL;

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
/// typedef BOOL    (__stdcall *SetDllDirectoryA_repr)(LPCSTR lpPathName);
/// typedef HMODULE (__stdcall *LoadLibraryA_repr)(LPCSTR lpLibFileName);
///
/// DWORD __stdcall thread_start_routine(LPVOID lpThreadParameter) {
///     if (((SetDllDirectoryA_repr) ${set_dll_directory_fn})(${set_dll_directory_arg}) == 0) {
///         return 1;
///     }
///     if (((LoadLibraryA_repr) ${load_library_fn})(${load_library_arg}) == NULL) {
///         return 2;
///     }
///     return 0;
/// }
/// ```
#[rustfmt::skip]
fn preloader_instructions(
    set_dll_directory_fn: SetDllDirectoryA, set_dll_directory_arg: u64,
    load_library_fn: LoadLibraryA, load_library_arg: u64,
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

pub fn preloader_bytecode(
    set_dll_directory_fn: SetDllDirectoryA,
    set_dll_directory_arg: u64,
    load_library_fn: LoadLibraryA,
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
