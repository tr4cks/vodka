#![feature(maybe_uninit_ref)]

use std::path::Path;

use tempfile::tempdir;
use winapi::um::winnt::PROCESS_ALL_ACCESS;

mod asset;
mod inject;
mod system;

use asset::unzip_python_library;
use inject::inject_dll_into_process;
use system::Process;

fn main() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let bundle = unzip_python_library(&dir)?;
    let process = Process::current(PROCESS_ALL_ACCESS)?;
    inject_dll_into_process(&process, Option::<&Path>::None, bundle.library)?;
    Ok(())
}
