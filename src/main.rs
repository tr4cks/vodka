use tempfile::tempdir;

mod asset;
mod system;

use system::Process;

fn main() -> anyhow::Result<()> {
    let dir = tempdir()?;
    asset::unzip_python_library(&dir)?;
    let process = Process::current()?;
    println!("Filename: {}", process.filename()?);
    for module in process.modules()? {
        let filename = module.filename()?;
        println!("Module: {}", filename);
        let info = module.info()?;
        println!(
            "{:x} {:x} {:x}",
            info.lpBaseOfDll as usize, info.SizeOfImage, info.EntryPoint as usize
        );
        if let Ok(addr) = module.proc_address("LoadLibraryA") {
            println!(
                "This module contains a function named LoadLibraryA at {:x}",
                addr as usize
            );
        }
    }
    Ok(())
}
