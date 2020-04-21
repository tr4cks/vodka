use tempfile::tempdir;

mod asset;
mod system;

use system::Process;

fn main() {
    let dir = tempdir().unwrap();
    // TODO: I think I can do it better -> <P: AsRef<Path>>
    asset::unzip_python_library(dir.as_ref());

    let process = Process::current().unwrap();
    println!("Filename: {}", process.filename().unwrap());
    for module in process.modules().unwrap() {
        let filename = module.filename().unwrap();
        println!("Module: {}", filename);
        let info = module.info().unwrap();
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
}
