mod system;

use system::Process;

fn main() {
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
    }
}
