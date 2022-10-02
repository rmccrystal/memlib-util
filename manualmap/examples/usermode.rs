use memlib::ProcessAttach;
use manualmap::{Mapper, ModuleResolver};
use memlib_usermode::Usermode;

fn main() {
    pretty_env_logger::init();
    let usermode = Usermode::default();
    let proc = usermode.attach("Notepad.exe").unwrap();
    let mapper = Mapper::new(include_bytes!("hello-world-x64.dll").as_slice()).unwrap();
    let image = mapper.manualmap(&proc, ModuleResolver::new(&proc.clone())).unwrap();
    let exit = usermode.create_remote_thread(&proc.context, image.entry, None).unwrap();
    dbg!(exit);
}