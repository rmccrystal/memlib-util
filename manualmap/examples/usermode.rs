use std::time::Duration;
use memlib::ProcessAttach;
use manualmap::{Mapper, ModuleResolver};
use usermode::Usermode;

fn main() {
    pretty_env_logger::init();
    let usermode = Usermode::default();
    let proc = usermode.attach("Notepad.exe").unwrap();
    let mapper = Mapper::new(include_bytes!("MessageBox-64.dll").as_slice()).unwrap();
    let image = mapper.manualmap(&proc, ModuleResolver::new(&proc.clone())).unwrap();
    let exit = usermode.create_remote_thread(&proc.context, image.entry, None, Some(Duration::from_secs(1))).unwrap();
    dbg!(exit);
}