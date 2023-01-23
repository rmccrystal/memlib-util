use memlib::{ModuleList, ProcessAttachInto};

fn main() {
    let um = usermode::Usermode::default();
    let notepad = um.attach_into("csgo.exe").unwrap();
    dbg!(notepad.get_module_list());
}