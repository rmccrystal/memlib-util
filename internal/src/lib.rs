use memlib::Module;
use windows::Win32::System::Memory::{IsBadReadPtr, IsBadWritePtr};
use windows::Win32::System::Threading::GetCurrentProcessId;

/// An implementation of memlib traits for dealing with memory internally.
pub struct Internal;

fn is_bad_read<T>(ptr: *const T) -> bool {
    ptr as usize == 0 || unsafe { IsBadReadPtr(Some(ptr as _), std::mem::size_of::<T>()) }.as_bool()
}

fn is_bad_write<T>(ptr: *const T) -> bool {
    ptr as usize == 0 || unsafe { IsBadWritePtr(Some(ptr as _), std::mem::size_of::<T>()) }.as_bool()
}

impl memlib::MemoryRead for Internal {
    fn try_read_bytes_into(&self, address: u64, buffer: &mut [u8]) -> Option<()> {
        if is_bad_read(address as *const u8) {
            return None;
        }
        // Copy bytes from `address` into `buffer
        unsafe {
            std::ptr::copy_nonoverlapping(address as *const u8, buffer.as_mut_ptr(), buffer.len());
            Some(())
        }
    }
}

impl memlib::MemoryWrite for Internal {
    fn try_write_bytes(&self, address: u64, buffer: &[u8]) -> Option<()> {
        if is_bad_write(address as *const u8) {
            return None;
        }
        // Copy bytes from `buffer` into `address`
        unsafe {
            std::ptr::copy_nonoverlapping(buffer.as_ptr(), address as *mut u8, buffer.len());
            Some(())
        }
    }
}

impl memlib::ModuleList for Internal {
    fn get_module_list(&self) -> Vec<Module> {
        winutil::get_module_list(&self).unwrap()
    }

    fn get_main_module(&self) -> Module {
        self.get_module_list().get(0).unwrap().clone()
    }
}

impl memlib::ProcessInfo for Internal {
    fn process_name(&self) -> String {
        // TODO
        "".into()
    }

    #[cfg(target_pointer_width = "64")]
    fn peb_base_address(&self) -> u64 {
        // Get peb
        // mov     rax, gs:60h
        let peb: u64;
        unsafe {
            std::arch::asm!("mov {}, gs:0x60", out(reg) peb);
        }
        peb
    }

    #[cfg(target_pointer_width = "32")]
    fn peb_base_address(&self) -> u32 {
        // Get peb
        // mov     eax, fs:30h
        let peb: u32;
        unsafe {
            std::arch::asm!("mov {}, fs:0x30", out(reg) peb);
        }
        peb
    }

    fn pid(&self) -> u32 {
        unsafe { GetCurrentProcessId() }
    }
}

#[cfg(test)]
mod tests {
    use memlib::{MemoryReadExt, MemoryWriteExt, ModuleList};

    #[test]
    fn test_read() {
        let mem = super::Internal;
        let num: u32 = 1234;
        let result: u32 = mem.read(&num as *const u32 as u64);
        assert_eq!(result, 1234);
    }

    #[test]
    fn test_write() {
        let mem = super::Internal;
        let mut num: u32 = 1234;
        mem.write(&mut num as *mut u32 as u64, &4321);
        assert_eq!(num, 4321);
    }

    #[test]
    fn test_modules() {
        let mem = super::Internal;
        let modules = mem.get_module_list();
        dbg!(&modules);
        assert!(!modules.is_empty());
    }
}