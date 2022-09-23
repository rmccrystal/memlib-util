#![feature(generic_associated_types)]

use memlib::{AttachedProcess, Module};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, OpenProcess, PROCESS_ALL_ACCESS};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::UI::Input::KeyboardAndMouse::{INPUT, INPUT_0, INPUT_MOUSE, INPUT_TYPE, MOUSE_EVENT_FLAGS, MOUSEEVENTF_MOVE, MOUSEINPUT, SendInput};

pub struct Usermode;

#[derive(Copy, Clone)]
pub struct UsermodeProcess {
    pub handle: HANDLE,
    pub pid: u32,
}

impl memlib::GetContext for Usermode {
    type Context = UsermodeProcess;

    fn get_context_from_name(&self, process_name: &str) -> Option<Self::Context> {
        winutil::get_process_list().unwrap().into_iter()
            .find(|p| p.name == process_name)
            .and_then(|p| self.get_context_from_pid(p.pid))
    }

    fn get_context_from_pid(&self, pid: u32) -> Option<Self::Context> {
        unsafe {
            let handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid).ok()?;
            Some(UsermodeProcess { handle, pid })
        }
    }

    fn get_current_context(&self) -> Self::Context {
        unsafe {
            match GetCurrentProcess() {
                HANDLE(0) => panic!("GetCurrentProcess returned 0"),
                handle => UsermodeProcess { handle, pid: GetCurrentProcessId() },
            }
        }
    }
}

impl memlib::MemoryReadPid for Usermode {
    fn try_read_bytes_into_pid(&self, ctx: &Self::Context, address: u64, buffer: &mut [u8]) -> Option<()> {
        let mut bytes_read = 0;
        unsafe {
            ReadProcessMemory(
                ctx.handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                Some(&mut bytes_read),
            );
        }
        if bytes_read == buffer.len() {
            Some(())
        } else {
            None
        }
    }
}

impl memlib::MemoryWritePid for Usermode {
    fn try_write_bytes_pid(&self, ctx: &Self::Context, address: u64, buffer: &[u8]) -> Option<()> {
        let mut bytes_written = 0;
        unsafe {
            WriteProcessMemory(
                ctx.handle,
                address as *mut _,
                buffer.as_ptr() as *const _,
                buffer.len(),
                Some(&mut bytes_written),
            );
        }
        if bytes_written == buffer.len() {
            Some(())
        } else {
            None
        }
    }
}

impl memlib::ProcessInfoPid for Usermode {
    fn process_name(&self, pid: &Self::Context) -> String {
        todo!()
    }

    fn peb_base_address(&self, pid: &Self::Context) -> u64 {
        winutil::get_peb_base(pid.pid).unwrap()
    }

    fn pid(&self, pid: &Self::Context) -> u32 {
        pid.pid
    }
}

impl memlib::ModuleListPid for Usermode {
    fn get_module_list(&self, pid: &Self::Context) -> Vec<Module> {
        winutil::get_module_list(&AttachedProcess::new(self, *pid)).unwrap()
    }

    fn get_main_module(&self, pid: &Self::Context) -> Module {
        self.get_module_list(pid).into_iter().next().unwrap()
    }
}

impl memlib::MouseMove for Usermode {
    fn mouse_move(&self, dx: i32, dy: i32) {
        unsafe {
            // use SendInput to send mouse input
            let input = INPUT { r#type: INPUT_MOUSE, Anonymous: INPUT_0 { mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: 0,
                dwFlags: MOUSEEVENTF_MOVE,
                time: 0,
                dwExtraInfo: 0
            } } };
            SendInput(&[input], std::mem::size_of::<INPUT>() as _);
        }
    }
}