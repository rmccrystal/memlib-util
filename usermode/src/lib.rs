#![feature(generic_associated_types)]

use std::mem;
use std::mem::MaybeUninit;
use std::time::Duration;
use memlib::{AttachedProcess, MemoryAllocateError, MemoryProtectError, MemoryProtection, MemoryRange, Module};
use windows::Win32::Foundation::{BOOL, CloseHandle, GetLastError, HANDLE};
use windows::Win32::System::Threading::{CreateRemoteThread, GetCurrentProcess, GetCurrentProcessId, GetExitCodeThread, LPTHREAD_START_ROUTINE, OpenProcess, PROCESS_ALL_ACCESS, WaitForSingleObject};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE, VirtualAlloc, VirtualAllocEx, VirtualFree, VirtualFreeEx, VirtualProtectEx};
use windows::Win32::UI::Input::KeyboardAndMouse::{INPUT, INPUT_0, INPUT_MOUSE, INPUT_TYPE, MOUSE_EVENT_FLAGS, MOUSEEVENTF_MOVE, MOUSEINPUT, SendInput};

#[derive(Default, Clone)]
pub struct Usermode;

impl Usermode {
    pub fn create_remote_thread(&self, pid: &Process, proc: u64, arg: Option<u64>, timeout: Option<Duration>) -> windows::core::Result<Option<u32>> {
        log::trace!("create_remote_thread({pid}): entry = {proc:#X}, arg = {arg:#X?}", pid=pid.pid);
        unsafe {
            let handle = CreateRemoteThread(pid.handle, None, 0, mem::transmute(proc as usize), arg.map(|n| n as _), 0, None)?;
            if let Some(timeout) = timeout {
                if WaitForSingleObject(handle, timeout.as_millis() as _).ok().is_err() {
                    return Ok(None)
                }
                let mut exit_code = 0;
                GetExitCodeThread(handle, &mut exit_code).ok()?;
                Ok(Some(exit_code))
            } else {
                Ok(None)
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Process {
    pub handle: HANDLE,
    pub pid: u32,
}

impl memlib::GetContext for Usermode {
    type Context = Process;

    fn get_context_from_name(&self, process_name: &str) -> Option<Self::Context> {
        winutil::get_process_list().unwrap().into_iter()
            .find(|p| p.name == process_name)
            .and_then(|p| self.get_context_from_pid(p.pid))
    }

    fn get_context_from_pid(&self, pid: u32) -> Option<Self::Context> {
        unsafe {
            let handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid).ok()?;
            Some(Process { handle, pid })
        }
    }

    fn get_current_context(&self) -> Self::Context {
        unsafe {
            match GetCurrentProcess() {
                HANDLE(0) => panic!("GetCurrentProcess returned 0"),
                handle => Process { handle, pid: GetCurrentProcessId() },
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

impl memlib::MemoryAllocatePid for Usermode {
    fn allocate_pid(&self, pid: &Self::Context, size: u64, protection: MemoryProtection) -> Result<u64, MemoryAllocateError> {
        log::trace!("allocate({pid}): size = {size:#X}, protection = {protection:?}", pid=pid.pid);
        unsafe {
            match VirtualAllocEx(Some(pid.handle), None, size as _, MEM_COMMIT | MEM_RESERVE, PAGE_PROTECTION_FLAGS(protection.bits())) as u64 {
                0 => Err(MemoryAllocateError::NtStatus(GetLastError().0)),
                n => Ok(n)
            }
        }
    }

    fn free_pid(&self, pid: &Self::Context, base: u64, size: u64) -> Result<(), MemoryAllocateError> {
        log::trace!("free({pid}): base = {base:#X}, size = {size:#X}", pid=pid.pid);
        unsafe {
            match VirtualFreeEx(pid.handle, base as _, size as _, MEM_RELEASE) {
                FALSE => Err(MemoryAllocateError::NtStatus(GetLastError().0)),
                TRUE => Ok(())
            }
        }
    }
}

impl memlib::MemoryProtectPid for Usermode {
    fn set_protection_pid(&self, pid: &Self::Context, range: MemoryRange, protection: MemoryProtection) -> Result<MemoryProtection, MemoryProtectError> {
        log::trace!("protect({pid}): range = {range:#X?}, protection = {protection:?}", pid=pid.pid);
        unsafe {
            let mut old_protection = MaybeUninit::<PAGE_PROTECTION_FLAGS>::uninit();
            match VirtualProtectEx(pid.handle, range.start as _, (range.end - range.start) as _, PAGE_PROTECTION_FLAGS(protection.bits()), old_protection.as_mut_ptr()).0 {
                0 => Err(MemoryProtectError::NtStatus(GetLastError().0)),
                1 => Ok(MemoryProtection::from_bits(old_protection.assume_init().0).unwrap()),
                _ => unreachable!(),
            }
        }
    }
}

impl memlib::MouseMove for Usermode {
    fn mouse_move(&self, dx: i32, dy: i32) {
        unsafe {
            // use SendInput to send mouse input
            let input = INPUT {
                r#type: INPUT_MOUSE,
                Anonymous: INPUT_0 {
                    mi: MOUSEINPUT {
                        dx,
                        dy,
                        mouseData: 0,
                        dwFlags: MOUSEEVENTF_MOVE,
                        time: 0,
                        dwExtraInfo: 0,
                    }
                },
            };
            SendInput(&[input], std::mem::size_of::<INPUT>() as _);
        }
    }
}