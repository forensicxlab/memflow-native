use memflow::os::process::*;
use memflow::prelude::v1::*;

use windows::core::PCSTR;
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};
use windows::Win32::Foundation::{
    CloseHandle, HANDLE, NTSTATUS, STATUS_ACCESS_DENIED, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS,
    STATUS_INVALID_PARAMETER, STATUS_NOT_IMPLEMENTED, STATUS_NO_MEMORY, STATUS_PRIVILEGE_NOT_HELD,
};

use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueA, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
};

use core::mem::{align_of, size_of};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

const SYSTEM_MODULE_INFORMATION_CLASS: SYSTEM_INFORMATION_CLASS = SYSTEM_INFORMATION_CLASS(11);
const MODULE_QUERY_INITIAL_CAPACITY: usize = 256 * 1024;
const MODULE_QUERY_MAX_RETRIES: usize = 6;

pub mod mem;
pub mod process;
pub use process::WindowsProcess;

pub mod keyboard;
pub use keyboard::{WindowsKeyboard, WindowsKeyboardState};

struct KernelModule {
    base: Address,
    size: umem,
    path: ReprCString,
    name: ReprCString,
}

#[repr(C)]
#[allow(non_snake_case)]
struct RtlProcessModuleInformation {
    Section: *mut core::ffi::c_void,
    MappedBase: *mut core::ffi::c_void,
    ImageBase: *mut core::ffi::c_void,
    ImageSize: u32,
    Flags: u32,
    LoadOrderIndex: u16,
    InitOrderIndex: u16,
    LoadCount: u16,
    OffsetToFileName: u16,
    FullPathName: [u8; 256],
}

pub(crate) struct Handle(HANDLE);

impl From<HANDLE> for Handle {
    fn from(handle: HANDLE) -> Handle {
        Handle(handle)
    }
}

impl core::ops::Deref for Handle {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) }.ok();
    }
}

pub fn conv_err(_err: windows::core::Error) -> Error {
    // TODO: proper error kind
    // TODO: proper origin
    Error(ErrorOrigin::OsLayer, ErrorKind::Unknown)
}

pub(crate) fn conv_ntstatus(status: NTSTATUS) -> Error {
    let kind = match status {
        STATUS_ACCESS_DENIED | STATUS_PRIVILEGE_NOT_HELD => ErrorKind::NotSupported,
        STATUS_INVALID_PARAMETER => ErrorKind::ArgValidation,
        STATUS_NOT_IMPLEMENTED | STATUS_INVALID_INFO_CLASS => ErrorKind::NotSupported,
        STATUS_INSUFFICIENT_RESOURCES | STATUS_NO_MEMORY => ErrorKind::Unknown,
        STATUS_INVALID_HANDLE => ErrorKind::ProcessNotFound,
        _ => ErrorKind::Unknown,
    };

    Error(ErrorOrigin::OsLayer, kind)
}

fn split_basename(path: &str) -> &str {
    path.rsplit_once('\\')
        .or_else(|| path.rsplit_once('/'))
        .map(|(_, name)| name)
        .unwrap_or(path)
}

fn parse_module_path(info: &RtlProcessModuleInformation) -> (ReprCString, ReprCString) {
    let path_end = info
        .FullPathName
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(info.FullPathName.len());

    let path_raw = &info.FullPathName[..path_end];
    let path = String::from_utf8_lossy(path_raw);
    let path = path.as_ref();

    let name = if (info.OffsetToFileName as usize) < path_end {
        let name_raw = &info.FullPathName[info.OffsetToFileName as usize..path_end];
        let parsed = String::from_utf8_lossy(name_raw);
        if parsed.is_empty() {
            split_basename(path).to_owned()
        } else {
            parsed.into_owned()
        }
    } else {
        split_basename(path).to_owned()
    };

    (path.into(), name.into())
}

unsafe fn enable_debug_privilege() -> Result<()> {
    let process = GetCurrentProcess();
    let mut token = HANDLE::default();

    OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES, &mut token).map_err(conv_err)?;

    let mut luid = Default::default();

    let mut se_debug_name = *b"SeDebugPrivilege\0";

    LookupPrivilegeValueA(
        PCSTR(core::ptr::null_mut()),
        PCSTR(se_debug_name.as_mut_ptr()),
        &mut luid,
    )
    .map_err(conv_err)?;

    let new_privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    AdjustTokenPrivileges(
        token,
        false,
        Some(&new_privileges),
        std::mem::size_of_val(&new_privileges) as _,
        None,
        None,
    )
    .map_err(conv_err)
}

pub struct WindowsOs {
    info: OsInfo,
}

impl WindowsOs {
    pub fn new(args: &OsArgs) -> Result<Self> {
        match args.extra_args.get("elevate_token") {
            Some("off") | Some("OFF") | Some("Off") | Some("n") | Some("N") | Some("0") => {}
            _ => {
                unsafe { enable_debug_privilege() }?;
            }
        }

        Ok(Default::default())
    }

    fn query_kernel_modules() -> Result<Vec<KernelModule>> {
        let mut buffer = vec![0u8; MODULE_QUERY_INITIAL_CAPACITY];

        for _ in 0..MODULE_QUERY_MAX_RETRIES {
            let mut return_len = 0u32;
            let status = unsafe {
                NtQuerySystemInformation(
                    SYSTEM_MODULE_INFORMATION_CLASS,
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    &mut return_len,
                )
            };

            if status == STATUS_INFO_LENGTH_MISMATCH {
                let table_off = align_of::<RtlProcessModuleInformation>();
                let next_len = usize::max(
                    buffer.len().saturating_mul(2),
                    (return_len as usize).saturating_add(table_off),
                );
                buffer.resize(next_len, 0);
                continue;
            }

            if status.is_err() {
                return Err(conv_ntstatus(status));
            }

            let valid_len = if return_len as usize > buffer.len() {
                buffer.len()
            } else {
                return_len as usize
            };

            let data = &buffer[..valid_len];
            let table_off = align_of::<RtlProcessModuleInformation>();

            if data.len() < table_off {
                return Err(Error(ErrorOrigin::OsLayer, ErrorKind::Unknown));
            }

            let mut header_buf = [0u8; core::mem::size_of::<u32>()];
            header_buf.copy_from_slice(&data[..core::mem::size_of::<u32>()]);
            let header_number = u32::from_ne_bytes(header_buf);
            let entry_size = core::mem::size_of::<RtlProcessModuleInformation>();
            let entries_len = header_number as usize;
            let table_len = entries_len
                .checked_mul(entry_size)
                .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::Unknown))?;
            let table_end = table_off
                .checked_add(table_len)
                .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::Unknown))?;

            if table_end > data.len() {
                return Err(Error(ErrorOrigin::OsLayer, ErrorKind::ArgValidation));
            }

            let mut parsed = Vec::with_capacity(entries_len);
            for idx in 0..entries_len {
                let module_off = table_off + idx * entry_size;
                let module = unsafe {
                    (data.as_ptr().add(module_off) as *const RtlProcessModuleInformation)
                        .read_unaligned()
                };
                let (path, name) = parse_module_path(&module);
                parsed.push(KernelModule {
                    base: Address::from(module.ImageBase as umem),
                    size: module.ImageSize as umem,
                    path,
                    name,
                });
            }

            return Ok(parsed);
        }

        Err(Error(ErrorOrigin::OsLayer, ErrorKind::Unknown))
    }
}

impl Clone for WindowsOs {
    fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
        }
    }
}

impl Default for WindowsOs {
    fn default() -> Self {
        let info = OsInfo {
            base: Address::NULL,
            size: 0,
            arch: ArchitectureIdent::X86(64, false),
        };

        Self { info }
    }
}

impl Os for WindowsOs {
    type ProcessType<'a> = WindowsProcess;
    type IntoProcessType = WindowsProcess;

    /// Walks a process list and calls a callback for each process structure address
    ///
    /// The callback is fully opaque. We need this style so that C FFI can work seamlessly.
    fn process_address_list_callback(&mut self, mut callback: AddressCallback) -> Result<()> {
        let handle =
            Handle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(conv_err)?);

        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        if unsafe { Process32FirstW(*handle, &mut entry) }.is_err() {
            return Ok(());
        }

        loop {
            if !callback.call(Address::from(entry.th32ProcessID as umem)) {
                break;
            }

            if unsafe { Process32NextW(*handle, &mut entry) }.is_err() {
                break;
            }
        }

        Ok(())
    }

    /// Find process information by its internal address
    fn process_info_by_address(&mut self, address: Address) -> Result<ProcessInfo> {
        let pid = address.to_umem() as Pid;
        let handle =
            Handle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(conv_err)?);

        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        if unsafe { Process32FirstW(*handle, &mut entry) }.is_err() {
            return Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound));
        }

        loop {
            if entry.th32ProcessID as Pid == pid {
                let len = entry.szExeFile.iter().take_while(|&&c| c != 0).count();

                let path = OsString::from_wide(&entry.szExeFile[..len]);
                let path = path.to_string_lossy();
                let path = &*path;
                let name = path.rsplit_once('\\').map(|(_, end)| end).unwrap_or(path);

                return Ok(ProcessInfo {
                    address,
                    pid,
                    state: ProcessState::Alive,
                    name: name.into(),
                    path: path.into(),
                    command_line: "".into(),
                    sys_arch: self.info.arch,
                    proc_arch: self.info.arch,
                    // dtb is not known/used here
                    dtb1: Address::invalid(),
                    dtb2: Address::invalid(),
                });
            }

            if unsafe { Process32NextW(*handle, &mut entry) }.is_err() {
                break;
            }
        }

        Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
    }

    /// Construct a process by its info, borrowing the OS
    ///
    /// It will share the underlying memory resources
    fn process_by_info(&mut self, info: ProcessInfo) -> Result<Self::ProcessType<'_>> {
        WindowsProcess::try_new(info)
    }

    /// Construct a process by its info, consuming the OS
    ///
    /// This function will consume the Kernel instance and move its resources into the process
    fn into_process_by_info(mut self, info: ProcessInfo) -> Result<Self::IntoProcessType> {
        self.process_by_info(info)
    }

    /// Walks the OS module list and calls the provided callback for each module structure
    /// address
    ///
    /// # Arguments
    /// * `callback` - where to pass each matching module to. This is an opaque callback.
    fn module_address_list_callback(&mut self, mut callback: AddressCallback) -> Result<()> {
        Self::query_kernel_modules()?
            .into_iter()
            .map(|m| m.base)
            .take_while(|a| callback.call(*a))
            .for_each(|_| {});

        Ok(())
    }

    /// Retrieves a module by its structure address
    ///
    /// # Arguments
    /// * `address` - address where module's information resides in
    fn module_by_address(&mut self, address: Address) -> Result<ModuleInfo> {
        Self::query_kernel_modules()?
            .into_iter()
            .find(|km| km.base == address)
            .map(|km| ModuleInfo {
                address,
                size: km.size,
                base: km.base,
                name: km.name.clone(),
                arch: self.info.arch,
                path: km.path.clone(),
                parent_process: Address::INVALID,
            })
            .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
    }

    /// Retrieves address of the primary module structure of the process
    ///
    /// This will generally be for the initial executable that was run
    fn primary_module_address(&mut self) -> Result<Address> {
        Ok(self.module_by_name("ntoskrnl.exe")?.address)
    }

    /// Retrieves information for the primary module of the process
    ///
    /// This will generally be the initial executable that was run
    fn primary_module(&mut self) -> Result<ModuleInfo> {
        self.module_by_name("ntoskrnl.exe")
    }

    /// Retrieves a list of all imports of a given module
    fn module_import_list_callback(
        &mut self,
        _info: &ModuleInfo,
        _callback: ImportCallback,
    ) -> Result<()> {
        //memflow::os::util::module_import_list_callback(&mut self.virt_mem, info, callback)
        Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotImplemented))
    }

    /// Retrieves a list of all exports of a given module
    fn module_export_list_callback(
        &mut self,
        _info: &ModuleInfo,
        _callback: ExportCallback,
    ) -> Result<()> {
        //memflow::os::util::module_export_list_callback(&mut self.virt_mem, info, callback)
        Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotImplemented))
    }

    /// Retrieves a list of all sections of a given module
    fn module_section_list_callback(
        &mut self,
        _info: &ModuleInfo,
        _callback: SectionCallback,
    ) -> Result<()> {
        //memflow::os::util::module_section_list_callback(&mut self.virt_mem, info, callback)
        Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotImplemented))
    }

    /// Retrieves the OS info
    fn info(&self) -> &OsInfo {
        &self.info
    }
}

impl OsKeyboard for WindowsOs {
    type KeyboardType<'a> = WindowsKeyboard;
    type IntoKeyboardType = WindowsKeyboard;

    fn keyboard(&mut self) -> memflow::error::Result<Self::KeyboardType<'_>> {
        Ok(WindowsKeyboard::new())
    }

    fn into_keyboard(self) -> memflow::error::Result<Self::IntoKeyboardType> {
        Ok(WindowsKeyboard::new())
    }
}
