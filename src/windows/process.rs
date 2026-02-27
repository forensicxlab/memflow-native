use memflow::cglue;
use memflow::os::process::*;
use memflow::prelude::v1::*;
use memflow::types::gap_remover::GapRemover;

use super::{conv_err, ProcessVirtualMemory};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

use windows::Win32::Foundation::{HINSTANCE, HMODULE, STILL_ACTIVE};

use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_FREE, MEM_RESERVE, PAGE_EXECUTE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOPY,
};

use windows::Win32::System::ProcessStatus::{
    K32EnumProcessModulesEx, K32GetModuleFileNameExA, K32GetModuleInformation, LIST_MODULES_32BIT,
    LIST_MODULES_64BIT,
};

use core::mem::size_of;

#[derive(Clone)]
pub struct WindowsProcess {
    virt_mem: ProcessVirtualMemory,
    info: ProcessInfo,
    cached_modules: Vec<HMODULE>,
}
unsafe impl Send for WindowsProcess {}
unsafe impl Sync for WindowsProcess {}

impl WindowsProcess {
    pub fn try_new(info: ProcessInfo) -> Result<Self> {
        Ok(Self {
            virt_mem: ProcessVirtualMemory::try_new(&info)?,
            info,
            cached_modules: vec![],
        })
    }

    fn process_exists(&self) -> bool {
        let pid = Pid::from_u32(self.info.pid);
        let mut system = System::new_with_specifics(
            RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
        );
        system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
        system.process(pid).is_some()
    }

    fn collect_envars(&self) -> Result<Vec<EnvVarInfo>> {
        let pid = Pid::from_u32(self.info.pid);
        let mut system = System::new_with_specifics(
            RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
        );
        system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
        let proc = system
            .process(pid)
            .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::EnvarNotFound))?;

        let mut out = Vec::new();
        for entry in proc.environ() {
            let s = entry.to_string_lossy().into_owned();
            if let Some((name, value)) = s.split_once('=') {
                out.push(EnvVarInfo {
                    name: ReprCString::from(name),
                    value: ReprCString::from(value),
                    address: Address::NULL,
                    arch: self.info.proc_arch,
                });
            }
        }

        Ok(out)
    }
}

cglue_impl_group!(WindowsProcess, ProcessInstance, {});
cglue_impl_group!(WindowsProcess, IntoProcessInstance, {});

impl Process for WindowsProcess {
    /// Retrieves the state of the process
    fn state(&mut self) -> ProcessState {
        if self.process_exists() {
            ProcessState::Alive
        } else {
            ProcessState::Dead(STILL_ACTIVE.0)
        }
    }

    /// Changes the dtb this process uses for memory translations.
    /// This function serves no purpose in memflow-native.
    fn set_dtb(&mut self, _dtb1: Address, _dtb2: Address) -> Result<()> {
        Ok(())
    }

    /// Walks the process' module list and calls the provided callback for each module structure
    /// address
    ///
    /// # Arguments
    /// * `target_arch` - sets which architecture to retrieve the modules for (if emulated). Choose
    /// between `Some(ProcessInfo::sys_arch())`, and `Some(ProcessInfo::proc_arch())`. `None` for all.
    /// * `callback` - where to pass each matching module to. This is an opaque callback.
    fn module_address_list_callback(
        &mut self,
        target_arch: Option<&ArchitectureIdent>,
        mut callback: ModuleAddressCallback,
    ) -> Result<()> {
        let filter_flags = match target_arch {
            Some(ident) => match ident.into_obj().bits() {
                32 => [Some(LIST_MODULES_32BIT), None],
                64 => [Some(LIST_MODULES_64BIT), None],
                _ => [Some(LIST_MODULES_32BIT), Some(LIST_MODULES_64BIT)],
            },
            None => [Some(LIST_MODULES_32BIT), Some(LIST_MODULES_64BIT)],
        };

        for f in IntoIterator::into_iter(filter_flags).flatten() {
            self.cached_modules.clear();
            self.cached_modules.resize(1024, HMODULE::default());

            let mut needed = 0;

            loop {
                unsafe {
                    K32EnumProcessModulesEx(
                        **self.virt_mem.handle,
                        self.cached_modules.as_mut_ptr(),
                        (self.cached_modules.len() * size_of::<HMODULE>()) as _,
                        &mut needed,
                        f.0,
                    )
                    .ok()
                    .map_err(conv_err)?
                }

                needed /= size_of::<HINSTANCE>() as u32;

                if needed as usize <= self.cached_modules.len() {
                    break;
                }

                self.cached_modules
                    .resize(self.cached_modules.len() * 2, HMODULE::default());
            }

            self.cached_modules.resize(needed as _, HMODULE::default());

            // TODO: ARM STUFF
            let arch = match f {
                LIST_MODULES_32BIT => ArchitectureIdent::X86(32, false),
                LIST_MODULES_64BIT => ArchitectureIdent::X86(64, false),
                _ => ArchitectureIdent::Unknown(0),
            };

            callback.extend(self.cached_modules.iter().map(|&m| ModuleAddressInfo {
                address: Address::from(m.0 as umem),
                arch,
            }));
        }

        Ok(())
    }

    /// Retrieves a module by its structure address and architecture
    ///
    /// # Arguments
    /// * `address` - address where module's information resides in
    /// * `architecture` - architecture of the module. Should be either `ProcessInfo::proc_arch`, or `ProcessInfo::sys_arch`.
    fn module_by_address(
        &mut self,
        address: Address,
        arch: ArchitectureIdent,
    ) -> Result<ModuleInfo> {
        let mut path = [0u8; 128];

        if unsafe {
            K32GetModuleFileNameExA(
                Some(**self.virt_mem.handle),
                Some(HMODULE(address.to_umem() as _)),
                &mut path,
            )
        } == 0
        {
            return Err(Error(ErrorOrigin::OsLayer, ErrorKind::Unknown));
        }

        let mut info = Default::default();

        unsafe {
            K32GetModuleInformation(
                **self.virt_mem.handle,
                HMODULE(address.to_umem() as _),
                &mut info,
                size_of_val(&info) as _,
            )
        }
        .ok()
        .map_err(conv_err)?;

        let path = String::from_utf8_lossy(&path);
        let path = &*path;
        let path = path.split_once('\0').map(|(i, _)| i).unwrap_or(path);
        let name = path.rsplit_once('\\').map(|(_, i)| i).unwrap_or(path);

        Ok(ModuleInfo {
            address,
            parent_process: self.info.address,
            arch,
            base: address,
            size: info.SizeOfImage as _,
            name: name.into(),
            path: path.into(),
        })
    }

    /// Retrieves address of the primary module structure of the process
    ///
    /// This will generally be for the initial executable that was run
    fn primary_module_address(&mut self) -> Result<Address> {
        let proc_arch = self.info.proc_arch;
        self.module_list_arch(Some(&proc_arch))
            .map_err(|_| Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))?
            .into_iter()
            .next()
            .map(|m| m.base)
            .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
    }

    fn module_import_list_callback(
        &mut self,
        info: &ModuleInfo,
        callback: ImportCallback,
    ) -> Result<()> {
        memflow::os::util::module_import_list_callback(&mut self.virt_mem, info, callback)
    }

    fn module_export_list_callback(
        &mut self,
        info: &ModuleInfo,
        callback: ExportCallback,
    ) -> Result<()> {
        memflow::os::util::module_export_list_callback(&mut self.virt_mem, info, callback)
    }

    fn module_section_list_callback(
        &mut self,
        info: &ModuleInfo,
        callback: SectionCallback,
    ) -> Result<()> {
        memflow::os::util::module_section_list_callback(&mut self.virt_mem, info, callback)
    }

    fn envar_list_callback(
        &mut self,
        target_arch: Option<&ArchitectureIdent>,
        mut callback: EnvVarCallback,
    ) -> Result<()> {
        if let Some(target_arch) = target_arch {
            if *target_arch != self.info.proc_arch {
                return Ok(());
            }
        }

        for ev in self.collect_envars()? {
            if !callback.call(ev) {
                break;
            }
        }

        Ok(())
    }

    fn environment_block_address(&mut self, _architecture: ArchitectureIdent) -> Result<Address> {
        Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotSupported))
    }

    fn envar_list_from_address(
        &mut self,
        _env_block: Address,
        architecture: ArchitectureIdent,
        mut callback: EnvVarCallback,
    ) -> Result<()> {
        if architecture != self.info.proc_arch {
            return Ok(());
        }

        for ev in self.collect_envars()? {
            if !callback.call(ev) {
                break;
            }
        }

        Ok(())
    }

    /// Retrieves the process info
    fn info(&self) -> &ProcessInfo {
        &self.info
    }

    fn mapped_mem_range(
        &mut self,
        gap_size: imem,
        start: Address,
        end: Address,
        out: MemoryRangeCallback,
    ) {
        let mut gap_remover = GapRemover::new(out, gap_size, start, end);

        let mut region = Default::default();

        let mut cur_addr = start;

        while unsafe {
            VirtualQueryEx(
                **self.virt_mem.handle,
                Some(cur_addr.to_umem() as *mut _),
                &mut region,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        } > 0
            && cur_addr < end
        {
            cur_addr = Address::from(
                (region.BaseAddress as umem).saturating_add(region.RegionSize as umem),
            );

            if region.State == MEM_FREE || region.State == MEM_RESERVE || region.RegionSize == 0 {
                continue;
            }

            let page_type = PageType::empty();

            let page_type = match region.Protect {
                PAGE_EXECUTE | PAGE_EXECUTE_READ => page_type.noexec(false),
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY => {
                    page_type.noexec(false).write(true)
                }
                PAGE_READWRITE | PAGE_WRITECOPY => page_type.write(true),
                PAGE_READONLY => page_type.write(false),
                _ => page_type,
            };

            let range = CTup3(
                Address::from(region.BaseAddress as umem),
                region.RegionSize as _,
                page_type,
            );

            gap_remover.push_range(range);
        }
    }
}

impl MemoryView for WindowsProcess {
    fn read_raw_iter(&mut self, data: ReadRawMemOps) -> Result<()> {
        self.virt_mem.read_raw_iter(data)
    }

    fn write_raw_iter(&mut self, data: WriteRawMemOps) -> Result<()> {
        self.virt_mem.write_raw_iter(data)
    }

    fn metadata(&self) -> MemoryViewMetadata {
        self.virt_mem.metadata()
    }
}
