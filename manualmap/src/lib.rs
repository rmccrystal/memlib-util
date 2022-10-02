#![feature(let_else)]
extern crate core;

use std::iter;
use pelite::{Wrap};
use pelite::PeFile;
use pelite::image;
use memlib::*;
use pelite::pe32::imports::Import;

#[derive(Debug)]
pub enum Error {
    Pe(pelite::Error),
    Protect(memlib::MemoryProtectError),
    Allocate(memlib::MemoryAllocateError),
    Memory,
}

pub enum Bitness {
    Bit32,
    Bit64,
}

/// A type that can resolve a PE file's imports to an address.
/// Has default implementations for the unit type and a closure.
pub trait ResolveImport {
    fn resolve_import(&mut self, module: &str, name: &str) -> Option<u64>;
}

impl ResolveImport for () {
    fn resolve_import(&mut self, _module: &str, _name: &str) -> Option<u64> {
        None
    }
}

impl<T: Fn(&str, &str) -> Option<u64>> ResolveImport for T {
    fn resolve_import(&mut self, module: &str, name: &str) -> Option<u64> {
        self(module, name)
    }
}

pub struct ModuleResolver<'a, T: memlib::ModuleList + memlib::MemoryRead> {
    api: &'a T,
    modules: Vec<Module>,
}

impl<'a, T: memlib::ModuleList + memlib::MemoryRead> ModuleResolver<'a, T> {
    pub fn new(api: &'a T) -> Self {
        let modules = api.get_module_list();
        Self {
            api,
            modules,
        }
    }
}

impl<'a, T: memlib::ModuleList + memlib::MemoryRead> ResolveImport for ModuleResolver<'a, T> {
    fn resolve_import(&mut self, module_name: &str, name: &str) -> Option<u64> {
        let Some(module) = self.modules.iter().find(|m| m.name.to_lowercase() == module_name.to_lowercase()) else {
            log::warn!("Could not find module {module_name}");
            return None;
        };

        let Some(header) = self.api.try_read_bytes(module.base, module.size as _) else {
            log::warn!("Could not read header at {base}", base = module.base);
            return None;
        };

        let pe = match pelite::PeView::from_bytes(&header) {
            Ok(n) => n,
            Err(e) => {
                log::error!("Could not parse PE module: {:?}", e);
                return None;
            }
        };

        let export = match pe.get_export_by_name(name) {
            Ok(n) => n,
            Err(e) => {
                log::warn!("Could not find export {module_name}!{name}: {e:?}");
                return None;
            }
        };

        let Some(rva) = export.symbol() else {
            log::warn!("Could not find export symbol");
            return None;
        };

        Some(module.base + rva as u64)
    }
}

pub struct MappedImage {
    pub base: u64,
    pub size: u64,
    pub entry: u64,
    pub bitness: Bitness,
}

/// The main structure for manual mapping a PE file. Contains the parsed PE file given
pub struct Mapper<'a>(PeFile<'a>);

impl<'a> Mapper<'a> {
    /// Creates a new instance of Pe from a byte slice of the PE file. Returns an error if the PE file is invalid.
    pub fn new(image: &'a [u8]) -> Result<Self, Error> {
        PeFile::from_bytes(image).map_err(Error::Pe).map(Mapper)
    }

    /// Returns the inner instance of pelite::PeFile
    pub fn pe(&self) -> &PeFile {
        &self.0
    }

    pub fn bitness(&self) -> Bitness {
        match self.0 {
            Wrap::T32(_) => Bitness::Bit32,
            Wrap::T64(_) => Bitness::Bit64,
        }
    }

    /// Returns the number of bytes needed to be allocated in order to map the PE file
    pub fn image_len(&self) -> u64 {
        match self.0.optional_header() {
            Wrap::T32(n) => n.SizeOfImage as _,
            Wrap::T64(n) => n.SizeOfImage as _,
        }
    }

    /// Manually maps an image into memory. Will allocate memory, map the image to it, resolve imports to the image, adjust the memory protections,
    /// and return a structure containing information about the mapped image. If any part of the manual mapping is not successful, the memory will be freed.
    pub fn manualmap(&self, api: &(impl memlib::MemoryRead + memlib::MemoryWrite + memlib::MemoryAllocate + memlib::MemoryProtect), resolver: impl ResolveImport) -> Result<MappedImage, Error> {
        // Allocate memory
        let image_len = self.image_len();
        let base = api.allocate(image_len, MemoryProtection::READWRITE).map_err(Error::Allocate)?;
        log::trace!("Allocated {image_len:#X} bytes at {base:#X}");
        api.set_protection(base..base+image_len, MemoryProtection::EXECUTE_READWRITE).unwrap();

        // Map sections
        log::debug!("Mapping sections");
        self.map(api, base).map_err(|e| {
            let _ = api.free(base, image_len);
            e
        })?;

        // Resolve imports
        log::debug!("Resolving Imports");
        self.resolve_imports(api, resolver, base).map_err(|e| {
            let _ = api.free(base, image_len);
            e
        })?;

        // Adjust protections
        log::debug!("Adjusting page protections");
        self.adjust_protections(api, base).map_err(|e| {
            let _ = api.free(base, image_len);
            e
        })?;

        let entry = match self.pe().optional_header() {
            Wrap::T32(n) => n.AddressOfEntryPoint as u64,
            Wrap::T64(n) => n.AddressOfEntryPoint as u64,
        };

        // Return the mapped image
        Ok(MappedImage {
            base,
            size: image_len,
            entry: base + entry,
            bitness: self.bitness(),
        })
    }

    /// Maps sections from the dll into the process and solves relocations. Does not allocate or protect memory.
    pub fn map(&self, api: &(impl memlib::MemoryRead + memlib::MemoryWrite), base: u64) -> Result<(), Error> {
        let pe = self.0;

        // Map sections
        for section in pe.section_headers().iter() {
            if let Ok(".rsrc") | Ok(".reloc") | Ok(".idata") = section.name() {
                log::info!("Skipping section {}", section.name().unwrap());
                continue;
            }

            let section_buf = pe.get_section_bytes(&section).map_err(Error::Pe)?;
            api.try_write_bytes(base + section.VirtualAddress as u64, section_buf).ok_or(Error::Memory)?;
            log::trace!("Wrote {:#X} bytes of section {} to {:#X}", section_buf.len(), section.name().unwrap(), base + section.VirtualAddress as u64);
        }

        // Fix relocs
        let delta = base - match pe.optional_header() {
            Wrap::T32(n) => n.ImageBase as u64,
            Wrap::T64(n) => n.ImageBase as u64,
        };
        log::trace!("Reloc delta is {:#X}", delta);

        if let Ok(relocs) = pe.base_relocs() {
            for block in relocs.iter_blocks() {
                for word in block.words() {
                    let rva = block.rva_of(word);
                    let ty = block.type_of(word);

                    match pe {
                        Wrap::T64(_) => {
                            if let pelite::image::IMAGE_REL_BASED_DIR64 = ty {
                                let addr = base + rva as u64;
                                let original = api.try_read::<u64>(addr).ok_or(Error::Memory)?;
                                let fixed = original + delta;
                                api.try_write(addr, &fixed).ok_or(Error::Memory)?;
                            }
                        }
                        Wrap::T32(_) => {
                            if let pelite::image::IMAGE_REL_BASED_HIGHLOW = ty {
                                let addr = base + rva as u64;
                                let original = api.try_read::<u32>(addr).ok_or(Error::Memory)?;
                                let fixed = original + delta as u32;
                                api.try_write(addr, &fixed).ok_or(Error::Memory)?;
                            }
                        }
                    }
                }
            }
        } else {
            log::debug!("No relocations found");
        }


        Ok(())
    }

    /// Adjusts the protections of all sections in the dll.
    pub fn adjust_protections(&self, api: &impl memlib::MemoryProtect, base: u64) -> Result<(), Error> {
        let pe = self.0;

        for section in pe.section_headers().iter() {
            let protection = match (section.Characteristics & image::IMAGE_SCN_MEM_READ != 0,
                                    section.Characteristics & image::IMAGE_SCN_MEM_WRITE != 0,
                                    section.Characteristics & image::IMAGE_SCN_MEM_EXECUTE != 0) {
                (true, false, false) => MemoryProtection::READONLY,
                (true, true, false) => MemoryProtection::READWRITE,
                (true, false, true) => MemoryProtection::EXECUTE_READ,
                (true, true, true) => MemoryProtection::EXECUTE_READWRITE,
                _ => panic!("Invalid section protections")
            };

            let protect_base = base + section.VirtualAddress as u64;
            api.set_protection(protect_base..protect_base + section.VirtualSize as u64, protection).map_err(Error::Protect)?;
        }

        Ok(())
    }

    /// Resolves imports for a successfully mapped Pe file. Takes a user supplied function to resolve each import.
    pub fn resolve_imports(&self, api: &(impl memlib::MemoryRead + memlib::MemoryWrite), mut resolver: impl ResolveImport, base: u64) -> Result<(), Error> {
        for import in self.pe().imports().map_err(Error::Pe)? {
            let module = import.dll_name().map_err(Error::Pe)?.to_str().unwrap();
            log::trace!("Resolving imports for {}", module);

            let int = import
                .int()
                .map_err(Error::Pe)?
                .collect::<Vec<_>>();

            let iat = base + import.image().FirstThunk as u64;

            // We need to support 32 bit and 64 bit so use the correct pointer length
            let ptr_length = match self.bitness() {
                Bitness::Bit32 => 4,
                Bitness::Bit64 => 8,
            };

            let len = int.len();
            for (imp, dst) in iter::zip(int.into_iter(), (iat..).step_by(ptr_length).take(len)) {
                let imp = imp.map_err(Error::Pe)?;
                match imp {
                    Import::ByName { name, .. } => {
                        let name = name.to_str().unwrap();
                        log::trace!("Resolving {}!{}", module, name);
                        if let Some(addr) = resolver.resolve_import(module, name) {
                            api.try_write(dst, &addr).ok_or(Error::Memory)?;
                            log::trace!("Resolved {}!{} to {:#X}", module, name, addr);
                        } else {
                            log::warn!("Failed to resolve {}!{}", module, name);
                        }
                    }
                    Import::ByOrdinal { ord } => log::warn!("Did not resolve import with module {module} and ordinal {ord}"),
                }
            }
        }

        Ok(())
    }
}