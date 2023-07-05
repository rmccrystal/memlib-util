#![feature(decl_macro)]

use std::any;
use std::borrow::Cow;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::string::{FromUtf16Error, FromUtf8Error};
use memlib::{MemoryRead, MemoryReadExt, MemoryWriteExt};

#[allow(non_camel_case_types)]
pub type umem = u32;

#[derive(Debug)]
pub enum Error {
    /// A memory address could not be read or written
    InvalidAddress {
        /// The base address of the address that could not be read or written
        base: umem,
        /// The offset, if any, from the base address that could not be read or written
        offset: u64,
    },
    /// A pointer could not be dereferenced. The pointer was successfully read, but the address the pointer points to is invalid
    DerefFailed {
        /// The base address of the address that could not be read or written
        base: umem,
        /// The value that was read
        deref: umem,
    },
    /// A pointer was successfully created but upon reading the pointer the memory address is no longer valid
    InvalidPointer {
        /// The address that could not be read
        deref: umem,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn log_error(self, err: impl std::fmt::Display) -> Self {
        log::error!("{}: {:#X?}", err, self);
        self
    }

    pub fn log_warn(self, err: impl std::fmt::Display) -> Self {
        log::warn!("{}: {:#X?}", err, self);
        self
    }

    pub fn log_info(self, err: impl std::fmt::Display) -> Self {
        log::info!("{}: {:#X?}", err, self);
        self
    }

    pub fn log_debug(self, err: impl std::fmt::Display) -> Self {
        log::debug!("{}: {:#X?}", err, self);
        self
    }

    pub fn log_trace(self, err: impl std::fmt::Display) -> Self {
        log::trace!("{}: {:#X?}", err, self);
        self
    }
}

pub trait Object {
    /// The base address of the object in memory
    fn base(&self) -> umem;

    /// An optional name of the object type
    fn object_name() -> Option<Cow<'static, str>> {
        None
    }

    /// Returns a debug string for the object
    fn debug(&self) -> String {
        if let Some(name) = Self::object_name() {
            format!("{}({:#x})", name, self.base())
        } else {
            format!("{:#x}", self.base())
        }
    }
}

pub trait ObjectExt: Object {
    /// Validates that the object base address is still mapped in memory
    fn valid(&self, memory: &impl memlib::MemoryRead) -> bool {
        memory.valid_address(self.base() as u64)
    }

    fn read_object(&self, memory: &impl memlib::MemoryRead, offset: u64) -> Result<BaseObject> {
        self.read_object_as(memory, offset)
    }

    fn read_object_as<T: FromAddress>(&self, memory: &impl memlib::MemoryRead, offset: u64) -> Result<T> {
        T::from_address(memory, self.read_offset::<umem>(memory, offset))
    }

    /// Reads an arbitrary type from the object's base address + offset
    fn try_read_offset<T: memlib::Pod>(&self, memory: &impl memlib::MemoryRead, offset: u64) -> crate::Result<T> {
        memory.try_read::<T>(self.base() as u64 + offset).ok_or(Error::InvalidAddress { base: self.base(), offset })
            .map_err(|e| e.log_error(format!("Failed to read offset {:#X} from {}", offset, self.debug())))
    }

    /// Reads an arbitrary type from the object's base address + offset; panics if the read fails
    fn read_offset<T: memlib::Pod>(&self, memory: &impl memlib::MemoryRead, offset: u64) -> T {
        self.try_read_offset(memory, offset).unwrap()
    }

    /// Writes an arbitrary type to the object's base address + offset
    fn try_write_offset<T: memlib::Pod>(&self, memory: &impl memlib::MemoryWrite, offset: u64, value: &T) -> crate::Result<()> {
        memory.try_write(self.base() as u64 + offset, value).ok_or(Error::InvalidAddress { base: self.base(), offset })
            .map_err(|e| e.log_error(format!("Failed to write offset {:#X} to {}", offset, self.debug())))
    }

    /// Writes an arbitrary type to the object's base address + offset; panics if the write fails
    fn write_offset<T: memlib::Pod>(&self, memory: &impl memlib::MemoryWrite, offset: u64, value: &T) {
        self.try_write_offset(memory, offset, value).unwrap()
    }

    fn get_offset<T: FromAddress>(&self, memory: &impl memlib::MemoryRead, offset: u64) -> Result<T> {
        T::from_address(memory, (self.base() as u64 + offset) as umem)
    }

    /// Casts the object to another Object type
    fn cast<T: Object + FromAddress>(&self) -> T {
        T::from_address_unchecked(self.base())
    }
}

impl<T: Object> ObjectExt for T {}

/// A type that can be constructed from a base address in process memory
pub trait FromAddress: Sized + Object {
    /// Constructs the type from a base address in process memory, validating that the address is valid
    fn from_address(memory: &impl memlib::MemoryRead, base: umem) -> Result<Self> {
        if memory.valid_address(base as u64) {
            Ok(Self::from_address_unchecked(base))
        } else {
            Err(Error::InvalidAddress { base, offset: 0 })
                .map_err(|e| e.log_error(format!("Failed to create {} from invalid address {:#X}", Self::object_name().unwrap_or(Cow::Borrowed("(unknown)")), base)))
        }
    }

    /// Constructs the type from a base address in process memory without validating that the address is valid
    fn from_address_unchecked(base: umem) -> Self;
}

/// A pointer to a type in memory. This will store an already dereferenced address which is read on creation.
/// It is up to the user to ensure the pointer is still valid
#[repr(C)]
pub struct Pointer<T: ?Sized> {
    deref: umem,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: ?Sized> Pointer<T> {
    /// Creates a new pointer with the specified dereferenced value
    pub fn new(deref: umem) -> Self {
        Self {
            deref,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T> Pointer<T> {
    /// Indexes the pointer by the specified number of elements, returning a new pointer
    pub fn index(&self, idx: u32) -> Self {
        Self {
            deref: self.deref + idx as umem * std::mem::size_of::<T>() as umem,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: ?Sized> Clone for Pointer<T> {
    fn clone(&self) -> Self {
        Pointer {
            deref: self.deref,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T> Debug for Pointer<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pointer<{}> -> {:#X}", any::type_name::<T>(), self.deref)
    }
}

unsafe impl<T: ?Sized + 'static> memlib::Pod for Pointer<T> {}

impl<T: ?Sized> Pointer<T> {
    pub fn offset(&self, offset: u64) -> Self {
        Self { deref: self.deref + offset as umem, _phantom: PhantomData::default() }
    }

    pub fn is_null(&self) -> bool {
        self.deref == 0
    }
}

impl<T: memlib::Pod> Pointer<T> {
    /// Reads a POD type from the pointer's dereferenced address
    pub fn read(&self, memory: &impl memlib::MemoryRead) -> Result<T> {
        memory.try_read(self.deref as u64).ok_or(Error::InvalidPointer { deref: self.deref })
    }
}

impl<T: FromAddress + ?Sized> Pointer<T> {
    /// Creates a new FromAddress type from the pointer's dereferenced address
    pub fn deref(&self, memory: &impl memlib::MemoryRead) -> Result<T> {
        T::from_address(memory, self.deref)
    }
}

impl Pointer<u8> {
    /// Reads a string from the pointer's dereferenced address
    pub fn read_string(&self, memory: &impl memlib::MemoryRead) -> Result<std::result::Result<String, FromUtf8Error>> {
        memory.try_read_string(self.deref as u64).ok_or(Error::InvalidPointer { deref: self.deref })
    }
}

impl Pointer<u16> {
    /// Reads a wide string from the pointer's dereferenced address
    pub fn read_string(&self, memory: &impl memlib::MemoryRead) -> Result<std::result::Result<String, FromUtf16Error>> {
        memory.try_read_string_wide(self.deref as u64).ok_or(Error::InvalidPointer { deref: self.deref })
    }
}

pub type PointerObject<T> = BaseObject<Pointer<T>>;

impl<T: FromAddress + 'static> PointerObject<T> {
    pub fn deref(&self, memory: &impl memlib::MemoryRead) -> Result<T> {
        self.read(memory)?.deref(memory)
    }
}

// /// A type that implements Iter for
// pub struct MemoryIter<T> {
//     buf: Pointer<T>,
//     len: usize,
//     n: usize,
// }

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct BaseObject<T = ()> {
    base: umem,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Object for BaseObject<T> {
    fn base(&self) -> umem {
        self.base
    }

    fn object_name() -> Option<Cow<'static, str>> {
        let type_name = std::any::type_name::<T>();
        if type_name == "()" {
            Some("BaseObject".into())
        } else {
            Some(format!("BaseObject<{}>", type_name).into())
        }
    }
}

impl<T> std::fmt::Debug for BaseObject<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BaseObject<{}>({:#X})", any::type_name::<T>(), self.base)
    }
}

impl<T: memlib::Pod> BaseObject<T> {
    pub fn read(&self, memory: &impl memlib::MemoryRead) -> Result<T> {
        memory.try_read(self.base as u64).ok_or(Error::InvalidAddress { base: self.base, offset: 0 })
            .map_err(|e| e.log_error(format!("Failed to read BaseObject<{}>", any::type_name::<T>())))
    }
}

impl<T> FromAddress for BaseObject<T> {
    fn from_address_unchecked(base: umem) -> Self {
        Self { base, _phantom: PhantomData }
    }
}

pub macro object {
// ($derived:ident) => {
//     $crate::object!($derived, $crate::BaseObject);
// },
($derived:ident, $base:ty) => {
        pub struct $derived($base);

        impl Object for $derived {
            fn base(&self) -> umem {
                self.0.base()
            }

            fn object_name() -> Option<std::borrow::Cow<'static, str>> {
                let parent = <$base>::object_name();
                if let Some(parent) = parent {
                    Some(format!("{}->{}", parent, stringify!($derived)).into())
                } else {
                    Some(stringify!($derived).into())
                }
            }
        }

        impl FromAddress for $derived {
            fn from_address_unchecked(base: umem) -> Self {
                Self(<$base>::from_address_unchecked(base))
            }
        }

        impl core::ops::Deref for $derived {
            type Target = $base;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl core::ops::DerefMut for $derived {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    },
}

// pub struct DerivedObject(BaseObject);
//
// impl Object for DerivedObject {
//     fn base(&self) -> umem {
//         self.0.base()
//     }
//
//     fn object_name() -> Option<&'static str> {
//         Some("DerivedObject")
//     }
// }
//
// impl FromAddress for DerivedObject {
//     fn from_address_unchecked(memory: &impl memlib::MemoryRead, base: umem) -> Result<Self> {
//         BaseObject::from_address_unchecked(memory, base).map(Self)
//     }
// }
//
// impl core::ops::Deref for DerivedObject {
//     type Target = BaseObject;
//
//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }
//
// impl core::ops::DerefMut for DerivedObject {
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         &mut self.0
//     }
// }
//
// unsafe impl memlib::Pod for DerivedObject {}