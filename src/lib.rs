//#![no_std]
extern crate alloc;

pub mod virtual_memory;
pub mod os;
pub mod allocator;
pub mod util;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Error {
    InvalidState,
    OutOfMemory,
    TooManyHandles,
    InvalidArgument,
    FailedToOpenAnonymousMemory,
    TooLarge,
}

pub use {
    virtual_memory::{
        protect_jit_memory, ProtectJitAccess,
        flush_instruction_cache
    },
    allocator::{JitAllocator, JitAllocatorOptions, ResetPolicy},
};
