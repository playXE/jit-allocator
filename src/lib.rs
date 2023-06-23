pub mod virtual_memory;
pub mod os;
pub mod allocator;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Error {
    InvalidState,
    OutOfMemory,
    TooManyHandles,
    InvalidArgument,
    FailedToOpenAnonymousMemory,
}
