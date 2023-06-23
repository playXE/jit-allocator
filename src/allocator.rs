pub struct JitAllocatorOptions {
    /// Enables the use of an anonymous memory-mapped memory that is mapped into two buffers having a different pointer.
    /// The first buffer has read and execute permissions and the second buffer has read+write permissions.
    ///
    /// See [alloc_dual_mapping](crate::virtual_memory::alloc_dual_mapping) for more details about this feature.
    ///
    /// ## Remarks
    ///
    /// Dual mapping would be automatically turned on by \ref JitAllocator in case of hardened runtime that
    /// enforces `W^X` policy, so specifying this flag is essentually forcing to use dual mapped pages even when RWX
    /// pages can be allocated and dual mapping is not necessary.
    pub use_dual_mapping: bool,
    /// Enables the use of multiple pools with increasing granularity instead of a single pool. This flag would enable
    /// 3 internal pools in total having 64, 128, and 256 bytes granularity.
    ///
    /// This feature is only recommended for users that generate a lot of code and would like to minimize the overhead
    /// of `JitAllocator` itself by having blocks of different allocation granularities. Using this feature only for
    /// few allocations won't pay off as the allocator may need to create more blocks initially before it can take the
    /// advantage of variable block granularity.
    pub use_multiple_pools: bool,
    /// Always fill reserved memory by a fill-pattern.
    ///
    /// Causes a new block to be cleared by the fill pattern and freshly released memory to be cleared before making
    /// it ready for another use.
    pub fill_unused_memory: bool,
    /// When this flag is set the allocator would immediately release unused blocks during `release()` or `reset()`.
    /// When this flag is not set the allocator would keep one empty block in each pool to prevent excessive virtual
    /// memory allocations and deallocations in border cases, which involve constantly allocating and deallocating a
    /// single block caused by repetitive calling `alloc()` and `release()` when the allocator has either no blocks
    /// or have all blocks fully occupied.
    pub immediate_release: bool,
    pub custom_fill_pattern: Option<u32>,
}

impl Default for JitAllocatorOptions {
    fn default() -> Self {
        Self {
            use_dual_mapping: true,
            use_multiple_pools: true,
            fill_unused_memory: true,
            immediate_release: false,
            custom_fill_pattern: None,
        }
    }
}
/// A simple implementation of memory manager that uses [virtual_memory](crate::virtual_memory).
/// functions to manage virtual memory for JIT compiled code.
///
/// Implementation notes:
///
/// - Granularity of allocated blocks is different than granularity for a typical C malloc. In addition, the allocator
///   can use several memory pools having a different granularity to minimize the maintenance overhead. Multiple pools
///   feature requires `kFlagUseMultiplePools` flag to be set.
///
/// - The allocator doesn't store any information in executable memory, instead, the implementation uses two
///   bit-vectors to manage allocated memory of each allocator-block. The first bit-vector called 'used' is used to
///   track used memory (where each bit represents memory size defined by granularity) and the second bit vector called
///   'stop' is used as a sentinel to mark where the allocated area ends.
///
/// - Internally, the allocator also uses RB tree to keep track of all blocks across all pools. Each inserted block is
///   added to the tree so it can be matched fast during `release()` and `shrink()`.
pub struct JitAllocator {
    options: JitAllocatorOptions,
    block_size: usize,
    granulariy: usize,
    fill_pattern: u32,
}