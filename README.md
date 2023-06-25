# jit-allocator

A simple memory allocator for executable code. Use `JitAllocator` type to allocate/release memory and `virtual_memory` module functions to enable proper access for executable code. So if you want to allocate a new code to execute it is usually done like this:

```rust
use jit_allocator::*;
let compiled_code = ...;
let compiled_code_size = ...;

let mut jit_allocator = JitAllocator::new(Default::default());
let (rx, rw) = jit_allocator.alloc(size)?;

protect_jit_memory(ProtectJitAccess::ReadWrite); // allows to write to RWX code in current thread,
                                                 // it is no-op on all platforms except macOS AArch64
unsafe { copy_nonoverlapping(compiled_code, rw, compiled_code_size);  }
protect_jit_memory(ProtectJitAccess::ReadExecute); // disables writes to RWX code in current thread, 
                                                   // it is no-op on all platforms except macOS AArch64
flush_instruction_cache(rx, compiled_code_size); // flush icache, not required on x86-64 
                                                 // but required on other platforms due 
                                                 // to lack of coherent dcache/icache.

// When you're done with your machine code you can release it:
unsafe { 
    jit_allocator.release(rx)?;
}
```