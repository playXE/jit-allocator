use jit_allocator::allocator::{JitAllocator, JitAllocatorOptions};
fn main() {
    let mut opts = JitAllocatorOptions::default();
    opts.use_dual_mapping = true;
    let mut alloc = JitAllocator::new(opts);

    let (rx, rw) = alloc.alloc(128).unwrap();

    println!("{:p} {:p}", rx, rw);

    unsafe {
        rw.write(0x42);
        assert_eq!(rx.read(), 0x42);
    }

    let (rx, rw) = alloc.alloc(128).unwrap();

    println!("{:p} {:p}", rx, rw);

    alloc.release(rx).unwrap();

    let (rx, rw) = alloc.alloc(128).unwrap();

    println!("{:p} {:p}", rx, rw);

    alloc.shrink(rx, 64).unwrap();

    let (rx, rw) = alloc.alloc(128).unwrap();

    println!("{:p} {:p}", rx, rw);
}
