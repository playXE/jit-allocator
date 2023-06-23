use jit_allocator::virtual_memory::*;

fn main() {
    let dm = alloc_dual_mapping(64 * 1024, MemoryFlags::ACCESS_RWX.into()).unwrap();

    println!("allocated {:p} {:p}", dm.rw, dm.rx);
    unsafe {

        dm.rw.write(42);
        println!("{}", dm.rx.read());
    }


}