

use jit_allocator::{allocator::JitAllocator, virtual_memory::{protect_jit_memory, ProtectJitAccess, flush_instruction_cache}};
use macroassembler::{assembler::*, jit::gpr_info::{ARGUMENT_GPR1, ARGUMENT_GPR0, RETURN_VALUE_GPR}};

fn main() {
    let mut asm = TargetAssembler::new();

    asm.push_r(TargetMacroAssembler::FRAME_POINTER_REGISTER);
    asm.movq_rr(TargetMacroAssembler::STACK_POINTER_REGISTER, TargetMacroAssembler::FRAME_POINTER_REGISTER);

    asm.addq_rr(ARGUMENT_GPR1, ARGUMENT_GPR0);
    asm.movq_rr(ARGUMENT_GPR0, RETURN_VALUE_GPR);

    asm.pop_r(TargetMacroAssembler::FRAME_POINTER_REGISTER);
    asm.ret();

    let mut alloc = JitAllocator::new(Default::default());

    let (rx, rw) = alloc.alloc(asm.buffer().data().len()).unwrap();

    unsafe {
        // enable write access to the memory for current thread
        protect_jit_memory(ProtectJitAccess::ReadWrite);
        std::ptr::copy_nonoverlapping(asm.buffer().data().as_ptr(), rw, asm.buffer().data().len());
        // disable write access to the memory for current thread
        protect_jit_memory(ProtectJitAccess::ReadExecute);
        // flush icache. This is required on some platforms where DCACHE and ICACHE are not coherent
        flush_instruction_cache(rx, asm.buffer().data().len());
    }

    let f: extern "C" fn(u64, u64) -> u64 = unsafe { std::mem::transmute(rx) };

    println!("f(1, 2) = {}", f(1, 2));

    alloc.release(rx).unwrap();
}

