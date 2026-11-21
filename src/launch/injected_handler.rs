use std::mem::offset_of;
use std::ops::Range;
use std::time::Instant;

use iced_x86::IcedError;
use iced_x86::code_asm::{
    CodeAssembler, al, byte_ptr, dword_ptr, eax, ebx, ecx, edx, esi, esp, qword_ptr, r8, r9, r10,
    r10d, r11, r11d, rax, rbx, rcx, rdx, rsp, word_ptr,
};
use windows::Win32::Foundation::{EXCEPTION_ACCESS_VIOLATION, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::Debug::{
    EXCEPTION_POINTERS, EXCEPTION_RECORD, EXCEPTION_RECORD32,
};
use windows::Win32::System::Memory::PAGE_EXECUTE_READ;
use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};

use super::code_cache::{CodeCache, Refusal};
use super::debug_loop::{self, BEFORE_PROGRAM};
use super::remote_memory;
use super::spawn::ChildProcess;
use super::stop_point::{self, Hit, Image, Stop};
use super::thread_context::{self, NATIVE_RIP, NATIVE_RSP, WOW64_EIP, WOW64_ESP};
use crate::pe::{PAGE_SIZE, PeKind};
use crate::{AppError, AppResult};

const ACCESS_VIOLATION: u32 = EXCEPTION_ACCESS_VIOLATION.0 as u32;
const READ_FAULT: i32 = debug_loop::READ_FAULT as i32;
const EXECUTE_FAULT: i32 = debug_loop::EXECUTE_FAULT as i32;
const CONTINUE_EXECUTION: i32 = -1;

const POINTERS_CONTEXT: usize = offset_of!(EXCEPTION_POINTERS, ContextRecord);
const RECORD_PC: usize = offset_of!(EXCEPTION_RECORD, ExceptionAddress);
const RECORD_FAULT_KIND: usize = offset_of!(EXCEPTION_RECORD, ExceptionInformation);
const RECORD_FAULT_TARGET: usize = RECORD_FAULT_KIND + size_of::<u64>();
const POINTERS32_CONTEXT: usize = size_of::<u32>();
const RECORD32_PC: usize = offset_of!(EXCEPTION_RECORD32, ExceptionAddress);
const RECORD32_FAULT_KIND: usize = offset_of!(EXCEPTION_RECORD32, ExceptionInformation);
const RECORD32_FAULT_TARGET: usize = RECORD32_FAULT_KIND + size_of::<u32>();
const RETURN: u32 = 0xC3;
const RETURN_POPPING: u32 = 0xC2;
const ADD_HANDLER: &str = "RtlAddVectoredExceptionHandler";
const FIRST: i32 = 1;

const LOCK: usize = 0x00;
const REPORT: usize = 0x08; // faulting thread's CONTEXT, zero when idle
const VERDICT: usize = 0x10;
const SERIAL: usize = 0x18; // tells a new report at the same address
const RANGES: usize = 0x40; // start/end pairs, a zero start ends
const RESUME: u64 = 1;

const BUCKETS: usize = 0x1000;
const PROBES: usize = 8;
const KNOWN_SIZE: usize = (BUCKETS + PROBES) * 2 * size_of::<u64>();

pub(super) struct InjectedHandler {
    code: usize,
    block: usize,
    known: usize, // address then copy, per bucket
    kind: PeKind,
    pub(super) stub: usize,
    pub(super) stub_breakpoint: usize,
}

pub(super) fn install(process: HANDLE, kind: PeKind, ntdll: usize) -> AppResult<InjectedHandler> {
    let module = super::read_module(process, ntdll)?;
    let add_handler = crate::pe::export_rva(&module, ADD_HANDLER)
        .map(|rva| ntdll + rva)
        .ok_or_else(|| AppError::new("ntdll has no vectored exception handlers"))?;

    let pages = remote_memory::allocate(process, None, 2 * PAGE_SIZE + KNOWN_SIZE)
        .ok_or_else(|| AppError::new("could not allocate memory in the program"))?;
    let mut handler = InjectedHandler {
        code: pages,
        block: pages + PAGE_SIZE,
        known: pages + 2 * PAGE_SIZE,
        kind,
        stub: 0,
        stub_breakpoint: 0,
    };

    let code = handler.assemble().map_err(assembly_error)?;
    handler.stub = handler.code + code.len().next_multiple_of(16);
    let stub = handler.assemble_stub(add_handler).map_err(assembly_error)?;
    handler.stub_breakpoint = handler.stub + stub.len() - 1;

    let written = remote_memory::write(process, handler.code, &code)
        && remote_memory::write(process, handler.stub, &stub)
        && remote_memory::protect(process, handler.code, PAGE_SIZE, PAGE_EXECUTE_READ).is_some();
    if !written {
        return Err(AppError::new(
            "could not write the handler into the program",
        ));
    }

    Ok(handler)
}

impl InjectedHandler {
    pub(super) fn watch(&self, process: HANDLE, code: &[Range<usize>]) -> AppResult<()> {
        let ranges = self.ranges(code)?;

        remote_memory::write(process, self.block + RANGES, &ranges)
            .then_some(())
            .ok_or_else(|| AppError::new("could not tell the handler which code to watch"))
    }

    pub(super) fn wait_for_stop(
        &self,
        child: &ChildProcess,
        image: &mut Image,
        deadline: Instant,
    ) -> AppResult<Stop> {
        let process = child.process.raw();
        let mut answered = None;
        let mut cache = CodeCache::new(process, self.kind, image.span.end);

        while Instant::now() < deadline {
            image.trap.arm(process);

            let report = self
                .pending_report(process)
                .filter(|(serial, _)| Some(*serial) != answered);
            let Some((serial, context)) = report else {
                fail_if_exited(process)?;
                std::thread::yield_now();
                continue;
            };

            let frame = thread_context::saved_frame(process, context, self.kind)
                .ok_or_else(|| AppError::new("could not read where the program started"))?;
            let hit = stop_point::classify(process, image, &frame).ok_or_else(|| {
                AppError::new("could not read the stack where the program started")
            })?;

            match hit {
                Hit::Returns { caller, stack } => {
                    self.answer_resume(process, context, caller, stack)?;
                    answered = Some(serial);
                }
                Hit::Program(stop) if stop_point::entered_by_windows(process, image, &frame) => {
                    child.freeze()?;
                    image.trap.release(process);
                    remote_memory::free(process, self.code);
                    if let Some(cache) = cache {
                        cache.release(process);
                    }
                    return Ok(stop);
                }
                Hit::Late { caller }
                    if !called_by_copy(cache.as_ref(), caller)
                        && stop_point::returns_into_call(process, image.kind, caller) =>
                {
                    return Err(super::late());
                }
                Hit::Program(_) | Hit::Late { .. } => {
                    let copy = cache
                        .as_mut()
                        .ok_or_else(no_room)?
                        .copy_of(process, frame.pc)
                        .map_err(not_followed)?;

                    self.remember(process, frame.pc, copy);
                    self.answer_resume(process, context, copy, frame.sp)?;
                    answered = Some(serial);
                }
            }
        }

        Err(AppError::new(
            match cache.is_some_and(|cache| cache.was_used()) {
                true => {
                    "the program's entry point was not reached in time; until then code inside the program's code section kept running and mempe followed it, without being able to tell whether it was the packer's or the program's"
                }
                false => "the program's own code was not reached in time",
            },
        ))
    }

    fn remember(&self, process: HANDLE, address: usize, copy: usize) {
        let width = self.kind.pointer_width();
        let first = self.known + (address & (BUCKETS - 1)) * 2 * width;
        let free = (0..PROBES)
            .map(|probe| first + probe * 2 * width)
            .find(|&bucket| remote_memory::read_pointer(process, bucket, self.kind) == Some(0));

        if let Some(bucket) = free {
            let _ = remote_memory::write(process, bucket + width, &copy.to_le_bytes()[..width])
                && remote_memory::write(process, bucket, &address.to_le_bytes()[..width]); // the handler matches on this one
        }
    }

    fn pending_report(&self, process: HANDLE) -> Option<(usize, usize)> {
        let read = |offset| remote_memory::read_pointer(process, self.block + offset, self.kind);
        let serial = read(SERIAL)?;
        let context = read(REPORT).filter(|&context| context != 0)?;

        (read(SERIAL)? == serial).then_some((serial, context)) // handler bumps the serial before publishing
    }

    fn answer_resume(
        &self,
        process: HANDLE,
        context: usize,
        pc: usize,
        sp: usize,
    ) -> AppResult<()> {
        if !thread_context::save_frame(process, context, self.kind, pc, sp) {
            return Err(AppError::new(
                "could not move the program's thread past its callback",
            ));
        }

        let settled = remote_memory::write(process, self.block + VERDICT, &RESUME.to_le_bytes());
        settled
            .then_some(())
            .ok_or_else(|| AppError::new("could not answer the handler"))
    }

    fn ranges(&self, code: &[Range<usize>]) -> AppResult<Vec<u8>> {
        let width = self.kind.pointer_width();
        if RANGES + (code.len() + 1) * 2 * width > PAGE_SIZE {
            return Err(AppError::new(
                "the program has too many code ranges to watch",
            ));
        }

        let terminator = [0, 0];
        Ok(code
            .iter()
            .flat_map(|range| [range.start, range.end])
            .chain(terminator)
            .flat_map(|bound| bound.to_le_bytes().into_iter().take(width))
            .collect())
    }

    fn assemble(&self) -> Result<Vec<u8>, IcedError> {
        match self.kind {
            PeKind::Pe32Plus => self.assemble64(),
            PeKind::Pe32 => self.assemble32(),
        }
    }

    fn assemble64(&self) -> Result<Vec<u8>, IcedError> {
        let mut a = CodeAssembler::new(64)?;
        let mut check = a.create_label();
        let mut next = a.create_label();
        let mut skip = a.create_label();
        let mut hit = a.create_label();
        let mut plain_return = a.create_label();
        let mut pop_return = a.create_label();
        let mut known = a.create_label();
        let mut probe = a.create_label();
        let mut found = a.create_label();
        let mut report = a.create_label();
        let mut claim = a.create_label();
        let mut wait = a.create_label();
        let mut pass = a.create_label();

        a.mov(rax, qword_ptr(rcx))?; // the exception record
        a.cmp(dword_ptr(rax), ACCESS_VIOLATION)?;
        a.jne(pass)?;
        a.mov(rdx, qword_ptr(rax + RECORD_FAULT_TARGET))?;
        a.cmp(qword_ptr(rax + RECORD_FAULT_KIND), EXECUTE_FAULT)?;
        a.je(check)?;
        a.cmp(qword_ptr(rax + RECORD_FAULT_KIND), READ_FAULT)?;
        a.jne(pass)?;
        a.cmp(rdx, qword_ptr(rax + RECORD_PC))?; // some cpus report execute faults as reads of pc
        a.jne(pass)?;

        a.set_label(&mut check)?;
        a.mov(r9, self.block as u64)?;
        a.lea(r10, qword_ptr(r9 + RANGES))?;
        a.set_label(&mut next)?;
        a.mov(r11, qword_ptr(r10))?;
        a.test(r11, r11)?;
        a.jz(pass)?;
        a.cmp(rdx, r11)?;
        a.jb(skip)?;
        a.cmp(rdx, qword_ptr(r10 + 8))?;
        a.jb(hit)?;
        a.set_label(&mut skip)?;
        a.add(r10, 16)?;
        a.jmp(next)?;

        a.set_label(&mut hit)?;
        a.mov(r8, qword_ptr(rcx + POINTERS_CONTEXT))?;
        a.movzx(eax, byte_ptr(rdx))?;
        a.cmp(al, RETURN)?;
        a.je(plain_return)?;
        a.cmp(al, RETURN_POPPING)?;
        a.jne(known)?;
        a.movzx(r11d, word_ptr(rdx + 1))?;
        a.jmp(pop_return)?;
        a.set_label(&mut plain_return)?;
        a.xor(r11d, r11d)?;
        a.set_label(&mut pop_return)?; // lone ret probes
        a.mov(r10, qword_ptr(r8 + NATIVE_RSP))?;
        a.mov(rax, qword_ptr(r10))?;
        a.mov(qword_ptr(r8 + NATIVE_RIP), rax)?;
        a.lea(r10, qword_ptr(r10 + r11 + 8))?;
        a.mov(qword_ptr(r8 + NATIVE_RSP), r10)?;
        a.mov(eax, CONTINUE_EXECUTION)?;
        a.ret()?;

        a.set_label(&mut known)?;
        a.mov(r10, rdx)?;
        a.and(r10d, (BUCKETS - 1) as i32)?;
        a.shl(r10, 4)?;
        a.mov(r11, self.known as u64)?;
        a.add(r10, r11)?;
        a.mov(eax, PROBES as i32)?;
        a.set_label(&mut probe)?;
        a.cmp(qword_ptr(r10), rdx)?;
        a.je(found)?;
        a.cmp(qword_ptr(r10), 0)?;
        a.je(report)?;
        a.add(r10, 16)?;
        a.dec(eax)?;
        a.jnz(probe)?;
        a.jmp(report)?;
        a.set_label(&mut found)?;
        a.mov(rax, qword_ptr(r10 + 8))?;
        a.mov(qword_ptr(r8 + NATIVE_RIP), rax)?;
        a.mov(eax, CONTINUE_EXECUTION)?;
        a.ret()?;

        a.set_label(&mut report)?;
        a.mov(r10d, 1)?;
        a.set_label(&mut claim)?;
        a.pause()?;
        a.xor(eax, eax)?;
        a.lock().cmpxchg(qword_ptr(r9 + LOCK), r10)?;
        a.jne(claim)?;
        a.inc(qword_ptr(r9 + SERIAL))?;
        a.mov(qword_ptr(r9 + REPORT), r8)?;

        a.set_label(&mut wait)?;
        a.pause()?;
        a.cmp(qword_ptr(r9 + VERDICT), RESUME as i32)?;
        a.jne(wait)?;
        a.mov(qword_ptr(r9 + VERDICT), 0)?;
        a.mov(qword_ptr(r9 + REPORT), 0)?;
        a.mov(qword_ptr(r9 + LOCK), 0)?;
        a.mov(eax, CONTINUE_EXECUTION)?;
        a.ret()?;

        a.set_label(&mut pass)?;
        a.xor(eax, eax)?;
        a.ret()?;

        a.assemble(self.code as u64)
    }

    fn assemble32(&self) -> Result<Vec<u8>, IcedError> {
        let block = self.block as u32;
        let mut a = CodeAssembler::new(32)?;
        let mut check = a.create_label();
        let mut next = a.create_label();
        let mut skip = a.create_label();
        let mut hit = a.create_label();
        let mut plain_return = a.create_label();
        let mut pop_return = a.create_label();
        let mut known = a.create_label();
        let mut probe = a.create_label();
        let mut found = a.create_label();
        let mut report = a.create_label();
        let mut claim = a.create_label();
        let mut wait = a.create_label();
        let mut done = a.create_label();
        let mut missed = a.create_label();
        let mut pass = a.create_label();

        a.mov(ecx, dword_ptr(esp + 4))?; // the exception pointers
        a.mov(eax, dword_ptr(ecx))?;
        a.cmp(dword_ptr(eax), ACCESS_VIOLATION)?;
        a.jne(pass)?;
        a.mov(edx, dword_ptr(eax + RECORD32_FAULT_TARGET))?;
        a.cmp(dword_ptr(eax + RECORD32_FAULT_KIND), EXECUTE_FAULT)?;
        a.je(check)?;
        a.cmp(dword_ptr(eax + RECORD32_FAULT_KIND), READ_FAULT)?;
        a.jne(pass)?;
        a.cmp(edx, dword_ptr(eax + RECORD32_PC))?;
        a.jne(pass)?;

        a.set_label(&mut check)?;
        a.push(ebx)?;
        a.push(esi)?;
        a.mov(ebx, block)?;
        a.lea(esi, dword_ptr(ebx + RANGES))?;
        a.set_label(&mut next)?;
        a.mov(eax, dword_ptr(esi))?;
        a.test(eax, eax)?;
        a.jz(missed)?;
        a.cmp(edx, eax)?;
        a.jb(skip)?;
        a.cmp(edx, dword_ptr(esi + 4))?;
        a.jb(hit)?;
        a.set_label(&mut skip)?;
        a.add(esi, 8)?;
        a.jmp(next)?;

        a.set_label(&mut hit)?;
        a.mov(ecx, dword_ptr(ecx + POINTERS32_CONTEXT))?;
        a.movzx(eax, byte_ptr(edx))?;
        a.cmp(al, RETURN)?;
        a.je(plain_return)?;
        a.cmp(al, RETURN_POPPING)?;
        a.jne(known)?;
        a.movzx(esi, word_ptr(edx + 1))?;
        a.jmp(pop_return)?;
        a.set_label(&mut plain_return)?;
        a.xor(esi, esi)?;
        a.set_label(&mut pop_return)?;
        a.mov(eax, dword_ptr(ecx + WOW64_ESP))?;
        a.mov(edx, dword_ptr(eax))?;
        a.mov(dword_ptr(ecx + WOW64_EIP), edx)?;
        a.lea(eax, dword_ptr(eax + esi + 4))?;
        a.mov(dword_ptr(ecx + WOW64_ESP), eax)?;
        a.jmp(done)?;

        a.set_label(&mut known)?;
        a.mov(esi, edx)?;
        a.and(esi, (BUCKETS - 1) as i32)?;
        a.lea(esi, dword_ptr(esi * 8 + self.known as u32))?;
        a.mov(eax, PROBES as i32)?;
        a.set_label(&mut probe)?;
        a.cmp(dword_ptr(esi), edx)?;
        a.je(found)?;
        a.cmp(dword_ptr(esi), 0)?;
        a.je(report)?;
        a.add(esi, 8)?;
        a.dec(eax)?;
        a.jnz(probe)?;
        a.jmp(report)?;
        a.set_label(&mut found)?;
        a.mov(eax, dword_ptr(esi + 4))?;
        a.mov(dword_ptr(ecx + WOW64_EIP), eax)?;
        a.jmp(done)?;

        a.set_label(&mut report)?;
        a.mov(edx, 1)?;
        a.set_label(&mut claim)?;
        a.pause()?;
        a.xor(eax, eax)?;
        a.lock().cmpxchg(dword_ptr(ebx + LOCK), edx)?;
        a.jne(claim)?;
        a.inc(dword_ptr(ebx + SERIAL))?;
        a.mov(dword_ptr(ebx + REPORT), ecx)?;

        a.set_label(&mut wait)?;
        a.pause()?;
        a.cmp(dword_ptr(ebx + VERDICT), RESUME as i32)?;
        a.jne(wait)?;
        a.mov(dword_ptr(ebx + VERDICT), 0)?;
        a.mov(dword_ptr(ebx + REPORT), 0)?;
        a.mov(dword_ptr(ebx + LOCK), 0)?;
        a.set_label(&mut done)?;
        a.pop(esi)?;
        a.pop(ebx)?;
        a.mov(eax, CONTINUE_EXECUTION)?;
        a.ret_1(4)?;

        a.set_label(&mut missed)?;
        a.pop(esi)?;
        a.pop(ebx)?;
        a.set_label(&mut pass)?;
        a.xor(eax, eax)?;
        a.ret_1(4)?;

        a.assemble(self.code as u64)
    }

    fn assemble_stub(&self, add_handler: usize) -> Result<Vec<u8>, IcedError> {
        if self.kind == PeKind::Pe32Plus {
            let mut a = CodeAssembler::new(64)?;
            a.mov(rbx, rsp)?;
            a.and(rsp, -16)?; // align for the call
            a.sub(rsp, 0x20)?;
            a.mov(ecx, FIRST)?;
            a.mov(rdx, self.code as u64)?;
            a.mov(rax, add_handler as u64)?;
            a.call(rax)?;
            a.mov(rsp, rbx)?;
            a.int3()?;
            return a.assemble(self.stub as u64);
        }

        let mut a = CodeAssembler::new(32)?;
        a.push(self.code as u32)?;
        a.push(FIRST)?;
        a.mov(eax, add_handler as u32)?;
        a.call(eax)?;
        a.int3()?;
        a.assemble(self.stub as u64)
    }
}

// only a followed copy pushes a return address into trapped code
fn called_by_copy(cache: Option<&CodeCache>, caller: usize) -> bool {
    cache.is_some_and(|cache| cache.pushed(caller))
}

fn no_room() -> AppError {
    AppError::new(
        "code inside the program's code section ran before its entry point, and mempe could not reserve memory beside the program to follow it",
    )
}

fn not_followed(refusal: Refusal) -> AppError {
    AppError::new(match refusal {
        Refusal::Unfollowable => {
            "code inside the program's code section ran before its entry point, and it is not code mempe can follow; it may be the program's own"
        }
        Refusal::Full => {
            "code inside the program's code section ran before its entry point, and mempe ran out of room to follow it"
        }
    })
}

fn fail_if_exited(process: HANDLE) -> AppResult<()> {
    if unsafe { WaitForSingleObject(process, 0) } != WAIT_OBJECT_0 {
        return Ok(());
    }

    let mut code = 0;
    let _ = unsafe { GetExitCodeProcess(process, &mut code) };
    Err(super::exited(code, BEFORE_PROGRAM))
}

fn assembly_error(error: IcedError) -> AppError {
    AppError::new(format!("could not assemble the handler: {error}"))
}
