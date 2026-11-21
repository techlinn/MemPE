use std::collections::HashMap;
use std::time::Instant;

use windows::Win32::Foundation::{
    DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_ACCESS_VIOLATION, EXCEPTION_BREAKPOINT,
    EXCEPTION_SINGLE_STEP, HANDLE, NTSTATUS, STATUS_WX86_SINGLE_STEP,
};
use windows::Win32::System::Diagnostics::Debug::{
    CREATE_PROCESS_DEBUG_EVENT, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT, EXCEPTION_DEBUG_INFO,
    EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
};

use super::execute_trap::HoleWrite;
use super::spawn::ChildProcess;
use super::stop_point::{Detour, Hit, Image};
use super::stop_point::{Reached, Stop};
use super::syscall_hooks::Hook;
use super::thread_context::Context64;
use super::{Flow, HostedDll, Policy, Stopped, Threads, close, late, prepare, pump, read_module};
use super::{
    hide_debugger, remote_memory, stop_point, syscall_hooks, system_files, thread_context,
};
use crate::pe::{PAGE_SIZE, PeKind};
use crate::unpack::x86::branches::{REL32_LEN, relative};
use crate::{AppError, AppResult};

const FIXER_SCAN_BYTES: usize = 0x800;
pub(super) const READ_FAULT: usize = 0;
const WRITE_FAULT: usize = 1;
pub(super) const EXECUTE_FAULT: usize = 8;
pub(super) const BEFORE_PROGRAM: &str = "before the program's own code ran";

type Step = Flow<Stop>;

pub(super) struct Debuggee<'a> {
    child: &'a ChildProcess,
    library: Option<&'a HostedDll>,
    kind: PeKind,
    threads: Threads,
    image: Option<Image>,
    hooks: Option<Vec<Hook>>,
    calls: HashMap<u32, [u64; 4]>,
    detour: Option<Detour>,
    entry_stub_opened: bool,
    crash: Option<NTSTATUS>,
}

impl<'a> Debuggee<'a> {
    pub(super) fn new(
        child: &'a ChildProcess,
        library: Option<&'a HostedDll>,
        kind: PeKind,
    ) -> Self {
        Self {
            child,
            library,
            kind,
            threads: Threads::default(),
            image: None,
            hooks: None,
            calls: HashMap::new(),
            detour: None,
            entry_stub_opened: false,
            crash: None,
        }
    }

    fn process(&self) -> HANDLE {
        self.child.process.raw()
    }

    pub(super) fn run(mut self, deadline: Instant) -> AppResult<Stopped> {
        if let Some((stop, _)) = pump(&mut self, deadline)? {
            let image = self
                .image
                .ok_or_else(|| AppError::new("stopped before the program was mapped"))?;
            return Ok(Stopped {
                stop,
                span: image.span,
                basis: image.basis,
            });
        }

        match self.library.is_some() && self.image.is_none() {
            true => Err(AppError::new(
                "the dll was never seen loading, so it may have run inside its host",
            )),
            false => Err(AppError::new(
                "the program's own code was not reached in time",
            )),
        }
    }

    fn arm(&mut self) {
        let process = self.process();
        if let Some(image) = &mut self.image {
            image.trap.arm(process);
        }
    }

    fn handle(&mut self, event: &DEBUG_EVENT) -> AppResult<Step> {
        let own = event.dwProcessId == self.child.pid;
        self.threads.track(event, own);

        match event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                let info = unsafe { event.u.CreateProcessInfo };
                close(info.hFile);

                if own {
                    if self.library.is_none() {
                        let image = prepare(self.process(), info.lpBaseOfImage as usize, false)?;
                        self.image = Some(image); // a dll is trapped at LOAD_DLL
                    }

                    let teb = info.lpThreadLocalBase as usize;
                    hide_debugger::clear_debugged_flag(self.process(), teb, self.kind)?;
                }
            }
            LOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { event.u.LoadDll };
                let base = info.lpBaseOfDll as usize;
                let library = own && self.image.is_none() && self.is_hosted_dll(info.hFile, base);
                close(info.hFile);

                if own
                    && self.hooks.is_none()
                    && system_files::is_native_ntdll(self.process(), base)
                {
                    self.hook_system_calls(base)?;
                }
                if library {
                    self.image = Some(prepare(self.process(), base, true)?);
                }
            }
            EXIT_PROCESS_DEBUG_EVENT if own => {
                let code = unsafe { event.u.ExitProcess }.dwExitCode;
                return Err(self.ended(code));
            }
            EXCEPTION_DEBUG_EVENT if own => {
                let info = unsafe { event.u.Exception };
                return self.exception(event.dwThreadId, &info);
            }
            _ => {}
        }

        Ok(Step::Continue(DBG_CONTINUE))
    }

    fn is_hosted_dll(&self, file: HANDLE, base: usize) -> bool {
        self.library
            .is_some_and(|library| library.is(file, self.process(), base))
    }

    fn hook_system_calls(&mut self, base: usize) -> AppResult<()> {
        let module = read_module(self.process(), base)?;
        self.hooks = Some(syscall_hooks::install(self.process(), base, &module)?);
        Ok(())
    }

    fn exception(&mut self, thread: u32, info: &EXCEPTION_DEBUG_INFO) -> AppResult<Step> {
        let record = info.ExceptionRecord;
        let code = record.ExceptionCode;
        let address = record.ExceptionAddress as usize;

        if info.dwFirstChance == 0 {
            self.crash = Some(code);
            return Ok(Step::Continue(DBG_EXCEPTION_NOT_HANDLED));
        }

        if code == EXCEPTION_BREAKPOINT && self.system_call(thread, address)? {
            return Ok(Step::Continue(DBG_CONTINUE));
        }

        let single_step = code == EXCEPTION_SINGLE_STEP || code == STATUS_WX86_SINGLE_STEP;
        let process = self.process();
        if single_step
            && self
                .image
                .as_mut()
                .is_some_and(|image| image.trap.stepped(process))
        {
            return Ok(Step::Continue(DBG_CONTINUE));
        }

        if code == EXCEPTION_ACCESS_VIOLATION {
            let kind = record.ExceptionInformation[0];
            let target = record.ExceptionInformation[1];
            let executes = kind == EXECUTE_FAULT || (kind == READ_FAULT && target == address);
            if kind == WRITE_FAULT
                && let Some(step) = self.hole_written(thread, target)?
            {
                return Ok(step);
            }

            if executes && let Some(step) = self.on_execute_fault(thread, target)? {
                return Ok(step);
            }
        }

        Ok(Step::Continue(DBG_EXCEPTION_NOT_HANDLED))
    }

    fn hole_written(&mut self, thread: u32, target: usize) -> AppResult<Option<Step>> {
        let process = self.process();
        let Some(image) = &mut self.image else {
            return Ok(None);
        };

        let kind = image.kind;
        match image.trap.hole_written(process, target) {
            None => Ok(None),
            Some(HoleWrite::Closed) => Ok(Some(Step::Continue(DBG_CONTINUE))),
            Some(HoleWrite::StubPatched) => {
                thread_context::single_step(self.threads.known(thread)?, kind)?;
                Ok(Some(Step::Continue(DBG_CONTINUE)))
            }
        }
    }

    fn system_call(&mut self, thread_id: u32, address: usize) -> AppResult<bool> {
        let Some(hook) = placed(&self.hooks)
            .iter()
            .find(|hook| hook.enter == address || hook.exit == address)
        else {
            return Ok(false);
        };
        let thread = self.threads.known(thread_id)?;
        let mut registers = Context64::of(thread)?;

        let entering = hook.enter == address;
        if entering && !hide_debugger::must_fake(hook.api, registers.arguments()) {
            hide_debugger::before(self.process(), hook.api, &registers)?;
            self.calls.insert(thread_id, registers.arguments());
            registers.jump(hook.syscall);
            registers.apply(thread)?;
            return Ok(true);
        }

        if entering {
            registers.set_result(0); // success without the kernel
        } else if let Some(arguments) = self.calls.remove(&thread_id) {
            let narrow = self.kind == PeKind::Pe32;
            hide_debugger::after(self.process(), hook.api, arguments, &mut registers, narrow)?;
        }

        let caller =
            remote_memory::read_pointer(self.process(), registers.stack(), PeKind::Pe32Plus)
                .ok_or_else(|| AppError::new("could not read the stack inside ntdll"))?;
        registers.simulate_ret(caller);
        registers.apply(thread)?;
        Ok(true)
    }

    fn on_execute_fault(&mut self, thread: u32, target: usize) -> AppResult<Option<Step>> {
        let process = self.process();
        let Some(image) = &mut self.image else {
            return Ok(None);
        };

        if let Some(detour) = self.detour.take_if(|_| target == image.span.start) {
            let thread = self.threads.known(thread)?;
            let frame = thread_context::read_frame(thread, image.kind)?;

            remote_memory::patch_code(process, detour.operand, &detour.original)?;
            thread_context::redirect(thread, image.kind, detour.entry, frame.sp)?;
            image.trap.release(process);
            syscall_hooks::remove(process, placed(&self.hooks));

            return Ok(Some(Step::Done(Stop {
                rva: (detour.entry - image.span.start) as u32,
                reached: Reached::EntryPoint,
            })));
        }

        if image.fixer == Some(target) && self.detour.is_none() {
            let detour = detour_fixer(process, image, target).ok_or_else(|| {
                AppError::new(
                    "the packer's import fixer started, but mempe could not find where it hands over to the program, so it could not stop there",
                )
            })?;

            self.detour = Some(detour);
            return Ok(Some(Step::Continue(DBG_CONTINUE)));
        }

        if !image.trap.covers(target) {
            let packer = image.kind == PeKind::Pe32 || image.span.contains(&target); // pre-dep stubs on non-exec pages
            let opened = packer && remote_memory::allow_execute_from(process, target).is_some();
            return Ok(opened.then_some(Step::Continue(DBG_CONTINUE)));
        }

        if image.entry_stub_in_code
            && target == image.entry
            && !std::mem::replace(&mut self.entry_stub_opened, true)
        {
            let opened = image.trap.open_hole(process, target);
            return Ok(opened.then_some(Step::Continue(DBG_CONTINUE)));
        }

        let thread = self.threads.known(thread)?;
        let frame = thread_context::read_frame(thread, image.kind)?;
        let hit = stop_point::classify(process, image, &frame)
            .ok_or_else(|| AppError::new("could not read the stack where the program started"))?;

        match hit {
            Hit::Returns { caller, stack } => {
                thread_context::redirect(thread, image.kind, caller, stack)?;
                Ok(Some(Step::Continue(DBG_CONTINUE)))
            }
            Hit::Program(stop) => {
                image.trap.release(process);
                syscall_hooks::remove(process, placed(&self.hooks));
                Ok(Some(Step::Done(stop)))
            }
            Hit::Late { .. } => Err(late()),
        }
    }

    fn ended(&self, exit_code: u32) -> AppError {
        match self.crash {
            Some(code) => AppError::new(format!(
                "the packer's code crashed with exception 0x{:08X} before the program's own code ran",
                code.0
            )),
            None => super::exited(exit_code, BEFORE_PROGRAM),
        }
    }
}

impl Policy for Debuggee<'_> {
    type Outcome = Stop;

    fn on_event(&mut self, event: &DEBUG_EVENT) -> AppResult<Step> {
        let step = self.handle(event)?;
        if matches!(step, Flow::Continue(_)) {
            self.arm();
        }

        Ok(step)
    }

    fn on_quiet(&mut self) {
        self.arm();
    }
}

fn placed(hooks: &Option<Vec<Hook>>) -> &[Hook] {
    hooks.as_deref().unwrap_or_default()
}

fn detour_fixer(process: HANDLE, image: &mut Image, fixer: usize) -> Option<Detour> {
    let mut code = [0u8; FIXER_SCAN_BYTES];
    remote_memory::read(process, fixer, &mut code).then_some(())?;

    let exit = crate::packers::fixer_exit(&code)?;
    let operand = exit + 1;
    let original: [u8; 4] = code.get(operand..exit + REL32_LEN)?.try_into().ok()?;
    let after = fixer + exit + REL32_LEN;
    let entry = relative(&code, operand, after)?;
    image.trap.covers(entry).then_some(())?;

    let headers = (image.span.start as isize - after as isize) as i32; // headers never execute
    remote_memory::patch_code(process, fixer + operand, &headers.to_le_bytes()).ok()?;
    image.trap.open(
        process,
        fixer & !(PAGE_SIZE - 1)..after.next_multiple_of(PAGE_SIZE),
    );

    Some(Detour {
        operand: fixer + operand,
        original,
        entry,
    })
}
