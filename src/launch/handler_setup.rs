use std::time::Instant;

use windows::Win32::Foundation::{
    DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_BREAKPOINT, HANDLE, STATUS_WX86_BREAKPOINT,
};
use windows::Win32::System::Diagnostics::Debug::{
    CREATE_PROCESS_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT, DebugActiveProcessStop,
    EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
};
use windows::Win32::System::Threading::{
    OpenThread, ResumeThread, SuspendThread, THREAD_SUSPEND_RESUME,
};

use super::injected_handler::{self, InjectedHandler};
use super::spawn::{ChildProcess, SUSPEND_FAILED};
use super::stop_point::Image;
use super::thread_context::{self, ThreadContext};
use super::{Flow, HostedDll, Policy, Threads, close, hide_debugger, prepare, pump, system_files};
use crate::pe::PeKind;
use crate::process::OwnedHandle;
use crate::windows_error;
use crate::{AppError, AppResult};

struct Borrowed {
    thread: u32,
    saved: ThreadContext,
}

struct Detach;

type Next = Flow<Detach>;

struct Handoff<'a> {
    child: &'a ChildProcess,
    library: Option<&'a HostedDll>,
    threads: Threads,
    image: Option<Image>,
    kind: PeKind,
    teb: usize,
    handler: Option<InjectedHandler>,
    borrowed: Option<Borrowed>,
    handler_added: bool,
}

pub(super) fn run(
    child: &ChildProcess,
    library: Option<&HostedDll>,
    kind: PeKind,
    deadline: Instant,
) -> AppResult<(InjectedHandler, Image)> {
    let mut handoff = Handoff {
        child,
        library,
        threads: Threads::default(),
        image: None,
        kind,
        teb: 0,
        handler: None,
        borrowed: None,
        handler_added: false,
    };

    match pump(&mut handoff, deadline)? {
        Some((Detach, event)) => handoff.detach(&event),
        None => Err(AppError::new(
            "windows did not finish loading the program in time",
        )),
    }
}

impl Policy for Handoff<'_> {
    type Outcome = Detach;

    fn on_event(&mut self, event: &DEBUG_EVENT) -> AppResult<Next> {
        let own = event.dwProcessId == self.child.pid;
        self.threads.track(event, own);

        match event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                let info = unsafe { event.u.CreateProcessInfo };
                close(info.hFile);

                if own {
                    self.teb = info.lpThreadLocalBase as usize;

                    if self.library.is_none() {
                        let image = prepare(self.process(), info.lpBaseOfImage as usize, false)?;
                        self.image = Some(image);
                    }
                }
            }
            LOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { event.u.LoadDll };
                let base = info.lpBaseOfDll as usize;
                let wanted = self
                    .library
                    .is_some_and(|library| library.is(info.hFile, self.process(), base));
                close(info.hFile);

                if own && wanted && self.image.is_none() {
                    return self.trap_library(base);
                }
            }
            EXIT_PROCESS_DEBUG_EVENT if own => {
                let code = unsafe { event.u.ExitProcess }.dwExitCode;
                return Err(super::exited(code, "while windows was loading it"));
            }
            EXCEPTION_DEBUG_EVENT if own => return self.exception(event),
            _ => {}
        }

        Ok(Next::Continue(DBG_CONTINUE))
    }
}

impl Handoff<'_> {
    fn process(&self) -> HANDLE {
        self.child.process.raw()
    }

    fn trap_library(&mut self, base: usize) -> AppResult<Next> {
        let Some(handler) = self.handler.as_ref().filter(|_| self.handler_added) else {
            return Err(AppError::new(
                "the dll was loaded before windows finished starting its host",
            ));
        };

        let image = prepare(self.process(), base, true)?;
        handler.watch(self.process(), image.trap.ranges())?;
        self.image = Some(image);

        Ok(Next::Done(Detach))
    }

    fn exception(&mut self, event: &DEBUG_EVENT) -> AppResult<Next> {
        let info = unsafe { event.u.Exception };
        let code = info.ExceptionRecord.ExceptionCode;
        let address = info.ExceptionRecord.ExceptionAddress as usize;
        let breakpoint = code == EXCEPTION_BREAKPOINT || code == STATUS_WX86_BREAKPOINT;

        if !breakpoint || info.dwFirstChance == 0 {
            return Ok(Next::Continue(DBG_EXCEPTION_NOT_HANDLED));
        }

        let registering = self
            .handler
            .as_ref()
            .is_some_and(|handler| handler.stub_breakpoint == address);
        if registering {
            return self.give_back();
        }

        let loader = match self.kind {
            PeKind::Pe32Plus => code == EXCEPTION_BREAKPOINT,
            PeKind::Pe32 => code == STATUS_WX86_BREAKPOINT, // 32-bit: the native loader stops first
        };
        if loader && self.handler.is_none() {
            self.borrow(event.dwThreadId)?;
        }

        Ok(Next::Continue(DBG_CONTINUE))
    }

    fn borrow(&mut self, thread_id: u32) -> AppResult<()> {
        let ntdll = system_files::find_ntdll(self.process(), self.kind)
            .ok_or_else(|| AppError::new("could not find ntdll in the program"))?;

        let handler = injected_handler::install(self.process(), self.kind, ntdll)?;
        if let Some(image) = &self.image {
            handler.watch(self.process(), image.trap.ranges())?;
        }

        let thread = self.threads.known(thread_id)?;
        let saved = ThreadContext::with_float_state(thread, self.kind)?;
        let frame = saved.frame();
        thread_context::redirect(thread, self.kind, handler.stub, frame.sp)?; // heap exists, no packer code ran yet

        self.handler = Some(handler);
        self.borrowed = Some(Borrowed {
            thread: thread_id,
            saved,
        });
        Ok(())
    }

    fn give_back(&mut self) -> AppResult<Next> {
        let Some(mut borrowed) = self.borrowed.take() else {
            return Err(AppError::new("the handler stopped before it was set up"));
        };
        let thread = self.threads.known(borrowed.thread)?;

        if ThreadContext::of(thread, self.kind)?.result() == 0 {
            return Err(AppError::new("windows refused mempe's exception handler"));
        }
        borrowed.saved.restore(self.process(), thread)?;
        self.handler_added = true;

        match self.image {
            Some(_) => Ok(Next::Done(Detach)),
            None => Ok(Next::Continue(DBG_CONTINUE)),
        }
    }

    fn detach(mut self, event: &DEBUG_EVENT) -> AppResult<(InjectedHandler, Image)> {
        let (Some(handler), Some(mut image)) = (self.handler.take(), self.image.take()) else {
            return Err(AppError::new("the handler stopped before it was set up"));
        };

        let held = unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, event.dwThreadId) }
            .map(OwnedHandle::adopt)
            .map_err(|error| windows_error("OpenThread", error))?; // detach closes the debugger's handles
        if unsafe { SuspendThread(held.raw()) } == SUSPEND_FAILED {
            return Err(AppError::new(
                "could not hold the program's thread while the debugger let go of it",
            ));
        }
        unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE) }
            .map_err(|error| windows_error("ContinueDebugEvent", error))?;
        unsafe { DebugActiveProcessStop(self.child.pid) }
            .map_err(|error| windows_error("DebugActiveProcessStop", error))?;

        hide_debugger::clear_debugged_flag(self.process(), self.teb, image.kind)?;
        hide_debugger::clear_debug_heap_flags(self.process(), self.teb, image.kind)?;
        image.trap.arm(self.process());
        unsafe { ResumeThread(held.raw()) };

        Ok((handler, image))
    }
}
