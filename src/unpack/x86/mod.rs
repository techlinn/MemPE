mod block_effects;
pub(crate) mod branches;
mod byte_patterns;
pub(crate) mod compiler_entry;
mod emulator;
mod execute;
pub(crate) mod opcodes;
mod sse;
mod step_budget;
mod stub_runner;
mod written_memory;
mod x87;

pub(crate) use block_effects::{FlagsAfter, Outcomes, Probe, Trial};
pub(crate) use byte_patterns::{find_pattern, find_patterns, hex, pattern_at};
pub(crate) use emulator::{
    Agreement, Failure, Flow, RSP, SEEDS, StubExit, gpr_count, mask, resolve, same_behaviour,
    stub_exit,
};
pub(crate) use step_budget::metered;
pub(crate) use stub_runner::{
    Argument, Handover, Landing, StubRunner, WrappedCall, WrapperLeadsTo,
};
