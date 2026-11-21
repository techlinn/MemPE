use std::cell::Cell;

const STEPS_PER_UNPACK: u64 = 2_000_000_000;

#[derive(Clone, Copy)]
struct Meter {
    left: u64,
    refused: bool,
    system_calls: usize,
    api_calls: usize,
}

const UNMETERED: Meter = Meter {
    left: u64::MAX,
    refused: false,
    system_calls: 0,
    api_calls: 0,
};

thread_local! {
    static METER: Cell<Meter> = const { Cell::new(UNMETERED) };
}

pub(crate) struct Metered<T> {
    pub(crate) result: T,
    pub(crate) ran_dry: bool,
    pub(crate) skipped_system_calls: usize,
    pub(crate) skipped_api_calls: usize,
}

pub(crate) fn metered<T>(run: impl FnOnce() -> T) -> Metered<T> {
    metered_within(STEPS_PER_UNPACK, run)
}

fn metered_within<T>(limit: u64, run: impl FnOnce() -> T) -> Metered<T> {
    let outer = METER.get();
    let granted = outer.left.min(limit);
    METER.set(Meter {
        left: granted,
        ..UNMETERED
    });

    let result = run();
    let inner = METER.get();

    let outer_was_the_limit = granted == outer.left;
    METER.set(Meter {
        left: outer.left - (granted - inner.left),
        refused: outer.refused || (inner.refused && outer_was_the_limit),
        system_calls: outer.system_calls + inner.system_calls,
        api_calls: outer.api_calls + inner.api_calls,
    });

    Metered {
        result,
        ran_dry: inner.refused,
        skipped_system_calls: inner.system_calls,
        skipped_api_calls: inner.api_calls,
    }
}

pub(super) fn burn() -> Option<()> {
    let mut meter = METER.get();
    let rest = meter.left.checked_sub(1);

    meter.left = rest.unwrap_or(0);
    meter.refused |= rest.is_none();
    METER.set(meter);
    rest.map(|_| ())
}

pub(super) fn ran_dry() -> bool {
    METER.get().refused
}

pub(super) fn note_system_call() {
    let mut meter = METER.get();
    meter.system_calls += 1;
    METER.set(meter);
}

pub(super) fn note_api_call() {
    let mut meter = METER.get();
    meter.api_calls += 1;
    METER.set(meter);
}
