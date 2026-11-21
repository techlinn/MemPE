#[derive(Clone, Copy)]
pub(crate) struct RegionProtection {
    pub(crate) offset: usize,
    pub(crate) size: usize,
    pub(crate) readable: bool,
    pub(crate) writable: bool,
    pub(crate) executable: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EntryOrigin {
    Manual,
    Observed,
    HandedOver, // reached from the packer's code, not confirmed by windows calling it
}

#[derive(Clone, Copy)]
pub(crate) struct EntryPointRva {
    rva: u32,
    origin: EntryOrigin,
}

impl EntryPointRva {
    fn with(rva: u32, origin: EntryOrigin) -> Option<Self> {
        (rva != 0).then_some(Self { rva, origin })
    }

    pub(crate) fn new(value: u32) -> Option<Self> {
        Self::with(value, EntryOrigin::Manual)
    }

    pub(crate) fn observed(value: u32) -> Option<Self> {
        Self::with(value, EntryOrigin::Observed)
    }

    pub(crate) fn handed_over(value: u32) -> Option<Self> {
        Self::with(value, EntryOrigin::HandedOver)
    }

    pub(crate) fn get(self) -> u32 {
        self.rva
    }

    pub(crate) fn is_observed(self) -> bool {
        self.origin != EntryOrigin::Manual
    }

    pub(crate) fn is_handed_over(self) -> bool {
        self.origin == EntryOrigin::HandedOver
    }
}
