use std::ops::Range;

use crate::pe::exports::ExportIndex;

#[derive(Clone, Copy)]
pub(crate) struct Process<'a> {
    pub(crate) exports: &'a ExportIndex,
    pub(crate) memory: &'a ProcessMemory<'a>,
}

#[derive(Default)]
pub(crate) struct ProcessMemory<'a> {
    spans: Vec<(usize, &'a [u8])>,
}

impl<'a> ProcessMemory<'a> {
    pub(crate) fn new(spans: impl IntoIterator<Item = (usize, &'a [u8])>) -> Self {
        let mut spans: Vec<_> = spans.into_iter().collect();
        spans.sort_unstable_by_key(|(base, _)| *base);

        Self { spans }
    }

    pub(super) fn slice(&self, address: usize, length: usize) -> Option<&'a [u8]> {
        let after = self.spans.partition_point(|(base, _)| *base <= address);
        let (base, bytes) = self.spans.get(after.checked_sub(1)?)?;
        let start = address - base;

        bytes.get(start..start.checked_add(length)?)
    }

    pub(super) fn overlaps(&self, range: &Range<usize>) -> bool {
        self.spans.iter().any(|(base, bytes)| {
            *base < range.end && range.start < base.saturating_add(bytes.len())
        })
    }

    pub(super) fn byte(&self, address: usize) -> Option<u8> {
        self.slice(address, 1)?.first().copied()
    }
}
