use std::collections::BTreeMap;
use std::ops::Range;

const PAGE: u64 = 4096;
const MAX_PAGES: usize = 16_384; // 64 MiB: a runaway loop

struct Page {
    bytes: [u8; PAGE as usize],
    written: [u64; PAGE as usize / 64], // one bit per byte
}

#[derive(Default)]
pub(super) struct Overlay {
    pages: BTreeMap<u64, Box<Page>>,
}

impl Overlay {
    pub(super) fn get(&self, address: u64) -> Option<u8> {
        let page = self.pages.get(&(address / PAGE))?;
        let at = (address % PAGE) as usize;

        (page.written[at / 64] >> (at % 64) & 1 == 1).then(|| page.bytes[at])
    }

    pub(super) fn insert(&mut self, address: u64, value: u8) -> Option<()> {
        let number = address / PAGE;
        if self.pages.len() >= MAX_PAGES && !self.pages.contains_key(&number) {
            return None;
        }

        let page = self.pages.entry(number).or_insert_with(|| {
            Box::new(Page {
                bytes: [0; PAGE as usize],
                written: [0; PAGE as usize / 64],
            })
        });
        let at = (address % PAGE) as usize;
        page.bytes[at] = value;
        page.written[at / 64] |= 1 << (at % 64);
        Some(())
    }

    pub(super) fn any_in(&self, range: Range<u64>) -> bool {
        range.into_iter().any(|address| self.get(address).is_some())
    }

    pub(super) fn into_writes(self) -> impl Iterator<Item = (u64, u8)> {
        self.pages.into_iter().flat_map(|(number, page)| {
            (0..PAGE as usize)
                .filter(|at| page.written[at / 64] >> (at % 64) & 1 == 1)
                .map(|at| (number * PAGE + at as u64, page.bytes[at]))
                .collect::<Vec<_>>()
        })
    }
}
