use std::collections::BTreeMap;
use std::ops::Range;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{MEM_COMMIT, PAGE_PROTECTION_FLAGS};

use super::remote_memory::{
    allow_execute_from, grants_execute, is_read_execute, protect, read_execute, without_execute,
};
use crate::pe::PAGE_SIZE;
use crate::process::{MAX_REGIONS, query_region, walk_regions};

const MAX_STUB: usize = 0x40; // pecompact entry stub

#[derive(Clone, Copy, PartialEq, Eq)]
struct Stripped {
    wanted: PAGE_PROTECTION_FLAGS,
    left: PAGE_PROTECTION_FLAGS,
}

struct Hole {
    pages: Range<usize>,
    stub: Range<usize>,
    protection: PAGE_PROTECTION_FLAGS,
    stepping: bool,
}

pub(super) enum HoleWrite {
    StubPatched,
    Closed,
}

pub(super) struct Trap {
    code: Vec<Range<usize>>,
    stripped: BTreeMap<usize, Stripped>, // by page
    hole: Option<Hole>,
}

impl Trap {
    pub(super) fn new(base: usize, code: &[Range<usize>]) -> Self {
        Self {
            code: code
                .iter()
                .map(|range| {
                    (base + range.start).next_multiple_of(PAGE_SIZE)
                        ..(base + range.end) & !(PAGE_SIZE - 1)
                })
                .filter(|pages| !pages.is_empty())
                .collect(),
            stripped: BTreeMap::new(),
            hole: None,
        }
    }

    pub(super) fn open_hole(&mut self, process: HANDLE, stub: usize) -> bool {
        let pages = stub & !(PAGE_SIZE - 1)..(stub + MAX_STUB).next_multiple_of(PAGE_SIZE);
        let Some(found) =
            query_region(process, pages.start).filter(|found| found.state == MEM_COMMIT.0)
        else {
            return false;
        };
        let protection = PAGE_PROTECTION_FLAGS(found.protect);
        if protect(process, pages.start, pages.len(), read_execute(protection)).is_none() {
            return false;
        }

        self.hole = Some(Hole {
            pages,
            stub: stub..stub + MAX_STUB,
            protection,
            stepping: false,
        });
        true
    }

    pub(super) fn hole_written(&mut self, process: HANDLE, at: usize) -> Option<HoleWrite> {
        let hole = self.hole.as_mut().filter(|hole| hole.pages.contains(&at))?;
        let _ = protect(process, hole.pages.start, hole.pages.len(), hole.protection);

        if hole.stub.contains(&at) {
            hole.stepping = true;
            return Some(HoleWrite::StubPatched);
        }
        self.hole = None;
        Some(HoleWrite::Closed)
    }

    pub(super) fn stepped(&mut self, process: HANDLE) -> bool {
        let Some(hole) = self.hole.as_mut().filter(|hole| hole.stepping) else {
            return false;
        };

        hole.stepping = false;
        let _ = protect(
            process,
            hole.pages.start,
            hole.pages.len(),
            read_execute(hole.protection),
        );
        true
    }

    pub(super) fn ranges(&self) -> &[Range<usize>] {
        &self.code
    }

    pub(super) fn covers(&self, address: usize) -> bool {
        self.code.iter().any(|range| range.contains(&address))
    }

    pub(super) fn open(&mut self, process: HANDLE, pages: Range<usize>) {
        self.code = self
            .code
            .iter()
            .flat_map(|range| {
                [
                    range.start..range.end.min(pages.start),
                    range.start.max(pages.end)..range.end,
                ]
            })
            .filter(|range| !range.is_empty())
            .collect();

        for page in pages.step_by(PAGE_SIZE) {
            allow_execute_from(process, page);
        }
    }

    pub(super) fn arm(&mut self, process: HANDLE) {
        for range in &self.code {
            let mut at = range.start;

            for _region in 0..MAX_REGIONS {
                let Some(found) = query_region(process, at).filter(|_| at < range.end) else {
                    break;
                };
                let protection = PAGE_PROTECTION_FLAGS(found.protect);
                let hole = self.hole.as_ref().map(|hole| &hole.pages);
                let pages = piece(at..found.end().min(range.end), hole);
                let in_hole = hole.is_some_and(|hole| hole.contains(&pages.start));
                let held = in_hole && is_read_execute(protection);
                let stepping = self.hole.as_ref().is_some_and(|hole| hole.stepping);
                if in_hole && !held && !stepping {
                    self.hole = None;
                }

                let left = without_execute(protection);
                if !held
                    && found.state == MEM_COMMIT.0
                    && grants_execute(protection)
                    && protect(process, pages.start, pages.len(), left).is_some()
                {
                    let stripped = Stripped {
                        wanted: protection,
                        left,
                    };
                    for page in pages.clone().step_by(PAGE_SIZE) {
                        self.stripped.insert(page, stripped);
                    }
                }

                at = pages.end;
            }
        }
    }

    pub(super) fn release(&self, process: HANDLE) {
        if let Some(hole) = &self.hole {
            let _ = protect(process, hole.pages.start, hole.pages.len(), hole.protection);
        }

        let mut pages = self.stripped.iter().peekable();
        while let Some((&start, &stripped)) = pages.next() {
            let mut end = start + PAGE_SIZE;
            while pages
                .next_if(|(next, same)| **next == end && **same == stripped)
                .is_some()
            {
                end += PAGE_SIZE;
            }
            restore(process, start..end, stripped);
        }
    }
}

// the start of a run, cut where it enters or leaves the hole
fn piece(run: Range<usize>, hole: Option<&Range<usize>>) -> Range<usize> {
    let end = match hole {
        Some(hole) if hole.contains(&run.start) => hole.end,
        Some(hole) if run.start < hole.start => hole.start,
        _ => run.end,
    };

    run.start..end.min(run.end)
}

fn restore(process: HANDLE, pages: Range<usize>, stripped: Stripped) {
    for found in walk_regions(process, pages.start).take_while(|found| found.base < pages.end) {
        let run = found.base.max(pages.start)..found.end().min(pages.end);
        if PAGE_PROTECTION_FLAGS(found.protect) == stripped.left {
            let _ = protect(process, run.start, run.len(), stripped.wanted);
        }
    }
}
