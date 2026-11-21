use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::{Duration, Instant};

use windows::Win32::System::Memory::{MEM_COMMIT, MEM_IMAGE};

use super::{AddressSpace, MemoryRegion, PAGE_SIZE, is_executable, is_readable, is_writable};
use crate::AppResult;
use crate::process::TargetProcess;

const STABLE_POLL_COUNT: usize = 30;

const STABLE_MATCH_COUNT: usize = 3;

const STABLE_POLL_DELAY: Duration = Duration::from_millis(100);

const MAX_STABILITY_READS: usize = 256;

pub(crate) struct StabilityResult {
    pub(crate) elapsed: Duration,
    pub(crate) settled: bool,
}

pub(crate) fn wait_until_stable(target: &TargetProcess) -> AppResult<StabilityResult> {
    let space = AddressSpace::open_live(target)?;
    let started = Instant::now();
    let main = target
        .main_module
        .as_ref()
        .map(|module| module.base)
        .or(target.image_base);
    let mut previous = None;
    let mut matches = 0usize;
    for _index in 0..STABLE_POLL_COUNT {
        let regions = space.regions()?;
        let signature = memory_signature(&space, &regions, main);

        if previous == Some(signature) {
            matches = matches.saturating_add(1);

            if matches >= STABLE_MATCH_COUNT {
                return Ok(StabilityResult {
                    elapsed: started.elapsed(),
                    settled: true,
                });
            }
        } else {
            matches = 0;
            previous = Some(signature);
        }

        std::thread::sleep(STABLE_POLL_DELAY);
    }

    Ok(StabilityResult {
        elapsed: started.elapsed(),
        settled: false,
    })
}

fn memory_signature(space: &AddressSpace, regions: &[MemoryRegion], main: Option<usize>) -> u64 {
    let mut hash = DefaultHasher::new();
    for region in regions.iter().filter(|region| watched(region, main)) {
        region.hash(&mut hash);
    }

    for (address, length) in stability_pages(regions, main) {
        let mut page = [0u8; PAGE_SIZE];

        if space.read_exact(address, &mut page[..length]) {
            page[..length].hash(&mut hash);
        } else {
            u64::MAX.hash(&mut hash);
        }
    }

    hash.finish()
}

fn stability_pages(regions: &[MemoryRegion], main: Option<usize>) -> Vec<(usize, usize)> {
    let total_pages = regions
        .iter()
        .filter(|region| watched(region, main))
        .map(|region| region.size.div_ceil(PAGE_SIZE))
        .fold(0usize, usize::saturating_add);
    let sample_count = total_pages.min(MAX_STABILITY_READS);
    let mut pages = Vec::with_capacity(sample_count);
    let mut first_page = 0usize;
    let mut sample = 0usize;
    for region in regions.iter().filter(|region| watched(region, main)) {
        let region_pages = region.size.div_ceil(PAGE_SIZE);
        let past_region = first_page.saturating_add(region_pages);

        while sample < sample_count {
            let target = sample_page(sample, total_pages, sample_count);

            if target >= past_region {
                break;
            }

            let page = target.saturating_sub(first_page);
            let offset = page.saturating_mul(PAGE_SIZE);
            let address = region.base.saturating_add(offset);
            let length = region.size.saturating_sub(offset).min(PAGE_SIZE);
            pages.push((address, length));
            sample = sample.saturating_add(1);
        }

        first_page = past_region;
    }

    pages
}

fn sample_page(sample: usize, total_pages: usize, sample_count: usize) -> usize {
    if sample_count <= 1 {
        return 0;
    }

    let numerator = (sample as u128) * (total_pages.saturating_sub(1) as u128);
    let denominator = sample_count.saturating_sub(1) as u128;
    (numerator / denominator) as usize
}

fn watched(region: &MemoryRegion, main: Option<usize>) -> bool {
    let unpacked_into = match main {
        Some(main) => region.kind != MEM_IMAGE.0 || region.allocation_base == main,
        None => true,
    };
    unpacked_into && is_stability_region(region)
}

fn is_stability_region(region: &MemoryRegion) -> bool {
    region.state == MEM_COMMIT.0
        && is_readable(region.protect)
        && ((region.kind == MEM_IMAGE.0 && is_writable(region.protect))
            || is_executable(region.protect))
}
