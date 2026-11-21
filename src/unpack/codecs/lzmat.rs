use super::{DecodeError, Decoded};
use super::{copy_match, output_buffer};

const FLAG_BITS: usize = 8;
const FLAG_MATCH: u32 = 0x80;
const SHORT_WINDOW: usize = 0x881; // short distance encoding below this
const RAW_RUN: u32 = 0x10110; // raw run marker
const RAW_CHUNK: usize = 4;

struct Nibbles<'a> {
    data: &'a [u8],
    at: usize,
    half: usize, // 1: half a byte into data[at]
}

impl Nibbles<'_> {
    // fields are read wider than they are; within() refuses what was used past the end
    fn byte(&self, at: usize) -> u32 {
        u32::from(self.data.get(at).copied().unwrap_or(0))
    }

    fn u8_at(&self, at: usize) -> u32 {
        match self.half {
            0 => self.byte(at),
            _ => (self.byte(at) >> 4) | ((self.byte(at + 1) << 4) & 0xFF),
        }
    }

    fn u16_at(&self, at: usize) -> u32 {
        let value = (0..4).fold(0, |value, index| {
            value | (self.byte(at + index) << (index * 8))
        });

        match self.half {
            0 => value & 0xFFFF,
            _ => (value >> 4) & 0xFFFF,
        }
    }

    fn nibble(&mut self) -> u32 {
        let value = match self.half {
            0 => self.byte(self.at) & 0xF,
            _ => {
                let value = self.byte(self.at) >> 4;
                self.at += 1;
                value
            }
        };

        self.half ^= 1;
        value
    }

    fn step_half(&mut self) {
        self.at += self.half;
        self.half ^= 1;
    }

    fn more(&self) -> bool {
        self.at < self.data.len().saturating_sub(self.half)
    }

    fn within(&self) -> Decoded<()> {
        let used = self.at.saturating_mul(2).saturating_add(self.half);

        match used <= self.data.len().saturating_mul(2) {
            true => Ok(()),
            false => Err(DecodeError::Truncated),
        }
    }
}

pub(crate) fn decompress(source: &[u8], size: usize) -> Decoded<Vec<u8>> {
    let mut output = output_buffer(size)?;
    if size == 0 {
        return Err(DecodeError::Corrupt);
    }
    output.push(*source.first().ok_or(DecodeError::Corrupt)?);

    let mut input = Nibbles {
        data: source,
        at: 1,
        half: 0,
    };

    while input.more() && output.len() < size {
        let mut flags = input.u8_at(input.at);
        input.at += 1;

        for _ in 0..FLAG_BITS {
            if !input.more() || output.len() >= size {
                break;
            }

            if flags & FLAG_MATCH == 0 {
                let byte = input.u8_at(input.at) as u8;
                input.at += 1;
                input.within()?;

                output.push(byte);
                flags <<= 1;
                continue;
            }

            let distance = read_distance(&mut input, output.len())?;
            let Length::Match(length) = read_length(&mut input) else {
                copy_raw_run(&mut input, &mut output, size, flags)?;
                break;
            };
            input.within()?;

            copy_match(&mut output, distance as usize, length as usize, size)?;
            flags <<= 1;
        }
    }

    match output.len() == size {
        true => Ok(output),
        false => Err(DecodeError::Truncated),
    }
}

fn read_distance(input: &mut Nibbles<'_>, written: usize) -> Decoded<u32> {
    let word = input.u16_at(input.at);
    input.at += 1;

    if written < SHORT_WINDOW {
        let distance = word >> 1;
        return Ok(match word & 1 {
            0 => (distance & 0x7F) + 1,
            _ => {
                input.step_half();
                (distance & 0x7FF) + 0x81
            }
        });
    }

    let distance = word >> 2;
    Ok(match word & 3 {
        0 => (distance & 0x3F) + 1,
        1 => {
            input.step_half();
            (distance & 0x3FF) + 0x41
        }
        2 => {
            input.at += 1;
            distance + 0x441
        }
        _ => {
            if input.at + 2 + input.half > input.data.len() {
                return Err(DecodeError::Corrupt);
            }
            input.at += 1;
            distance + (input.nibble() << 14) + 0x4441
        }
    })
}

enum Length {
    Match(u32),
    RawRun,
}

fn read_length(input: &mut Nibbles<'_>) -> Length {
    let length = input.nibble();
    if length != 0xF {
        return Length::Match(length + 3);
    }

    let length = input.u8_at(input.at);
    input.at += 1;
    if length != 0xFF {
        return Length::Match(length + 0x12);
    }

    let length = input.u16_at(input.at) + 0x111;
    input.at += 2;
    match length == RAW_RUN {
        true => Length::RawRun,
        false => Length::Match(length),
    }
}

fn copy_raw_run(
    input: &mut Nibbles<'_>,
    output: &mut Vec<u8>,
    size: usize,
    flags: u32,
) -> Decoded<()> {
    input.within()?;

    let count = match input.half {
        0 => (input.u16_at(input.at.checked_sub(5).ok_or(DecodeError::Corrupt)?) & 0xFC0) << 1,
        _ => {
            let count =
                (input.byte(input.at.checked_sub(4).ok_or(DecodeError::Corrupt)?) & 0xFC) << 5;
            input.at += 1;
            input.half = 0;
            count
        }
    };
    let chunks = (count + (flags & 0x7F) + 4) << 1;
    let length = (chunks as usize).saturating_mul(RAW_CHUNK);

    if output.len().saturating_add(length) > size {
        return Err(DecodeError::Overrun);
    }

    let end = input.at.checked_add(length).ok_or(DecodeError::Truncated)?;
    let run = input
        .data
        .get(input.at..end)
        .ok_or(DecodeError::Truncated)?;

    output.extend_from_slice(run);
    input.at = end;
    Ok(())
}
