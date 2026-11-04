const FLAG_BITS: usize = 8;
const FLAG_MATCH: u32 = 0x80;
const SHORT_WINDOW: usize = 0x881; // before this much output, distances use the short encoding
const RAW_RUN: u32 = 0x10110; // this length marks a run of bytes copied as is
const RAW_CHUNK: usize = 4;

struct Nibbles<'a> {
    data: &'a [u8],
    at: usize,
    half: usize, // 1 when the stream sits half a byte into data[at]
}

impl Nibbles<'_> {
    fn byte(&self, at: usize) -> u32 {
        u32::from(self.data.get(at).copied().unwrap_or(0)) // the format reads a little past its end
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
}

pub(super) fn decompress(source: &[u8], size: usize) -> Option<Vec<u8>> {
    let mut output = vec![0u8; size];
    *output.first_mut()? = *source.first()?;

    let mut input = Nibbles {
        data: source,
        at: 1,
        half: 0,
    };
    let mut written = 1;

    while input.more() && written < size {
        let mut flags = input.u8_at(input.at);
        input.at += 1;

        for _ in 0..FLAG_BITS {
            if !input.more() || written >= size {
                break;
            }

            if flags & FLAG_MATCH == 0 {
                output[written] = input.u8_at(input.at) as u8;
                input.at += 1;
                written += 1;
                flags <<= 1;
                continue;
            }

            let distance = read_distance(&mut input, written)?;
            let Some(length) = read_length(&mut input) else {
                copy_raw_run(&mut input, &mut output, &mut written, flags)?;
                break;
            };

            let from = written.checked_sub(distance as usize)?;
            let count = (length as usize).min(size - written);
            for index in 0..count {
                output[written + index] = output[from + index];
            }

            written += count;
            flags <<= 1;
        }
    }

    Some(output)
}

fn read_distance(input: &mut Nibbles<'_>, written: usize) -> Option<u32> {
    let word = input.u16_at(input.at);
    input.at += 1;

    if written < SHORT_WINDOW {
        let distance = word >> 1;
        return Some(match word & 1 {
            0 => (distance & 0x7F) + 1,
            _ => {
                input.step_half();
                (distance & 0x7FF) + 0x81
            }
        });
    }

    let distance = word >> 2;
    Some(match word & 3 {
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
            (input.at + 2 + input.half <= input.data.len()).then_some(())?;
            input.at += 1;
            distance + (input.nibble() << 14) + 0x4441
        }
    })
}

fn read_length(input: &mut Nibbles<'_>) -> Option<u32> {
    let length = input.nibble();
    if length != 0xF {
        return Some(length + 3);
    }

    let length = input.u8_at(input.at);
    input.at += 1;
    if length != 0xFF {
        return Some(length + 0x12);
    }

    let length = input.u16_at(input.at) + 0x111;
    input.at += 2;
    (length != RAW_RUN).then_some(length)
}

fn copy_raw_run(
    input: &mut Nibbles<'_>,
    output: &mut [u8],
    written: &mut usize,
    flags: u32,
) -> Option<()> {
    let count = match input.half {
        0 => (input.u16_at(input.at.checked_sub(5)?) & 0xFC0) << 1,
        _ => {
            let count = (input.byte(input.at.checked_sub(4)?) & 0xFC) << 5;
            input.at += 1;
            input.half = 0;
            count
        }
    };
    let chunks = (count + (flags & 0x7F) + 4) << 1;

    for _ in 0..chunks {
        if *written >= output.len() {
            break;
        }

        let take = RAW_CHUNK.min(output.len() - *written);
        for index in 0..take {
            output[*written + index] = input.byte(input.at + index) as u8;
        }

        *written += RAW_CHUNK;
        input.at += RAW_CHUNK;
    }

    Some(())
}
