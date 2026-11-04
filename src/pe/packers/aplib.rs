const TAG_SENTINEL: u8 = 0x80;
const REPEAT_OFFSET: u32 = 2; // a gamma offset of 2 reuses the previous match offset
const OFFSET_BIAS: u32 = 3;
const LONG_OFFSET: u32 = 0x7D00;
const MEDIUM_OFFSET: u32 = 0x500;
const SHORT_OFFSET: u32 = 0x80;
const NEAR_BITS: u32 = 4;

struct Bits<'a> {
    data: &'a [u8],
    next: usize,
    tag: u8,
}

impl Bits<'_> {
    fn byte(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.next)?;
        self.next += 1;
        Some(byte)
    }

    fn bit(&mut self) -> Option<u32> {
        let mut bit = u32::from(self.tag >> 7);
        self.tag <<= 1;

        if self.tag == 0 {
            let byte = self.byte()?;
            bit = u32::from(byte >> 7);
            self.tag = (byte << 1) | 1; // the sentinel that just left marks the refill
        }

        Some(bit)
    }

    fn gamma(&mut self) -> Option<u32> {
        let mut value = 1u32;
        loop {
            value = value.checked_mul(2)?.checked_add(self.bit()?)?;
            if self.bit()? == 0 {
                return Some(value);
            }
        }
    }
}

pub(super) fn decompress(source: &[u8], size: usize) -> Option<Vec<u8>> {
    let mut bits = Bits {
        data: source,
        next: 0,
        tag: TAG_SENTINEL,
    };
    let mut output = Vec::with_capacity(size);
    let mut last_offset = 0u32;

    output.push(bits.byte()?);

    loop {
        (output.len() <= size).then_some(())?; // a full buffer may only be followed by the end marker

        if bits.bit()? == 0 {
            output.push(bits.byte()?);
            continue;
        }

        let (offset, length) = if bits.bit()? == 0 {
            let high = bits.gamma()?;

            if high == REPEAT_OFFSET {
                (last_offset, bits.gamma()?)
            } else {
                let offset = ((high - OFFSET_BIAS) << 8) | u32::from(bits.byte()?);
                let length = bits.gamma()?
                    + match offset {
                        LONG_OFFSET.. => 2,
                        MEDIUM_OFFSET.. => 1,
                        0..SHORT_OFFSET => 2,
                        _ => 0,
                    };
                last_offset = offset;
                (offset, length)
            }
        } else if bits.bit()? == 0 {
            let byte = u32::from(bits.byte()?);
            let offset = byte >> 1;

            if offset == 0 {
                return Some(output);
            }

            last_offset = offset;
            (offset, 2 + (byte & 1))
        } else {
            let offset = (0..NEAR_BITS).try_fold(0, |value, _| Some((value << 1) | bits.bit()?))?;
            let byte = match offset {
                0 => 0,
                _ => *output.get(output.len().checked_sub(offset as usize)?)?,
            };

            output.push(byte);
            continue;
        };

        let from = output.len().checked_sub(offset as usize)?;
        (output.len().checked_add(length as usize)? <= size).then_some(())?;

        for index in from..from + length as usize {
            output.push(output[index]);
        }
    }
}
