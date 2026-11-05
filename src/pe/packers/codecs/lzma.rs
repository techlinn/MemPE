use super::output_buffer;

const PROBABILITY_BITS: u32 = 11;
const PROBABILITY_START: u16 = 1 << (PROBABILITY_BITS - 1);
const MOVE_BITS: u32 = 5;
const TOP: u32 = 1 << 24;
const READ_SLACK: usize = 8; // the range coder may look a few bytes past the stream
const STATES: usize = 12;
const LITERAL_STATES: usize = 7; // states below this one came after a literal
const POSITION_STATES: usize = 16;
const LITERAL_CODER_SIZE: usize = 0x300;
const MAX_LITERAL_CONTEXT: u8 = 8;
const MAX_POSITION_BITS: u8 = 4;
const LENGTH_LOW_BITS: u32 = 3;
const LENGTH_HIGH_BITS: u32 = 8;
const LENGTH_MID_START: usize = 8;
const LENGTH_HIGH_START: usize = 16;
const LENGTH_STATES: usize = 4;
const SLOT_BITS: u32 = 6;
const FIRST_SLOT_WITH_BITS: u32 = 4;
const END_SLOT_MODEL: u32 = 14;
const ALIGN_BITS: u32 = 4;
const SPECIAL_POSITIONS: usize = 115; // 114 models plus one below, where the first reverse tree starts
const MIN_MATCH: usize = 2;
const END_MARKER: u32 = u32::MAX;
const LITERAL_CONTEXTS: u8 = 9; // the standard properties byte packs (pb * 5 + lp) * 9 + lc
const LITERAL_POSITIONS: u8 = 5;
const PACKED_PROPERTY_LIMIT: u8 = 9 * 5 * 5;

pub(crate) struct Properties {
    pub(crate) literal_context: u8,
    pub(crate) literal_position: u8,
    pub(crate) position: u8,
}

impl Properties {
    pub(crate) fn from_packed(packed: u8) -> Option<Self> {
        (packed < PACKED_PROPERTY_LIMIT).then_some(())?;
        Some(Self {
            literal_context: packed % LITERAL_CONTEXTS,
            literal_position: packed / LITERAL_CONTEXTS % LITERAL_POSITIONS,
            position: packed / (LITERAL_CONTEXTS * LITERAL_POSITIONS),
        })
    }
}

struct RangeDecoder<'a> {
    data: &'a [u8],
    next: usize,
    range: u32,
    code: u32,
}

impl<'a> RangeDecoder<'a> {
    fn new(data: &'a [u8]) -> Option<Self> {
        (*data.first()? == 0).then_some(())?;
        let code = u32::from_be_bytes(data.get(1..5)?.try_into().ok()?);

        Some(Self {
            data,
            next: 5,
            range: u32::MAX,
            code,
        })
    }

    fn normalize(&mut self) -> Option<()> {
        if self.range < TOP {
            (self.next <= self.data.len() + READ_SLACK).then_some(())?;

            let byte = self.data.get(self.next).copied().unwrap_or(0);
            self.next += 1;
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(byte);
        }

        Some(())
    }

    fn bit(&mut self, probability: &mut u16) -> Option<u32> {
        self.normalize()?;
        let bound = (self.range >> PROBABILITY_BITS) * u32::from(*probability);

        if self.code < bound {
            self.range = bound;
            *probability += ((1 << PROBABILITY_BITS) - *probability) >> MOVE_BITS;
            return Some(0);
        }

        self.range -= bound;
        self.code -= bound;
        *probability -= *probability >> MOVE_BITS;
        Some(1)
    }

    fn direct(&mut self, count: u32) -> Option<u32> {
        let mut value = 0;
        for _ in 0..count {
            self.normalize()?;
            self.range >>= 1;

            let bit = u32::from(self.code >= self.range);
            if bit == 1 {
                self.code -= self.range;
            }
            value = (value << 1) | bit;
        }

        Some(value)
    }

    fn tree(&mut self, probabilities: &mut [u16], bits: u32) -> Option<u32> {
        let mut node = 1usize;
        for _ in 0..bits {
            node = (node << 1) | self.bit(probabilities.get_mut(node)?)? as usize;
        }

        Some(node as u32 - (1 << bits))
    }

    fn reverse_tree(&mut self, probabilities: &mut [u16], bits: u32) -> Option<u32> {
        let mut node = 1usize;
        let mut value = 0;

        for index in 0..bits {
            let bit = self.bit(probabilities.get_mut(node)?)?;
            node = (node << 1) | bit as usize;
            value |= bit << index;
        }

        Some(value)
    }
}

struct LengthDecoder {
    choice: u16,
    second_choice: u16,
    low: [[u16; 8]; POSITION_STATES],
    mid: [[u16; 8]; POSITION_STATES],
    high: [u16; 256],
}

impl LengthDecoder {
    fn new() -> Self {
        Self {
            choice: PROBABILITY_START,
            second_choice: PROBABILITY_START,
            low: [[PROBABILITY_START; 8]; POSITION_STATES],
            mid: [[PROBABILITY_START; 8]; POSITION_STATES],
            high: [PROBABILITY_START; 256],
        }
    }

    fn decode(&mut self, range: &mut RangeDecoder<'_>, position_state: usize) -> Option<usize> {
        if range.bit(&mut self.choice)? == 0 {
            return Some(range.tree(&mut self.low[position_state], LENGTH_LOW_BITS)? as usize);
        }

        if range.bit(&mut self.second_choice)? == 0 {
            let mid = range.tree(&mut self.mid[position_state], LENGTH_LOW_BITS)? as usize;
            return Some(LENGTH_MID_START + mid);
        }

        Some(LENGTH_HIGH_START + range.tree(&mut self.high, LENGTH_HIGH_BITS)? as usize)
    }
}

pub(crate) fn decompress(source: &[u8], properties: &Properties, size: usize) -> Option<Vec<u8>> {
    let Properties {
        literal_context,
        literal_position,
        position,
    } = *properties;
    let valid = literal_context <= MAX_LITERAL_CONTEXT
        && literal_position <= MAX_POSITION_BITS
        && position <= MAX_POSITION_BITS;
    valid.then_some(())?; // mpress allows any literal context up to 8, unlike lzma alone

    let mut range = RangeDecoder::new(source)?;
    let position_mask = (1usize << position) - 1;
    let literal_mask = (1usize << literal_position) - 1;

    let mut literals =
        vec![PROBABILITY_START; LITERAL_CODER_SIZE << (literal_context + literal_position)];
    let mut is_match = [PROBABILITY_START; STATES * POSITION_STATES];
    let mut is_repeat = [PROBABILITY_START; STATES];
    let mut is_repeat0 = [PROBABILITY_START; STATES];
    let mut is_repeat1 = [PROBABILITY_START; STATES];
    let mut is_repeat2 = [PROBABILITY_START; STATES];
    let mut is_repeat0_long = [PROBABILITY_START; STATES * POSITION_STATES];
    let mut slots = [[PROBABILITY_START; 1 << SLOT_BITS]; LENGTH_STATES];
    let mut special = [PROBABILITY_START; SPECIAL_POSITIONS];
    let mut align = [PROBABILITY_START; 1 << ALIGN_BITS];
    let mut lengths = LengthDecoder::new();
    let mut repeat_lengths = LengthDecoder::new();

    let mut output = output_buffer(size)?;
    let mut state = 0usize;
    let mut repeats = [0usize; 4];

    while output.len() < size {
        let position_state = output.len() & position_mask;
        let state_index = (state << 4) + position_state;

        if range.bit(&mut is_match[state_index])? == 0 {
            let previous = usize::from(output.last().copied().unwrap_or(0));
            let context = ((output.len() & literal_mask) << literal_context)
                + (previous >> (8 - literal_context));
            let start = context * LITERAL_CODER_SIZE;
            let coder = literals.get_mut(start..start + LITERAL_CODER_SIZE)?;

            let byte = match state < LITERAL_STATES {
                true => range.tree(coder, 8)?,
                false => {
                    let matched = *output.get(output.len().checked_sub(repeats[0] + 1)?)?;
                    matched_literal(&mut range, coder, matched)?
                }
            };

            output.push(byte as u8);
            state = match state {
                0..4 => 0,
                4..10 => state - 3,
                _ => state - 6,
            };
            continue;
        }

        let length = if range.bit(&mut is_repeat[state])? == 1 {
            (!output.is_empty()).then_some(())?;

            if range.bit(&mut is_repeat0[state])? == 0 {
                if range.bit(&mut is_repeat0_long[state_index])? == 0 {
                    state = if state < LITERAL_STATES { 9 } else { 11 };
                    let byte = *output.get(output.len().checked_sub(repeats[0] + 1)?)?;
                    output.push(byte);
                    continue;
                }
            } else {
                let index = if range.bit(&mut is_repeat1[state])? == 0 {
                    1
                } else if range.bit(&mut is_repeat2[state])? == 0 {
                    2
                } else {
                    3
                };
                repeats[..=index].rotate_right(1);
            }

            state = if state < LITERAL_STATES { 8 } else { 11 };
            repeat_lengths.decode(&mut range, position_state)?
        } else {
            repeats.rotate_right(1);
            let length = lengths.decode(&mut range, position_state)?;
            state = if state < LITERAL_STATES { 7 } else { 10 };

            let slot_state = length.min(LENGTH_STATES - 1);
            let slot = range.tree(&mut slots[slot_state], SLOT_BITS)?;
            let distance = match slot < FIRST_SLOT_WITH_BITS {
                true => slot,
                false => {
                    let bits = (slot >> 1) - 1;
                    let base = (2 | (slot & 1)) << bits;

                    if slot < END_SLOT_MODEL {
                        let models = special.get_mut((base - slot) as usize..)?;
                        base + range.reverse_tree(models, bits)?
                    } else {
                        let high = range.direct(bits - ALIGN_BITS)? << ALIGN_BITS;
                        base + high + range.reverse_tree(&mut align, ALIGN_BITS)?
                    }
                }
            };

            if distance == END_MARKER {
                break;
            }

            repeats[0] = distance as usize;
            length
        };

        let from = output.len().checked_sub(repeats[0] + 1)?;
        let count = (length + MIN_MATCH).min(size - output.len());
        for index in from..from + count {
            output.push(output[index]);
        }
    }

    Some(output)
}

fn matched_literal(range: &mut RangeDecoder<'_>, coder: &mut [u16], matched: u8) -> Option<u32> {
    let mut matched = u32::from(matched);
    let mut node = 1u32;

    while node < 0x100 {
        let match_bit = (matched >> 7) & 1;
        matched <<= 1;

        let index = 0x100 + (match_bit << 8) + node;
        let bit = range.bit(coder.get_mut(index as usize)?)?;
        node = (node << 1) | bit;

        if match_bit != bit {
            while node < 0x100 {
                node = (node << 1) | range.bit(coder.get_mut(node as usize)?)?;
            }
        }
    }

    Some(node - 0x100)
}
