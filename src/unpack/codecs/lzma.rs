use super::{DecodeError, Decoded};
use super::{copy_match, output_buffer};

const PROBABILITY_BITS: u32 = 11;
const PROBABILITY_START: u16 = 1 << (PROBABILITY_BITS - 1);
const MOVE_BITS: u32 = 5;
const TOP: u32 = 1 << 24;
const STATES: usize = 12;
const LITERAL_STATES: usize = 7; // below: came after a literal
const POSITION_STATE_BITS: u32 = 4;
const POSITION_STATES: usize = 1 << POSITION_STATE_BITS;
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
const SPECIAL_POSITIONS: usize = 115; // 114 models plus one below
const MIN_MATCH: usize = 2;
const END_MARKER: u32 = u32::MAX;
const LITERAL_CONTEXTS: u8 = 9; // (pb * 5 + lp) * 9 + lc
const LITERAL_POSITIONS: u8 = 5;
const PACKED_PROPERTY_LIMIT: u8 = LITERAL_CONTEXTS * LITERAL_POSITIONS * (MAX_POSITION_BITS + 1);

pub(crate) struct Properties {
    pub(crate) literal_context: u8,
    pub(crate) literal_position: u8,
    pub(crate) position: u8,
}

impl Properties {
    pub(crate) fn from_packed(packed: u8) -> Decoded<Self> {
        if packed >= PACKED_PROPERTY_LIMIT {
            return Err(DecodeError::BadHeader);
        }
        Ok(Self {
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
    fn new(data: &'a [u8]) -> Decoded<Self> {
        if *data.first().ok_or(DecodeError::BadHeader)? != 0 {
            return Err(DecodeError::BadHeader);
        }
        let code = u32::from_be_bytes(
            data.get(1..5)
                .ok_or(DecodeError::Truncated)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
        );

        Ok(Self {
            data,
            next: 5,
            range: u32::MAX,
            code,
        })
    }

    fn normalize(&mut self) -> Decoded<()> {
        if self.range < TOP {
            let byte = *self.data.get(self.next).ok_or(DecodeError::Truncated)?;
            self.next += 1;
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(byte);
        }

        Ok(())
    }

    fn bit(&mut self, probability: &mut u16) -> Decoded<u32> {
        self.normalize()?;
        let bound = (self.range >> PROBABILITY_BITS) * u32::from(*probability);

        if self.code < bound {
            self.range = bound;
            *probability += ((1 << PROBABILITY_BITS) - *probability) >> MOVE_BITS;
            return Ok(0);
        }

        self.range -= bound;
        self.code -= bound;
        *probability -= *probability >> MOVE_BITS;
        Ok(1)
    }

    fn direct(&mut self, count: u32) -> Decoded<u32> {
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

        Ok(value)
    }

    fn tree(&mut self, probabilities: &mut [u16], bits: u32) -> Decoded<u32> {
        let mut node = 1usize;
        for _ in 0..bits {
            node = (node << 1)
                | self.bit(probabilities.get_mut(node).ok_or(DecodeError::Corrupt)?)? as usize;
        }

        Ok(node as u32 - (1 << bits))
    }

    fn reverse_tree(&mut self, probabilities: &mut [u16], bits: u32) -> Decoded<u32> {
        let mut node = 1usize;
        let mut value = 0;

        for index in 0..bits {
            let bit = self.bit(probabilities.get_mut(node).ok_or(DecodeError::Corrupt)?)?;
            node = (node << 1) | bit as usize;
            value |= bit << index;
        }

        Ok(value)
    }
}

struct LengthDecoder {
    choice: u16,
    second_choice: u16,
    low: [[u16; 1 << LENGTH_LOW_BITS]; POSITION_STATES],
    mid: [[u16; 1 << LENGTH_LOW_BITS]; POSITION_STATES],
    high: [u16; 1 << LENGTH_HIGH_BITS],
}

impl LengthDecoder {
    fn new() -> Self {
        Self {
            choice: PROBABILITY_START,
            second_choice: PROBABILITY_START,
            low: [[PROBABILITY_START; 1 << LENGTH_LOW_BITS]; POSITION_STATES],
            mid: [[PROBABILITY_START; 1 << LENGTH_LOW_BITS]; POSITION_STATES],
            high: [PROBABILITY_START; 1 << LENGTH_HIGH_BITS],
        }
    }

    fn decode(&mut self, range: &mut RangeDecoder<'_>, position_state: usize) -> Decoded<usize> {
        if range.bit(&mut self.choice)? == 0 {
            return Ok(range.tree(&mut self.low[position_state], LENGTH_LOW_BITS)? as usize);
        }

        if range.bit(&mut self.second_choice)? == 0 {
            let mid = range.tree(&mut self.mid[position_state], LENGTH_LOW_BITS)? as usize;
            return Ok(LENGTH_MID_START + mid);
        }

        Ok(LENGTH_HIGH_START + range.tree(&mut self.high, LENGTH_HIGH_BITS)? as usize)
    }
}

struct History {
    state: usize,
    repeats: [usize; 4], // distances, one less than the bytes back
}

struct Models {
    literals: Vec<u16>,
    is_match: [u16; STATES * POSITION_STATES],
    is_repeat: [u16; STATES],
    is_repeat0: [u16; STATES],
    is_repeat1: [u16; STATES],
    is_repeat2: [u16; STATES],
    is_repeat0_long: [u16; STATES * POSITION_STATES],
    slots: [[u16; 1 << SLOT_BITS]; LENGTH_STATES],
    special: [u16; SPECIAL_POSITIONS],
    align: [u16; 1 << ALIGN_BITS],
    lengths: LengthDecoder,
    repeat_lengths: LengthDecoder,
}

impl Models {
    fn new(properties: &Properties) -> Self {
        let literal_coders = properties.literal_context + properties.literal_position;

        Self {
            literals: vec![PROBABILITY_START; LITERAL_CODER_SIZE << literal_coders],
            is_match: [PROBABILITY_START; STATES * POSITION_STATES],
            is_repeat: [PROBABILITY_START; STATES],
            is_repeat0: [PROBABILITY_START; STATES],
            is_repeat1: [PROBABILITY_START; STATES],
            is_repeat2: [PROBABILITY_START; STATES],
            is_repeat0_long: [PROBABILITY_START; STATES * POSITION_STATES],
            slots: [[PROBABILITY_START; 1 << SLOT_BITS]; LENGTH_STATES],
            special: [PROBABILITY_START; SPECIAL_POSITIONS],
            align: [PROBABILITY_START; 1 << ALIGN_BITS],
            lengths: LengthDecoder::new(),
            repeat_lengths: LengthDecoder::new(),
        }
    }

    fn literal(
        &mut self,
        range: &mut RangeDecoder<'_>,
        output: &[u8],
        properties: &Properties,
        history: &History,
    ) -> Decoded<u8> {
        let literal_mask = (1usize << properties.literal_position) - 1;
        let previous = usize::from(output.last().copied().unwrap_or(0));
        let context = ((output.len() & literal_mask) << properties.literal_context)
            + (previous >> (8 - properties.literal_context));
        let start = context * LITERAL_CODER_SIZE;
        let coder = self
            .literals
            .get_mut(start..start + LITERAL_CODER_SIZE)
            .ok_or(DecodeError::Corrupt)?;

        let byte = match history.state < LITERAL_STATES {
            true => range.tree(coder, 8)?,
            false => matched_literal(range, coder, look_back(output, history.repeats[0])?)?,
        };

        Ok(byte as u8)
    }

    // none: one byte from the last distance
    fn repeat(
        &mut self,
        range: &mut RangeDecoder<'_>,
        history: &mut History,
        position_state: usize,
    ) -> Decoded<Option<usize>> {
        let state = history.state;
        let state_index = (state << POSITION_STATE_BITS) + position_state;

        if range.bit(&mut self.is_repeat0[state])? == 0 {
            if range.bit(&mut self.is_repeat0_long[state_index])? == 0 {
                history.state = if state < LITERAL_STATES { 9 } else { 11 };
                return Ok(None);
            }
        } else {
            let index = if range.bit(&mut self.is_repeat1[state])? == 0 {
                1
            } else if range.bit(&mut self.is_repeat2[state])? == 0 {
                2
            } else {
                3
            };
            history.repeats[..=index].rotate_right(1);
        }

        history.state = if state < LITERAL_STATES { 8 } else { 11 };
        self.repeat_lengths.decode(range, position_state).map(Some)
    }

    // none: the end marker
    fn new_match(
        &mut self,
        range: &mut RangeDecoder<'_>,
        history: &mut History,
        position_state: usize,
    ) -> Decoded<Option<usize>> {
        let length = self.lengths.decode(range, position_state)?;
        let Some(distance) = self.distance(range, length)? else {
            return Ok(None);
        };

        history.repeats.rotate_right(1);
        history.repeats[0] = distance;
        history.state = if history.state < LITERAL_STATES {
            7
        } else {
            10
        };
        Ok(Some(length))
    }

    fn distance(&mut self, range: &mut RangeDecoder<'_>, length: usize) -> Decoded<Option<usize>> {
        let slot_state = length.min(LENGTH_STATES - 1);
        let slot = range.tree(&mut self.slots[slot_state], SLOT_BITS)?;
        if slot < FIRST_SLOT_WITH_BITS {
            return Ok(Some(slot as usize));
        }

        let bits = (slot >> 1) - 1;
        let base = (2 | (slot & 1)) << bits;
        let low = if slot < END_SLOT_MODEL {
            let models = self
                .special
                .get_mut((base - slot) as usize..)
                .ok_or(DecodeError::Corrupt)?;
            range.reverse_tree(models, bits)?
        } else {
            let high = range.direct(bits - ALIGN_BITS)? << ALIGN_BITS;
            high + range.reverse_tree(&mut self.align, ALIGN_BITS)?
        };
        let distance = base + low;

        Ok((distance != END_MARKER).then_some(distance as usize))
    }
}

pub(crate) fn decompress(source: &[u8], properties: &Properties, size: usize) -> Decoded<Vec<u8>> {
    let valid = properties.literal_context <= MAX_LITERAL_CONTEXT
        && properties.literal_position <= MAX_POSITION_BITS
        && properties.position <= MAX_POSITION_BITS;
    if !valid {
        // mpress allows lc up to 8
        return Err(DecodeError::Corrupt);
    }

    let mut range = RangeDecoder::new(source)?;
    let mut models = Models::new(properties);
    let mut output = output_buffer(size)?;
    let mut history = History {
        state: 0,
        repeats: [0; 4],
    };
    let position_mask = (1usize << properties.position) - 1;

    while output.len() < size {
        let position_state = output.len() & position_mask;
        let state_index = (history.state << POSITION_STATE_BITS) + position_state;

        if range.bit(&mut models.is_match[state_index])? == 0 {
            let byte = models.literal(&mut range, &output, properties, &history)?;
            output.push(byte);
            history.state = match history.state {
                0..4 => 0,
                4..10 => history.state - 3,
                _ => history.state - 6,
            };
            continue;
        }

        let length = if range.bit(&mut models.is_repeat[history.state])? == 1 {
            if output.is_empty() {
                return Err(DecodeError::Corrupt);
            }

            let Some(length) = models.repeat(&mut range, &mut history, position_state)? else {
                let byte = look_back(&output, history.repeats[0])?;
                output.push(byte);
                continue;
            };
            length
        } else {
            // the size is not reached yet, so an end marker is early
            models
                .new_match(&mut range, &mut history, position_state)?
                .ok_or(DecodeError::Truncated)?
        };

        let back = history.repeats[0]
            .checked_add(1)
            .ok_or(DecodeError::BadDistance)?;
        copy_match(&mut output, back, length + MIN_MATCH, size)?;
    }

    Ok(output)
}

fn look_back(output: &[u8], repeat: usize) -> Decoded<u8> {
    let back = repeat.checked_add(1).ok_or(DecodeError::BadDistance)?;
    let from = output
        .len()
        .checked_sub(back)
        .ok_or(DecodeError::BadDistance)?;

    output.get(from).copied().ok_or(DecodeError::BadDistance)
}

fn matched_literal(range: &mut RangeDecoder<'_>, coder: &mut [u16], matched: u8) -> Decoded<u32> {
    let mut matched = u32::from(matched);
    let mut node = 1u32;

    while node < 0x100 {
        let match_bit = (matched >> 7) & 1;
        matched <<= 1;

        let index = 0x100 + (match_bit << 8) + node;
        let bit = range.bit(coder.get_mut(index as usize).ok_or(DecodeError::Corrupt)?)?;
        node = (node << 1) | bit;

        if match_bit != bit {
            while node < 0x100 {
                node = (node << 1)
                    | range.bit(coder.get_mut(node as usize).ok_or(DecodeError::Corrupt)?)?;
            }
        }
    }

    Ok(node - 0x100)
}
