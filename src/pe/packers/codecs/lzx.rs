use super::output_buffer;

const MAIN_SYMBOLS: usize = 721;
const LENGTH_SYMBOLS: usize = 28;
const ALIGNED_SYMBOLS: usize = 8;
const ALL_SYMBOLS: usize = MAIN_SYMBOLS + LENGTH_SYMBOLS + ALIGNED_SYMBOLS;
const PRETREE_SYMBOLS: usize = 19;
const PRETREE_BITS: u32 = 4;
const NEW_TABLES: u16 = 720; // a fresh set of code lengths follows in the stream
const LITERALS: u16 = 256;
const MATCH_LENGTH_BITS: u16 = 3;
const LONG_MATCH: u16 = 7;
const MIN_MATCH: usize = 2;
const OFFSET_SLOTS: usize = 58;
const REPEATED_OFFSETS: usize = 3;
const ALIGNED_BITS: u32 = 3;
const DEFAULT_ALIGNED_LENGTH: u8 = 3; // every aligned length at 3 switches the aligned tree off
const MAX_CODE_LENGTH: u32 = 15;
const WINDOW_BITS: u32 = 24;
const LENGTH_WRAP: u8 = 16;
const REPEAT_LENGTH: u16 = 16;
const SHORT_ZEROS: u16 = 17;
const LONG_ZEROS: u16 = 18;
const READ_SLACK: usize = 8; // the stub reads a little past each block
const FILTER_SPAN: usize = 5;
const FILTER_CALL: u8 = 0xE8;
const FILTER_JUMP: u8 = 0xE9;

pub(crate) struct Tables<'a> {
    length_base: &'a [u8],
    length_bits: &'a [u8],
    offset_bits: &'a [u8],
}

impl<'a> Tables<'a> {
    pub(crate) const SIZE: usize = LENGTH_SYMBOLS * 2 + OFFSET_SLOTS; // length bases, length bits, offset bits

    pub(crate) fn new(bytes: &'a [u8]) -> Option<Self> {
        let bytes = bytes.get(..Self::SIZE)?;
        let (lengths, offset_bits) = bytes.split_at(LENGTH_SYMBOLS * 2);
        let (length_base, length_bits) = lengths.split_at(LENGTH_SYMBOLS);
        Some(Self {
            length_base,
            length_bits,
            offset_bits,
        })
    }
}

struct Bits<'a> {
    data: &'a [u8],
    next: usize,
    buffer: u64,
    count: u32,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            next: 0,
            buffer: 0,
            count: 0,
        }
    }

    fn peek(&mut self) -> Option<u32> {
        while self.count < WINDOW_BITS {
            if self.next > self.data.len().saturating_add(READ_SLACK) {
                return None;
            }

            let byte = self.data.get(self.next).copied().unwrap_or(0);
            self.next += 1;
            self.buffer = (self.buffer << 8) | u64::from(byte);
            self.count += 8;
        }

        let window = (self.buffer >> (self.count - WINDOW_BITS)) & ((1 << WINDOW_BITS) - 1);

        Some(window as u32)
    }

    fn skip(&mut self, bits: u32) {
        self.count -= bits;
    }

    fn take(&mut self, bits: u32) -> Option<u32> {
        if bits == 0 {
            return Some(0);
        }

        let value = self.peek()? >> (WINDOW_BITS - bits);
        self.skip(bits);
        Some(value)
    }
}

struct Huffman {
    limits: [u64; MAX_CODE_LENGTH as usize + 1],
    starts: [u64; MAX_CODE_LENGTH as usize + 1],
    firsts: [usize; MAX_CODE_LENGTH as usize + 1],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Option<Self> {
        let mut counts = [0u64; MAX_CODE_LENGTH as usize + 1];
        for length in lengths {
            *counts.get_mut(usize::from(*length))? += 1;
        }

        let mut symbols = (0..lengths.len())
            .filter(|symbol| lengths[*symbol] != 0)
            .map(|symbol| u16::try_from(symbol).ok())
            .collect::<Option<Vec<_>>>()?;
        symbols.sort_by_key(|symbol| lengths[usize::from(*symbol)]);

        let mut tree = Self {
            limits: [0; MAX_CODE_LENGTH as usize + 1],
            starts: [0; MAX_CODE_LENGTH as usize + 1],
            firsts: [0; MAX_CODE_LENGTH as usize + 1],
            symbols,
        };

        let mut total = 0u64;
        let mut index = 0usize;

        for (length, count) in counts.iter().enumerate().skip(1) {
            tree.starts[length] = total;
            tree.firsts[length] = index;
            total += count << (WINDOW_BITS as usize - length);
            tree.limits[length] = total;
            index += *count as usize;
        }

        (total == 0 || total == 1 << WINDOW_BITS).then_some(tree) // an unused tree may be empty
    }

    fn decode(&self, bits: &mut Bits<'_>) -> Option<u16> {
        let window = u64::from(bits.peek()?);
        let length = (1..=MAX_CODE_LENGTH as usize).find(|length| window < self.limits[*length])?;
        bits.skip(length as u32);

        let offset = (window - self.starts[length]) >> (WINDOW_BITS as usize - length);
        self.symbols
            .get(self.firsts[length].checked_add(offset as usize)?)
            .copied()
    }
}

struct Trees {
    main: Huffman,
    length: Huffman,
    aligned: Option<Huffman>,
}

fn read_trees(bits: &mut Bits<'_>, previous: &mut [u8; ALL_SYMBOLS]) -> Option<Trees> {
    if bits.take(1)? == 0 {
        previous.fill(0);
    }

    let pretree = (0..PRETREE_SYMBOLS)
        .map(|_| u8::try_from(bits.take(PRETREE_BITS)?).ok())
        .collect::<Option<Vec<_>>>()?;
    let pretree = Huffman::new(&pretree)?;

    let mut lengths = Vec::with_capacity(ALL_SYMBOLS);
    while lengths.len() < ALL_SYMBOLS {
        let code = pretree.decode(bits)?;
        let (value, count) = match code {
            REPEAT_LENGTH => (lengths.last().copied().unwrap_or(0), 3 + bits.take(2)?),
            SHORT_ZEROS => (0, 3 + bits.take(3)?),
            LONG_ZEROS => (0, 11 + bits.take(7)?),
            delta => {
                let delta = u8::try_from(delta).ok()?;
                ((previous[lengths.len()] + delta) % LENGTH_WRAP, 1)
            }
        };

        lengths.extend(std::iter::repeat_n(value, count as usize));
    }

    lengths.truncate(ALL_SYMBOLS);
    previous.copy_from_slice(&lengths);

    let (main, rest) = lengths.split_at(MAIN_SYMBOLS);
    let (length, aligned) = rest.split_at(LENGTH_SYMBOLS);
    let uses_aligned = aligned.iter().any(|bits| *bits != DEFAULT_ALIGNED_LENGTH);

    Some(Trees {
        main: Huffman::new(main)?,
        length: Huffman::new(length)?,
        aligned: match uses_aligned {
            true => Some(Huffman::new(aligned)?),
            false => None,
        },
    })
}

pub(crate) fn decompress(source: &[u8], size: usize, tables: &Tables<'_>) -> Option<Vec<u8>> {
    let offset_base = tables
        .offset_bits
        .iter()
        .scan(0u32, |base, bits| {
            let current = *base;
            *base = base.checked_add(1u32.checked_shl(u32::from(*bits))?)?;
            Some(current)
        })
        .collect::<Vec<_>>();
    (offset_base.len() == OFFSET_SLOTS).then_some(())?;

    let mut bits = Bits::new(source);
    let mut previous = [0u8; ALL_SYMBOLS];
    let mut trees = read_trees(&mut bits, &mut previous)?;
    let mut output = output_buffer(size)?;
    let mut repeats = [0usize; REPEATED_OFFSETS];

    while output.len() < size {
        let symbol = trees.main.decode(&mut bits)?;

        if symbol < LITERALS {
            output.push(u8::try_from(symbol).ok()?);
            continue;
        }

        if symbol >= NEW_TABLES {
            trees = read_trees(&mut bits, &mut previous)?;
            continue;
        }

        let code = symbol - LITERALS;
        let slot = usize::from(code >> MATCH_LENGTH_BITS);
        let short = code & ((1 << MATCH_LENGTH_BITS) - 1);
        let mut length = usize::from(short) + MIN_MATCH;

        if short == LONG_MATCH {
            let index = usize::from(trees.length.decode(&mut bits)?);
            let extra = bits.take(u32::from(*tables.length_bits.get(index)?))?;
            length += usize::from(*tables.length_base.get(index)?) + extra as usize;
        }

        let extra_bits = u32::from(*tables.offset_bits.get(slot)?);
        let mut value = *offset_base.get(slot)? as usize;

        match &trees.aligned {
            Some(aligned) if extra_bits >= ALIGNED_BITS => {
                value += (bits.take(extra_bits - ALIGNED_BITS)? as usize) << ALIGNED_BITS;
                value += usize::from(aligned.decode(&mut bits)?);
            }
            _ => value += bits.take(extra_bits)? as usize,
        }

        let offset = match value {
            0..REPEATED_OFFSETS => {
                repeats.swap(value, 0);
                repeats[0]
            }
            _ => {
                let offset = value - REPEATED_OFFSETS;
                repeats = [offset, repeats[0], repeats[1]];
                offset
            }
        };

        let distance = offset.checked_add(1)?;
        let from = output.len().checked_sub(distance)?;

        for index in 0..length.min(size - output.len()) {
            output.push(output[from + index]);
        }
    }

    Some(output)
}

pub(crate) fn unfilter_calls(bytes: &mut [u8], marker: u8) {
    let mut at = 0;
    while at + FILTER_SPAN < bytes.len() {
        if matches!(bytes[at], FILTER_CALL | FILTER_JUMP) && bytes[at + 1] == marker {
            let operand = at + 1;
            let mut target = [0u8; 4];
            target.copy_from_slice(&bytes[operand..operand + 4]);

            let absolute = u32::from_le_bytes(target) >> 8;
            let relative = absolute.wrapping_sub(at as u32);
            bytes[operand..operand + 4].copy_from_slice(&relative.to_le_bytes());
            at += FILTER_SPAN;
        } else {
            at += 1;
        }
    }
}
