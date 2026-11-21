use super::{DecodeError, Decoded};
use super::{copy_match, output_buffer};

const MAIN_SYMBOLS: usize = 721;
const LENGTH_SYMBOLS: usize = 28;
const ALIGNED_SYMBOLS: usize = 8;
const ALL_SYMBOLS: usize = MAIN_SYMBOLS + LENGTH_SYMBOLS + ALIGNED_SYMBOLS;
const PRETREE_SYMBOLS: usize = 19;
const PRETREE_BITS: u32 = 4;
const NEW_TABLES: u16 = 720; // new code lengths follow
const LITERALS: u16 = 256;
const MATCH_LENGTH_BITS: u16 = 3;
const LONG_MATCH: u16 = 7;
const MIN_MATCH: usize = 2;
const OFFSET_SLOTS: usize = 58;
const REPEATED_OFFSETS: usize = 3;
const ALIGNED_BITS: u32 = 3;
const DEFAULT_ALIGNED_LENGTH: u8 = 3; // all 3: aligned tree off
const MAX_CODE_LENGTH: usize = 15;
const CODE_LENGTHS: usize = MAX_CODE_LENGTH + 1;
const WINDOW_BITS: u32 = 24;
const WIDE_LOW_BITS: u32 = 16;
const LENGTH_WRAP: u8 = 16;
const REPEAT_LENGTH: u16 = 16;
const SHORT_ZEROS: u16 = 17;
const LONG_ZEROS: u16 = 18;

pub(crate) struct Tables<'a> {
    length_base: &'a [u8],
    length_bits: &'a [u8],
    offset_bits: &'a [u8],
}

impl<'a> Tables<'a> {
    pub(crate) const SIZE: usize = LENGTH_SYMBOLS * 2 + OFFSET_SLOTS; // length bases, length bits, offset bits

    pub(crate) fn new(bytes: &'a [u8]) -> Decoded<Self> {
        let bytes = bytes.get(..Self::SIZE).ok_or(DecodeError::Truncated)?;
        let (lengths, offset_bits) = bytes.split_at(LENGTH_SYMBOLS * 2);
        let (length_base, length_bits) = lengths.split_at(LENGTH_SYMBOLS);
        Ok(Self {
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

    // the window may look past the end; skip refuses to use those bits
    fn peek(&mut self) -> u32 {
        while self.count < WINDOW_BITS {
            let byte = self.data.get(self.next).copied().unwrap_or(0);
            self.next += 1;
            self.buffer = (self.buffer << u8::BITS) | u64::from(byte);
            self.count += u8::BITS;
        }

        let window = (self.buffer >> (self.count - WINDOW_BITS)) & ((1 << WINDOW_BITS) - 1);

        window as u32
    }

    fn skip(&mut self, bits: u32) -> Decoded<()> {
        self.count = self.count.checked_sub(bits).ok_or(DecodeError::Corrupt)?;

        let fetched = self.next.saturating_mul(u8::BITS as usize);
        let used = fetched.saturating_sub(self.count as usize);
        match used <= self.data.len().saturating_mul(u8::BITS as usize) {
            true => Ok(()),
            false => Err(DecodeError::Truncated),
        }
    }

    fn take(&mut self, bits: u32) -> Decoded<u32> {
        match bits {
            0 => Ok(0),
            1..=WINDOW_BITS => {
                let value = self.peek() >> (WINDOW_BITS - bits);
                self.skip(bits)?;
                Ok(value)
            }
            _ if bits <= u32::BITS => {
                let high = self.take(bits - WIDE_LOW_BITS)?;
                Ok((high << WIDE_LOW_BITS) | self.take(WIDE_LOW_BITS)?)
            }
            _ => Err(DecodeError::Corrupt),
        }
    }
}

struct Huffman {
    limits: [u64; CODE_LENGTHS],
    starts: [u64; CODE_LENGTHS],
    firsts: [usize; CODE_LENGTHS],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Decoded<Self> {
        let mut counts = [0u64; CODE_LENGTHS];
        for length in lengths {
            *counts
                .get_mut(usize::from(*length))
                .ok_or(DecodeError::Corrupt)? += 1;
        }

        let mut symbols = (0..lengths.len())
            .filter(|symbol| lengths[*symbol] != 0)
            .map(|symbol| u16::try_from(symbol).ok())
            .collect::<Option<Vec<_>>>()
            .ok_or(DecodeError::Corrupt)?;
        symbols.sort_by_key(|symbol| lengths[usize::from(*symbol)]);

        let mut tree = Self {
            limits: [0; CODE_LENGTHS],
            starts: [0; CODE_LENGTHS],
            firsts: [0; CODE_LENGTHS],
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

        match total <= 1 << WINDOW_BITS {
            true => Ok(tree), // empty or one symbol leave codes unused
            false => Err(DecodeError::Corrupt),
        }
    }

    fn decode(&self, bits: &mut Bits<'_>) -> Decoded<u16> {
        let window = u64::from(bits.peek());
        let length = (1..=MAX_CODE_LENGTH)
            .find(|length| window < self.limits[*length])
            .ok_or(DecodeError::Corrupt)?;
        bits.skip(length as u32)?;

        let offset = (window - self.starts[length]) >> (WINDOW_BITS as usize - length);
        self.symbols
            .get(
                self.firsts[length]
                    .checked_add(offset as usize)
                    .ok_or(DecodeError::Corrupt)?,
            )
            .copied()
            .ok_or(DecodeError::Corrupt)
    }
}

struct Trees {
    main: Huffman,
    length: Huffman,
    aligned: Option<Huffman>,
}

fn read_trees(bits: &mut Bits<'_>, previous: &mut [u8; ALL_SYMBOLS]) -> Decoded<Trees> {
    if bits.take(1)? == 0 {
        previous.fill(0);
    }

    let pretree = (0..PRETREE_SYMBOLS)
        .map(|_| {
            let length = bits.take(PRETREE_BITS)?;
            u8::try_from(length).map_err(|_| DecodeError::Corrupt)
        })
        .collect::<Decoded<Vec<_>>>()?;
    let pretree = Huffman::new(&pretree)?;

    let mut lengths = Vec::with_capacity(ALL_SYMBOLS);
    while lengths.len() < ALL_SYMBOLS {
        let code = pretree.decode(bits)?;
        let (value, count) = match code {
            REPEAT_LENGTH => (lengths.last().copied().unwrap_or(0), 3 + bits.take(2)?),
            SHORT_ZEROS => (0, 3 + bits.take(3)?),
            LONG_ZEROS => (0, 11 + bits.take(7)?),
            delta => {
                let delta = u8::try_from(delta).map_err(|_| DecodeError::Corrupt)?;
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

    Ok(Trees {
        main: Huffman::new(main)?,
        length: Huffman::new(length)?,
        aligned: match uses_aligned {
            true => Some(Huffman::new(aligned)?),
            false => None,
        },
    })
}

pub(crate) fn decompress(source: &[u8], size: usize, tables: &Tables<'_>) -> Decoded<Vec<u8>> {
    let offset_base = tables
        .offset_bits
        .iter()
        .scan(0u32, |base, bits| {
            let current = *base;
            *base = base.checked_add(1u32.checked_shl(u32::from(*bits))?)?;
            Some(current)
        })
        .collect::<Vec<_>>();
    if offset_base.len() != OFFSET_SLOTS {
        return Err(DecodeError::Corrupt);
    }

    let mut bits = Bits::new(source);
    let mut previous = [0u8; ALL_SYMBOLS];
    let mut trees = read_trees(&mut bits, &mut previous)?;
    let mut output = output_buffer(size)?;
    let mut repeats = [0usize; REPEATED_OFFSETS];

    while output.len() < size {
        let symbol = trees.main.decode(&mut bits)?;

        if symbol < LITERALS {
            output.push(u8::try_from(symbol).map_err(|_| DecodeError::Corrupt)?);
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
            let extra = bits.take(u32::from(
                *tables.length_bits.get(index).ok_or(DecodeError::Corrupt)?,
            ))?;
            length += usize::from(*tables.length_base.get(index).ok_or(DecodeError::Corrupt)?)
                + extra as usize;
        }

        let extra_bits = u32::from(*tables.offset_bits.get(slot).ok_or(DecodeError::Corrupt)?);
        let mut value = *offset_base.get(slot).ok_or(DecodeError::Corrupt)? as usize;

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

        let distance = offset.checked_add(1).ok_or(DecodeError::Corrupt)?;
        copy_match(&mut output, distance, length, size)?;
    }

    Ok(output)
}
