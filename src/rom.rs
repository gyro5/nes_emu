#[derive(Debug, PartialEq)]
pub enum Mirroring {
    Vertical,
    Horizontal,
    FourScreen,
}

pub struct Rom {
    pub prg_rom: Vec<u8>,            // Program ROM for CPU
    pub chr_rom: Vec<u8>,            // Graphic ROM for PPU
    pub mapper: u8,                  // iNES mapper mode (only mapper 0 supported)
    pub screen_mirroring: Mirroring, // Mirroring mode
}

/*
iNES ROM format:
- 16-byte header
- Optional 512-byte trainer region (ignored)
- PRG ROM
- CHR ROM

Header format: 16 bytes
- First 4 bytes should be [4E 45 53 1A] ("NES\x1A")
- 1 byte for number of 16KiB PRG ROM banks
- 1 byte for number of 8KiB CHR ROM banks
- 2 control bytes
- 1 byte for PRG RAM in 8KBs
- Rest of header: must be all 0x00

Control byte 1: [7][6][5][4][3][2][1][0]
- [7-4]: 4 lower bits of mapper type
- [3]: 1 if four-screen VRAM layout
- [2]: 1 if has trainer region
- [1]: 1 if has battery-backed RAM (for game save)
- [0]: Mirroring, 0 for horizontal, 1 for vertical

Control byte 2: [7][6][5][4][3][2][1][0]
- [7-4]: 4 upper bits of mapper type
- [3-2]: 00 if iNES 1.0, 10 if iNES 2.0
- [1-0]: Should be 00 for iNES 1.0
*/

const NES_TAG: [u8; 4] = [0x4E, 0x45, 0x53, 0x1A];
const PRG_PAGE_SIZE: usize = 0x4000; // 16KiB
const CHR_PAGE_SIZE: usize = 0x2000; // 8KiB

impl Rom {
    pub fn new(raw: &[u8]) -> Result<Rom, String> {
        // Check length and first 4 bytes of header
        if raw.len() < 16 || raw[0..4] != NES_TAG {
            return Err("File is not in iNES format".to_string());
        }

        // Check mapper type (see note above about 4 upper bits and 4 lower bits)
        let mapper = (raw[7] & 0b1111_0000) | (raw[6] >> 4);

        // Get iNES format version
        let ines_ver = (raw[7] >> 2) & 0b11;
        if ines_ver != 0 {
            return Err("iNES 2.0 is not supported".to_string());
        }

        // Get mirroring mode
        let four_screen = (raw[6] & 0b1000) != 0;
        let vertical = (raw[6] & 0b1) != 0;
        let screen_mirroring = match (four_screen, vertical) {
            (true, _) => Mirroring::FourScreen,
            (false, true) => Mirroring::Vertical,
            (false, false) => Mirroring::Horizontal,
        };

        // Get PRG and CHR part sizes
        let prg_size = raw[4] as usize * PRG_PAGE_SIZE;
        let chr_size = raw[5] as usize * CHR_PAGE_SIZE;

        // Check if there is a trainer region that should be skipped
        let trainer_to_skip = (raw[6] & 0b100) != 0;

        // Calculate starting position of PRG and CHR regions
        let prg_start = 16 + if trainer_to_skip { 512 } else { 0 };
        let chr_start = prg_start + prg_size; // CHR right after PRG

        Ok(Rom {
            prg_rom: raw[prg_start..(prg_start + prg_size)].to_vec(),
            chr_rom: raw[chr_start..(chr_start + chr_size)].to_vec(),
            mapper,
            screen_mirroring,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_file_not_ines() {
        // Last byte is different from expected
        let result = Rom::new(&vec![0x4E, 0x45, 0x53, 0x1B]);
        assert!(result.is_err_and(|msg| { msg == "File is not in iNES format" }));
    }

    #[test]
    fn test_good_ines_file() {
        let header = vec![
            0x4E,        // |
            0x45,        // |
            0x53,        // |
            0x1A,        // +-> 4 header bytes
            0x01,        // 1 page PRG
            0x01,        // 1 page CHR
            0b0000_0001, // 1 in last bit for vertical mirroring
            0b1111_0000, // "0000" for iNES 1.0
        ];
        let header_res = vec![0; 16 - header.len()];
        let raw_prg = vec![0; PRG_PAGE_SIZE];
        let raw_chr = vec![0; CHR_PAGE_SIZE];
        let raw = [header, header_res, raw_prg, raw_chr].concat();
        assert_eq!(raw.len(), 16 + PRG_PAGE_SIZE + CHR_PAGE_SIZE);

        let result = Rom::new(&raw);
        assert!(result.is_ok_and(|rom| {
            rom.prg_rom.len() == PRG_PAGE_SIZE
                && rom.chr_rom.len() == CHR_PAGE_SIZE
                && rom.mapper == 0b1111_0000
                && rom.screen_mirroring == Mirroring::Vertical
        }))
    }
}
