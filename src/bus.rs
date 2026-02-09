use crate::mem::Mem;

pub struct Bus {
    cpu_vram: [u8; 2048], // 2 KiB of ram
}

impl Bus {
    pub fn new() -> Self {
        Bus {
            cpu_vram: [0; 2048],
        }
    }
}

/*
About RAM mirroring:

- CPU's 2 KiB of memory is mirrored 3 times (4 copies in total), at addresses
[0x000..0x800], [0x800..0x1000], [0x1000..0x1800], [0x1800..0x2000] (ie. ignore
2 high bits of the 13-bit address, only use 11 bits).

- PPU memory is also mirrored at [0x2000..0x2008], ..., [0x2008..0x4000] (ie.
mirrored many times the 8 bits).

This is because how the physical wiring works (ie. the chip only uses 11 pin
for memory address for example, so the 2 high bits are ignored).
*/

const RAM_START: u16 = 0x0000;
const RAM_MIRROR_END: u16 = 0x1FFF;
const PPU_REGISTERS_START: u16 = 0x2000;
const PPU_REGISTERS_MIRROR_END: u16 = 0x3FFF;

impl Mem for Bus {
    fn mem_read(&self, addr: u16) -> u8 {
        match addr {
            RAM_START..=RAM_MIRROR_END => {
                // Only take 11 bits
                let mirror_down_addr = addr & 0b111_1111_1111;
                self.cpu_vram[mirror_down_addr as usize]
            }

            PPU_REGISTERS_START..=PPU_REGISTERS_MIRROR_END => {
                // TODO comment about the bit mask
                let _mirror_down_addr = addr & 0b00100000_00000111;
                todo!("PPU is not supported yet")
            }

            _ => {
                println!("Ignoring memory access at address {addr:#x}");
                0
            }
        }
    }

    fn mem_write(&mut self, addr: u16, data: u8) {
        match addr {
            RAM_START..=RAM_MIRROR_END => {
                // Only take 11 bits
                let mirror_down_addr = addr & 0b111_1111_1111;
                self.cpu_vram[mirror_down_addr as usize] = data;
            }

            PPU_REGISTERS_START..=PPU_REGISTERS_MIRROR_END => {
                let _mirror_down_addr = addr & 0b00100000_00000111;
                todo!("PPU is not supported yet");
            }

            _ => {
                println!("Ignoring memory write at address {addr:#x}");
            }
        }
    }
}
