pub struct CPU {
    pub register_a: u8,
    pub register_x: u8,
    pub status: u8,
    pub pc: u16,
    mem: [u8; 0xFFFF], // 64 KiB of RAM
}

impl CPU {
    pub fn new() -> Self {
        CPU {
            register_a: 0,
            register_x: 0,
            status: 0,
            pc: 0,
            mem: [0; 0xFFFF],
        }
    }

    /// Return a byte at addr from the memory
    fn mem_read(&self, addr: u16) -> u8 {
        self.mem[addr as usize]
    }

    /// Write a byte to the address addr in the memory
    fn mem_write(&mut self, addr: u16, data: u8) {
        self.mem[addr as usize] = data;
    }

    /// Read 2 bytes from the memory
    fn mem_read_u16(&mut self, addr: u16) -> u16 {
        // Address is in little-endian
        let lo = self.mem_read(addr) as u16;
        let hi = self.mem_read(addr + 1) as u16;
        (hi << 8) | (lo as u16)
    }

    /// Write 2 bytes to the memory
    fn mem_write_u16(&mut self, addr: u16, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;
        self.mem_write(addr, lo);
        self.mem_write(addr + 1, hi);
    }

    /// Reset the register state of the CPU and load the starting program address
    fn reset(&mut self) {
        self.register_a = 0;
        self.register_x = 0;
        self.status = 0;

        self.pc = self.mem_read_u16(0xFFFC);
    }

    /// Load a program to the memory
    pub fn load(&mut self, program: Vec<u8>) {
        self.mem[0x8000..(0x8000 + program.len())].copy_from_slice(&program);
        self.mem_write_u16(0xFFFC, 0x8000); // NES uses 0xFFFC to store program's start addr
    }

    /// Set the zero flag and negative flag according to the result
    fn update_zero_and_neg_flags(&mut self, result: u8) {
        // Zero flag
        if result == 0 {
            self.status |= 0b0000_0010;
        } else {
            self.status &= 0b1111_1101;
        }

        // Negative flag
        if result & 0b1000_0000 != 0 {
            self.status |= 0b1000_0000;
        } else {
            self.status &= 0b0111_1111;
        }
    }

    fn lda(&mut self, value: u8) {
        self.register_a = value;
        self.update_zero_and_neg_flags(self.register_a);
    }

    fn tax(&mut self) {
        self.register_x = self.register_a;
        self.update_zero_and_neg_flags(self.register_x);
    }

    fn inx(&mut self) {
        // Increment and allow overflow (but don't set overflow flag)
        self.register_x = self.register_x.wrapping_add(1);
        self.update_zero_and_neg_flags(self.register_x);
    }

    /// Run the given program
    pub fn run(&mut self) {
        loop {
            let opcode = self.mem_read(self.pc);
            self.pc += 1;

            match opcode {
                // LDA - Load to A
                0xA9 => {
                    let param = self.mem_read(self.pc);
                    self.pc += 1;

                    self.lda(param);
                }

                // TAX - Take A to X
                0xAA => self.tax(),

                // INX - Increment X
                0xe8 => self.inx(),

                // BRK - Break program
                0x00 => {
                    return;
                }

                _ => todo!(),
            }
        }
    }

    /// Load a program to memory and run it
    pub fn load_and_run(&mut self, program: Vec<u8>) {
        self.load(program);
        self.reset();
        self.run();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_0xa9_lda_immediate_load_data() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x05, 0x00]);
        assert_eq!(cpu.register_a, 0x05);
        assert!(cpu.status & 0b0000_0010 == 0b00);
        assert!(cpu.status & 0b1000_0000 == 0);
    }

    #[test]
    fn test_0xa9_lda_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x00, 0x00]);
        assert!(cpu.status & 0b0000_0010 == 0b10);
    }

    #[test]
    fn test_0xaa_tax_move_a_to_x() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x12, 0xaa, 0x00]);
        assert_eq!(cpu.register_x, 0x12)
    }

    #[test]
    fn test_5_ops_working_together() {
        // LDA #$c0
        // TAX
        // INX
        // BRK
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0xc0, 0xaa, 0xe8, 0x00]);

        assert_eq!(cpu.register_x, 0xc1)
    }

    #[test]
    fn test_inx_overflow() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0xff, 0xaa, 0xe8, 0xe8, 0x00]);

        assert_eq!(cpu.register_x, 1)
    }
}
